"""
SQL Server connectivity.

Raw ODBC through ``pyodbc``, no ORM -- the same choice the desktop pull tool makes with
``Microsoft.Data.SqlClient`` and for the same reason: ATTENDANCEDB is a legacy schema this codebase does
not own and must not migrate. An ORM would want to model it, and the first thing a model wants is a
migration.

Two rules hold for every statement in this package:

* **Every value is a parameter.** Identifiers are module-level constants; values are ``?``
  placeholders. Nothing is ever formatted into SQL text.
* **The connection string never escapes.** Driver errors are re-raised as
  :class:`~adms.errors.AttendanceDbError` with a fixed message, because ODBC error text frequently
  embeds the DSN it was handed -- password included.

Threading and connection reuse
------------------------------
Connections are cached **per thread** in a :class:`threading.local`.

That is not a detail. A ``pyodbc`` connection must not be used concurrently from two threads, and
this service is hosted by ``waitress``, which serves from a thread pool -- so a single shared
connection would corrupt result sets under load in a way that shows up as nonsense data rather than a
clean error. One connection per worker thread bounds the total to waitress's thread count (see
``adms/hosting/serve.py``, which keeps that number deliberately small).

Reuse still matters: a cold TCP + TLS + login handshake to a remote SQL Server is 100-300 ms, and paying
it on every ``getrequest`` poll from every device would dominate both latency and the server's login
rate. The cost of reuse is stale handles -- the far side may have dropped an idle socket -- so
:meth:`ConnectionFactory.get` validates with ``SELECT 1`` and reconnects once on failure, which is
cheaper than failing a real batch to discover it.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Any, Iterator

from ..errors import AttendanceDbError, ConfigError

__all__ = ["ConnectionFactory", "transaction", "chunked", "BATCH_SIZE", "DELETE_CHUNK_SIZE"]

#: Rows per round trip for batched writes. 100 x 7 parameters = 700, well under SQL Server's
#: 2100-parameter ceiling -- the same bound ``SqlServerAttendanceDb`` uses.
BATCH_SIZE = 100

#: Keys per DELETE/IN(...) list, same rationale with a wider margin.
DELETE_CHUNK_SIZE = 1000


def chunked(items: list, size: int) -> Iterator[list]:
    """Yield ``items`` in slices of at most ``size``."""
    for start in range(0, len(items), size):
        yield items[start : start + size]


class ConnectionFactory:
    """
    Opens and caches one ``pyodbc`` connection per calling thread.

    Safe to share the factory itself across threads; the connections it hands out are not shared.
    """

    __slots__ = ("_connection_string", "_query_timeout", "_local", "_log", "_all", "_all_lock")

    def __init__(self, connection_string: str, *, query_timeout: int = 25, log=None) -> None:
        if not connection_string or not connection_string.strip():
            raise ConfigError("An empty SQL connection string was supplied.")
        self._connection_string = connection_string
        self._query_timeout = query_timeout
        self._local = threading.local()
        self._log = log
        # Every connection handed out, so close() can shut them all down on process exit. Held as a
        # plain list under a lock rather than a WeakSet: pyodbc connections are not weak-referenceable
        # on every build, and the count is bounded by the thread pool size anyway.
        self._all: list[Any] = []
        self._all_lock = threading.Lock()

    def get(self) -> Any:
        """Return this thread's connection, reconnecting once if the cached one is dead."""
        connection = getattr(self._local, "connection", None)
        if connection is not None and self._is_alive(connection):
            return connection

        if connection is not None:
            self._discard(connection)

        connection = self._open()
        self._local.connection = connection
        with self._all_lock:
            self._all.append(connection)
        return connection

    def _open(self) -> Any:
        try:
            import pyodbc
        except ImportError as exc:  # pragma: no cover - deployment problem, not a runtime one
            raise ConfigError(
                "pyodbc is not installed. Run 'pip install -r requirements.txt' in the site's "
                "virtual environment."
            ) from exc

        try:
            connection = pyodbc.connect(self._connection_string, autocommit=False)
            connection.timeout = self._query_timeout
            return connection
        except Exception as exc:  # noqa: BLE001 - pyodbc raises several unrelated error classes
            # str(exc) is deliberately not included: ODBC error text routinely echoes the full DSN.
            raise AttendanceDbError("Could not connect to the attendance database.") from exc

    def _is_alive(self, connection: Any) -> bool:
        try:
            cursor = connection.cursor()
            try:
                cursor.execute("SELECT 1")
                cursor.fetchall()
            finally:
                cursor.close()
            return True
        except Exception:  # noqa: BLE001 - any failure means "reconnect", never "propagate"
            if self._log is not None:
                self._log.info("Cached SQL connection was stale; reconnecting.")
            return False

    def _discard(self, connection: Any) -> None:
        self._local.connection = None
        with self._all_lock:
            if connection in self._all:
                self._all.remove(connection)
        try:
            connection.close()
        except Exception:  # noqa: BLE001
            pass

    def close(self) -> None:
        """Close every connection this factory opened. For shutdown and tests."""
        with self._all_lock:
            connections, self._all = self._all, []
        for connection in connections:
            try:
                connection.close()
            except Exception:  # noqa: BLE001
                pass
        self._local = threading.local()

    def test(self) -> None:
        """Cheap reachability and credentials check. Raises on failure."""
        cursor = self.get().cursor()
        try:
            cursor.execute("SELECT 1")
            cursor.fetchall()
        except Exception as exc:  # noqa: BLE001
            raise AttendanceDbError("The attendance database rejected a test query.") from exc
        finally:
            cursor.close()


@contextmanager
def transaction(factory: ConnectionFactory, *, what: str) -> Iterator[Any]:
    """
    Run a block in one explicit transaction on this thread's connection, yielding a cursor.

    Commit on success, roll back on any failure, and re-raise as
    :class:`~adms.errors.AttendanceDbError` so no driver text -- and therefore no connection detail --
    reaches a caller or a log. ``what`` becomes the message: it must describe the operation, never the
    data.

    All-or-nothing matters more here than in a desktop pull. A device re-sends anything we do not
    acknowledge, so a half-applied batch would be re-sent and partly duplicated; a fully rolled back
    one is simply re-sent and stored once.
    """
    connection = factory.get()
    cursor = connection.cursor()
    try:
        yield cursor
        connection.commit()
    except AttendanceDbError:
        _rollback(connection)
        raise
    except Exception as exc:  # noqa: BLE001
        _rollback(connection)
        raise AttendanceDbError(f"Failed to {what}.") from exc
    finally:
        try:
            cursor.close()
        except Exception:  # noqa: BLE001
            pass


def _rollback(connection: Any) -> None:
    try:
        connection.rollback()
    except Exception:  # noqa: BLE001 - the original failure is what matters
        pass
