"""
Property test for ``adms.db.connection.ConnectionFactory`` -- per-thread connection caching,
validation, and reconnect-once behaviour.

One property lives here, in one test, exercised with **real threads** (``threading.Thread``), not
mocked concurrency: a ``pyodbc`` connection used concurrently from two threads corrupts result sets
in a way that presents as nonsense data, not a clean error, and that failure mode does not show up
against a synchronous stand-in for "two callers at once". A real thread pool is the only thing that
proves ``threading.local`` is actually doing its job here.

``ConnectionFactory._open`` does ``import pyodbc`` and calls ``pyodbc.connect(...)`` directly -- the
class takes no injectable ``connect`` parameter, so the only seam is the module itself. This module
installs a fake ``pyodbc`` into ``sys.modules`` for the duration of each test via ``monkeypatch``, with
a ``connect`` callable that counts calls and hands back simple fake connection objects whose "is this
still good" answer (a plain ``SELECT 1`` through a fake cursor) is fully controllable. **No real driver
is imported and nothing is connected to** -- the real ``pyodbc`` package need not even be installed for
this test to run or to mean anything.
"""

from __future__ import annotations

import sys
import threading
import types
from typing import Any

import pytest

from adms.db.connection import ConnectionFactory

# ── The fake driver ──────────────────────────────────────────────────────────────────────────


class _FakeCursor:
    """
    Answers ``SELECT 1`` based on whether its owning connection is still marked alive.

    That is the entire validation surface ``ConnectionFactory._is_alive`` uses: ``cursor()``,
    ``execute``, ``fetchall``, ``close``. Nothing else is implemented, on purpose -- a fake with a
    bigger surface than the real code needs would silently stop testing what the factory actually
    calls.
    """

    __slots__ = ("_connection",)

    def __init__(self, connection: _FakeConnection) -> None:
        self._connection = connection

    def execute(self, _statement: str, *_params: object) -> None:
        if not self._connection.alive:
            raise RuntimeError("simulated stale connection: SELECT 1 failed")

    def fetchall(self) -> list[object]:
        return []

    def close(self) -> None:
        pass


class _FakeConnection:
    """
    A stand-in ``pyodbc`` connection.

    ``owner_thread`` records which OS thread actually created it, so the per-thread-distinctness half
    of the property can be checked by more than object identity -- the connection itself can say which
    thread it belongs to.
    """

    __slots__ = ("alive", "closed", "owner_thread", "timeout")

    def __init__(self) -> None:
        self.alive = True
        self.closed = False
        self.timeout: int | None = None
        self.owner_thread = threading.current_thread().ident

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self)

    def close(self) -> None:
        self.closed = True


class _FakeConnect:
    """
    The injected ``pyodbc.connect`` callable.

    Counts calls and keeps every connection it ever produced under a lock, because this is exercised
    by real concurrent threads and the whole point of the first half of the property is "how many
    times, and from where, did the factory actually dial out".
    """

    def __init__(self) -> None:
        self.calls = 0
        self.connections: list[_FakeConnection] = []
        self.last_connection_string: str = ""
        self.last_autocommit: bool = False
        self._lock = threading.Lock()

    def __call__(self, connection_string: str, autocommit: bool = False) -> _FakeConnection:
        # connection_string and autocommit are recorded rather than ignored: pyodbc.connect is
        # called with autocommit as a keyword, so the parameter name here must match exactly, and
        # recording both is what lets a test assert on them later if it ever needs to.
        with self._lock:
            self.calls += 1
            self.last_connection_string = connection_string
            self.last_autocommit = autocommit
            connection = _FakeConnection()
            self.connections.append(connection)
            return connection


@pytest.fixture
def fake_connect(monkeypatch: pytest.MonkeyPatch) -> _FakeConnect:
    """
    Install a fake ``pyodbc`` module for the duration of one test.

    ``monkeypatch.setitem(sys.modules, ...)`` rather than patching an attribute on the real package:
    ``import pyodbc`` inside ``_open`` resolves against ``sys.modules`` first, so seeding that cache is
    enough to make the import succeed with our fake regardless of whether the real driver is installed,
    and pytest restores whatever was there afterwards.
    """
    connect = _FakeConnect()
    fake_module = types.SimpleNamespace(connect=connect)
    monkeypatch.setitem(sys.modules, "pyodbc", fake_module)
    return connect


# ── The property ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("thread_count", [2, 6, 17], ids=["two", "six", "seventeen"])
def test_property_62_connections_are_per_thread_validated_and_reconnected_once(
    fake_connect: _FakeConnect, thread_count: int
) -> None:
    # Feature: adms-attendance-system, Property 62: Connections are per-thread, validated, and
    # reconnected once. For any number of calling threads, each receives a distinct connection and
    # no connection is shared; for any cached connection that fails a trivial query, it is closed
    # and exactly one reconnect is attempted; and after shutdown, every connection the factory
    # opened is closed.
    factory = ConnectionFactory("fake connection string", query_timeout=5)

    # ---- Part 1: real threads, distinct connections, no sharing --------------------------------
    # A barrier maximises the chance that get() is entered by every thread at close to the same
    # moment, which is exactly the situation a shared (rather than thread-local) connection would
    # get wrong.
    received: dict[int, Any] = {}
    barrier = threading.Barrier(thread_count)

    def worker(index: int) -> None:
        barrier.wait()
        received[index] = factory.get()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(thread_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert all(not thread.is_alive() for thread in threads), "a worker thread did not finish in time"
    assert len(received) == thread_count, "not every thread returned a connection"

    connection_identities = {id(conn) for conn in received.values()}
    assert len(connection_identities) == thread_count, (
        f"expected {thread_count} distinct connection objects from {thread_count} threads, got "
        f"{len(connection_identities)} distinct objects -- a connection was shared"
    )
    # Each connection really was opened on the thread that ended up holding it: this is thread-local
    # caching keyed by the calling thread, not, say, a pool indexed by arrival order.
    for index, conn in received.items():
        assert conn.owner_thread == threads[index].ident, (
            f"thread {index}'s connection was actually opened on a different thread"
        )
    assert fake_connect.calls == thread_count, (
        f"expected exactly one connect() per thread on first use, got {fake_connect.calls} calls "
        f"for {thread_count} threads"
    )

    # ---- Part 2: a live cached connection is reused, not reopened, on its own thread -----------
    # Established on the thread running this test, which is distinct from every worker above -- so
    # this exercises a fresh thread-local slot, not one of the eight already populated.
    main_connection = factory.get()
    assert id(main_connection) not in connection_identities
    calls_after_main_open = fake_connect.calls
    assert calls_after_main_open == thread_count + 1
    assert factory.get() is main_connection, "a live cached connection must be returned unchanged"
    assert fake_connect.calls == calls_after_main_open, "a live connection must not be reopened"

    # ---- Part 3: a failed validation closes the stale connection and reconnects exactly once ----
    main_connection.alive = False  # the next SELECT 1 through it will now raise
    calls_before_reconnect = fake_connect.calls

    reconnected = factory.get()

    assert main_connection.closed, "a connection that failed validation must be closed"
    assert reconnected is not main_connection, "the stale connection must never be handed out again"
    assert fake_connect.calls == calls_before_reconnect + 1, (
        "a failed validation must cause exactly one reconnect -- not zero, and not a retry loop"
    )
    # The reconnected connection is itself live and now cached, so nothing reconnects again on top
    # of it -- "reconnected once" means once, not "once per subsequent call".
    calls_after_reconnect = fake_connect.calls
    assert factory.get() is reconnected
    assert fake_connect.calls == calls_after_reconnect

    # ---- Part 4: close() shuts down every connection the factory ever opened -------------------
    all_opened = list(fake_connect.connections)
    assert len(all_opened) == thread_count + 2  # one per worker thread, plus main's two (stale + new)
    assert any(not conn.closed for conn in all_opened), "sanity: not everything was closed already"

    factory.close()

    assert all(conn.closed for conn in all_opened), (
        "close() must close every connection the factory ever handed out, including ones already "
        "discarded by a failed reconnect"
    )
