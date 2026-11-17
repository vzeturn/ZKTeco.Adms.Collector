"""
``ADMS_COMMAND`` — the pull-based downlink queue.

Delivery semantics: **at most once.** :meth:`SqlServerCommandQueue.dequeue` claims rows in the
same statement that reads them (``UPDATE … OUTPUT``), so two concurrent invocations polling for the
same device cannot hand out the same command twice.

That bias is deliberate. The alternative — read, dispatch, mark sent — risks redelivering a
command whose ack was lost, and this queue can carry ``CLEAR DATA`` and ``AC_UNLOCK``. A command
that quietly needs re-queueing is a nuisance; a door that opens twice, or a device wiped twice, is
not. Commands that are dispatched but never acked are visible as ``Status='Sent'`` with a
``SentUtc`` in the past, which is a queryable condition an operator can act on.
"""

from __future__ import annotations

from ..errors import AttendanceDbError
from ..models import CommandAck, DeviceCommand
from .connection import ConnectionFactory, transaction
from .schema import TABLE_ADMS_COMMAND

__all__ = ["SqlServerCommandQueue"]


class SqlServerCommandQueue:
    """Implements :class:`~adms.ports.CommandQueue`."""

    __slots__ = ("_factory", "_log")

    def __init__(self, factory: ConnectionFactory, log=None) -> None:
        self._factory = factory
        self._log = log

    def dequeue(self, serial: str, limit: int) -> list[DeviceCommand]:
        """
        Claim up to ``limit`` pending commands and return them in queue order.

        One statement does the read and the claim. ``READPAST`` skips rows another transaction has
        locked instead of blocking on them: a blocked poll would hold the device's HTTP request
        open until timeout, and the device would treat that as a server failure and back off for
        ``ErrorDelay`` seconds.
        """
        capped = max(0, min(int(limit), 100))
        if capped == 0:
            return []

        sql = f"""
            WITH claimed AS (
                SELECT TOP (?) CommandId, CommandText, Status, SentUtc
                  FROM {TABLE_ADMS_COMMAND} WITH (ROWLOCK, READPAST, UPDLOCK)
                 WHERE SerialNumber = ? AND Status = 'Pending'
                 ORDER BY CommandId
            )
            UPDATE claimed
               SET Status  = 'Sent',
                   SentUtc = SYSUTCDATETIME()
            OUTPUT inserted.CommandId, inserted.CommandText;
        """
        try:
            with transaction(self._factory, what="claim queued device commands") as cursor:
                cursor.execute(sql, (capped, serial))
                rows = cursor.fetchall()
        except AttendanceDbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AttendanceDbError("Failed to read the device command queue.") from exc

        return [DeviceCommand(command_id=int(row[0]), body=(row[1] or "").strip()) for row in rows]

    def ack(self, serial: str, acks: list[CommandAck]) -> int:
        """
        Record device results.

        Scoped by ``SerialNumber`` as well as ``CommandId`` so a device cannot acknowledge — and
        thereby close — a command queued for a different device. Since the id travels to the device
        and comes back unverified, that scoping is the only thing making the ack trustworthy.
        """
        if not acks:
            return 0

        sql = f"""
            UPDATE {TABLE_ADMS_COMMAND}
               SET Status     = ?,
                   ReturnCode = ?,
                   ReturnCmd  = ?,
                   AckedUtc   = SYSUTCDATETIME()
             WHERE CommandId = ? AND SerialNumber = ?
        """
        rows = [
            (
                "Done" if ack.succeeded else "Failed",
                ack.return_code,
                (ack.command or "")[:64],
                ack.command_id,
                serial,
            )
            for ack in acks
        ]

        with transaction(self._factory, what="record device command acknowledgements") as cursor:
            cursor.executemany(sql, rows)
        return len(rows)

    def pins_with_recent_request(self, serial: str, pins: set[int], since) -> set[int]:
        """
        Which of ``pins`` this device was already asked about since ``since``.

        Matches on ``CommandText LIKE '%PIN=<pin>%'``. That is a string match rather than a proper
        column, and the reason is worth stating: adding a ``TargetPin`` column would mean the collector
        owning a schema change to a table an operator also writes to by hand, for a query that runs at
        most once per ATTLOG batch over a filtered, bounded set of rows.

        The pattern is built from an integer, never from device input -- ``pins`` are already parsed
        ``int`` values -- so there is nothing to escape. The trailing delimiter guard matters though:
        ``PIN=12`` would otherwise match ``PIN=123``, so the LIKE requires the PIN to be followed by
        end-of-string or a non-digit.
        """
        if not pins:
            return set()

        requested: set[int] = set()
        try:
            connection = self._factory.get()
            cursor = connection.cursor()
            try:
                for pin in sorted(pins):
                    cursor.execute(
                        f"""
                        SELECT TOP 1 1 FROM {TABLE_ADMS_COMMAND}
                         WHERE SerialNumber = ?
                           AND CreatedUtc  >= ?
                           AND (CommandText LIKE ? OR CommandText LIKE ?)
                        """,
                        (serial, since, f"%PIN={pin}", f"%PIN={pin}[^0-9]%"),
                    )
                    if cursor.fetchone() is not None:
                        requested.add(pin)
            finally:
                cursor.close()
        except AttendanceDbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AttendanceDbError("Failed to check recent enrolment requests.") from exc

        return requested

    def enqueue(self, serial: str, body: str) -> int:
        """
        Queue one command. Returns the new ``CommandId``.

        The id is fetched with ``SCOPE_IDENTITY()`` in the same batch, so it cannot pick up an
        identity value from a trigger or another session the way ``@@IDENTITY`` can.

        Not called by the request path — this exists for the operator tooling and for an
        administrative job that mirrors the roster down to devices.
        """
        text = (body or "").strip()
        if not text:
            raise ValueError("Refusing to queue an empty command.")

        sql = f"""
            INSERT INTO {TABLE_ADMS_COMMAND} (SerialNumber, CommandText, Status, CreatedUtc)
            VALUES (?, ?, 'Pending', SYSUTCDATETIME());
            SELECT CAST(SCOPE_IDENTITY() AS INT);
        """
        with transaction(self._factory, what="queue a device command") as cursor:
            cursor.execute(sql, (serial, text))
            # The INSERT produces a rowcount-only result set; step past it to reach the SELECT.
            while cursor.description is None:
                if not cursor.nextset():
                    raise AttendanceDbError("Queued the command but could not read back its id.")
            row = cursor.fetchone()
            if row is None or row[0] is None:
                raise AttendanceDbError("Queued the command but could not read back its id.")
            return int(row[0])
