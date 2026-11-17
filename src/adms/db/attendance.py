"""
``CheckInOut`` writes, plus the lossless ``ADMS_ATTLOG_RAW`` archive.

The critical property: a punch written here is **indistinguishable** from one the desktop tool
wrote. Same stored procedure, same ``KieuCham='1'``, same ``NguonCham=''``. That is what lets a
site run ADMS collection and desktop pulls against one database during a migration — and what
makes the shared ``(MaChamCong, GioCham)`` dedup key work in both directions.

Why the raw archive exists
--------------------------
``CheckInOut`` has no column for the punch state, verification method or work code — the desktop
app hardcodes ``KieuCham`` and discards the rest. Over ADMS the device sends all of it, and once
acknowledged it is deleted from the device. Dropping it on the floor would make the upload lossy
in a way nothing could recover, so ``ADMS_ATTLOG_RAW`` keeps the full record while ``CheckInOut``
stays byte-compatible with the legacy shape.
"""

from __future__ import annotations

import datetime as dt

from ..errors import AttendanceDbError
from ..models import AttendanceLog, PunchKey
from .connection import BATCH_SIZE, ConnectionFactory, chunked, transaction
from .schema import (
    COL_CC_GIOCHAM,
    COL_CC_MACHAMCONG,
    COL_CC_MASOMAY,
    KIEU_CHAM,
    NGUON_CHAM,
    PROC_CHECKINOUT_ADD,
    TABLE_ADMS_ATTLOG_RAW,
    TABLE_PUNCHES,
)

__all__ = ["SqlServerAttendanceStore"]


class SqlServerAttendanceStore:
    """Implements :class:`~adms.ports.AttendanceStore`."""

    __slots__ = ("_factory", "_log")

    def __init__(self, factory: ConnectionFactory, log=None) -> None:
        self._factory = factory
        self._log = log

    # ── Duplicate detection ──────────────────────────────────────────────────────────────

    def existing_punch_keys(
        self, machine_id: int, from_inclusive: dt.datetime, to_exclusive: dt.datetime
    ) -> set[PunchKey]:
        """
        ``(MaChamCong, GioCham)`` already stored for this machine in ``[from, to)``.

        NOTE: reading the deployed procedure shows it deduplicates. The desktop tool's comments state
        that ``dbo.CheckInOut_add`` is a bare INSERT and that duplicate suppression is therefore the
        caller's only guard. **That is not true of this database.** The deployed procedure is::

            IF NOT EXISTS (SELECT TOP 1 MaChamCong, GioCham FROM CheckInOut
                           WHERE MaChamCong = @MaChamCong AND GioCham = @GioCham)
                INSERT INTO CheckInOut (...) VALUES (...)

        So the database already deduplicates on exactly the key this method returns, and it does so
        **without scoping to MaSoMay** — its check is global across machines, while this one is
        per-machine and therefore narrower.

        This method is kept for two reasons that survive that discovery:

        * It keeps the reported ``inserted`` count truthful. Without it we would report every row
          handed to the procedure, including ones the procedure silently discarded.
        * It keeps the service correct against a ATTENDANCEDB instance whose procedure lacks the guard,
          or against a future edit to it. Depending on a stored procedure's body for a correctness
          property the application promises is a coupling worth not having.

        Cost is one indexed SELECT per batch, served by ``IX_CheckInOut_GioCham``.
        """
        sql = f"""
            SELECT {COL_CC_MACHAMCONG}, {COL_CC_GIOCHAM}
              FROM {TABLE_PUNCHES}
             WHERE {COL_CC_MASOMAY}   = ?
               AND {COL_CC_GIOCHAM}  >= ?
               AND {COL_CC_GIOCHAM}   < ?
        """
        try:
            connection = self._factory.get()
            cursor = connection.cursor()
            try:
                cursor.execute(sql, (machine_id, from_inclusive, to_exclusive))
                return {
                    (int(row[0]), row[1])
                    for row in cursor.fetchall()
                    if row[0] is not None and row[1] is not None
                }
            finally:
                cursor.close()
        except AttendanceDbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AttendanceDbError("Failed to read existing attendance keys.") from exc

    # ── Insert ───────────────────────────────────────────────────────────────────────────

    def add_attendance(
        self,
        logs: list[AttendanceLog],
        *,
        machine_id: int,
        machine_name: str,
        existing_keys: set[PunchKey] | None = None,
    ) -> int:
        """
        Insert punches through ``dbo.CheckInOut_add``, one transaction for the batch.

        Three filters run before the insert, in this order:

        1. Non-numeric PINs are dropped — ``MaChamCong`` is an ``int`` column, so there is nowhere
           to put them. Logged, because it means a device PIN that will never reach payroll.
        2. In-batch duplicates on ``(PIN, timestamp)`` are collapsed. Devices do occasionally send
           the same record twice in one body.
        3. Keys already in the database are removed, which is what makes a device retry idempotent.
           The deployed procedure guards this too (see :meth:`existing_punch_keys`), so this filter is
           belt and braces — but it is what makes the returned count reflect rows actually written
           rather than rows merely offered.

        Returns rows attempted after filtering. The procedure reports nothing, so an exact count is
        not available; since filter 3 has already removed the keys the procedure would reject, this is
        accurate except where the procedure's cross-machine check rejects a row our per-machine check
        allowed through.

        Known divergence (V4): "rows attempted after filtering" is rows **offered** to
        ``dbo.CheckInOut_add``, not rows confirmed written. Requirement 14.7 asks for the count of
        rows written; after the three filters above this value is accurate *except* for the gap
        between this store's per-machine duplicate check and the procedure's own cross-machine
        ``IF NOT EXISTS`` on ``(MaChamCong, GioCham)`` (see :meth:`existing_punch_keys`) — a row this
        method's filters let through can still be silently rejected by the procedure if another
        machine already holds that exact key. With ``MAYCHAMCONG.IDMCC = 1`` on ten of the eleven
        machines, that window is narrow but not empty. ODBC's ``executemany`` gives no reliable
        per-statement rowcount, so this gap cannot be closed with the current driver interface --
        there is no way to ask the procedure which of the offered rows it actually inserted.

        This is not changed here: the count returned by this method is not what reaches the device.
        ``AdmsService`` reports the count the device *sent* (D17) rather than a stored or verified
        count, because firmware reads a short count as partial rejection and re-sends; changing what
        this method reports could change device-facing behaviour, which is out of scope for
        recording this divergence.
        """
        if not logs:
            return 0

        seen: set[PunchKey] = set()
        rows: list[tuple] = []
        skipped_non_numeric = 0

        for log in logs:
            key = log.key
            if key is None:
                skipped_non_numeric += 1
                continue
            if key in seen:
                continue
            seen.add(key)
            if existing_keys is not None and key in existing_keys:
                continue
            pin, timestamp = key
            rows.append(
                (
                    pin,
                    # NgayCham is the date bucket, GioCham the full timestamp. Both are written
                    # from the same value so they can never disagree.
                    timestamp.date(),
                    timestamp,
                    KIEU_CHAM,
                    NGUON_CHAM,
                    machine_id,
                    machine_name[:30],
                )
            )

        if skipped_non_numeric and self._log is not None:
            self._log.warn(
                "Punches with a non-numeric PIN were skipped; NHANVIEN.MaChamCong is an integer key.",
                count=skipped_non_numeric,
            )

        if not rows:
            return 0

        sql = f"{{CALL {PROC_CHECKINOUT_ADD} (?, ?, ?, ?, ?, ?, ?)}}"
        inserted = 0
        with transaction(self._factory, what="insert attendance records") as cursor:
            for chunk in chunked(rows, BATCH_SIZE):
                # executemany, not a concatenated EXEC list: it keeps every value bound as a
                # parameter and keeps the statement text constant so the plan is reused.
                cursor.executemany(sql, chunk)
                inserted += len(chunk)

        return inserted

    # ── Lossless archive ─────────────────────────────────────────────────────────────────

    def archive_attlog(self, serial: str, logs: list[AttendanceLog]) -> int:
        """
        Store the full push detail in ``ADMS_ATTLOG_RAW``.

        Inserted with ``WHERE NOT EXISTS`` against the table's natural key rather than relying on
        the unique index to reject duplicates: a constraint violation would abort the whole
        transaction, and on the retry path duplicates are expected, not exceptional.

        Unlike :meth:`add_attendance` this keeps non-numeric PINs. The archive's job is to record
        what arrived; filtering belongs to the projection into ``CheckInOut``.
        """
        if not logs:
            return 0

        sql = f"""
            INSERT INTO {TABLE_ADMS_ATTLOG_RAW}
                (SerialNumber, Pin, PunchTime, Status, Verify, WorkCode, Reserved1, Reserved2, ReceivedUtc)
            SELECT ?, ?, ?, ?, ?, ?, ?, ?, SYSUTCDATETIME()
             WHERE NOT EXISTS (
                   SELECT 1 FROM {TABLE_ADMS_ATTLOG_RAW}
                    WHERE SerialNumber = ? AND Pin = ? AND PunchTime = ? AND Status = ?
             )
        """
        rows = [
            (
                serial,
                log.pin[:32],
                log.timestamp,
                log.status,
                int(log.verify),
                log.work_code,
                log.reserved1[:64],
                log.reserved2[:64],
                serial,
                log.pin[:32],
                log.timestamp,
                log.status,
            )
            for log in logs
        ]

        written = 0
        with transaction(self._factory, what="archive raw attendance records") as cursor:
            for chunk in chunked(rows, BATCH_SIZE):
                cursor.executemany(sql, chunk)
                written += len(chunk)
        return written
