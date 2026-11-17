"""
``NHANVIEN`` upsert from device ``USER`` records (device → DB).

A MERGE keyed on ``MaChamCong``, with one asymmetry that matters: the UPDATE branch does **not**
touch ``MaNhanVien``. A device has no concept of an HR employee code, so refreshing an existing
employee from a device must never overwrite the real code someone typed into the HR system —
that is not recoverable from the device side. On INSERT the column is NOT NULL and has to be
given something, so it falls back to the PIN (see :func:`~adms.db.schema.resolve_employee_code`).

This is the same contract as ``SqlServerAttendanceDb.UpsertEmployees``; the asymmetry is
reproduced deliberately rather than reinvented.
"""

from __future__ import annotations

from ..errors import AttendanceDbError
from ..models import DeviceUser
from .connection import BATCH_SIZE, DELETE_CHUNK_SIZE, ConnectionFactory, chunked, transaction
from .schema import (
    COL_NV_MACHAMCONG,
    COL_NV_MANHANVIEN,
    COL_NV_MATHE,
    COL_NV_PHANQUYEN,
    COL_NV_TENCHAMCONG,
    COL_NV_TENNHANVIEN,
    COL_NV_USERENABLE,
    TABLE_EMPLOYEES,
    format_enabled,
    resolve_employee_code,
)

__all__ = ["SqlServerEmployeeStore"]

#: One statement per row, batched into one transaction. A multi-row MERGE would need the values
#: as a derived table, and building one means generating placeholders per row — which is fine, but
#: buys little here: an OPERLOG batch carries a handful of users, not thousands.
_MERGE_SQL = f"""
    MERGE {TABLE_EMPLOYEES} AS target
    USING (SELECT ? AS {COL_NV_MACHAMCONG}) AS source
       ON target.{COL_NV_MACHAMCONG} = source.{COL_NV_MACHAMCONG}
    WHEN MATCHED THEN
        UPDATE SET {COL_NV_TENCHAMCONG} = ?,
                   {COL_NV_TENNHANVIEN} = ?,
                   {COL_NV_MATHE}       = ?,
                   {COL_NV_PHANQUYEN}   = ?,
                   {COL_NV_USERENABLE}  = ?
    WHEN NOT MATCHED THEN
        INSERT ({COL_NV_MACHAMCONG}, {COL_NV_MANHANVIEN}, {COL_NV_TENCHAMCONG},
                {COL_NV_TENNHANVIEN}, {COL_NV_MATHE}, {COL_NV_PHANQUYEN}, {COL_NV_USERENABLE})
        VALUES (?, ?, ?, ?, ?, ?, ?);
"""


class SqlServerEmployeeStore:
    """Implements :class:`~adms.ports.EmployeeStore`."""

    __slots__ = ("_factory", "_log")

    def __init__(self, factory: ConnectionFactory, log=None) -> None:
        self._factory = factory
        self._log = log

    def upsert_employees(self, users: list[DeviceUser]) -> int:
        """
        MERGE device users into ``NHANVIEN``. Returns rows affected.

        Non-numeric PINs are skipped — ``MaChamCong`` is an ``int`` primary key. Duplicate PINs
        within one batch are collapsed to the last occurrence, since MERGE raises if the source
        matches the same target row twice.
        """
        if not users:
            return 0

        # dict keyed by PIN: last write wins, and insertion order is preserved so the batch stays
        # in the order the device sent it (useful when reading the log next to the raw archive).
        deduped: dict[int, DeviceUser] = {}
        skipped = 0
        for user in users:
            pin = user.numeric_pin
            if pin is None:
                skipped += 1
                continue
            deduped[pin] = user

        if skipped and self._log is not None:
            self._log.warn(
                "Device users with a non-numeric PIN were skipped; NHANVIEN.MaChamCong is an "
                "integer key.",
                count=skipped,
            )

        if not deduped:
            return 0

        rows = []
        for pin, user in deduped.items():
            name = user.name.strip()
            # NHANVIEN.MaThe is nvarchar(20) -- the schema reports
            # max_length 40 bytes. An earlier [:50] here would have raised a string
            # truncation error and failed the whole OPERLOG batch for any card number over 20
            # characters, which some ViceCard formats reach.
            card = user.card.strip()[:20]
            privilege = int(user.privilege)
            enabled = format_enabled(user.enabled)
            employee_code = resolve_employee_code("", str(pin))
            rows.append(
                (
                    pin,               # USING key
                    name[:100],        # UPDATE TenChamCong
                    name[:100],        # UPDATE TenNhanVien
                    card,              # UPDATE MaThe
                    privilege,         # UPDATE PhanQuyen
                    enabled,           # UPDATE UserEnable
                    pin,               # INSERT MaChamCong
                    employee_code[:20],  # INSERT MaNhanVien — PIN fallback, INSERT only
                    name[:100],        # INSERT TenChamCong
                    name[:100],        # INSERT TenNhanVien
                    card,              # INSERT MaThe
                    privilege,         # INSERT PhanQuyen
                    enabled,           # INSERT UserEnable
                )
            )

        affected = 0
        with transaction(self._factory, what="upsert employees") as cursor:
            for chunk in chunked(rows, BATCH_SIZE):
                cursor.executemany(_MERGE_SQL, chunk)
                # executemany does not report a reliable per-statement rowcount across ODBC
                # drivers, so this counts rows attempted — the same convention the desktop app's
                # batched paths use.
                affected += len(chunk)

        return affected

    def missing_employee_pins(self, pins: set[int]) -> set[int]:
        """
        Which of ``pins`` have no ``NHANVIEN`` row.

        One query per chunk with the PINs as bound parameters in an ``IN`` list, chunked at
        :data:`DELETE_CHUNK_SIZE` for the usual reason: SQL Server refuses more than 2100 parameters in
        a statement, and an ATTLOG batch from a device that was offline over a weekend can carry a lot
        of distinct PINs.

        An empty input costs no round trip at all, which is the common case -- most punches come from
        employees the roster already knows.
        """
        if not pins:
            return set()

        found: set[int] = set()
        try:
            cursor = self._factory.get().cursor()
            try:
                for chunk in chunked(sorted(pins), DELETE_CHUNK_SIZE):
                    placeholders = ", ".join("?" for _ in chunk)
                    cursor.execute(
                        f"SELECT {COL_NV_MACHAMCONG} FROM {TABLE_EMPLOYEES} "
                        f"WHERE {COL_NV_MACHAMCONG} IN ({placeholders})",
                        tuple(chunk),
                    )
                    found.update(int(row[0]) for row in cursor.fetchall() if row[0] is not None)
            finally:
                cursor.close()
        except AttendanceDbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AttendanceDbError("Failed to check which employees are missing.") from exc

        return pins - found
