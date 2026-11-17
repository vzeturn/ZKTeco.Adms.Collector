"""
``ADMS_DEVICE`` — the serial allow-list, joined to ``MAYCHAMCONG``.

Read on every request, so the query is a single indexed seek with a LEFT JOIN. The join is LEFT
rather than INNER on purpose: a registered device whose ``MaMCC`` does not resolve must be
distinguishable from one that is not registered at all. The first is a half-finished
configuration (fix the link), the second is an unknown device (a security event). Collapsing them
into "no row" makes the operator guess.
"""

from __future__ import annotations

import datetime as dt

from ..errors import AttendanceDbError
from ..models import DeviceInfo, DeviceRegistration
from .connection import ConnectionFactory, transaction
from .schema import (
    COL_IDMCC,
    COL_MAMCC,
    COL_TENMCC,
    TABLE_ADMS_DEVICE,
    TABLE_MACHINES,
)

__all__ = ["SqlServerDeviceRegistry"]

#: Only these three are accepted, so the column name interpolated below can never come from a
#: request. The table parameter arrives from a device-supplied query string.
_STAMP_COLUMNS = {
    "ATTLOG": "AttLogStamp",
    "OPERLOG": "OperLogStamp",
    "ATTPHOTO": "AttPhotoStamp",
}


class SqlServerDeviceRegistry:
    """Implements :class:`~adms.ports.DeviceRegistry`."""

    __slots__ = ("_factory", "_log")

    def __init__(self, factory: ConnectionFactory, log=None) -> None:
        self._factory = factory
        self._log = log

    # ── Lookup ───────────────────────────────────────────────────────────────────────────

    def find(self, serial: str) -> DeviceRegistration | None:
        sql = f"""
            SELECT  d.SerialNumber,
                    d.Enabled,
                    d.MaMCC,
                    m.{COL_IDMCC}   AS MachineId,
                    m.{COL_TENMCC}  AS MachineName,
                    d.AttLogStamp,
                    d.OperLogStamp,
                    d.AttPhotoStamp,
                    d.TimeZoneOffset,
                    d.SyncGroup,
                    d.RosterSyncStamp
            FROM    {TABLE_ADMS_DEVICE} d
            LEFT JOIN {TABLE_MACHINES}  m
                   ON LTRIM(RTRIM(m.{COL_MAMCC})) = LTRIM(RTRIM(d.MaMCC))
            WHERE   d.SerialNumber = ?
        """
        try:
            connection = self._factory.get()
            cursor = connection.cursor()
            try:
                cursor.execute(sql, (serial,))
                row = cursor.fetchone()
            finally:
                cursor.close()
        except AttendanceDbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AttendanceDbError("Failed to look up the device registration.") from exc

        if row is None:
            return None

        return DeviceRegistration(
            serial=(row.SerialNumber or "").strip(),
            enabled=bool(row.Enabled),
            # MaMCC is NCHAR(8): space-padded on read, so trim or every comparison downstream
            # silently fails.
            machine_code=(row.MaMCC or "").strip(),
            machine_id=int(row.MachineId) if row.MachineId is not None else None,
            machine_name=(row.MachineName or "").strip(),
            attlog_stamp=(row.AttLogStamp or "0").strip(),
            operlog_stamp=(row.OperLogStamp or "0").strip(),
            attphoto_stamp=(row.AttPhotoStamp or "0").strip(),
            timezone_offset=int(row.TimeZoneOffset) if row.TimeZoneOffset is not None else 7,
            # multi-device-employee-sync. NULL SyncGroup -> "" (Requirement 25's own convention:
            # empty means "not in this feature", matching machine_code's existing nullable-in-SQL,
            # non-optional-in-Python pattern).
            sync_group=(row.SyncGroup or "").strip(),
            roster_sync_stamp=int(row.RosterSyncStamp) if row.RosterSyncStamp is not None else 0,
        )

    # ── Contact tracking ─────────────────────────────────────────────────────────────────

    def record_contact(
        self,
        serial: str,
        *,
        seen_at: dt.datetime,
        source_ip: str = "",
        info: DeviceInfo | None = None,
    ) -> None:
        """
        Update last-seen, and firmware details when a handshake supplied them.

        Two statements rather than one conditional UPDATE: the heartbeat path runs on every
        request and touches three narrow columns, while the options path runs rarely and writes
        several wide ones. Keeping them apart keeps the hot path cheap.
        """
        if info is None:
            sql = f"""
                UPDATE {TABLE_ADMS_DEVICE}
                   SET LastSeenUtc = ?, LastIp = ?, ContactCount = ContactCount + 1
                 WHERE SerialNumber = ?
            """
            params: tuple = (seen_at, source_ip[:64], serial)
        else:
            sql = f"""
                UPDATE {TABLE_ADMS_DEVICE}
                   SET LastSeenUtc     = ?,
                       LastIp          = ?,
                       ContactCount    = ContactCount + 1,
                       DeviceName      = ?,
                       FirmwareVersion = ?,
                       Platform        = ?,
                       PushVersion     = ?,
                       OptionsJson     = ?
                 WHERE SerialNumber = ?
            """
            params = (
                seen_at,
                source_ip[:64],
                info.device_name[:100],
                info.firmware[:64],
                info.platform[:64],
                info.push_version[:32],
                _options_json(info),
                serial,
            )

        with transaction(self._factory, what="record device contact") as cursor:
            cursor.execute(sql, params)

    def register_pending(self, serial: str, *, seen_at: dt.datetime, source_ip: str = "") -> None:
        """
        Insert an unknown serial as ``Enabled = 0``, ``MaMCC = NULL``.

        ``WHERE NOT EXISTS`` rather than MERGE: this runs on an *unauthenticated* path, so it must
        be safe to call at whatever rate a caller chooses, and it must never update an existing
        row — otherwise a spoofed serial could edit the record of a real, enabled device.
        """
        sql = f"""
            INSERT INTO {TABLE_ADMS_DEVICE}
                (SerialNumber, Enabled, MaMCC, LastIp, FirstSeenUtc, LastSeenUtc, ContactCount)
            SELECT ?, 0, NULL, ?, ?, ?, 1
             WHERE NOT EXISTS (SELECT 1 FROM {TABLE_ADMS_DEVICE} WHERE SerialNumber = ?)
        """
        with transaction(self._factory, what="record a pending device") as cursor:
            cursor.execute(sql, (serial, source_ip[:64], seen_at, seen_at, serial))

    # ── Resumption cursors ───────────────────────────────────────────────────────────────

    def advance_stamp(self, serial: str, table: str, stamp: str) -> None:
        """
        Store the resumption cursor for one table.

        The column is chosen from :data:`_STAMP_COLUMNS`, so the device-supplied ``table`` value
        can only ever select one of three compile-time constants — it is never interpolated. An
        unknown table is ignored rather than raising: the caller has already committed the data,
        and a stamp is an optimisation.
        """
        column = _STAMP_COLUMNS.get((table or "").upper())
        if column is None:
            return

        sql = f"UPDATE {TABLE_ADMS_DEVICE} SET {column} = ? WHERE SerialNumber = ?"
        with transaction(self._factory, what="advance the device resumption stamp") as cursor:
            cursor.execute(sql, (stamp[:32], serial))


def _options_json(info: DeviceInfo) -> str:
    """
    Serialise the device's option mapping for ``OptionsJson``.

    Stored as JSON in one ``NVARCHAR(MAX)`` rather than promoted to columns: the key set differs
    per model and grows every firmware release, and none of it drives logic. ``OPENJSON`` is there
    if someone needs to query it.
    """
    import json

    return json.dumps(info.values, ensure_ascii=False, sort_keys=True)[:8000]
