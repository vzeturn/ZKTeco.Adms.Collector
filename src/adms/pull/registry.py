"""
``dbo.ADMS_DEVICE`` -- the pull agent's read of the device list, and its write of the
denormalised last-pull status.

Same table the push collector's :class:`~adms.db.registry.SqlServerDeviceRegistry` reads --
deliberately, see ``sql/pull-schema.sql``'s own module docstring for why this feature adds
columns to ``ADMS_DEVICE`` rather than creating a second device table. This adapter never writes
``Enabled``, ``MaMCC`` or any of the push-side columns; it only reads them (to resolve
``MachineId``/``MachineName`` for attendance writes) and owns the ``Pull*``/``LastPull*`` columns
it added.
"""

from __future__ import annotations

import datetime as dt

from ..db.connection import ConnectionFactory, transaction
from ..db.schema import COL_IDMCC, COL_MAMCC, COL_TENMCC, TABLE_ADMS_DEVICE, TABLE_MACHINES
from ..errors import AttendanceDbError
from .models import PullDevice

__all__ = ["SqlServerPullDeviceRegistry"]


class SqlServerPullDeviceRegistry:
    """Implements :class:`~adms.pull.ports.PullDeviceRegistry`."""

    __slots__ = ("_factory", "_log")

    def __init__(self, factory: ConnectionFactory, log=None) -> None:
        self._factory = factory
        self._log = log

    def list_pull_enabled(self, *, group: str = "") -> list[PullDevice]:
        sql = f"""
            SELECT  d.SerialNumber, d.DeviceName, d.PullIp, d.PullPort, d.PullPassword,
                    d.PullTimeoutSeconds, d.PullGroup, d.MaMCC,
                    m.{COL_IDMCC}  AS MachineId,
                    m.{COL_TENMCC} AS MachineName,
                    d.LastPullUtc, d.LastPullStatus
            FROM    {TABLE_ADMS_DEVICE} d
            LEFT JOIN {TABLE_MACHINES} m ON LTRIM(RTRIM(m.{COL_MAMCC})) = LTRIM(RTRIM(d.MaMCC))
            WHERE   d.PullEnabled = 1
              AND   (? = '' OR d.PullGroup = ?)
            ORDER BY d.SerialNumber
        """
        try:
            cursor = self._factory.get().cursor()
            try:
                cursor.execute(sql, (group, group))
                rows = cursor.fetchall()
            finally:
                cursor.close()
        except AttendanceDbError:
            raise
        except Exception as exc:
            raise AttendanceDbError("Failed to read the pull-enabled device list.") from exc

        return [_row_to_device(row) for row in rows]

    def record_pull_result(self, serial: str, *, at: dt.datetime, status: str) -> None:
        """
        Best-effort by contract, same as :meth:`~adms.ports.DeviceRegistry.record_contact`: losing
        this timestamp is cosmetic, and a failure here must never take down an otherwise-successful
        pull run. The caller (:mod:`adms.pull.agent`) wraps this in its own ``except Exception``.
        """
        sql = f"UPDATE {TABLE_ADMS_DEVICE} SET LastPullUtc = ?, LastPullStatus = ? WHERE SerialNumber = ?"
        with transaction(self._factory, what="record the pull agent's last result") as cursor:
            cursor.execute(sql, (at, status[:20], serial))


def _row_to_device(row) -> PullDevice:
    return PullDevice(
        serial=(row.SerialNumber or "").strip(),
        device_name=(row.DeviceName or "").strip(),
        ip=(row.PullIp or "").strip(),
        port=int(row.PullPort) if row.PullPort is not None else 4370,
        comm_password=int(row.PullPassword) if row.PullPassword is not None else 0,
        timeout_seconds=int(row.PullTimeoutSeconds) if row.PullTimeoutSeconds is not None else 10,
        pull_group=(row.PullGroup or "").strip(),
        machine_id=int(row.MachineId) if row.MachineId is not None else None,
        machine_name=(row.MachineName or "").strip(),
        last_pull_utc=row.LastPullUtc,
        last_pull_status=(row.LastPullStatus or "").strip(),
    )
