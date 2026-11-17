"""
``dbo.ADMS_PULL_RUN`` / ``dbo.ADMS_PULL_LOG`` -- the durable, queryable audit trail of every pull
invocation.

This is the "ghi log day du" (full logging) requirement in table form: every stage of every
device, in every run, with status, record count, timing and the exact error text, so an operator
can answer "did the pull have a problem, and what exactly went wrong" without reading application
log files. :mod:`adms.pull.agent` also emits the same information through the structured JSON
logger (:mod:`adms.logging_setup`) for real-time/console visibility -- the two are complementary,
not a substitute for each other: the JSON log is what you tail while a run is happening, this
table is what you query a week later.
"""

from __future__ import annotations

from ..db.connection import ConnectionFactory, transaction
from ..errors import AttendanceDbError
from .models import DeviceStageResult, PullStatus

__all__ = ["SqlServerPullRunLog"]

_TABLE_RUN = "dbo.ADMS_PULL_RUN"
_TABLE_LOG = "dbo.ADMS_PULL_LOG"


class SqlServerPullRunLog:
    """Implements :class:`~adms.pull.ports.PullRunLog`."""

    __slots__ = ("_factory", "_log")

    def __init__(self, factory: ConnectionFactory, log=None) -> None:
        self._factory = factory
        self._log = log

    def start_run(self, *, mode: str, triggered_by: str, devices_requested: int) -> int:
        sql = f"""
            INSERT INTO {_TABLE_RUN} (Mode, Status, TriggeredBy, DevicesRequested, StartedUtc)
            VALUES (?, 'Running', ?, ?, SYSUTCDATETIME());
            SELECT CAST(SCOPE_IDENTITY() AS INT);
        """
        with transaction(self._factory, what="open a pull run") as cursor:
            cursor.execute(sql, (mode, triggered_by[:64], devices_requested))
            while cursor.description is None:
                if not cursor.nextset():
                    raise AttendanceDbError("Started a pull run but could not read back its id.")
            row = cursor.fetchone()
            if row is None or row[0] is None:
                raise AttendanceDbError("Started a pull run but could not read back its id.")
            return int(row[0])

    def record_stage(self, run_id: int, result: DeviceStageResult) -> None:
        """
        Append one stage outcome.

        Never raises into the caller: a failure to *record* that a device's pull failed must not
        mask the failure itself, nor abort the rest of the run over a logging problem. The agent
        already has the same information in hand to log through :mod:`adms.logging_setup`
        regardless of whether this write succeeds.
        """
        sql = f"""
            INSERT INTO {_TABLE_LOG}
                (RunId, SerialNumber, DeviceName, Stage, Status, RecordCount, DurationMs, ErrorMessage)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        try:
            with transaction(self._factory, what="record a pull stage result") as cursor:
                cursor.execute(
                    sql,
                    (
                        run_id,
                        result.serial[:64],
                        result.device_name[:100],
                        result.stage.value,
                        result.status.value,
                        result.record_count,
                        result.duration_ms,
                        result.error[:1024],
                    ),
                )
        except Exception as exc:
            if self._log is not None:
                self._log.warn(
                    "Could not record a pull stage result.",
                    exc,
                    run_id=run_id,
                    serial=result.serial,
                    stage=result.stage.value,
                )

    def finish_run(self, run_id: int, results: list[DeviceStageResult]) -> None:
        devices = {r.serial for r in results}
        failed = {r.serial for r in results if r.status is PullStatus.FAILED}
        succeeded = devices - failed

        if not devices:
            status = "Failed"
        elif not failed:
            status = "Success"
        elif succeeded:
            status = "PartialFailure"
        else:
            status = "Failed"

        sql = f"""
            UPDATE {_TABLE_RUN}
               SET Status = ?, DevicesSucceeded = ?, DevicesFailed = ?, FinishedUtc = SYSUTCDATETIME()
             WHERE RunId = ?
        """
        try:
            with transaction(self._factory, what="close a pull run") as cursor:
                cursor.execute(sql, (status, len(succeeded), len(failed), run_id))
        except Exception as exc:
            if self._log is not None:
                self._log.warn("Could not close a pull run.", exc, run_id=run_id)
