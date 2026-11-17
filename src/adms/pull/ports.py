"""
Ports for the pull agent -- same ``typing.Protocol`` discipline as :mod:`adms.ports`, so the
orchestrator (:mod:`adms.pull.agent`) can be exercised against fakes with no real device and no
database anywhere in sight (see :mod:`tests.test_pull_agent`).
"""

from __future__ import annotations

import datetime as dt
from typing import Protocol, runtime_checkable

from ..models import AttendanceLog, DeviceUser, FingerTemplate
from .models import DeviceStageResult, PullDevice

__all__ = ["DeviceClient", "PullDeviceRegistry", "PullRunLog"]


@runtime_checkable
class DeviceClient(Protocol):
    """
    One open session to a single physical device, over the vendor TCP protocol.

    A context manager: ``connect()`` returns something usable as ``with client.connect(device) as
    session:``. Every method below is called only from inside that block. Kept deliberately small
    -- read employees, read attendance, write one employee, write one fingerprint template -- which
    is exactly the vendor operation set :mod:`adms.pull.zkclient`'s ``pyzk``-backed implementation
    needs and nothing a mock has to guess about.
    """

    def connect(self, device: PullDevice) -> DeviceSession: ...


@runtime_checkable
class DeviceSession(Protocol):
    """An open connection to one device. See :class:`DeviceClient`."""

    def __enter__(self) -> DeviceSession: ...

    def __exit__(self, exc_type, exc, tb) -> bool | None: ...

    def get_employees(self) -> list[DeviceUser]:
        """Every user record the device holds."""

    def get_attendance(self) -> list[AttendanceLog]:
        """Every attendance record currently in the device's buffer."""

    def get_fingerprints(self, pin: str) -> list[FingerTemplate]:
        """Every enrolled fingerprint template for one PIN."""

    def set_employee(self, user: DeviceUser) -> None:
        """Create or update one user on the device (for cross-device sync)."""

    def set_fingerprint(self, template: FingerTemplate) -> None:
        """Push one fingerprint template to the device (for cross-device sync)."""


@runtime_checkable
class PullDeviceRegistry(Protocol):
    """The pull-enabled subset of ``ADMS_DEVICE`` -- read side for the agent, write side for status."""

    def list_pull_enabled(self, *, group: str = "") -> list[PullDevice]:
        """
        Every device with ``PullEnabled = 1``.

        ``group`` filters to one ``PullGroup`` when given, empty means every pull-enabled device
        regardless of group -- the two call shapes ``adms.pull.cli`` needs: "pull everything now"
        and "sync just this office".
        """

    def record_pull_result(self, serial: str, *, at: dt.datetime, status: str) -> None:
        """Best-effort denormalised status, read back by ``vw_ADMS_PullStatus``."""


@runtime_checkable
class PullRunLog(Protocol):
    """Durable, queryable history of every pull invocation -- ``ADMS_PULL_RUN`` / ``ADMS_PULL_LOG``."""

    def start_run(self, *, mode: str, triggered_by: str, devices_requested: int) -> int:
        """Open a run row. Returns the new ``RunId``."""

    def record_stage(self, run_id: int, result: DeviceStageResult) -> None:
        """Append one (device, stage) outcome. Never raises -- see the implementation's contract."""

    def finish_run(self, run_id: int, results: list[DeviceStageResult]) -> None:
        """Close the run row with a summary status derived from ``results``."""
