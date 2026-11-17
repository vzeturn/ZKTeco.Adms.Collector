"""
Domain models for the pull agent.

Kept separate from :mod:`adms.models` even though a few concepts overlap (an employee, a punch):
those are the *push* collector's vocabulary, tied to what a device's HTTP upload contains. This
subpackage talks to a device directly over the vendor TCP protocol, and the shapes below are
about *that* conversation -- a device to dial into, and what happened when it did -- not about a
parsed HTTP body. Where the two vocabularies coincide (an employee record, a punch, a fingerprint
template) this package produces plain :mod:`adms.models` values (``DeviceUser``,
``AttendanceLog``, ``FingerTemplate``) so the existing SQL adapters
(:mod:`adms.db.employees`, :mod:`adms.db.attendance`, :mod:`adms.db.templates`) can be reused
unchanged -- a pulled punch must be indistinguishable from a pushed one, same as the desktop app
and the collector already agree to be.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from enum import Enum

__all__ = [
    "DeviceStageResult",
    "PullDevice",
    "PullRunResult",
    "PullStage",
    "PullStatus",
]


class PullStage(str, Enum):
    """One phase of a device's pull run. Ordered as they actually execute."""

    CONNECT = "Connect"
    PULL_EMPLOYEES = "PullEmployees"
    PULL_ATTENDANCE = "PullAttendance"
    SYNC_EMPLOYEES = "SyncEmployees"


class PullStatus(str, Enum):
    """Outcome of one stage, or of a whole run."""

    SUCCESS = "Success"
    FAILED = "Failed"
    SKIPPED = "Skipped"


@dataclass(frozen=True, slots=True)
class PullDevice:
    """
    One row of the pull agent's own device list -- ``ADMS_DEVICE`` joined the same way the push
    collector's :class:`~adms.db.registry.SqlServerDeviceRegistry` already does, plus the
    ``Pull*`` columns this feature owns.

    Deliberately the *same* allow-list table the push collector reads, not a second list: an
    estate has one set of physical machines, and keeping two independent device tables invites
    them to drift (a device disabled in one, forgotten in the other). ``pull_enabled`` is its own
    column rather than reusing ``Enabled`` -- a device can legitimately accept ADMS pushes but
    never be dialled into directly (e.g. it is not reachable from the machine running this tool),
    and the reverse also happens during commissioning.
    """

    serial: str
    device_name: str = ""
    ip: str = ""
    port: int = 4370
    #: The vendor "communication password" (an integer PIN set in the device's Comm menu, 0 when
    #: none is set). Never a login credential in the web-application sense -- it is the same weak,
    #: device-local secret the desktop app already stores per machine.
    comm_password: int = 0
    timeout_seconds: int = 10
    #: The "area" this device belongs to for employee sync (devices in the same area). Empty
    #: means this device never participates in cross-device employee sync, mirroring
    #: ``DeviceRegistration.sync_group``'s own "empty means opted out" convention.
    pull_group: str = ""
    machine_id: int | None = None
    machine_name: str = ""
    last_pull_utc: dt.datetime | None = None
    last_pull_status: str = ""

    @property
    def is_linked(self) -> bool:
        """Whether a ``MAYCHAMCONG`` row resolved -- required to write attendance."""
        return self.machine_id is not None

    @property
    def address(self) -> str:
        return f"{self.ip}:{self.port}"


@dataclass(frozen=True, slots=True)
class DeviceStageResult:
    """One logged step: connect to a device, pull its employees, pull its attendance, sync it."""

    serial: str
    stage: PullStage
    status: PullStatus
    device_name: str = ""
    record_count: int = 0
    duration_ms: int = 0
    error: str = ""

    @property
    def succeeded(self) -> bool:
        return self.status is PullStatus.SUCCESS


@dataclass(frozen=True, slots=True)
class PullRunResult:
    """Everything one invocation of the pull agent did, for the CLI's own exit-code decision."""

    run_id: int
    mode: str
    started_utc: dt.datetime
    finished_utc: dt.datetime
    stages: list[DeviceStageResult] = field(default_factory=list)

    @property
    def devices_attempted(self) -> set[str]:
        return {s.serial for s in self.stages}

    @property
    def devices_failed(self) -> set[str]:
        return {s.serial for s in self.stages if s.status is PullStatus.FAILED}

    @property
    def succeeded(self) -> bool:
        """
        Whether the run is clean enough to exit ``0``.

        A run with **zero** attempted devices (an empty or fully-disabled list) is not a success
        story -- see ``adms.pull.cli``, which treats it as a configuration problem to flag rather
        than a quiet no-op an operator's script would never notice.
        """
        return bool(self.stages) and not self.devices_failed

    def summary(self) -> dict[str, int]:
        return {
            "devices": len(self.devices_attempted),
            "succeeded": len(self.devices_attempted - self.devices_failed),
            "failed": len(self.devices_failed),
            "stages": len(self.stages),
        }
