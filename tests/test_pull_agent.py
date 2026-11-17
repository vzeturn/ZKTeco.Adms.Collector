"""
``PullAgent`` -- the pull tool's orchestrator, exercised entirely with in-memory fakes.

No real device, no ``pyzk``, no database: :class:`FakeDeviceClient` stands in for
:class:`~adms.pull.ports.DeviceClient`, :class:`FakePullDeviceRegistry` and
:class:`FakePullRunLog` stand in for the SQL adapters, and every write flows through the real
:mod:`adms.memory` fakes (``InMemoryAttendanceStore``, ``InMemoryEmployeeStore``,
``InMemoryTemplateStore``) the collector's own suite already trusts -- so a punch or an employee
pulled here goes through the exact same dedup and upsert rules a pushed one would.

Covers:
* a clean pull (employees + attendance) for one device;
* one device failing to connect does not stop the run from covering the rest;
* an unlinked device's attendance pull is skipped, not attempted;
* the durable run log (``ADMS_PULL_RUN``/``ADMS_PULL_LOG`` in production) records every stage;
* cross-device employee sync pushes a person missing from one device in a shared ``PullGroup``
  to that device, and never touches a device with no group or a lone device in its group.
"""

from __future__ import annotations

import datetime as dt

from adms.memory import FixedClock, InMemoryAttendanceStore, InMemoryEmployeeStore, InMemoryTemplateStore
from adms.models import AttendanceLog, DeviceUser
from adms.pull.agent import PullAgent
from adms.pull.models import PullDevice, PullStage, PullStatus


class FakeSession:
    """One in-memory device conversation. See :class:`~adms.pull.ports.DeviceSession`."""

    def __init__(self, device: PullDevice, *, employees=None, attendance=None, fail: bool = False) -> None:
        self.device = device
        self._employees = employees or []
        self._attendance = attendance or []
        self._fail = fail
        self.pushed_employees: list[DeviceUser] = []
        self.pushed_fingerprints: list = []

    def __enter__(self) -> FakeSession:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def get_employees(self) -> list[DeviceUser]:
        if self._fail:
            raise RuntimeError("simulated employee read failure")
        return list(self._employees)

    def get_attendance(self) -> list[AttendanceLog]:
        if self._fail:
            raise RuntimeError("simulated attendance read failure")
        return list(self._attendance)

    def get_fingerprints(self, pin: str) -> list:  # noqa: ARG002
        return []

    def set_employee(self, user: DeviceUser) -> None:
        self.pushed_employees.append(user)

    def set_fingerprint(self, template) -> None:
        self.pushed_fingerprints.append(template)


class FakeDeviceClient:
    """Hands back a scripted :class:`FakeSession` per serial. See :class:`~adms.pull.ports.DeviceClient`."""

    def __init__(self) -> None:
        self.sessions: dict[str, FakeSession] = {}
        self.unreachable: set[str] = set()
        self.connect_calls: list[str] = []

    def script(self, device: PullDevice, *, employees=None, attendance=None) -> FakeSession:
        session = FakeSession(device, employees=employees, attendance=attendance)
        self.sessions[device.serial] = session
        return session

    def mark_unreachable(self, serial: str) -> None:
        self.unreachable.add(serial)

    def connect(self, device: PullDevice) -> FakeSession:
        self.connect_calls.append(device.serial)
        if device.serial in self.unreachable:
            raise ConnectionError(f"cannot reach {device.serial}")
        return self.sessions[device.serial]


class FakePullDeviceRegistry:
    """In-memory ``ADMS_DEVICE`` pull-side read/write. See :class:`~adms.pull.ports.PullDeviceRegistry`."""

    def __init__(self, devices: list[PullDevice]) -> None:
        self.devices = devices
        self.recorded_status: dict[str, str] = {}

    def list_pull_enabled(self, *, group: str = "") -> list[PullDevice]:
        if not group:
            return list(self.devices)
        return [d for d in self.devices if d.pull_group == group]

    def record_pull_result(self, serial: str, *, at: dt.datetime, status: str) -> None:  # noqa: ARG002
        self.recorded_status[serial] = status


class FakePullRunLog:
    """In-memory ``ADMS_PULL_RUN``/``ADMS_PULL_LOG``. See :class:`~adms.pull.ports.PullRunLog`."""

    def __init__(self) -> None:
        self.runs: dict[int, dict] = {}
        self.stages: list = []
        self._next_id = 1

    def start_run(self, *, mode: str, triggered_by: str, devices_requested: int) -> int:
        run_id = self._next_id
        self._next_id += 1
        self.runs[run_id] = {
            "mode": mode,
            "triggered_by": triggered_by,
            "devices_requested": devices_requested,
            "status": "Running",
        }
        return run_id

    def record_stage(self, run_id: int, result) -> None:
        self.stages.append((run_id, result))

    def finish_run(self, run_id: int, results: list) -> None:
        self.runs[run_id]["status"] = "Closed"
        self.runs[run_id]["results"] = list(results)


class NullLogger:
    def debug(self, message: str, **fields) -> None: ...
    def info(self, message: str, **fields) -> None: ...
    def warn(self, message: str, exc=None, **fields) -> None: ...
    def error(self, message: str, exc=None, **fields) -> None: ...


def build_agent(
    client: FakeDeviceClient,
    registry: FakePullDeviceRegistry,
    *,
    employees=None,
    attendance=None,
    templates=None,
):
    runlog = FakePullRunLog()
    agent = PullAgent(
        client=client,
        registry=registry,
        employees=employees or InMemoryEmployeeStore(),
        attendance=attendance or InMemoryAttendanceStore(),
        templates=templates or InMemoryTemplateStore(),
        runlog=runlog,
        clock=FixedClock(),
        log=NullLogger(),
    )
    return agent, runlog


def linked_pull_device(serial: str = "DEV1", **overrides) -> PullDevice:
    fields = {"serial": serial, "ip": "10.0.0.1", "machine_id": 1, "machine_name": "Cong 1"}
    fields.update(overrides)
    return PullDevice(**fields)


# ── Basic pull ──────────────────────────────────────────────────────────────────────────────────


def test_pulls_employees_and_attendance_for_one_device():
    device = linked_pull_device()
    client = FakeDeviceClient()
    client.script(
        device,
        employees=[DeviceUser(pin="101", name="An")],
        attendance=[AttendanceLog(pin="101", timestamp=dt.datetime(2026, 1, 1, 8, 0, 0))],
    )
    registry = FakePullDeviceRegistry([device])
    employees = InMemoryEmployeeStore()
    attendance = InMemoryAttendanceStore()

    agent, runlog = build_agent(client, registry, employees=employees, attendance=attendance)
    result = agent.run(sync_employees=False)

    assert result.succeeded
    assert 101 in employees.employees
    assert len(attendance.rows) == 1
    assert registry.recorded_status[device.serial] == "Success"
    # Every stage this device went through was logged durably.
    stage_names = {r.stage for _rid, r in runlog.stages if r.serial == device.serial}
    assert stage_names == {PullStage.CONNECT, PullStage.PULL_EMPLOYEES, PullStage.PULL_ATTENDANCE}


def test_one_device_unreachable_does_not_stop_the_run():
    good = linked_pull_device("DEV1")
    bad = linked_pull_device("DEV2", ip="10.0.0.2", machine_id=2)
    client = FakeDeviceClient()
    client.script(good, employees=[], attendance=[])
    client.mark_unreachable(bad.serial)

    registry = FakePullDeviceRegistry([good, bad])
    agent, runlog = build_agent(client, registry)
    result = agent.run(sync_employees=False)

    assert not result.succeeded  # one device failed
    assert good.serial in result.devices_attempted
    assert bad.serial in result.devices_failed
    assert registry.recorded_status[good.serial] == "Success"
    assert registry.recorded_status[bad.serial] == "Failed"
    # The unreachable device produced exactly one stage: a failed Connect.
    bad_stages = [r for _rid, r in runlog.stages if r.serial == bad.serial]
    assert len(bad_stages) == 1
    assert bad_stages[0].stage is PullStage.CONNECT
    assert bad_stages[0].status is PullStatus.FAILED


def test_unlinked_device_skips_attendance_but_still_pulls_employees():
    device = linked_pull_device("DEV1", machine_id=None)
    client = FakeDeviceClient()
    client.script(device, employees=[DeviceUser(pin="55", name="Binh")], attendance=[])
    registry = FakePullDeviceRegistry([device])
    employees = InMemoryEmployeeStore()

    agent, runlog = build_agent(client, registry, employees=employees)
    agent.run(sync_employees=False)

    assert 55 in employees.employees
    stage = next(r for _rid, r in runlog.stages if r.stage is PullStage.PULL_ATTENDANCE)
    assert stage.status is PullStatus.SKIPPED


def test_empty_device_list_is_not_a_success():
    client = FakeDeviceClient()
    registry = FakePullDeviceRegistry([])
    agent, _runlog = build_agent(client, registry)
    result = agent.run()
    assert not result.succeeded
    assert result.summary()["devices"] == 0


# ── Run log durability ──────────────────────────────────────────────────────────────────────────


def test_run_is_opened_and_closed_exactly_once():
    device = linked_pull_device()
    client = FakeDeviceClient()
    client.script(device, employees=[], attendance=[])
    registry = FakePullDeviceRegistry([device])
    agent, runlog = build_agent(client, registry)

    result = agent.run(mode="All", triggered_by="operator1", sync_employees=False)

    assert runlog.runs[result.run_id]["mode"] == "All"
    assert runlog.runs[result.run_id]["triggered_by"] == "operator1"
    assert runlog.runs[result.run_id]["status"] == "Closed"


# ── Cross-device employee sync (same PullGroup) ─────────────────────────────────────────────────


def test_syncs_missing_employee_to_other_device_in_same_group():
    a = linked_pull_device("DEV_A", machine_id=1, pull_group="OFFICE1")
    b = linked_pull_device("DEV_B", ip="10.0.0.2", machine_id=2, pull_group="OFFICE1")

    client = FakeDeviceClient()
    client.script(a, employees=[DeviceUser(pin="200", name="Only On A")], attendance=[])
    session_b = client.script(b, employees=[], attendance=[])

    registry = FakePullDeviceRegistry([a, b])
    agent, runlog = build_agent(client, registry)

    result = agent.run(sync_employees=True)

    assert result.succeeded
    pushed_pins = {u.pin for u in session_b.pushed_employees}
    assert "200" in pushed_pins
    sync_stages = [r for _rid, r in runlog.stages if r.stage is PullStage.SYNC_EMPLOYEES]
    assert any(r.serial == b.serial and r.status is PullStatus.SUCCESS for r in sync_stages)


def test_lone_device_in_a_group_triggers_no_sync():
    solo = linked_pull_device("DEV_SOLO", pull_group="ONLY_ONE")
    client = FakeDeviceClient()
    client.script(solo, employees=[DeviceUser(pin="1", name="X")], attendance=[])
    registry = FakePullDeviceRegistry([solo])
    agent, runlog = build_agent(client, registry)

    agent.run(sync_employees=True)

    sync_stages = [r for _rid, r in runlog.stages if r.stage is PullStage.SYNC_EMPLOYEES]
    assert sync_stages == []


def test_devices_with_no_group_are_never_synced():
    a = linked_pull_device("DEV_A", machine_id=1)  # pull_group="" (default)
    b = linked_pull_device("DEV_B", ip="10.0.0.2", machine_id=2)

    client = FakeDeviceClient()
    client.script(a, employees=[DeviceUser(pin="9", name="Only On A")], attendance=[])
    session_b = client.script(b, employees=[], attendance=[])
    registry = FakePullDeviceRegistry([a, b])
    agent, runlog = build_agent(client, registry)

    agent.run(sync_employees=True)

    assert session_b.pushed_employees == []
    sync_stages = [r for _rid, r in runlog.stages if r.stage is PullStage.SYNC_EMPLOYEES]
    assert sync_stages == []


def test_group_filter_only_pulls_matching_devices():
    a = linked_pull_device("DEV_A", pull_group="SITE_A")
    b = linked_pull_device("DEV_B", ip="10.0.0.2", machine_id=2, pull_group="SITE_B")

    client = FakeDeviceClient()
    client.script(a, employees=[], attendance=[])
    client.script(b, employees=[], attendance=[])
    registry = FakePullDeviceRegistry([a, b])
    agent, _runlog = build_agent(client, registry)

    result = agent.run(group="SITE_A", sync_employees=False)

    assert result.devices_attempted == {a.serial}
    assert b.serial not in client.connect_calls


# ── Insert-only employee pull: never overwrite an existing NHANVIEN row ──────────────────────────


def test_employee_pull_never_overwrites_an_existing_employee():
    """A PIN NHANVIEN already has must be left exactly as it was -- the device's copy of that
    PIN's name/card is not written, even though the device reports a different name."""
    device = linked_pull_device()
    client = FakeDeviceClient()
    client.script(
        device,
        employees=[DeviceUser(pin="42", name="Device's Idea Of The Name", card="9999")],
        attendance=[],
    )
    registry = FakePullDeviceRegistry([device])
    employees = InMemoryEmployeeStore()
    # Pre-existing row for PIN 42, as if HR/the desktop app/a push upload already wrote it.
    employees.employees[42] = DeviceUser(pin="42", name="Existing HR Name", card="1111")

    agent, _runlog = build_agent(client, registry, employees=employees)
    agent.run(sync_employees=False, pull_attendance=False)

    # Untouched: still the pre-existing name/card, not the device's.
    assert employees.employees[42].name == "Existing HR Name"
    assert employees.employees[42].card == "1111"


def test_employee_pull_inserts_a_pin_nhanvien_does_not_have():
    device = linked_pull_device()
    client = FakeDeviceClient()
    client.script(device, employees=[DeviceUser(pin="777", name="Brand New")], attendance=[])
    registry = FakePullDeviceRegistry([device])
    employees = InMemoryEmployeeStore()

    agent, runlog = build_agent(client, registry, employees=employees)
    agent.run(sync_employees=False, pull_attendance=False)

    assert 777 in employees.employees
    assert employees.employees[777].name == "Brand New"
    stage = next(r for _rid, r in runlog.stages if r.stage is PullStage.PULL_EMPLOYEES)
    assert stage.record_count == 1


def test_employee_pull_mixed_batch_only_inserts_the_missing_pin():
    device = linked_pull_device()
    client = FakeDeviceClient()
    client.script(
        device,
        employees=[
            DeviceUser(pin="1", name="Already Known From Device"),
            DeviceUser(pin="2", name="New From Device"),
        ],
        attendance=[],
    )
    registry = FakePullDeviceRegistry([device])
    employees = InMemoryEmployeeStore()
    employees.employees[1] = DeviceUser(pin="1", name="Existing Name")

    agent, runlog = build_agent(client, registry, employees=employees)
    agent.run(sync_employees=False, pull_attendance=False)

    assert employees.employees[1].name == "Existing Name"  # untouched
    assert employees.employees[2].name == "New From Device"  # inserted
    stage = next(r for _rid, r in runlog.stages if r.stage is PullStage.PULL_EMPLOYEES)
    assert stage.record_count == 1  # only the missing one was written


# ── Cross-device employee sync is insert-only in the other direction too ─────────────────────────


def test_sync_never_overwrites_an_employee_a_device_already_has():
    """Device B already has PIN 200 under a different name than device A -- sync must not push
    A's copy over B's, because B was never missing that PIN."""
    a = linked_pull_device("DEV_A", machine_id=1, pull_group="OFFICE1")
    b = linked_pull_device("DEV_B", ip="10.0.0.2", machine_id=2, pull_group="OFFICE1")

    client = FakeDeviceClient()
    client.script(a, employees=[DeviceUser(pin="200", name="A's Version")], attendance=[])
    session_b = client.script(
        b, employees=[DeviceUser(pin="200", name="B's Own Version")], attendance=[]
    )

    registry = FakePullDeviceRegistry([a, b])
    agent, _runlog = build_agent(client, registry)

    agent.run(sync_employees=True, pull_attendance=False)

    # B already reported having PIN 200, so nothing was pushed to it for that PIN.
    assert session_b.pushed_employees == []


# ── Attendance: since-date filtering and insert-only dedup ──────────────────────────────────────


def test_since_filters_out_punches_before_the_cutoff():
    device = linked_pull_device()
    client = FakeDeviceClient()
    client.script(
        device,
        employees=[],
        attendance=[
            AttendanceLog(pin="1", timestamp=dt.datetime(2026, 8, 1, 8, 0, 0)),  # before cutoff
            AttendanceLog(pin="1", timestamp=dt.datetime(2026, 8, 21, 8, 0, 0)),  # at cutoff
            AttendanceLog(pin="1", timestamp=dt.datetime(2026, 8, 25, 8, 0, 0)),  # after cutoff
        ],
    )
    registry = FakePullDeviceRegistry([device])
    attendance = InMemoryAttendanceStore()

    agent, runlog = build_agent(client, registry, attendance=attendance)
    agent.run(sync_employees=False, pull_employees=False, since=dt.datetime(2026, 8, 21))

    # Only the two punches on/after the cutoff were inserted.
    assert len(attendance.rows) == 2
    stamps = {row["GioCham"] for row in attendance.rows}
    assert dt.datetime(2026, 8, 1, 8, 0, 0) not in stamps
    assert dt.datetime(2026, 8, 21, 8, 0, 0) in stamps
    assert dt.datetime(2026, 8, 25, 8, 0, 0) in stamps

    stage = next(r for _rid, r in runlog.stages if r.stage is PullStage.PULL_ATTENDANCE)
    assert stage.record_count == 2


def test_no_since_pulls_every_punch():
    device = linked_pull_device()
    client = FakeDeviceClient()
    client.script(
        device,
        employees=[],
        attendance=[
            AttendanceLog(pin="1", timestamp=dt.datetime(2020, 1, 1, 8, 0, 0)),
            AttendanceLog(pin="1", timestamp=dt.datetime(2026, 8, 25, 8, 0, 0)),
        ],
    )
    registry = FakePullDeviceRegistry([device])
    attendance = InMemoryAttendanceStore()

    agent, _runlog = build_agent(client, registry, attendance=attendance)
    agent.run(sync_employees=False, pull_employees=False, since=None)

    assert len(attendance.rows) == 2


def test_attendance_pull_does_not_duplicate_an_already_stored_punch():
    """A punch already in CheckInOut (e.g. from a previous pull, or a push upload) must be
    skipped, not re-inserted or overwritten -- the shared (MaChamCong, GioCham) dedup key."""
    device = linked_pull_device()
    stamp = dt.datetime(2026, 8, 25, 8, 0, 0)
    client = FakeDeviceClient()
    client.script(device, employees=[], attendance=[AttendanceLog(pin="1", timestamp=stamp)])
    registry = FakePullDeviceRegistry([device])
    attendance = InMemoryAttendanceStore()
    # Pre-existing punch for this exact (pin, timestamp) on this machine.
    attendance.punches[device.machine_id] = {(1, stamp)}

    agent, runlog = build_agent(client, registry, attendance=attendance)
    agent.run(sync_employees=False, pull_employees=False)

    # Still exactly one row for this key -- not duplicated.
    assert len(attendance.rows) == 0
    stage = next(r for _rid, r in runlog.stages if r.stage is PullStage.PULL_ATTENDANCE)
    assert stage.record_count == 0


# ── Phase ordering: employees (and sync) complete before any attendance pull starts ──────────────


def test_employees_and_sync_run_before_any_attendance_pull():
    """Every PULL_EMPLOYEES and SYNC_EMPLOYEES stage, across every device, must be recorded
    before the first PULL_ATTENDANCE stage -- phase 3 never starts until phases 1-2 finish for
    the whole run, not just for one device."""
    a = linked_pull_device("DEV_A", machine_id=1, pull_group="OFFICE1")
    b = linked_pull_device("DEV_B", ip="10.0.0.2", machine_id=2, pull_group="OFFICE1")

    client = FakeDeviceClient()
    client.script(
        a,
        employees=[DeviceUser(pin="1", name="A")],
        attendance=[AttendanceLog(pin="1", timestamp=dt.datetime(2026, 1, 1))],
    )
    client.script(
        b,
        employees=[],
        attendance=[AttendanceLog(pin="1", timestamp=dt.datetime(2026, 1, 1))],
    )
    registry = FakePullDeviceRegistry([a, b])
    agent, runlog = build_agent(client, registry)

    agent.run(sync_employees=True)

    ordered_stages = [r.stage for _rid, r in runlog.stages if r.stage is not PullStage.CONNECT]
    first_attendance_index = ordered_stages.index(PullStage.PULL_ATTENDANCE)
    roster_stages_after = [
        s for s in ordered_stages[first_attendance_index:]
        if s in (PullStage.PULL_EMPLOYEES, PullStage.SYNC_EMPLOYEES)
    ]
    assert roster_stages_after == [], (
        f"a roster stage ran after attendance started: {ordered_stages}"
    )
