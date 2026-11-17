"""
The pull agent -- runs on demand (whenever an operator wants), against a
configured list of attendance devices, in three ordered phases:

1. **Pull employees, insert-only.** Read each device's user list; a PIN already present in
   ``NHANVIEN`` is left untouched -- only a PIN ``NHANVIEN`` does not have yet is inserted. A
   device's copy of a person's name/card must never overwrite what HR, the desktop app, or a
   push upload already recorded for that PIN. See :meth:`PullAgent._insert_missing_employees`.
2. **Sync employees between devices sharing a ``PullGroup``.** Same insert-only rule in the
   other direction: a person missing from a device (but known from some other device in the
   same group, pulled in phase 1) is pushed to fill the gap; a person the device already has is
   never touched. See :meth:`PullAgent._push_missing_employees`.
3. **Pull attendance**, only after phases 1-2 have finished for every device -- a punch pulled in
   this phase can always find the employee it belongs to, because the roster gap that phase 1/2
   exist to close has already been closed. Optionally scoped to ``since`` (e.g. only punches on
   or after a given date), inserted into ``CheckInOut`` / ``ADMS_ATTLOG_RAW`` through the exact same
   adapters and dedup key the push collector uses (:class:`~adms.ports.AttendanceStore`), so a
   pulled punch is indistinguishable from a pushed one, and a punch already stored is skipped
   rather than duplicated or overwritten.

Phases run to completion across *every* device before the next phase starts -- not per device --
which is the whole point of the ordering: attendance must never run ahead of a roster fix-up that
was still in progress for some other device in the same group.

**Full logging, by design.** Every stage of every device is logged twice: once immediately, in
real time, through the same structured JSON logger the push collector uses
(:mod:`adms.logging_setup` -- so an operator watching the console sees exactly what is happening);
and once durably, into ``ADMS_PULL_RUN``/``ADMS_PULL_LOG`` (:mod:`adms.pull.runlog`), so the
history survives after the console is closed and can be queried later. One device's failure is
recorded and the run continues with the next device -- because a single unreachable machine must
not hide whether the other eleven worked.
"""

from __future__ import annotations

import datetime as dt
import time
from collections import defaultdict

from ..models import AttendanceLog, DeviceUser, PunchKey
from ..ports import AttendanceStore, Clock, EmployeeStore, Logger, TemplateStore
from .models import DeviceStageResult, PullDevice, PullRunResult, PullStage, PullStatus
from .ports import DeviceClient, PullDeviceRegistry, PullRunLog

__all__ = ["PullAgent"]


class PullAgent:
    """
    Orchestrates one invocation across a list of devices.

    Every dependency is a port, injected by :mod:`adms.pull.composition` -- the same shape as
    :class:`adms.service.AdmsService`, so this class is testable with the in-memory fakes in
    :mod:`tests.test_pull_agent` and carries no adapter-specific knowledge of its own.
    """

    __slots__ = (
        "_attendance",
        "_client",
        "_clock",
        "_employees",
        "_log",
        "_registry",
        "_runlog",
        "_templates",
    )

    def __init__(
        self,
        *,
        client: DeviceClient,
        registry: PullDeviceRegistry,
        employees: EmployeeStore,
        attendance: AttendanceStore,
        templates: TemplateStore,
        runlog: PullRunLog,
        clock: Clock,
        log: Logger,
    ) -> None:
        self._client = client
        self._registry = registry
        self._employees = employees
        self._attendance = attendance
        self._templates = templates
        self._runlog = runlog
        self._clock = clock
        self._log = log

    def run(
        self,
        *,
        mode: str = "All",
        group: str = "",
        triggered_by: str = "",
        pull_employees: bool = True,
        pull_attendance: bool = True,
        sync_employees: bool = True,
        since: dt.datetime | None = None,
    ) -> PullRunResult:
        """
        Run all three phases, in order, across every pull-enabled device (or just those in
        ``group``): employees in (insert-only) -> employees synced between devices in the same
        group (insert-only) -> attendance in (optionally scoped to ``since``).

        ``pull_employees``/``pull_attendance``/``sync_employees`` let the CLI offer "just
        attendance, right now" without also touching the roster, while still recording a run and
        a full log either way -- see ``adms.pull.cli``'s own ``--employees-only`` /
        ``--attendance-only`` / ``--no-sync`` flags. ``since`` (naive, device-local wall-clock,
        matching every other timestamp in this schema) limits phase 3 to punches at or after that
        moment -- e.g. a cutover date -- without touching phases 1-2 at all.
        """
        started = self._clock.utc_now()
        devices = self._registry.list_pull_enabled(group=group)

        run_id = self._runlog.start_run(mode=mode, triggered_by=triggered_by, devices_requested=len(devices))
        self._log.info(
            "Pull run started.",
            run_id=run_id,
            mode=mode,
            group=group or "(all)",
            devices=len(devices),
            since=since.isoformat() if since else None,
        )

        if not devices:
            self._log.warn(
                "No pull-enabled devices matched; nothing to do.",
                run_id=run_id,
                group=group or "(all)",
            )

        results: list[DeviceStageResult] = []
        sessions: dict[str, object] = {}
        rosters: dict[str, list[DeviceUser]] = {}

        # ── Phase 1: connect + pull employees (insert-only) for every device ────────────
        for device in devices:
            connect_result, session = self._connect(run_id, device)
            results.append(connect_result)
            if session is None:
                self._mark_status(device.serial, "Failed")
                continue
            sessions[device.serial] = session

            if not pull_employees:
                continue
            employees_result, roster = self._pull_employees(run_id, device, session)
            results.append(employees_result)
            rosters[device.serial] = roster

        # ── Phase 2: sync employees between devices sharing a PullGroup (insert-only) ───
        if sync_employees and pull_employees:
            results.extend(self._sync_groups(run_id, devices, rosters, sessions))

        # ── Phase 3: pull attendance, only after every roster fix-up above is done ──────
        if pull_attendance:
            for device in devices:
                session = sessions.get(device.serial)
                if session is None:
                    continue  # this device failed to connect in phase 1; already recorded
                results.append(self._pull_attendance(run_id, device, session, since=since))

        # ── Close every open session and roll up a final status per device ──────────────
        for device in devices:
            session = sessions.pop(device.serial, None)
            if session is not None:
                self._close_session(session, device)

        failed_serials = {r.serial for r in results if r.status is PullStatus.FAILED}
        for device in devices:
            device_touched = any(r.serial == device.serial for r in results)
            if not device_touched:
                continue
            self._mark_status(device.serial, "Failed" if device.serial in failed_serials else "Success")

        finished = self._clock.utc_now()
        self._runlog.finish_run(run_id, results)

        result = PullRunResult(
            run_id=run_id, mode=mode, started_utc=started, finished_utc=finished, stages=results
        )
        self._log.info(
            "Pull run finished.",
            run_id=run_id,
            duration_ms=int((finished - started).total_seconds() * 1000),
            **result.summary(),
        )
        return result

    def _close_session(self, session, device: PullDevice) -> None:
        try:
            session.__exit__(None, None, None)
        except Exception as exc:
            self._log.warn("Could not cleanly close a device session.", exc, serial=device.serial)

    def _connect(self, run_id: int, device: PullDevice):
        start = time.monotonic()
        try:
            session = self._client.connect(device)
            session.__enter__()
        except Exception as exc:
            duration = int((time.monotonic() - start) * 1000)
            result = DeviceStageResult(
                serial=device.serial,
                device_name=device.device_name,
                stage=PullStage.CONNECT,
                status=PullStatus.FAILED,
                duration_ms=duration,
                error=str(exc),
            )
            self._log.error(
                "Could not connect to device.",
                exc,
                serial=device.serial,
                address=device.address,
            )
            self._runlog.record_stage(run_id, result)
            return result, None

        duration = int((time.monotonic() - start) * 1000)
        result = DeviceStageResult(
            serial=device.serial,
            device_name=device.device_name,
            stage=PullStage.CONNECT,
            status=PullStatus.SUCCESS,
            duration_ms=duration,
        )
        self._log.info("Connected to device.", serial=device.serial, address=device.address)
        self._runlog.record_stage(run_id, result)
        return result, session

    def _pull_employees(
        self, run_id: int, device: PullDevice, session
    ) -> tuple[DeviceStageResult, list[DeviceUser]]:
        """
        Phase 1: read the device's roster, and insert only the PINs ``NHANVIEN`` does not
        already have -- see :meth:`_insert_missing_employees` for why an existing PIN is left
        alone rather than refreshed from the device.

        Returns the stage result *and* every user the device reported (not only the ones
        actually inserted), because phase 2's cross-device sync needs "what this device knows",
        independent of what already existed in ``NHANVIEN`` before this pull.
        """
        start = time.monotonic()
        try:
            users = session.get_employees()
            inserted = self._insert_missing_employees(users) if users else 0
        except Exception as exc:
            return (
                self._log_stage(
                    run_id, device, PullStage.PULL_EMPLOYEES, PullStatus.FAILED,
                    error=str(exc), duration_ms=int((time.monotonic() - start) * 1000),
                ),
                [],
            )

        result = self._log_stage(
            run_id, device, PullStage.PULL_EMPLOYEES, PullStatus.SUCCESS,
            record_count=inserted, duration_ms=int((time.monotonic() - start) * 1000),
        )
        return result, users

    def _insert_missing_employees(self, users: list[DeviceUser]) -> int:
        """
        Insert-only: a PIN already present in ``NHANVIEN`` is never touched by a pull. Only a PIN
        with no ``NHANVIEN`` row yet is written, through the same
        :meth:`~adms.ports.EmployeeStore.upsert_employees` MERGE the push collector uses -- safe
        here specifically *because* the pre-filter below guarantees every row this call sees is a
        ``WHEN NOT MATCHED`` (a fresh insert), never a ``WHEN MATCHED`` (an overwrite of an
        existing employee's name/card with whatever this device happens to have on file for that
        PIN, which is exactly the "sai lech" -- data corruption via overwrite -- this pull-agent
        must not cause).
        """
        pins: set[int] = set()
        by_pin: dict[int, DeviceUser] = {}
        for user in users:
            pin = user.numeric_pin
            if pin is None:
                continue
            pins.add(pin)
            by_pin[pin] = user

        if not pins:
            return 0

        missing = self._employees.missing_employee_pins(pins)
        if not missing:
            return 0

        to_insert = [by_pin[pin] for pin in missing]
        return self._employees.upsert_employees(to_insert)

    def _pull_attendance(
        self, run_id: int, device: PullDevice, session, *, since: dt.datetime | None = None
    ) -> DeviceStageResult:
        start = time.monotonic()
        if not device.is_linked:
            # Same rule the push collector enforces in AdmsService._require_link: with no MaMCC
            # resolving to a MAYCHAMCONG row there is no IDMCC for CheckInOut.MaSoMay, and
            # inventing one would file punches against the wrong machine.
            return self._log_stage(
                run_id, device, PullStage.PULL_ATTENDANCE, PullStatus.SKIPPED,
                error="Device is not linked to a MAYCHAMCONG row; cannot resolve MaSoMay.",
            )

        try:
            logs = session.get_attendance()
        except Exception as exc:
            return self._log_stage(
                run_id, device, PullStage.PULL_ATTENDANCE, PullStatus.FAILED,
                error=str(exc), duration_ms=int((time.monotonic() - start) * 1000),
            )

        fetched = len(logs)
        skipped_before_cutoff = 0
        if since is not None:
            filtered = [log for log in logs if log.timestamp >= since]
            skipped_before_cutoff = len(logs) - len(filtered)
            logs = filtered

        if not logs:
            self._log.info(
                "No attendance to pull.",
                serial=device.serial,
                fetched=fetched,
                skipped_before_cutoff=skipped_before_cutoff,
            )
            return self._log_stage(
                run_id, device, PullStage.PULL_ATTENDANCE, PullStatus.SUCCESS,
                record_count=0, duration_ms=int((time.monotonic() - start) * 1000),
            )

        try:
            inserted = self._insert_punches(logs, device)
            archived = self._attendance.archive_attlog(device.serial, logs)
        except Exception as exc:
            return self._log_stage(
                run_id, device, PullStage.PULL_ATTENDANCE, PullStatus.FAILED,
                error=str(exc), duration_ms=int((time.monotonic() - start) * 1000),
            )

        self._log.info(
            "Pulled attendance.",
            serial=device.serial,
            fetched=fetched,
            skipped_before_cutoff=skipped_before_cutoff,
            considered=len(logs),
            inserted=inserted,
            duplicates=len(logs) - inserted,
            archived=archived,
        )
        return self._log_stage(
            run_id, device, PullStage.PULL_ATTENDANCE, PullStatus.SUCCESS,
            record_count=inserted, duration_ms=int((time.monotonic() - start) * 1000),
        )

    def _insert_punches(self, logs: list[AttendanceLog], device: PullDevice) -> int:
        """
        Insert-only, same as the push collector's own contract: ``AttendanceStore.add_attendance``
        (through ``dbo.CheckInOut_add``) is itself an ``IF NOT EXISTS`` insert on
        ``(MaChamCong, GioCham)`` -- a punch already stored is skipped, never rewritten. The
        window-scoped ``existing_punch_keys`` lookup below is what makes that check an index seek
        rather than a table scan (same approach as ``AdmsService._insert_punches``). Callers only
        reach here after confirming ``device.is_linked``, so ``machine_id`` is never ``None``.
        """
        machine_id = device.machine_id
        if machine_id is None:  # pragma: no cover - guarded by the caller; kept for mypy/safety
            raise ValueError(f"Device {device.serial!r} is not linked to a machine.")
        stamps = [log.timestamp for log in logs]
        window_start = min(stamps)
        window_end = max(stamps) + dt.timedelta(seconds=1)
        existing: set[PunchKey] = self._attendance.existing_punch_keys(machine_id, window_start, window_end)
        return self._attendance.add_attendance(
            logs, machine_id=machine_id, machine_name=device.machine_name, existing_keys=existing
        )

    # ── Cross-device employee sync ──────────────────────────────────────────────────────

    def _sync_groups(
        self,
        run_id: int,
        devices: list[PullDevice],
        rosters: dict[str, list[DeviceUser]],
        sessions: dict[str, object],
    ) -> list[DeviceStageResult]:
        """
        Reconcile every ``PullGroup`` represented among ``devices`` this run: for each group,
        build the union of employees known from any device pulled successfully in that group, and
        push whoever is missing to every other device in the group -- insert-only in this
        direction too, since only PINs *absent* from a target device's own roster (read fresh in
        phase 1, right before this runs) are ever pushed to it; a PIN the device already reports
        having is left exactly as that device already has it.

        Only groups with at least two devices actually pulled this run produce any work -- a lone
        device in a group has nothing to reconcile against ("dong bo nhan vien giua cac may cung
        khu vuc" -- sync employees between machines in the same area -- needs at least two).
        """
        by_group: dict[str, list[PullDevice]] = defaultdict(list)
        for device in devices:
            if device.pull_group and device.serial in rosters:
                by_group[device.pull_group].append(device)

        results: list[DeviceStageResult] = []
        for group, group_devices in by_group.items():
            if len(group_devices) < 2:
                continue
            results.extend(self._sync_one_group(run_id, group, group_devices, rosters, sessions))
        return results

    def _sync_one_group(
        self,
        run_id: int,
        group: str,
        devices: list[PullDevice],
        rosters: dict[str, list[DeviceUser]],
        sessions: dict[str, object],
    ) -> list[DeviceStageResult]:
        # Union of PINs known anywhere in the group, keyed by PIN so "which devices already have
        # this person" is easy to compute per target device below.
        union: dict[str, DeviceUser] = {}
        for device in devices:
            for user in rosters.get(device.serial, []):
                if user.pin.strip():
                    union.setdefault(user.pin, user)

        self._log.debug("Reconciling a pull group.", group=group, devices=len(devices), people=len(union))

        results: list[DeviceStageResult] = []
        for device in devices:
            known_pins = {u.pin for u in rosters.get(device.serial, [])}
            missing_pins = [pin for pin in union if pin not in known_pins]
            if not missing_pins:
                results.append(
                    self._log_stage(
                        run_id, device, PullStage.SYNC_EMPLOYEES, PullStatus.SUCCESS, record_count=0
                    )
                )
                continue
            session = sessions.get(device.serial)
            results.append(self._push_missing_employees(run_id, device, missing_pins, union, session))
        return results

    def _push_missing_employees(
        self,
        run_id: int,
        device: PullDevice,
        missing_pins: list[str],
        union: dict[str, DeviceUser],
        session: object | None,
    ) -> DeviceStageResult:
        """
        Push every PIN in ``missing_pins`` to ``device`` -- reuses the session already open from
        phase 1 rather than reconnecting, since a device only reaches this method when its own
        phase-1 connect already succeeded (see the ``sessions.get`` guard at the call site: a
        ``None`` session means phase 1 never got this far, and this method is not called at all).

        Each PIN is pushed independently: one PIN's failure (a malformed template, a value the
        device rejects) is logged and skipped, and every other PIN in the batch is still
        attempted -- a single bad record must not silently drop the rest of a legitimate sync.
        """
        start = time.monotonic()
        if session is None:
            return self._log_stage(
                run_id, device, PullStage.SYNC_EMPLOYEES, PullStatus.SKIPPED,
                error="No open session (device did not connect successfully in phase 1).",
            )

        pushed = 0
        failed_pins: list[str] = []
        for pin in missing_pins:
            try:
                session.set_employee(union[pin])
                pushed += 1
                self._push_known_fingerprints(session, device, pin)
            except Exception as exc:
                failed_pins.append(pin)
                self._log.warn(
                    "Could not sync one employee to a device.",
                    exc,
                    serial=device.serial,
                    pin=pin,
                )

        self._log.info(
            "Synced missing employees into a device.",
            serial=device.serial,
            group=device.pull_group,
            pushed=pushed,
            failed=len(failed_pins),
        )
        status = PullStatus.FAILED if pushed == 0 and failed_pins else PullStatus.SUCCESS
        error = (
            f"{len(failed_pins)} PIN(s) could not be synced: {', '.join(failed_pins[:10])}"
            if failed_pins
            else ""
        )
        return self._log_stage(
            run_id, device, PullStage.SYNC_EMPLOYEES, status,
            record_count=pushed, duration_ms=int((time.monotonic() - start) * 1000), error=error,
        )

    def _push_known_fingerprints(self, session, device: PullDevice, pin: str) -> None:
        """
        Push whatever fingerprint templates ``dbo.TEMPLATE`` already holds for ``pin`` -- the
        database, not any specific source device. By the time sync runs, the employee pull for
        every device in the group has already committed, and reading from ``dbo.TEMPLATE``
        (which the desktop app and any prior pull already populate) means a person enrolled on
        any device at any time is find-able for sync, without needing this run to have pulled
        *that exact device's* fingerprints first. Best-effort: a person still gets their employee
        record even if their templates cannot be read or pushed.
        """
        reader = getattr(self._templates, "read_fingerprints", None)
        if reader is None:
            return
        try:
            for finger in reader(pin):
                session.set_fingerprint(finger)
        except Exception as exc:
            self._log.warn(
                "Could not push a fingerprint template during employee sync.",
                exc,
                serial=device.serial,
                pin=pin,
            )

    # ── Shared helpers ───────────────────────────────────────────────────────────────────

    def _log_stage(
        self,
        run_id: int,
        device: PullDevice,
        stage: PullStage,
        status: PullStatus,
        *,
        record_count: int = 0,
        duration_ms: int = 0,
        error: str = "",
    ) -> DeviceStageResult:
        result = DeviceStageResult(
            serial=device.serial,
            device_name=device.device_name,
            stage=stage,
            status=status,
            record_count=record_count,
            duration_ms=duration_ms,
            error=error,
        )
        if status is PullStatus.FAILED:
            self._log.error(
                f"{stage.value} failed.", None, serial=device.serial, error=error,
            )
        elif status is PullStatus.SKIPPED:
            self._log.warn(f"{stage.value} skipped.", None, serial=device.serial, reason=error)
        elif error:
            # A "successful" stage that still carries an error message is a partial success
            # (e.g. sync pushed some PINs and skipped others) -- worth a WARN, not a silent INFO.
            self._log.warn(
                f"{stage.value} succeeded with some failures.",
                None,
                serial=device.serial,
                records=record_count,
                duration_ms=duration_ms,
                detail=error,
            )
        else:
            self._log.info(
                f"{stage.value} succeeded.",
                serial=device.serial,
                records=record_count,
                duration_ms=duration_ms,
            )
        self._runlog.record_stage(run_id, result)
        return result

    def _mark_status(self, serial: str, status: str) -> None:
        try:
            self._registry.record_pull_result(serial, at=self._clock.utc_now(), status=status)
        except Exception as exc:
            self._log.warn("Could not record the device's last-pull status.", exc, serial=serial)
