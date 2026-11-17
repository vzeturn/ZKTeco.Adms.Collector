"""
In-memory adapters for every port.

Two real uses, neither of them throwaway:

* **Protocol work without infrastructure.** ``tools/local_server.py --fake`` serves the full ADMS
  conversation with no SQL Server, no ODBC driver and no cloud account. Pointing a real device at a
  laptop running that is the fastest way to find out what a given firmware actually sends.
* **Exercising :class:`~adms.service.AdmsService`** — all of its ordering rules (commit before
  acknowledge, advance the stamp last, count what the device sent) are observable here.

Behaviour deliberately matches the SQL adapters where a difference would be misleading: PINs that
are not integers are skipped, ``(pin, timestamp)`` dedup is enforced, and templates are
replace-per-PIN. A fake that is more permissive than production is worse than no fake, because it
green-lights payloads that will fail for real.
"""

from __future__ import annotations

import datetime as dt

from .models import (
    AttendanceLog,
    BackfillResult,
    CommandAck,
    DeviceCommand,
    DeviceInfo,
    DeviceRegistration,
    DeviceUser,
    FaceTemplate,
    FanOutResult,
    FingerTemplate,
    OperationEvent,
    PunchKey,
    ReconcileResult,
    UserPhoto,
)
from .protocol.commands import delete_userinfo, update_facetmp, update_fingertmp, update_user

__all__ = [
    "InMemoryDeviceRegistry",
    "InMemoryAttendanceStore",
    "InMemoryEmployeeStore",
    "InMemoryTemplateStore",
    "InMemoryCommandQueue",
    "InMemoryPushArchive",
    "InMemoryRosterSync",
    "FixedClock",
]


class FixedClock:
    """A clock that does not move, so timestamps in assertions are stable."""

    __slots__ = ("_now", "_offset")

    def __init__(self, now: dt.datetime | None = None, utc_offset_hours: int = 7) -> None:
        self._now = now or dt.datetime(2026, 1, 1, 0, 0, 0)
        self._offset = dt.timedelta(hours=utc_offset_hours)

    def utc_now(self) -> dt.datetime:
        return self._now

    def local_now(self) -> dt.datetime:
        return self._now + self._offset


class InMemoryDeviceRegistry:
    """Allow-list held in a dict."""

    def __init__(self, devices: list[DeviceRegistration] | None = None) -> None:
        self.devices: dict[str, DeviceRegistration] = {d.serial: d for d in (devices or [])}
        self.contacts: list[tuple[str, dt.datetime, str]] = []
        self.options: dict[str, DeviceInfo] = {}
        self.pending: list[str] = []

    def find(self, serial: str) -> DeviceRegistration | None:
        return self.devices.get(serial)

    def record_contact(
        self,
        serial: str,
        *,
        seen_at: dt.datetime,
        source_ip: str = "",
        info: DeviceInfo | None = None,
    ) -> None:
        self.contacts.append((serial, seen_at, source_ip))
        if info is not None:
            self.options[serial] = info

    def register_pending(self, serial: str, *, seen_at: dt.datetime, source_ip: str = "") -> None:
        # Records the sighting but grants nothing — same as the SQL adapter, whose INSERT sets
        # Enabled = 0. A fake that quietly enabled the device would make the allow-list untestable.
        if serial not in self.pending:
            self.pending.append(serial)

    def advance_stamp(self, serial: str, table: str, stamp: str) -> None:
        current = self.devices.get(serial)
        if current is None:
            return
        field = {
            "ATTLOG": "attlog_stamp",
            "OPERLOG": "operlog_stamp",
            "ATTPHOTO": "attphoto_stamp",
        }.get(table.upper())
        if field is None:
            return
        # DeviceRegistration is frozen, so advancing means replacing.
        self.devices[serial] = DeviceRegistration(
            **{**{f: getattr(current, f) for f in current.__slots__}, field: stamp}
        )


class InMemoryAttendanceStore:
    """Punch store enforcing the same ``(pin, timestamp)`` uniqueness as ``CheckInOut`` dedup."""

    def __init__(self) -> None:
        self.punches: dict[int, set[PunchKey]] = {}
        self.rows: list[dict] = []
        self.archived: list[tuple[str, AttendanceLog]] = []

    def existing_punch_keys(
        self, machine_id: int, from_inclusive: dt.datetime, to_exclusive: dt.datetime
    ) -> set[PunchKey]:
        return {
            key
            for key in self.punches.get(machine_id, set())
            if from_inclusive <= key[1] < to_exclusive
        }

    def add_attendance(
        self,
        logs: list[AttendanceLog],
        *,
        machine_id: int,
        machine_name: str,
        existing_keys: set[PunchKey] | None = None,
    ) -> int:
        stored = self.punches.setdefault(machine_id, set())
        inserted = 0
        seen_in_batch: set[PunchKey] = set()

        for log in logs:
            key = log.key
            if key is None or key in seen_in_batch:
                continue
            seen_in_batch.add(key)
            if existing_keys is not None and key in existing_keys:
                continue
            stored.add(key)
            self.rows.append(
                {
                    "MaChamCong": key[0],
                    "NgayCham": key[1].date(),
                    "GioCham": key[1],
                    "KieuCham": "1",
                    "NguonCham": "",
                    "MaSoMay": machine_id,
                    "TenMay": machine_name,
                }
            )
            inserted += 1
        return inserted

    def archive_attlog(self, serial: str, logs: list[AttendanceLog]) -> int:
        self.archived.extend((serial, log) for log in logs)
        return len(logs)


class InMemoryEmployeeStore:
    def __init__(self, known_pins: set[int] | None = None) -> None:
        self.employees: dict[int, DeviceUser] = {}
        #: PINs that exist in NHANVIEN without the console having upserted them, so a test can model a
        #: roster that already knows some people.
        self.preexisting: set[int] = set(known_pins or ())

    def upsert_employees(self, users: list[DeviceUser]) -> int:
        affected = 0
        for user in users:
            pin = user.numeric_pin
            if pin is None:
                continue
            self.employees[pin] = user
            affected += 1
        return affected

    def missing_employee_pins(self, pins: set[int]) -> set[int]:
        return {p for p in pins if p not in self.employees and p not in self.preexisting}


class InMemoryTemplateStore:
    def __init__(self) -> None:
        self.fingers: dict[int, list[FingerTemplate]] = {}
        self.faces: dict[int, list[FaceTemplate]] = {}

    def save_fingerprints(self, templates: list[FingerTemplate]) -> int:
        return _replace_per_pin(self.fingers, templates)

    def save_faces(self, templates: list[FaceTemplate]) -> int:
        return _replace_per_pin(self.faces, templates)


def _replace_per_pin(target: dict[int, list], templates: list) -> int:
    grouped: dict[int, list] = {}
    for template in templates:
        if not template.template:
            continue
        try:
            pin = int(template.pin.strip())
        except (AttributeError, ValueError):
            continue
        grouped.setdefault(pin, []).append(template)

    written = 0
    for pin, items in grouped.items():
        target[pin] = items          # replace, never merge — matches the SQL adapter
        written += len(items)
    return written


class InMemoryCommandQueue:
    def __init__(self, now: dt.datetime | None = None) -> None:
        self.pending: dict[str, list[DeviceCommand]] = {}
        self.sent: list[DeviceCommand] = []
        self.acks: list[CommandAck] = []
        #: (serial, command_id, body, created_at) for every command ever queued, so the cooldown check
        #: can see dispatched ones too.
        self.history: list[tuple[str, int, str, dt.datetime]] = []
        self._next_id = 1
        self._now = now or dt.datetime(2026, 1, 1)

    def dequeue(self, serial: str, limit: int) -> list[DeviceCommand]:
        queue = self.pending.get(serial, [])
        claimed = queue[: max(0, limit)]
        # Removed on read, mirroring the SQL adapter's claim-on-read / at-most-once semantics.
        self.pending[serial] = queue[len(claimed) :]
        self.sent.extend(claimed)
        return claimed

    def ack(self, serial: str, acks: list[CommandAck]) -> int:
        # Scoped by serial as well as command id, mirroring the SQL adapter's
        # `WHERE CommandId = ? AND SerialNumber = ?`. A command id travels to the device and
        # comes back unverified, so an ack for an id this serial never had queued (self.history
        # says who owns each id) is dropped rather than accepted -- otherwise one device could
        # close a command queued for another.
        owned_ids = {
            cmd_id for entry_serial, cmd_id, _body, _created in self.history if entry_serial == serial
        }
        accepted = [ack for ack in acks if ack.command_id in owned_ids]
        self.acks.extend(accepted)
        return len(accepted)

    def enqueue(self, serial: str, body: str) -> int:
        # Matches SqlServerCommandQueue.enqueue's own contract: a blank or whitespace-only body
        # is refused rather than queued. Letting it through here would be the fake green-lighting
        # a payload that the real adapter -- and the device -- would reject.
        text = (body or "").strip()
        if not text:
            raise ValueError("Refusing to queue an empty command.")
        command_id = self._next_id
        self._next_id += 1
        self.pending.setdefault(serial, []).append(DeviceCommand(command_id=command_id, body=body))
        # Kept separately from `pending`, because dequeue() removes from that list and the cooldown
        # below has to see commands that were already dispatched -- the SQL adapter matches on
        # CreatedUtc regardless of status, and a fake that forgets would let the service enqueue
        # duplicates that production would suppress.
        self.history.append((serial, command_id, body, self._now))
        return command_id

    def pins_with_recent_request(self, serial: str, pins: set[int], since) -> set[int]:
        """Mirrors the SQL adapter: any status counts, and PIN=12 must not match PIN=123."""
        import re

        hit: set[int] = set()
        for entry_serial, _cmd_id, body, created in self.history:
            if entry_serial != serial or created < since:
                continue
            for pin in pins:
                if re.search(rf"PIN={pin}(?![0-9])", body):
                    hit.add(pin)
        return hit


class InMemoryRosterSync:
    """
    In-memory twin of :class:`~adms.db.roster_sync.SqlServerRosterSync`.

    Mirrors the SQL adapter's observable behaviour rather than re-deriving its own: same
    Sync_Group boundary (Requirement 25), same "Fan_Out never touches the target's
    Sync_Cursor, only Backfill does" split (see the SQL adapter's own module docstring for why),
    same one-shared-sequence-per-group Roster_Version assignment (see
    ``ADMS_DEVICE_ROSTER_SEQUENCE``'s own schema comment for why two different PINs must never be
    able to land on the same version number), same "due" combination for Backfill (owed > 0 AND
    (never backfilled OR silent past threshold)). Constructed with references to the other
    in-memory stores it reads from, exactly as the SQL adapter is constructed with references to
    the tables it reads from -- there is no separate "employee data" living inside this class.
    """

    def __init__(
        self,
        *,
        employees: InMemoryEmployeeStore,
        templates: InMemoryTemplateStore,
        registry: InMemoryDeviceRegistry,
        commands: InMemoryCommandQueue,
        settings,
        clock: FixedClock | None = None,
        log=None,
    ) -> None:
        self._employees = employees
        self._templates = templates
        self._registry = registry
        self._commands = commands
        self._settings = settings
        self._clock = clock
        self._log = log
        #: (Pin, SyncGroup) -> version. Mirrors ADMS_DEVICE_ROSTER_VERSION.
        self.versions: dict[tuple[int, str], int] = {}
        #: (Pin, SyncGroup) -> is this version a deletion snapshot. Mirrors
        #: ADMS_DEVICE_ROSTER_VERSION.IsDeleted. Missing key means False, same as a live column
        #: default -- a (pin, group) that fan_out (not fan_out_delete) last touched is absent
        #: here, not present-and-False, but callers use .get(key, False) either way.
        self.deleted: dict[tuple[int, str], bool] = {}
        #: SyncGroup -> next value to draw. Mirrors ADMS_DEVICE_ROSTER_SEQUENCE -- see that
        #: table's own schema comment for why every change in a group must draw from ONE shared
        #: counter rather than each PIN incrementing independently (two different PINs could
        #: otherwise land on the same version number, making a single scalar cursor ambiguous).
        self._sequence: dict[str, int] = {}
        #: (serial, Pin) -> version. Mirrors ADMS_DEVICE_ROSTER (diagnostic only).
        self.pushed: dict[tuple[str, int], int] = {}

    def fan_out(
        self,
        origin_serial: str,
        sync_group: str,
        pin: int,
        *,
        fingers: list[FingerTemplate] | None = None,
        faces: list[FaceTemplate] | None = None,
    ) -> FanOutResult:
        user = self._employees.employees.get(pin)
        if user is None:
            return FanOutResult(pins=[pin], targets_notified=0, commands_enqueued=0, deferred=0)

        version = self._sequence.get(sync_group, 0) + 1
        self._sequence[sync_group] = version
        self.versions[(pin, sync_group)] = version
        self.deleted[(pin, sync_group)] = False

        targets = [
            d.serial
            for d in self._registry.devices.values()
            if d.enabled and d.is_linked and d.sync_group == sync_group and d.serial != origin_serial
        ]

        cap = self._settings.roster_sync_max_commands_per_cycle
        push_faces = self._settings.roster_sync_push_faces
        fingers = fingers or []
        faces = (faces or []) if push_faces else []

        total_enqueued = 0
        total_deferred = 0
        for target_serial in targets:
            bodies = [update_user(user)]
            for finger in sorted(fingers, key=lambda f: f.finger_id):
                bodies.append(update_fingertmp(finger.pin, finger.finger_id, finger.template, valid=finger.normalized_flag))
            for face in sorted(faces, key=lambda f: f.face_id):
                bodies.append(update_facetmp(face.pin, face.face_id, face.template, size=face.size or None, valid=face.valid))

            to_send, deferred = bodies[:cap], max(0, len(bodies) - cap)
            for body in to_send:
                try:
                    self._commands.enqueue(target_serial, body)
                    total_enqueued += 1
                except Exception as exc:  # noqa: BLE001
                    if self._log is not None:
                        self._log.warn(
                            "Could not enqueue a Push_Command for one Fan_Out target.",
                            exc,
                            serial=target_serial,
                            pin=pin,
                        )
            total_deferred += deferred
            self.pushed[(target_serial, pin)] = version

        return FanOutResult(
            pins=[pin],
            targets_notified=len(targets),
            commands_enqueued=total_enqueued,
            deferred=total_deferred,
        )

    def fan_out_delete(self, origin_serial: str, sync_group: str, pin: int) -> FanOutResult:
        version = self._sequence.get(sync_group, 0) + 1
        self._sequence[sync_group] = version
        self.versions[(pin, sync_group)] = version
        self.deleted[(pin, sync_group)] = True

        targets = [
            d.serial
            for d in self._registry.devices.values()
            if d.enabled and d.is_linked and d.sync_group == sync_group and d.serial != origin_serial
        ]

        body = delete_userinfo(str(pin))
        enqueued = 0
        for target_serial in targets:
            try:
                self._commands.enqueue(target_serial, body)
                enqueued += 1
            except Exception as exc:  # noqa: BLE001
                if self._log is not None:
                    self._log.warn(
                        "Could not enqueue a delete Push_Command for one Fan_Out target.",
                        exc,
                        serial=target_serial,
                        pin=pin,
                    )
            self.pushed[(target_serial, pin)] = version

        return FanOutResult(pins=[pin], targets_notified=len(targets), commands_enqueued=enqueued, deferred=0)

    def reconcile_deletions(self, sync_group: str) -> ReconcileResult | None:
        live_pins = {
            pin
            for (pin, group), is_deleted in self.deleted.items()
            if group == sync_group and not is_deleted
        }
        vanished = sorted(pin for pin in live_pins if pin not in self._employees.employees)
        if not vanished:
            return None

        total_enqueued = 0
        deleted_pins: list[int] = []
        for pin in vanished:
            try:
                result = self.fan_out_delete("", sync_group, pin)
                total_enqueued += result.commands_enqueued
                deleted_pins.append(pin)
            except Exception as exc:  # noqa: BLE001
                if self._log is not None:
                    self._log.warn(
                        "Could not fan out a DB-side deletion for one PIN.",
                        exc,
                        sync_group=sync_group,
                        pin=pin,
                    )

        return ReconcileResult(sync_group=sync_group, deleted_pins=deleted_pins, commands_enqueued=total_enqueued)

    def backfill_if_due(self, registration: DeviceRegistration) -> BackfillResult | None:
        if not registration.sync_group:
            return None

        group_versions = {k: v for k, v in self.versions.items() if k[1] == registration.sync_group}
        group_max = max(group_versions.values(), default=0)
        owed = group_max - registration.roster_sync_stamp
        if owed <= 0:
            return None

        never_backfilled = registration.roster_sync_stamp == 0
        contacts = [c for c in self._registry.contacts if c[0] == registration.serial]
        last_seen = contacts[-1][1] if contacts else None
        now = self._clock.utc_now() if self._clock is not None else last_seen
        silent_too_long = (
            last_seen is None
            or (now is not None and (now - last_seen).total_seconds() >= self._settings.roster_sync_backfill_silence_hours * 3600)
        )
        if not (never_backfilled or silent_too_long):
            return None

        owed_pins = sorted(
            ((pin, ver, self.deleted.get((pin, group), False)) for (pin, group), ver in self.versions.items()
             if group == registration.sync_group and ver > registration.roster_sync_stamp),
            key=lambda pv: pv[1],
        )
        if not owed_pins:
            self._advance_stamp(registration.serial, group_max)
            return BackfillResult(serial=registration.serial, enqueued=0, remaining=0)

        cap = self._settings.roster_sync_max_commands_per_cycle
        slice_pins, remaining_pins = owed_pins[:cap], owed_pins[cap:]

        enqueued = 0
        highest = registration.roster_sync_stamp
        for pin, version, is_deleted in slice_pins:
            if is_deleted:
                try:
                    self._commands.enqueue(registration.serial, delete_userinfo(str(pin)))
                    enqueued += 1
                    self.pushed[(registration.serial, pin)] = version
                except Exception as exc:  # noqa: BLE001
                    if self._log is not None:
                        self._log.warn(
                            "Could not enqueue a Backfill delete Push_Command for one PIN.",
                            exc,
                            serial=registration.serial,
                            pin=pin,
                        )
                highest = max(highest, version)
                continue

            user = self._employees.employees.get(pin)
            if user is None:
                highest = max(highest, version)
                continue
            try:
                self._commands.enqueue(registration.serial, update_user(user))
                enqueued += 1
                for finger in self._templates.fingers.get(pin, []):
                    self._commands.enqueue(
                        registration.serial,
                        update_fingertmp(finger.pin, finger.finger_id, finger.template, valid=finger.normalized_flag),
                    )
                    enqueued += 1
                if self._settings.roster_sync_push_faces:
                    for face in self._templates.faces.get(pin, []):
                        self._commands.enqueue(
                            registration.serial,
                            update_facetmp(face.pin, face.face_id, face.template, size=face.size or None, valid=face.valid),
                        )
                        enqueued += 1
                self.pushed[(registration.serial, pin)] = version
                highest = max(highest, version)
            except Exception as exc:  # noqa: BLE001
                if self._log is not None:
                    self._log.warn(
                        "Could not enqueue a Backfill Push_Command for one PIN.",
                        exc,
                        serial=registration.serial,
                        pin=pin,
                    )

        self._advance_stamp(registration.serial, highest)
        return BackfillResult(serial=registration.serial, enqueued=enqueued, remaining=len(remaining_pins))

    def _advance_stamp(self, serial: str, stamp: int) -> None:
        current = self._registry.devices.get(serial)
        if current is None or current.roster_sync_stamp >= stamp:
            return
        self._registry.devices[serial] = DeviceRegistration(
            **{**{f: getattr(current, f) for f in current.__slots__}, "roster_sync_stamp": stamp}
        )


class InMemoryPushArchive:
    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.operations: list[tuple[str, OperationEvent]] = []
        self.photos: list[tuple[str, UserPhoto]] = []
        self.unparsed: list[tuple[str, str, str]] = []

    def archive_request(
        self,
        *,
        serial: str,
        route: str,
        table: str,
        query: str,
        body: str,
        record_count: int,
    ) -> None:
        self.requests.append(
            {
                "serial": serial,
                "route": route,
                "table": table,
                "query": query,
                "body": body,
                "record_count": record_count,
            }
        )

    def archive_operations(self, serial: str, events: list[OperationEvent]) -> int:
        self.operations.extend((serial, event) for event in events)
        return len(events)

    def archive_photos(self, serial: str, photos: list[UserPhoto]) -> int:
        self.photos.extend((serial, photo) for photo in photos)
        return len(photos)

    def archive_unparsed(self, serial: str, table: str, lines: list[str]) -> int:
        self.unparsed.extend((serial, table, line) for line in lines)
        return len(lines)
