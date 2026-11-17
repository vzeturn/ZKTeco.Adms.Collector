"""
multi-device-employee-sync: propagating one device's roster/template changes to every other
device sharing its Sync_Group (Fan_Out), and catching a new or long-silent device up with
everything it is missing (Backfill).

Reads ``NHANVIEN``/``dbo.TEMPLATE``/``dbo.Face`` directly (Requirement 27.3: "not from another
device's queue") using the same table/column identifiers :mod:`adms.db.schema` already defines
for :mod:`adms.db.employees`/:mod:`adms.db.templates` -- this module does not call those adapters,
it reads the same locked tables independently, because Backfill must never depend on another
device being reachable and neither of those adapters' existing methods answer "give me PIN N's
full row" (they are shaped for device-upload batches, not for a single-PIN read).

Writes go through the existing :class:`~adms.ports.CommandQueue` (``ADMS_COMMAND``) via the same
``enqueue(serial, body)`` contract the enrolment loop already uses -- a Push_Command is, from
every other part of this codebase's perspective, indistinguishable from any other queued command.

**Known trade-off, stated once here rather than re-discovered:** Fan_Out never advances a target
device's Sync_Cursor (``ADMS_DEVICE.RosterSyncStamp``) -- only :meth:`SqlServerRosterSync.
backfill_if_due` does. That means ``vw_ADMS_RosterSyncStatus.PinsOwed`` is a conservative upper
bound for a device that is actually current via Fan_Out alone: it will read as "owed" something
until that device's next Backfill check clears it, even though the device already received the
update in real time. This mirrors other documented approximations in this schema (``IDMCC`` not
being a unique machine identity, ``KieuCham``'s ambiguous in/out semantics) -- correct for what it
promises (the device has the data), approximate for what it reports (the view's own gap number).
"""

from __future__ import annotations

from ..errors import AttendanceDbError
from ..models import (
    BackfillResult,
    DeviceUser,
    FaceTemplate,
    FanOutResult,
    FingerTemplate,
    ReconcileResult,
    UserPrivilege,
)
from ..protocol.commands import delete_userinfo, update_facetmp, update_fingertmp, update_user
from .connection import ConnectionFactory, transaction
from .schema import (
    COL_NV_MACHAMCONG,
    COL_NV_MATHE,
    COL_NV_PHANQUYEN,
    COL_NV_TENCHAMCONG,
    COL_NV_USERENABLE,
    COL_ROSTER_VERSION_IS_DELETED,
    TABLE_ADMS_DEVICE,
    TABLE_ADMS_DEVICE_ROSTER,
    TABLE_ADMS_DEVICE_ROSTER_VERSION,
    TABLE_EMPLOYEES,
    TABLE_FACE,
    TABLE_FINGER,
    parse_enabled,
)



__all__ = ["SqlServerRosterSync"]


class SqlServerRosterSync:
    """Implements :class:`~adms.ports.RosterSync`."""

    __slots__ = ("_factory", "_commands", "_settings", "_log")

    def __init__(self, factory: ConnectionFactory, *, commands, settings, log=None) -> None:
        self._factory = factory
        self._commands = commands
        self._settings = settings
        self._log = log

    # ── Fan_Out (Requirement 26) ────────────────────────────────────────────────────────

    def fan_out(
        self,
        origin_serial: str,
        sync_group: str,
        pin: int,
        *,
        fingers: list[FingerTemplate] | None = None,
        faces: list[FaceTemplate] | None = None,
    ) -> FanOutResult:
        row = self._read_employee_row(pin)
        if row is None:
            # The employee upsert that triggered this call is expected to have committed already
            # (Requirement 26.1 runs Fan_Out after that commit) -- a missing row here means the
            # PIN was not actually persisted (a non-numeric PIN slipped through, or a race), and
            # there is nothing to propagate. Not an error: the caller already logs it as "found
            # nothing to fan out" via an empty result.
            return FanOutResult(pins=[pin], targets_notified=0, commands_enqueued=0, deferred=0)

        version = self._bump_version(pin, sync_group)
        targets = self._fan_out_targets(origin_serial, sync_group)

        cap = self._settings.roster_sync_max_commands_per_cycle
        push_faces = self._settings.roster_sync_push_faces
        fingers = fingers or []
        faces = faces or [] if push_faces else []

        total_enqueued = 0
        total_deferred = 0
        for target_serial in targets:
            bodies = [_render_update_user(row)]
            for finger in sorted(fingers, key=lambda f: f.finger_id):
                bodies.append(_render_update_fingertmp(finger))
            for face in sorted(faces, key=lambda f: f.face_id):
                bodies.append(_render_update_facetmp(face))

            to_send, deferred = bodies[:cap], max(0, len(bodies) - cap)
            for body in to_send:
                try:
                    self._commands.enqueue(target_serial, body)
                    total_enqueued += 1
                except Exception as exc:  # noqa: BLE001 -- Requirement 26.7: one target's failure
                    # must not stop the others.
                    if self._log is not None:
                        self._log.warn(
                            "Could not enqueue a Push_Command for one Fan_Out target.",
                            exc,
                            serial=target_serial,
                            pin=pin,
                        )
            total_deferred += deferred
            self._record_pushed(target_serial, pin, version)

        return FanOutResult(
            pins=[pin],
            targets_notified=len(targets),
            commands_enqueued=total_enqueued,
            deferred=total_deferred,
        )

    # ── Delete fan-out (ISO 27001 traceability) ─────────────────────────────────────────

    def fan_out_delete(self, origin_serial: str, sync_group: str, pin: int) -> FanOutResult:
        version = self._bump_version(pin, sync_group, is_deleted=True)
        targets = self._fan_out_targets(origin_serial, sync_group)

        body = delete_userinfo(str(pin))
        enqueued = 0
        for target_serial in targets:
            try:
                self._commands.enqueue(target_serial, body)
                enqueued += 1
            except Exception as exc:  # noqa: BLE001 -- one target's failure must not stop others
                if self._log is not None:
                    self._log.warn(
                        "Could not enqueue a delete Push_Command for one Fan_Out target.",
                        exc,
                        serial=target_serial,
                        pin=pin,
                    )
            self._record_pushed(target_serial, pin, version)

        return FanOutResult(pins=[pin], targets_notified=len(targets), commands_enqueued=enqueued, deferred=0)

    def reconcile_deletions(self, sync_group: str) -> ReconcileResult | None:
        """
        Find every PIN this group has ever pushed and still counts as live (a row in
        ``ADMS_DEVICE_ROSTER_VERSION`` with ``IsDeleted = 0``) whose ``NHANVIEN`` row is gone, and
        fan out a delete for each one.

        Anti-join against ``NHANVIEN`` rather than a per-PIN existence check in a loop: one
        indexed query for the whole group, matching the same "batch, not N+1" discipline
        :meth:`~adms.db.employees.SqlServerEmployeeStore.missing_employee_pins` already applies
        for the enrolment path.
        """
        sql = f"""
            SELECT v.Pin
            FROM   {TABLE_ADMS_DEVICE_ROSTER_VERSION} v
            WHERE  v.SyncGroup = ? AND v.{COL_ROSTER_VERSION_IS_DELETED} = 0
              AND  NOT EXISTS (
                        SELECT 1 FROM {TABLE_EMPLOYEES} e WHERE e.{COL_NV_MACHAMCONG} = v.Pin
                   )
        """
        try:
            cursor = self._factory.get().cursor()
            try:
                cursor.execute(sql, (sync_group,))
                rows = cursor.fetchall()
            finally:
                cursor.close()
        except AttendanceDbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AttendanceDbError("Failed to read PINs pending delete reconciliation.") from exc

        vanished_pins = [int(row[0]) for row in rows]
        if not vanished_pins:
            return None

        total_enqueued = 0
        deleted: list[int] = []
        for pin in vanished_pins:
            try:
                # origin_serial="" -- a DB-side deletion has no originating device to exclude,
                # so every Enabled_Device in the group is a legitimate target.
                result = self.fan_out_delete("", sync_group, pin)
                total_enqueued += result.commands_enqueued
                deleted.append(pin)
            except Exception as exc:  # noqa: BLE001 -- one PIN's failure must not stop the rest
                if self._log is not None:
                    self._log.warn(
                        "Could not fan out a DB-side deletion for one PIN.",
                        exc,
                        sync_group=sync_group,
                        pin=pin,
                    )

        return ReconcileResult(sync_group=sync_group, deleted_pins=deleted, commands_enqueued=total_enqueued)

    def _read_employee_row(self, pin: int) -> "_EmployeeRow | None":
        sql = f"""
            SELECT  {COL_NV_MACHAMCONG}, {COL_NV_TENCHAMCONG}, {COL_NV_MATHE},
                    {COL_NV_PHANQUYEN}, {COL_NV_USERENABLE}
            FROM    {TABLE_EMPLOYEES}
            WHERE   {COL_NV_MACHAMCONG} = ?
        """
        try:
            cursor = self._factory.get().cursor()
            try:
                cursor.execute(sql, (pin,))
                row = cursor.fetchone()
            finally:
                cursor.close()
        except AttendanceDbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AttendanceDbError("Failed to read the employee row for Roster_Sync.") from exc

        if row is None:
            return None
        return _EmployeeRow(
            pin=int(row[0]),
            name=(row[1] or "").strip(),
            card=(row[2] or "").strip(),
            privilege=int(row[3] or 0),
            enabled=parse_enabled(row[4]),
        )

    def _bump_version(self, pin: int, sync_group: str, *, is_deleted: bool = False) -> int:
        """
        Draw the next value from the group's shared sequence (``ADMS_DEVICE_ROSTER_SEQUENCE``)
        and record it as this PIN's current ``RosterVersion``. Returns the drawn value.

        ``is_deleted`` flags the snapshot as a deletion (Requirement extension for ISO 27001
        traceability) rather than a live entry -- see sql/adms-schema.sql's own rationale for why
        this cannot be inferred later from whether ``NHANVIEN`` currently has a row for ``pin``.

        Two statements in one transaction, not two calls: the sequence advance and the per-PIN
        snapshot must commit together, or a crash between them would either lose a drawn value
        (never assigned to any PIN, harmless) or -- worse -- leave the sequence one behind what a
        PIN claims to be at (a value that could then be reused by a different PIN, which is
        exactly the collision this design exists to prevent). Reusing one value for two different
        PINs would resurrect the original bug this table split was built to avoid, so both writes
        share one transaction rather than running as two independent round trips.
        """
        with transaction(self._factory, what="bump a Roster_Version") as cursor:
            cursor.execute(
                f"""
                MERGE dbo.ADMS_DEVICE_ROSTER_SEQUENCE AS target
                USING (SELECT ? AS SyncGroup) AS source
                   ON target.SyncGroup = source.SyncGroup
                WHEN MATCHED THEN
                    UPDATE SET NextVersion = target.NextVersion + 1
                WHEN NOT MATCHED THEN
                    INSERT (SyncGroup, NextVersion) VALUES (source.SyncGroup, 1)
                OUTPUT inserted.NextVersion;
                """,
                (sync_group,),
            )
            row = cursor.fetchone()
            if row is None:
                raise AttendanceDbError("Could not read back the drawn Roster_Version.")
            version = int(row[0])
            deleted_flag = 1 if is_deleted else 0

            cursor.execute(
                f"""
                MERGE {TABLE_ADMS_DEVICE_ROSTER_VERSION} AS target
                USING (SELECT ? AS Pin, ? AS SyncGroup) AS source
                   ON target.Pin = source.Pin AND target.SyncGroup = source.SyncGroup
                WHEN MATCHED THEN
                    UPDATE SET RosterVersion = ?, UpdatedUtc = SYSUTCDATETIME(),
                               {COL_ROSTER_VERSION_IS_DELETED} = ?
                WHEN NOT MATCHED THEN
                    INSERT (Pin, SyncGroup, RosterVersion, UpdatedUtc, {COL_ROSTER_VERSION_IS_DELETED})
                    VALUES (source.Pin, source.SyncGroup, ?, SYSUTCDATETIME(), ?);
                """,
                (pin, sync_group, version, deleted_flag, version, deleted_flag),
            )
            return version

    def _fan_out_targets(self, origin_serial: str, sync_group: str) -> list[str]:
        """
        Every Enabled_Device sharing ``sync_group``, linked, other than ``origin_serial``
        (Requirement 25.3-25.5, 26.6).

        Linked is enforced with the same join ``SqlServerDeviceRegistry.find`` uses --
        ``MaMCC`` resolving to a ``MAYCHAMCONG`` row -- rather than duplicating that adapter's
        method, because this is the one place in the codebase two device tables are joined for
        eligibility rather than for a single lookup.
        """
        sql = f"""
            SELECT  d.SerialNumber
            FROM    {TABLE_ADMS_DEVICE} d
            INNER JOIN MAYCHAMCONG m ON LTRIM(RTRIM(m.MaMCC)) = LTRIM(RTRIM(d.MaMCC))
            WHERE   d.Enabled = 1
              AND   d.SyncGroup = ?
              AND   d.SerialNumber <> ?
        """
        try:
            cursor = self._factory.get().cursor()
            try:
                cursor.execute(sql, (sync_group, origin_serial))
                rows = cursor.fetchall()
            finally:
                cursor.close()
        except AttendanceDbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AttendanceDbError("Failed to resolve Fan_Out targets.") from exc
        return [(row[0] or "").strip() for row in rows]

    def _record_pushed(self, serial: str, pin: int, version: int) -> None:
        """
        Best-effort audit row in ``ADMS_DEVICE_ROSTER`` (diagnostic only -- see the module
        docstring's trade-off note). A failure here must never undo the enqueue that already
        happened; it would only make ``vw_ADMS_RosterSyncStatus`` less accurate for this one PIN.
        """
        sql = f"""
            MERGE {TABLE_ADMS_DEVICE_ROSTER} AS target
            USING (SELECT ? AS SerialNumber, ? AS Pin) AS source
               ON target.SerialNumber = source.SerialNumber AND target.Pin = source.Pin
            WHEN MATCHED THEN
                UPDATE SET RosterVersion = ?, LastPushedUtc = SYSUTCDATETIME()
            WHEN NOT MATCHED THEN
                INSERT (SerialNumber, Pin, RosterVersion, LastPushedUtc)
                VALUES (source.SerialNumber, source.Pin, ?, SYSUTCDATETIME());
        """
        try:
            with transaction(self._factory, what="record a Roster_Sync audit row") as cursor:
                cursor.execute(sql, (serial, pin, version, version))
        except Exception as exc:  # noqa: BLE001 -- diagnostic only, never fails Fan_Out over this
            if self._log is not None:
                self._log.warn(
                    "Could not record a Roster_Sync audit row.", exc, serial=serial, pin=pin
                )

    # ── Backfill (Requirement 27) ────────────────────────────────────────────────────────

    def backfill_if_due(self, registration) -> BackfillResult | None:
        if not registration.sync_group:
            return None

        group_max = self._group_max_version(registration.sync_group)
        owed = group_max - registration.roster_sync_stamp
        if owed <= 0:
            return None  # Requirement 27.6: current devices cost exactly this one query.

        never_backfilled = registration.roster_sync_stamp == 0
        silent_too_long = self._silent_past_threshold(registration.serial)
        if not (never_backfilled or silent_too_long):
            return None

        owed_pins = self._owed_pins(registration.serial, registration.sync_group, registration.roster_sync_stamp)
        if not owed_pins:
            # The version counter is ahead of what any PIN individually needs (can happen if a
            # PIN was deleted after bumping its version) -- nothing to enqueue, but the cursor is
            # still allowed to catch up to the group max, since nothing was left owing.
            self._advance_stamp(registration.serial, group_max)
            return BackfillResult(serial=registration.serial, enqueued=0, remaining=0)

        cap = self._settings.roster_sync_max_commands_per_cycle
        slice_pins, remaining_pins = owed_pins[:cap], owed_pins[cap:]

        enqueued = 0
        highest_version_enqueued = registration.roster_sync_stamp
        for pin, version, is_deleted in slice_pins:
            if is_deleted:
                # A deletion snapshot: there is no NHANVIEN row to deliver, and there never will
                # be one for this version -- catching this device up means telling it to remove
                # the user, not asking _read_employee_row for a row that by definition is gone.
                try:
                    self._commands.enqueue(registration.serial, delete_userinfo(str(pin)))
                    enqueued += 1
                    self._record_pushed(registration.serial, pin, version)
                except Exception as exc:  # noqa: BLE001 -- one PIN must not stop the slice
                    if self._log is not None:
                        self._log.warn(
                            "Could not enqueue a Backfill delete Push_Command for one PIN.",
                            exc,
                            serial=registration.serial,
                            pin=pin,
                        )
                highest_version_enqueued = max(highest_version_enqueued, version)
                continue

            row = self._read_employee_row(pin)
            if row is None:
                highest_version_enqueued = max(highest_version_enqueued, version)
                continue
            try:
                self._commands.enqueue(registration.serial, _render_update_user(row))
                enqueued += 1
                for finger in self._read_fingers(pin):
                    self._commands.enqueue(registration.serial, _render_update_fingertmp(finger))
                    enqueued += 1
                if self._settings.roster_sync_push_faces:
                    for face in self._read_faces(pin):
                        self._commands.enqueue(registration.serial, _render_update_facetmp(face))
                        enqueued += 1
                self._record_pushed(registration.serial, pin, version)
                highest_version_enqueued = max(highest_version_enqueued, version)
            except Exception as exc:  # noqa: BLE001 -- one PIN's failure must not stop the slice
                if self._log is not None:
                    self._log.warn(
                        "Could not enqueue a Backfill Push_Command for one PIN.",
                        exc,
                        serial=registration.serial,
                        pin=pin,
                    )

        # Requirement 27.5: advance only up to what was actually enqueued in this slice, never
        # speculatively -- an interrupted Backfill resumes from here, not from the group max.
        self._advance_stamp(registration.serial, highest_version_enqueued)

        return BackfillResult(
            serial=registration.serial, enqueued=enqueued, remaining=len(remaining_pins)
        )

    def _group_max_version(self, sync_group: str) -> int:
        sql = f"SELECT MAX(RosterVersion) FROM {TABLE_ADMS_DEVICE_ROSTER_VERSION} WHERE SyncGroup = ?"
        try:
            cursor = self._factory.get().cursor()
            try:
                cursor.execute(sql, (sync_group,))
                row = cursor.fetchone()
            finally:
                cursor.close()
        except AttendanceDbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AttendanceDbError("Failed to read the group's max Roster_Version.") from exc
        return int(row[0]) if row and row[0] is not None else 0

    def _silent_past_threshold(self, serial: str) -> bool:
        sql = f"""
            SELECT CASE WHEN LastSeenUtc IS NULL THEN 1
                        WHEN DATEDIFF(HOUR, LastSeenUtc, SYSUTCDATETIME()) >= ? THEN 1
                        ELSE 0 END
            FROM   {TABLE_ADMS_DEVICE}
            WHERE  SerialNumber = ?
        """
        try:
            cursor = self._factory.get().cursor()
            try:
                cursor.execute(sql, (self._settings.roster_sync_backfill_silence_hours, serial))
                row = cursor.fetchone()
            finally:
                cursor.close()
        except AttendanceDbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AttendanceDbError("Failed to check a device's silence window.") from exc
        return bool(row and row[0])

    def _owed_pins(self, serial: str, sync_group: str, stamp: int) -> list[tuple[int, int, bool]]:
        """Every ``(Pin, RosterVersion, IsDeleted)`` in the group whose version exceeds ``stamp``,
        ordered by version so a capped slice always takes the oldest owed PINs first -- a device
        that falls behind is caught up in the order changes actually happened, not an arbitrary
        one. ``IsDeleted`` is what tells the caller whether to deliver a fresh row or a delete."""
        sql = f"""
            SELECT Pin, RosterVersion, {COL_ROSTER_VERSION_IS_DELETED}
            FROM   {TABLE_ADMS_DEVICE_ROSTER_VERSION}
            WHERE  SyncGroup = ? AND RosterVersion > ?
            ORDER BY RosterVersion ASC
        """
        try:
            cursor = self._factory.get().cursor()
            try:
                cursor.execute(sql, (sync_group, stamp))
                rows = cursor.fetchall()
            finally:
                cursor.close()
        except AttendanceDbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AttendanceDbError("Failed to read owed PINs for a Backfill.") from exc
        return [(int(row[0]), int(row[1]), bool(row[2])) for row in rows]

    def _advance_stamp(self, serial: str, stamp: int) -> None:
        """
        Advance ``ADMS_DEVICE.RosterSyncStamp``, never backward.

        The ``WHERE RosterSyncStamp < ?`` guard makes this safe to call with a value that turns
        out to be stale by the time it runs (e.g. two Backfill checks racing) -- the higher value
        always wins, matching the "advance-only-forward" contract Requirement 27.5 sets out.
        """
        sql = f"UPDATE {TABLE_ADMS_DEVICE} SET RosterSyncStamp = ? WHERE SerialNumber = ? AND RosterSyncStamp < ?"
        with transaction(self._factory, what="advance a device's Roster_Sync cursor") as cursor:
            cursor.execute(sql, (stamp, serial, stamp))

    def _read_fingers(self, pin: int) -> list[FingerTemplate]:
        sql = f"SELECT FingerID, FingerTemplate, Flag FROM {TABLE_FINGER} WHERE MaChamCong = ? ORDER BY FingerID"
        try:
            cursor = self._factory.get().cursor()
            try:
                cursor.execute(sql, (pin,))
                rows = cursor.fetchall()
            finally:
                cursor.close()
        except AttendanceDbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AttendanceDbError("Failed to read fingerprint templates for Backfill.") from exc
        return [
            FingerTemplate(pin=str(pin), finger_id=int(row[0]), template=row[1] or "", valid=int(row[2] or 1))
            for row in rows
            if row[1]
        ]

    def _read_faces(self, pin: int) -> list[FaceTemplate]:
        sql = f"SELECT FaceID, FaceTemplate, ChieuDai FROM {TABLE_FACE} WHERE MaChamCong = ? ORDER BY FaceID"
        try:
            cursor = self._factory.get().cursor()
            try:
                cursor.execute(sql, (pin,))
                rows = cursor.fetchall()
            finally:
                cursor.close()
        except AttendanceDbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AttendanceDbError("Failed to read face templates for Backfill.") from exc
        return [
            FaceTemplate(pin=str(pin), face_id=int(row[0]), template=row[1] or "", size=int(row[2] or 0))
            for row in rows
            if row[1]
        ]


class _EmployeeRow:
    """The subset of one ``NHANVIEN`` row Roster_Sync needs to render ``update_user``."""

    __slots__ = ("pin", "name", "card", "privilege", "enabled")

    def __init__(self, *, pin: int, name: str, card: str, privilege: int, enabled: bool) -> None:
        self.pin = pin
        self.name = name
        self.card = card
        self.privilege = privilege
        self.enabled = enabled


def _render_update_user(row: _EmployeeRow) -> str:
    return update_user(
        DeviceUser(
            pin=str(row.pin),
            name=row.name,
            privilege=UserPrivilege.parse(row.privilege),
            password="",
            card=row.card,
            enabled=row.enabled,
        )
    )


def _render_update_fingertmp(finger: FingerTemplate) -> str:
    return update_fingertmp(finger.pin, finger.finger_id, finger.template, valid=finger.normalized_flag)


def _render_update_facetmp(face: FaceTemplate) -> str:
    return update_facetmp(face.pin, face.face_id, face.template, size=face.size or None, valid=face.valid)
