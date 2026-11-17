"""
Ports — the boundaries :mod:`adms.service` depends on.

``typing.Protocol`` rather than ABCs, so adapters need no import of this module and no
inheritance: the SQL adapters in :mod:`adms.db` and the in-memory ones in :mod:`adms.memory`
satisfy these structurally. That is the Python equivalent of the desktop pull tool's
``Abstractions/`` folder, and it buys the same thing — the orchestration logic can be exercised
against fakes with no SQL Server anywhere in sight.

The split between stores mirrors the tables they own, not the calls the service happens to make.
Attendance and templates have very different write patterns (high-frequency small batches
versus occasional replace-all), and keeping them apart means the hot path does not carry the
cold one's concerns.
"""

from __future__ import annotations

import datetime as dt
from typing import Protocol, runtime_checkable

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
    PushBatch,
    ReconcileResult,
    UserPhoto,
)

__all__ = [
    "Clock",
    "Logger",
    "DeviceRegistry",
    "AttendanceStore",
    "EmployeeStore",
    "TemplateStore",
    "CommandQueue",
    "PushArchive",
    "BatchSink",
    "RosterSync",
    "SystemClock",
]


@runtime_checkable
class Clock(Protocol):
    """Injected so time-dependent behaviour is testable and so UTC/local intent is explicit."""

    def utc_now(self) -> dt.datetime: ...

    def local_now(self) -> dt.datetime: ...


class SystemClock:
    """
    Real clock.

    ``local_now`` is site-local wall-clock derived from a fixed offset, not from the host's
    timezone: a UTC-based host (such as a container) always runs in UTC, so relying on the host would put every locally-stamped
    row seven hours behind in a Vietnamese deployment.
    """

    __slots__ = ("_offset",)

    def __init__(self, utc_offset_hours: int = 7) -> None:
        self._offset = dt.timedelta(hours=utc_offset_hours)

    def utc_now(self) -> dt.datetime:
        return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)

    def local_now(self) -> dt.datetime:
        return self.utc_now() + self._offset


@runtime_checkable
class Logger(Protocol):
    def debug(self, message: str, **fields: object) -> None: ...

    def info(self, message: str, **fields: object) -> None: ...

    def warn(self, message: str, exc: BaseException | None = None, **fields: object) -> None: ...

    def error(self, message: str, exc: BaseException | None = None, **fields: object) -> None: ...


@runtime_checkable
class DeviceRegistry(Protocol):
    """
    The serial-number allow-list (``ADMS_DEVICE``) joined to ``MAYCHAMCONG``.

    Consulted on **every** request. ADMS carries no credential, so this lookup is the
    authorisation decision, and its result is also what supplies ``MaSoMay``/``TenMay`` for the
    punch insert.
    """

    def find(self, serial: str) -> DeviceRegistration | None:
        """The registration, or ``None`` when the serial is not on the allow-list."""

    def record_contact(
        self, serial: str, *, seen_at: dt.datetime, source_ip: str = "", info: DeviceInfo | None = None
    ) -> None:
        """
        Update last-seen (and firmware details when a handshake supplied them).

        Best-effort by contract: a failure here must not fail the request. Losing a heartbeat
        timestamp is cosmetic; rejecting a batch of punches over it is not.
        """

    def register_pending(self, serial: str, *, seen_at: dt.datetime, source_ip: str = "") -> None:
        """
        Record an unknown serial as disabled and unlinked, so it appears in the operator's UI
        instead of only in logs.

        Creating the row does **not** grant access — ``Enabled`` stays 0. This exists because
        the alternative workflow is "read the serial off a label on a wall in another province".
        """

    def advance_stamp(self, serial: str, table: str, stamp: str) -> None:
        """
        Persist the resumption cursor for one table, after its records are committed.

        Ordering is the whole point: the stamp is what the device uses to decide it may discard
        records, so it must never move ahead of durable storage.
        """


@runtime_checkable
class AttendanceStore(Protocol):
    """Writes ``CheckInOut`` through ``dbo.CheckInOut_add``, exactly as the desktop app does."""

    def existing_punch_keys(
        self, machine_id: int, from_inclusive: dt.datetime, to_exclusive: dt.datetime
    ) -> set[PunchKey]:
        """
        ``(MaChamCong, GioCham)`` already stored for this machine in the window.

        The stored procedure is a bare INSERT with no existence check, so this set is the only
        thing standing between a device retry and duplicated punches.
        """

    def add_attendance(
        self,
        logs: list[AttendanceLog],
        *,
        machine_id: int,
        machine_name: str,
        existing_keys: set[PunchKey] | None = None,
    ) -> int:
        """
        Insert punches, skipping duplicates.

        Known divergence (V4): returns rows *offered* to the stored procedure after this store's
        own filtering (non-numeric PINs dropped, in-batch duplicates collapsed, already-stored
        keys removed) -- not rows confirmed written. The procedure's own cross-machine
        ``IF NOT EXISTS`` check can still reject a row this filtering allowed through, and ODBC's
        ``executemany`` gives no reliable per-statement rowcount to detect that. See
        :meth:`~adms.db.attendance.SqlServerAttendanceStore.add_attendance` for the detail.
        """

    # NOTE: the desktop tool's comments claim dbo.CheckInOut_add performs no existence check. Reading
    # the deployed procedure showed it does, on exactly (MaChamCong, GioCham). See
    # SqlServerAttendanceStore.existing_punch_keys for why this port still asks for the key set.

    def archive_attlog(self, serial: str, logs: list[AttendanceLog]) -> int:
        """
        Store the full push detail (status, verify mode, work code) in ``ADMS_ATTLOG_RAW``.

        ``CheckInOut`` has no column for any of it — the desktop app hardcodes ``KieuCham='1'``
        — so this table is what keeps the upload lossless while the punch itself stays
        byte-identical to a desktop-app row.
        """


@runtime_checkable
class EmployeeStore(Protocol):
    """Upserts ``NHANVIEN`` from device ``USER`` records."""

    def upsert_employees(self, users: list[DeviceUser]) -> int:
        """
        MERGE on ``MaChamCong``. Non-numeric PINs are skipped (the key is ``int``).

        Must never overwrite ``MaNhanVien`` on update: a device knows nothing about HR codes,
        and clobbering the real code with a PIN is not recoverable from the device side.
        """

    def missing_employee_pins(self, pins: set[int]) -> set[int]:
        """
        Which of ``pins`` have no ``NHANVIEN`` row.

        Drives auto-enrolment: a punch from an unknown PIN means the roster is behind what the devices
        know, and the fix is to ask the device rather than to wait for a person to notice. One indexed
        query for the whole batch, not one per punch.
        """


@runtime_checkable
class TemplateStore(Protocol):
    """Writes ``dbo.TEMPLATE`` / ``dbo.Face``."""

    def save_fingerprints(self, templates: list[FingerTemplate]) -> int:
        """
        Replace the stored fingerprint set for each PIN present.

        Replace-per-PIN, not per-finger: a device uploads a user's fingers as a set, and
        merging per finger would leave a finger the user deleted on the device alive in the DB.
        """

    def save_faces(self, templates: list[FaceTemplate]) -> int:
        """Replace the stored face template for each PIN present."""


@runtime_checkable
class CommandQueue(Protocol):
    """``ADMS_COMMAND`` — the pull-based downlink."""

    def dequeue(self, serial: str, limit: int) -> list[DeviceCommand]:
        """
        Claim up to ``limit`` pending commands, marking them Sent.

        Claim-on-read, so two concurrent requests polling for the same device cannot
        hand out the same command twice. At-most-once delivery is the right bias here: a
        redelivered ``CLEAR DATA`` is far worse than one that quietly needs re-queueing.
        """

    def ack(self, serial: str, acks: list[CommandAck]) -> int:
        """Record device results. Returns rows updated."""

    def enqueue(self, serial: str, body: str) -> int:
        """Queue one command. Returns the new command id."""

    def pins_with_recent_request(self, serial: str, pins: set[int], since: dt.datetime) -> set[int]:
        """
        Which of ``pins`` this device was already asked about since ``since``, in any status.

        The cooldown that makes auto-enrolment safe. An unknown PIN punches again within minutes, so
        without it every punch would queue another query and the device's command queue would grow
        without bound.

        Deliberately counts commands in **any** status, including Done and Failed. Only counting
        outstanding ones would mean a device that cannot answer -- because the user was deleted on the
        hardware too, or because the firmware rejects the wording -- gets asked again forever.
        """


@runtime_checkable
class PushArchive(Protocol):
    """
    Verbatim archive of what arrived (``ADMS_PUSH_LOG`` and the operlog detail tables).

    Worth its storage for three reasons: replay after a mapping bug, evidence when a site
    disputes a punch, and a decodable record of payloads a future firmware sends that the
    current parsers do not understand.
    """

    def archive_request(
        self,
        *,
        serial: str,
        route: str,
        table: str,
        query: str,
        body: str,
        record_count: int,
    ) -> None: ...

    def archive_operations(self, serial: str, events: list[OperationEvent]) -> int: ...

    def archive_photos(self, serial: str, photos: list[UserPhoto]) -> int: ...

    def archive_unparsed(self, serial: str, table: str, lines: list[str]) -> int: ...


@runtime_checkable
class BatchSink(Protocol):
    """
    Optional convenience port for an adapter that wants one transaction across a whole
    :class:`~adms.models.PushBatch` rather than the per-store calls the service makes by
    default. Unused by the SQL adapters today; declared because the service checks for it, so a
    future adapter can opt in without touching the service.
    """

    def write_batch(self, batch: PushBatch, registration: DeviceRegistration) -> dict[str, int]: ...


@runtime_checkable
class RosterSync(Protocol):
    """
    multi-device-employee-sync: propagating one device's roster/template changes to every other
    Enabled_Device sharing its Sync_Group (Fan_Out), and catching a new or long-silent device up
    with everything it is missing (Backfill).

    ``AdmsService`` holds this as ``roster_sync: RosterSync | None`` -- ``None`` means the feature
    is fully absent from that instance, which is how ``ADMS_ROSTER_SYNC_ENABLED=false`` (the
    default) is enforced at the composition root rather than with a scattered flag check
    (Requirement 29.1): disabled means the object does not exist, not that it exists and checks a
    setting on every call.

    Every method here is called by the service from a *best-effort* site -- after the write that
    triggered it has already committed (Fan_Out) or before the route handler that will not be
    delayed by it (Backfill) -- and every call is wrapped in the service's own ``except
    Exception`` (Requirement 26.7, 26.9). An adapter implementing this raises
    :class:`~adms.errors.AttendanceDbError` on a genuine failure, exactly like every other SQL
    adapter's contract; it is the service's wrapping, not this port's contract, that turns that
    into "logged and ignored" rather than a failed request.
    """

    def fan_out(
        self,
        origin_serial: str,
        sync_group: str,
        pin: int,
        *,
        fingers: list[FingerTemplate] | None = None,
        faces: list[FaceTemplate] | None = None,
    ) -> FanOutResult:
        """
        Propagate PIN's current ``NHANVIEN`` row, plus any given templates, to every
        Enabled_Device sharing ``sync_group`` other than ``origin_serial`` (Requirement 26.1,
        26.2, 26.4, 26.6, 28.1-28.3).

        One call bumps that PIN's Roster_Version exactly once (Requirement 26.3), covering the
        employee record and its templates together -- a caller with both a ``USER`` and ``FP``/
        ``FACE`` change for the same PIN in one upload makes exactly one call here, never two,
        which is what keeps "exactly once per triggering upload" true regardless of how many
        different things about that PIN the upload touched. ``fingers``/``faces`` are the
        templates that were just written by the caller, not re-read from storage.

        Never advances any target's Sync_Cursor (``ADMS_DEVICE.RosterSyncStamp``) -- only
        :meth:`backfill_if_due` does that. A device that misses a Fan_Out (offline, or a transient
        enqueue failure) simply shows as owed on its next Backfill check; Fan_Out's own job is
        best-effort, real-time delivery to whichever targets are enabled and linked right now, not
        a durability guarantee about which devices are "caught up".
        """

    def backfill_if_due(self, registration: DeviceRegistration) -> BackfillResult | None:
        """
        ``None`` when ``registration`` is not due for a Backfill right now (Requirement 27.6's
        zero-cost guarantee: exactly one query, no rows, no commands). Otherwise enqueues up to
        Sync_Pace_Cap owed PINs, advances ``registration``'s Sync_Cursor only as far as what was
        actually enqueued (Requirement 27.4-27.5), and returns what it did.

        "Due" combines two conditions, both needed because Fan_Out alone keeps an always-online
        device current without ever touching its cursor (see :meth:`fan_out`): a device is due
        when it is owed at least one PIN *and* either it has never been backfilled before
        (``roster_sync_stamp == 0``, covering Requirement 27.1's "on the next handshake" for a
        newly linked device) or it has been silent past Backfill_Silence_Threshold (Requirement
        27.2). Without the second half of that disjunction, an actively polling device would
        Backfill on every single request forever, since Fan_Out's own conservatism means "owed"
        rarely reaches zero on its own.
        """

    def fan_out_delete(self, origin_serial: str, sync_group: str, pin: int) -> FanOutResult:
        """
        Propagate a user deletion to every Enabled_Device sharing ``sync_group`` other than
        ``origin_serial`` -- the delete-fan-out half of multi-device-employee-sync, added for
        ISO 27001 traceability: a deletion performed anywhere in the estate (the desktop app
        removing a ``NHANVIEN`` row, or a device's own admin menu deleting a user) must remove
        that person's biometrics everywhere, not just where the delete happened.

        Bumps PIN's Roster_Version exactly once, the same as :meth:`fan_out`, but records that
        version as a deletion (``ADMS_DEVICE_ROSTER_VERSION.IsDeleted``) rather than a fresh
        snapshot. That distinction is what :meth:`backfill_if_due` reads to decide whether a
        device it is catching up should receive ``update_user`` (deliver the current row) or
        ``delete_userinfo`` (there is no current row any more) for a given owed PIN -- a plain
        Roster_Version bump alone cannot carry that, because a deleted PIN's ``NHANVIEN`` row is
        gone by the time Backfill runs and there is nothing left to re-derive "this was a
        deletion" from.

        Two triggers, both best-effort and independently gated:

        * DB-side: a PIN present in ``ADMS_DEVICE_ROSTER_VERSION`` with no matching ``NHANVIEN``
          row any more. Detected by polling (Requirement: never a trigger on the locked
          ``NHANVIEN`` table -- see :mod:`adms.db.roster_sync`'s own module docstring for why),
          gated by ``ADMS_ROSTER_SYNC_FANOUT_DELETES``.
        * Device-side: a device's own ``OPLOG`` reports a delete operation. Gated separately
          (``ADMS_ROSTER_SYNC_DELETE_OPCODES``, default empty/disabled) because the OpCode that
          means "user deleted" has not been confirmed against a device's ``ADMS_OPERLOG``
          data -- enabling this with a guessed OpCode risks fanning out a deletion nothing
          actually asked for, which is irreversible for the biometrics on every other device in
          the group.

        Same error posture as :meth:`fan_out`: one target's enqueue failure is logged and does
        not stop the others (Requirement 26.7's discipline extended to deletes), and this never
        touches any target's Sync_Cursor -- only :meth:`backfill_if_due` does that.
        """

    def reconcile_deletions(self, sync_group: str) -> ReconcileResult | None:
        """
        DB-side delete detection for ``sync_group``: find every PIN this group has ever pushed
        (a live row in ``ADMS_DEVICE_ROSTER_VERSION`` for this group with ``IsDeleted = 0``)
        whose ``NHANVIEN`` row no longer exists, and call :meth:`fan_out_delete` for each one.

        ``None`` when nothing needed reconciling (mirrors :meth:`backfill_if_due`'s zero-cost
        contract: a group with no deletions since the last pass costs exactly one query).

        Polling by design, never a trigger on ``NHANVIEN`` -- see :mod:`adms.db.roster_sync`'s
        module docstring for why a trigger was rejected. Gated by
        ``Settings.roster_sync_fanout_deletes`` AND ``Settings.roster_sync_reconcile_deletes``
        together at the call site, not inside this method: the port's job is "how", the setting
        check is "whether", and keeping that split means an adapter under test never has to
        fake a setting object just to exercise this method.

        ``origin_serial`` for the resulting :meth:`fan_out_delete` calls is deliberately empty --
        a DB-side deletion has no originating device, so every Enabled_Device in the group
        (there is no device to exclude) is a legitimate target.
        """
