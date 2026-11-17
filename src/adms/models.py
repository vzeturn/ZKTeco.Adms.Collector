"""
Domain models.

Frozen dataclasses, mirroring the ``sealed record`` style of the desktop pull tool — a parsed
device payload is a value, and nothing downstream should be able to edit it. Field names and
enum values are kept identical to the desktop app wherever the same concept exists, so the
two codebases stay readable side by side.

Every ``parse`` helper is deliberately lenient. These values come off the wire from a dozen
firmware generations that disagree about capitalisation, padding and which fields they send
at all; a strict parser would turn a cosmetic firmware quirk into lost attendance data. The
rule applied throughout: never invent a punch, but never drop one over a field we do not need.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from enum import IntEnum

__all__ = [
    "VerifyMode",
    "UserPrivilege",
    "PunchKey",
    "AttendanceLog",
    "DeviceUser",
    "FingerTemplate",
    "FaceTemplate",
    "BioTemplate",
    "UserPhoto",
    "OperationEvent",
    "DeviceInfo",
    "DeviceRegistration",
    "DeviceCommand",
    "CommandAck",
    "PushBatch",
    "AdmsRequest",
    "AdmsResponse",
    "FanOutResult",
    "BackfillResult",
]


# ── Enums ────────────────────────────────────────────────────────────────────────────────


class VerifyMode(IntEnum):
    """
    How the punch was verified. Values match ``the desktop pull tool``.

    PUSH firmware reports codes the COM SDK never did (palm, mask, QR, and vendor-specific
    numbers above 20). They collapse to :attr:`OTHER` rather than raising: the verification
    method is descriptive metadata, and the exact raw code survives in ``ADMS_ATTLOG_RAW``
    anyway, so an unrecognised value is not a reason to reject a punch.
    """

    PASSWORD = 0
    FINGERPRINT = 1
    CARD = 2
    FACE = 15
    OTHER = -1

    @classmethod
    def parse(cls, raw: object) -> "VerifyMode":
        try:
            return cls(int(str(raw).strip()))
        except (TypeError, ValueError):
            return cls.OTHER


class UserPrivilege(IntEnum):
    """Device privilege level. Values match ``the desktop pull tool``."""

    USER = 0
    ENROLLER = 2
    MANAGER = 6
    ADMINISTRATOR = 14

    @classmethod
    def parse(cls, raw: object) -> "UserPrivilege":
        """
        Unknown levels fall back to :attr:`USER`.

        Downgrading is the only safe direction: guessing *upward* from an unrecognised number
        would hand device-admin rights to whoever the device happened to describe oddly.
        """
        try:
            return cls(int(str(raw).strip()))
        except (TypeError, ValueError):
            return cls.USER


# ── Attendance ───────────────────────────────────────────────────────────────────────────

#: ``(MaChamCong, GioCham)`` — the natural key of a stored punch, and the unit of duplicate
#: detection. Same tuple the desktop app uses in ``GetExistingPunchKeys``.
PunchKey = tuple[int, dt.datetime]


@dataclass(frozen=True, slots=True)
class AttendanceLog:
    """
    One punch from an ``ATTLOG`` upload.

    ``timestamp`` is **naive local device time**. It is stored as-is, exactly like the desktop
    app: the whole ATTENDANCEDB schema and every report built on it treats ``GioCham`` as local
    wall-clock. Converting to UTC here would silently shift years of history relative to rows
    the desktop app wrote, and would also break dedup between the two writers.
    """

    pin: str
    timestamp: dt.datetime
    status: int = 0
    verify: VerifyMode = VerifyMode.OTHER
    work_code: int = 0
    reserved1: str = ""
    reserved2: str = ""

    @property
    def numeric_pin(self) -> int | None:
        """
        The PIN as ``NHANVIEN.MaChamCong``, or ``None`` when it is not an integer.

        ``MaChamCong`` is an ``int`` column, so an alphanumeric device PIN has nowhere to go.
        Callers skip those rows rather than fail the batch.
        """
        try:
            return int(self.pin.strip())
        except (AttributeError, ValueError):
            return None

    @property
    def key(self) -> PunchKey | None:
        pin = self.numeric_pin
        return None if pin is None else (pin, self.timestamp)


# ── Users and biometrics ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class DeviceUser:
    """A ``USER`` record from an ``OPERLOG`` upload (device → DB direction)."""

    pin: str
    name: str = ""
    privilege: UserPrivilege = UserPrivilege.USER
    password: str = ""
    card: str = ""
    group: str = ""
    timezone: str = ""
    verify_mode: int = -1
    enabled: bool = True

    @property
    def numeric_pin(self) -> int | None:
        try:
            return int(self.pin.strip())
        except (AttributeError, ValueError):
            return None


@dataclass(frozen=True, slots=True)
class FingerTemplate:
    """
    A ``FP`` record: one enrolled finger.

    ``template`` is kept as the base64 text the device sent, never decoded. ``dbo.TEMPLATE``
    stores it as ``NVARCHAR`` and the desktop app writes the SDK's own string form there; any
    re-encoding on the way through would produce templates the device cannot load back.
    """

    pin: str
    finger_id: int
    template: str
    size: int = 0
    valid: int = 1

    @property
    def normalized_flag(self) -> int:
        """
        A stored finger is by definition valid, so a ``0`` flag becomes ``1``; duress (``3``)
        passes through. Same coercion as ``SqlServerTemplateStore.NormalizeFlag``.
        """
        return 1 if self.valid == 0 else self.valid


@dataclass(frozen=True, slots=True)
class FaceTemplate:
    """A ``FACE`` record. ``size`` maps to ``dbo.Face.ChieuDai``."""

    pin: str
    face_id: int
    template: str
    size: int = 0
    valid: int = 1


@dataclass(frozen=True, slots=True)
class BioTemplate:
    """
    A ``BIODATA`` record — the pushver 2.4+ unified biometric envelope that replaces the
    separate ``FP``/``FACE`` lines on newer firmware.

    ``bio_type`` selects the modality (1=fingerprint, 2=face, 7=palm, 9=visible-light face,
    among others). Only the types with a home in ATTENDANCEDB are persisted; the rest are
    archived and counted so an operator can see they arrived. Silently dropping them would
    make "the device says it uploaded 40 templates, the DB has 12" unexplainable.
    """

    pin: str
    template: str
    bio_type: int = 0
    no: int = 0
    index: int = 0
    valid: int = 1
    duress: int = 0
    major_ver: str = ""
    minor_ver: str = ""
    fmt: str = ""

    TYPE_FINGERPRINT = 1
    TYPE_FACE = 2

    def as_finger(self) -> FingerTemplate:
        return FingerTemplate(
            pin=self.pin,
            finger_id=self.no,
            template=self.template,
            size=len(self.template),
            valid=self.valid,
        )

    def as_face(self) -> FaceTemplate:
        return FaceTemplate(
            pin=self.pin,
            face_id=self.no,
            template=self.template,
            size=len(self.template),
            valid=self.valid,
        )


@dataclass(frozen=True, slots=True)
class UserPhoto:
    """
    A ``USERPIC`` / ``BIOPHOTO`` record.

    ATTENDANCEDB has no column for an enrollment photo, so this is archived only. Kept as a
    model rather than ignored at the parser so the counts we report back to the device match
    what it actually sent.
    """

    pin: str
    filename: str = ""
    size: int = 0
    content: str = ""


@dataclass(frozen=True, slots=True)
class OperationEvent:
    """
    An ``OPLOG`` record: a device-side administrative action (enrollment, deletion, door
    unlock, time change, firmware update…).

    Worth storing even though it never touches attendance: when someone asks why a user's
    templates disappeared, this is the only record that a delete happened *on the device* at
    a given time by a given admin.
    """

    op_code: int
    operator_pin: str = ""
    timestamp: dt.datetime | None = None
    param1: str = ""
    param2: str = ""
    param3: str = ""
    raw: str = ""


# ── Device identity ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class DeviceInfo:
    """
    Self-description a device uploads to ``table=options`` on handshake (firmware version,
    user capacity, fingerprint algorithm…).

    Stored as a flat mapping because the key set differs per model and grows with every
    firmware release; promoting a fixed subset to columns would mean a migration each time a
    new device model arrives.
    """

    serial: str
    values: dict[str, str] = field(default_factory=dict)

    def get(self, *names: str, default: str = "") -> str:
        """Case-insensitive lookup across several spellings of the same option."""
        lowered = {k.lower().lstrip("~"): v for k, v in self.values.items()}
        for name in names:
            hit = lowered.get(name.lower().lstrip("~"))
            if hit:
                return hit
        return default

    @property
    def device_name(self) -> str:
        return self.get("~DeviceName", "DeviceName")

    @property
    def firmware(self) -> str:
        return self.get("FirmVer", "~FirmVer", "FirmwareVersion")

    @property
    def platform(self) -> str:
        return self.get("~Platform", "Platform")

    @property
    def push_version(self) -> str:
        return self.get("PushVersion", "~PushVersion", "pushver")


@dataclass(frozen=True, slots=True)
class DeviceRegistration:
    """
    An ``ADMS_DEVICE`` row: the allow-list entry that maps a serial number onto a
    ``MAYCHAMCONG`` machine.

    This mapping cannot be derived. A pushing device announces only its serial, while
    ``CheckInOut.MaSoMay`` needs ``MAYCHAMCONG.IDMCC`` — an operator has to state the link
    once. Hence :attr:`machine_id` being optional, and :class:`~adms.errors.DeviceNotLinkedError`
    for the window between "device found us" and "operator linked it".
    """

    serial: str
    enabled: bool = False
    machine_code: str = ""
    machine_id: int | None = None
    machine_name: str = ""
    attlog_stamp: str = "0"
    operlog_stamp: str = "0"
    attphoto_stamp: str = "0"
    timezone_offset: int = 7
    #: multi-device-employee-sync, Requirement 25.1. Empty string for a NULL ADMS_DEVICE.SyncGroup
    #: column -- the same "nullable in SQL, non-optional in Python" convention machine_code/the
    #: three *_stamp fields already use. Empty means this device never exchanges anything through
    #: Roster_Sync (Requirement 25.2): a falsy check (`if registration.sync_group:`) is the whole
    #: of the gate at every call site, deliberately, so there is one obvious way to ask "is this
    #: device in a group" rather than two (empty string vs. some sentinel).
    sync_group: str = ""
    #: multi-device-employee-sync, Requirement 27.5. ADMS_DEVICE.RosterSyncStamp -- the highest
    #: Roster_Version this device is known to have received. Advanced only after the
    #: corresponding Push_Commands are durably enqueued (never speculatively), the same ordering
    #: discipline attlog_stamp/operlog_stamp/attphoto_stamp already follow for their own cursors.
    roster_sync_stamp: int = 0

    @property
    def is_linked(self) -> bool:
        return self.machine_id is not None

    def stamp_for(self, table: str) -> str:
        return {
            "ATTLOG": self.attlog_stamp,
            "OPERLOG": self.operlog_stamp,
            "ATTPHOTO": self.attphoto_stamp,
        }.get(table.upper(), "0")


@dataclass(frozen=True, slots=True)
class DeviceCommand:
    """
    One queued command, rendered on the wire as ``C:<id>:<body>``.

    ``command_id`` is the ``ADMS_COMMAND`` identity value and is echoed back by the device in
    its ack, which is the only way to correlate a result with a request.
    """

    command_id: int
    body: str

    def render(self) -> str:
        return f"C:{self.command_id}:{self.body}"


@dataclass(frozen=True, slots=True)
class CommandAck:
    """A ``devicecmd`` ack: ``ID=<id>&Return=<code>&CMD=<name>``."""

    command_id: int
    return_code: int
    command: str = ""

    @property
    def succeeded(self) -> bool:
        """Per the PUSH spec a non-negative ``Return`` is success; negatives are errors."""
        return self.return_code >= 0


# ── Roster sync (multi-device-employee-sync) ────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class FanOutResult:
    """
    What one Fan_Out call did, for logging only (Requirement 30.2) -- the service never branches
    on this beyond deciding INFO vs. DEBUG (Requirement 30.4: zero enqueued logs at DEBUG).
    """

    pins: list[int]
    targets_notified: int
    commands_enqueued: int
    deferred: int


@dataclass(frozen=True, slots=True)
class BackfillResult:
    """
    What one Backfill call did, for logging only (Requirement 30.3). ``None`` (not this type) is
    what a caller gets when Backfill was not due at all (Requirement 27.6's zero-cost guarantee) --
    this type only exists once there was something to report.
    """

    serial: str
    enqueued: int
    remaining: int


@dataclass(frozen=True, slots=True)
class ReconcileResult:
    """
    What one DB-side delete-reconciliation pass did, for logging only. ``None`` (not this type) is
    what a caller gets when reconciliation was not due for this Sync_Group yet -- same "cheap when
    there is nothing to do" contract as :class:`BackfillResult`.

    Unlike Fan_Out/Backfill, one pass can cover several PINs at once: reconciliation is a group-
    wide diff (every PIN this group has ever pushed, versus who still has a ``NHANVIEN`` row), not
    a per-PIN operation, so ``deleted_pins`` is a list rather than this type existing once per PIN.
    """

    sync_group: str
    deleted_pins: list[int]
    commands_enqueued: int


# ── Request / response plumbing ──────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class PushBatch:
    """
    Everything one ``cdata`` POST body decoded to.

    A single upload can legitimately mix kinds — an ``OPERLOG`` body often carries ``USER``,
    ``FP`` and ``OPLOG`` lines together — so this is a bag of lists rather than a union type.
    """

    table: str
    serial: str
    stamp: str = ""
    attendance: list[AttendanceLog] = field(default_factory=list)
    users: list[DeviceUser] = field(default_factory=list)
    fingers: list[FingerTemplate] = field(default_factory=list)
    faces: list[FaceTemplate] = field(default_factory=list)
    biodata: list[BioTemplate] = field(default_factory=list)
    photos: list[UserPhoto] = field(default_factory=list)
    operations: list[OperationEvent] = field(default_factory=list)
    options: DeviceInfo | None = None
    #: Lines the parser recognised as records but could not classify. Counted, never dropped
    #: silently — an unexplained count gap is the first symptom of new firmware.
    unparsed: list[str] = field(default_factory=list)

    @property
    def record_count(self) -> int:
        """
        Records the device believes it sent. This is the number echoed back as ``OK: <n>``;
        getting it wrong makes some firmware re-send the batch forever.
        """
        return (
            len(self.attendance)
            + len(self.users)
            + len(self.fingers)
            + len(self.faces)
            + len(self.biodata)
            + len(self.photos)
            + len(self.operations)
            + len(self.unparsed)
        )

    @property
    def is_empty(self) -> bool:
        return self.record_count == 0 and self.options is None


@dataclass(frozen=True, slots=True)
class AdmsRequest:
    """
    A transport-neutral inbound request.

    Deliberately not an API Gateway event: the same service handles Function URL, REST API,
    ALB and the local dev server in :mod:`tools.local_server`. Only
    :mod:`adms.handler` knows about any hosting event shapes.
    """

    method: str
    path: str
    query: dict[str, str]
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    source_ip: str = ""

    def q(self, *names: str, default: str = "") -> str:
        """
        Case-insensitive query lookup.

        Firmware is inconsistent about parameter casing (``SN`` vs ``sn``, ``table`` vs
        ``Table``), and a miss here would look exactly like a device that forgot to identify
        itself.
        """
        lowered = {k.lower(): v for k, v in self.query.items()}
        for name in names:
            hit = lowered.get(name.lower())
            if hit:
                return hit
        return default

    @property
    def serial(self) -> str:
        return self.q("SN", "sn").strip()


@dataclass(frozen=True, slots=True)
class AdmsResponse:
    """
    A plain-text reply.

    Always ``text/plain``: devices parse the body with a hand-rolled scanner and some
    firmware rejects anything with a ``charset`` it does not expect, so the content type is
    fixed rather than negotiated.
    """

    body: str = "OK"
    status: int = 200
    content_type: str = "text/plain"

    def encode(self) -> bytes:
        return self.body.encode("utf-8")
