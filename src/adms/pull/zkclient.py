"""
``pyzk``-backed :class:`~adms.pull.ports.DeviceClient`.

This is the one module in this codebase that opens an outbound TCP connection to a device --
everything else in :mod:`adms` (the push collector) is deliberately the other direction. ``pyzk``
speaks ZKTeco's own binary protocol on port 4370, the same one the sibling desktop app's 32-bit
``zkemkeeper`` COM SDK uses, just from pure Python with no 32-bit dependency -- which is what makes
it usable from this 64-bit service without a second process or interop layer.

Import is lazy and guarded, mirroring :func:`adms.db.connection.ConnectionFactory._open`'s own
``pyodbc`` guard: a host that never runs the pull agent (e.g. the IIS collector's own app pool)
must not need ``pyzk`` installed at all, so nothing above this module imports it eagerly.

Field mapping notes
--------------------
``pyzk``'s ``User.user_id`` is the device's own PIN string (what a person types at the keypad);
``User.uid`` is an internal slot index the vendor protocol uses to address templates and is *not*
what ATTENDANCEDB keys on. Every read here maps to ``user_id`` (falling back to ``uid`` only when
``user_id`` is blank, which happens on very old firmware) so a pulled employee lines up with
``NHANVIEN.MaChamCong`` and a pulled punch lines up with ``CheckInOut.MaChamCong`` -- the same key
the push collector's parsers already produce from a device's HTTP upload.
"""

from __future__ import annotations

import datetime as dt

from ..errors import AttendanceDbError, ConfigError
from ..models import AttendanceLog, DeviceUser, FingerTemplate, UserPrivilege, VerifyMode
from .models import PullDevice

__all__ = ["PyzkDeviceClient"]


def _import_zk():
    try:
        import zk as zk_module
        import zk.exception as zk_exception_module
    except ImportError as exc:
        raise ConfigError(
            "pyzk is not installed. Run 'pip install -r requirements-pull.txt' in this tool's "
            "virtual environment -- it is not part of the collector's own runtime dependencies "
            "because the push collector never needs it."
        ) from exc
    return zk_module.ZK, zk_exception_module.ZKError


class PyzkDeviceClient:
    """Implements :class:`~adms.pull.ports.DeviceClient` using the ``pyzk`` package."""

    __slots__ = ("_log",)

    def __init__(self, log=None) -> None:
        self._log = log

    def connect(self, device: PullDevice) -> _PyzkSession:
        zk_class, zk_error_class = _import_zk()

        if not device.ip:
            raise ConfigError(
                f"Device {device.serial!r} has no configured pull IP address (ADMS_DEVICE.PullIp)."
            )

        client = zk_class(
            device.ip,
            port=device.port,
            timeout=device.timeout_seconds,
            password=device.comm_password,
            force_udp=False,
            ommit_ping=False,
        )
        try:
            connection = client.connect()
        except Exception as exc:
            raise AttendanceDbError(
                f"Could not connect to device {device.serial!r} at {device.address}."
            ) from exc

        return _PyzkSession(connection, device=device, zk_error=zk_error_class)


class _PyzkSession:
    """One open ``pyzk`` connection. See :class:`~adms.pull.ports.DeviceSession`."""

    __slots__ = ("_connection", "_device", "_uid_to_pin", "_zk_error")

    def __init__(self, connection, *, device: PullDevice, zk_error: type[Exception]) -> None:
        self._connection = connection
        self._device = device
        self._zk_error = zk_error
        #: Built lazily on first use -- populated by get_employees(), consulted by
        #: get_attendance() (whose records key on uid on some firmware builds) and by
        #: get_fingerprints() (whose templates are always keyed on uid, never on the PIN).
        self._uid_to_pin: dict[int, str] = {}

    def __enter__(self) -> _PyzkSession:
        return self

    def __exit__(self, exc_type, exc, tb) -> bool | None:
        import contextlib

        with contextlib.suppress(Exception):
            self._connection.disconnect()
        return None

    def get_employees(self) -> list[DeviceUser]:
        try:
            users = self._connection.get_users()
        except self._zk_error as exc:
            raise AttendanceDbError(
                f"Could not read the employee list from {self._device.serial!r}."
            ) from exc

        out: list[DeviceUser] = []
        for user in users:
            pin = str(user.user_id or user.uid).strip()
            self._uid_to_pin[int(user.uid)] = pin
            out.append(
                DeviceUser(
                    pin=pin,
                    name=(user.name or "").strip(),
                    privilege=UserPrivilege.parse(user.privilege),
                    password=str(user.password or ""),
                    card=str(user.card or ""),
                    group=str(user.group_id or ""),
                    # Disabled is bit 0 of the raw privilege value -- computed here directly
                    # rather than via pyzk's own User.is_disabled()/is_enabled(), which exist on
                    # the GitHub master branch but not on the pyzk==0.9 release on PyPI
                    # (confirmed against a device: that release's User class
                    # has no such method at all). Replicating the one-line bit check keeps this
                    # working regardless of which pyzk build is installed.
                    enabled=not (int(user.privilege) & 1),
                )
            )
        return out

    def get_attendance(self) -> list[AttendanceLog]:
        # get_users() first, unconditionally: some builds' attendance records carry only the
        # internal uid, and without this map those punches would come back keyed on a value that
        # is not NHANVIEN.MaChamCong at all.
        if not self._uid_to_pin:
            self.get_employees()

        try:
            records = self._connection.get_attendance()
        except self._zk_error as exc:
            raise AttendanceDbError(f"Could not read attendance from {self._device.serial!r}.") from exc

        out: list[AttendanceLog] = []
        for record in records:
            pin = str(record.user_id).strip()
            if not pin or pin == "0":
                pin = self._uid_to_pin.get(int(record.uid or 0), "")
            if not pin:
                continue
            timestamp = record.timestamp
            if not isinstance(timestamp, dt.datetime):
                continue
            out.append(
                AttendanceLog(
                    pin=pin,
                    timestamp=timestamp,
                    # `punch` (in/out/break) is the more specific field when firmware reports it;
                    # `status` is 0 on builds that do not distinguish. Falling back keeps this a
                    # faithful pull rather than inventing detail no read source actually offered.
                    status=int(record.punch or record.status or 0),
                    verify=VerifyMode.OTHER,
                )
            )
        return out

    def get_fingerprints(self, pin: str) -> list[FingerTemplate]:
        if not self._uid_to_pin:
            self.get_employees()
        uid = _find_uid(self._uid_to_pin, pin)
        if uid is None:
            return []

        try:
            templates = self._connection.get_templates()
        except self._zk_error as exc:
            raise AttendanceDbError(f"Could not read templates from {self._device.serial!r}.") from exc

        return [
            FingerTemplate(
                pin=pin,
                finger_id=int(finger.fid),
                # pyzk hands back raw bytes; dbo.TEMPLATE stores the device's own base64 text, so
                # this is encoded the same way an OPERLOG FP line already arrives on the push
                # path -- see adms.protocol.operlog's own template handling.
                template=_b64(finger.template),
                size=int(finger.size),
                valid=int(finger.valid),
            )
            for finger in templates
            if int(finger.uid) == uid
        ]

    def set_employee(self, user: DeviceUser) -> None:
        """
        Push one employee to this device -- the write half of cross-device sync.

        ``uid`` and ``user_id`` are different things on the wire: ``uid`` is a 16-bit internal
        slot index (``pyzk`` packs it with struct format ``'H'``, 0-65535) the device uses to
        address templates, while ``user_id`` is the PIN a person actually types at the keypad and
        can be any numeric string. A PIN this codebase's own PINs regularly exceed 65535 (real
        PINs can run into the hundreds of millions) must never be used as ``uid`` --
        confirmed against a device, where doing so raised
        ``struct.error: 'H' format requires 0 <= number <= 65535`` before anything was sent.
        Passing ``uid=None`` instead lets ``pyzk`` assign the device's own next free internal
        slot (``self.next_uid``) while ``user_id`` still carries the real PIN, which is what
        ``get_employees`` reads back afterwards -- exactly the same pattern the device's own
        enrollment flow uses.
        """
        try:
            self._connection.set_user(
                uid=None,
                name=user.name or user.pin,
                privilege=int(user.privilege),
                password=user.password,
                group_id=user.group or "",
                user_id=user.pin,
                card=_to_card_int(user.card),
            )
        except self._zk_error as exc:
            raise AttendanceDbError(
                f"Could not write employee {user.pin!r} to {self._device.serial!r}."
            ) from exc

    def set_fingerprint(self, template: FingerTemplate) -> None:
        """
        Push one fingerprint template to this device.

        ``pyzk``'s ``save_user_template`` takes a ``User`` plus a list of ``Finger`` objects and
        writes them together, so the corresponding user must already exist on the device --
        callers sync employees before templates for exactly this reason (see
        :meth:`adms.pull.agent.PullAgent._push_missing_employees`).

        The ``uid`` cache is refreshed (not just lazily built once) whenever the target PIN is
        not already in it, not only when the cache is empty: a PIN pushed by ``set_employee``
        earlier in the same sync batch is, by definition, not yet in a cache built before that
        push happened, and skipping the refresh in that case silently dropped every fingerprint
        for a person sync had just created (confirmed against a device).
        """
        try:
            from zk.finger import Finger as ZkFinger
        except ImportError as exc:
            raise ConfigError("pyzk is not installed.") from exc

        uid = _find_uid(self._uid_to_pin, template.pin)
        if uid is None:
            self.get_employees()  # refresh: the PIN may have just been created by set_employee
            uid = _find_uid(self._uid_to_pin, template.pin)
        if uid is None:
            raise AttendanceDbError(
                f"Cannot push a fingerprint for PIN {template.pin!r}: the user does not exist on "
                f"{self._device.serial!r} yet."
            )

        try:
            users = self._connection.get_users()
            zk_user = next((u for u in users if int(u.uid) == uid), None)
            if zk_user is None:
                raise AttendanceDbError(f"User {template.pin!r} vanished from {self._device.serial!r}.")
            finger = ZkFinger(
                uid=uid,
                fid=template.finger_id,
                valid=template.valid,
                template=_unb64(template.template),
            )
            self._connection.save_user_template(zk_user, [finger])
        except self._zk_error as exc:
            raise AttendanceDbError(
                f"Could not write a fingerprint template for {template.pin!r} to "
                f"{self._device.serial!r}."
            ) from exc


def _find_uid(uid_to_pin: dict[int, str], pin: str) -> int | None:
    for uid, mapped_pin in uid_to_pin.items():
        if mapped_pin == pin:
            return uid
    return None


def _to_card_int(card: str) -> int:
    try:
        return int(card.strip()) if card.strip() else 0
    except ValueError:
        return 0


def _b64(raw: bytes) -> str:
    import base64

    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    import base64

    return base64.b64decode(text)
