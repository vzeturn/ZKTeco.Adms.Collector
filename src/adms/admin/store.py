"""
SQL adapter for the admin console.

Same discipline as :mod:`adms.db`: raw ODBC, every value a bound parameter, driver errors wrapped so no
connection detail escapes. It reuses the collector's :class:`~adms.db.ConnectionFactory`, so the console
process gets the same per-thread connection handling and the same stale-handle recovery.

Reads of device state go through ``dbo.vw_APP_DeviceOverview`` rather than assembling the same joins
here, so the UI and any ad-hoc query an operator runs cannot disagree about what "Silent" means.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass

from ..db.connection import ConnectionFactory, transaction
from ..db.schema import (
    FINGER_VERSION,
    TABLE_ADMS_DEVICE,
    TABLE_EMPLOYEES,
    TABLE_FACE,
    TABLE_FINGER,
    parse_enabled,
)
from ..errors import AttendanceDbError
from ..models import DeviceUser
from ..protocol import commands

#: The console's domain vocabulary is lowercase (see :class:`adms.admin.auth.Role`); System A's
#: ``APP_ROLE`` stores ``Admin``/``Operator``/``Viewer``. Convert at this boundary so the domain and
#: the templates never see the DB casing. Keyed off the three standard rows.
_ROLE_DB_TO_DOMAIN = {"Admin": "admin", "Operator": "operator", "Viewer": "viewer"}
_ROLE_DOMAIN_TO_DB = {v: k for k, v in _ROLE_DB_TO_DOMAIN.items()}
#: PBKDF2-HMAC-SHA256 is the only scheme the console mints (see :mod:`adms.admin.auth`). Written to the
#: NOT NULL ``KdfAlgorithm`` column on insert; not otherwise interpreted.
_KDF_ALGORITHM = "PBKDF2-HMAC-SHA256"

__all__ = [
    "AdminStore", "UserRow", "SessionRow", "DeviceRow", "AuditRow", "EmployeeRow", "GrantResult",
    "RosterSyncRow", "DeletionEventRow",
]


def _utc(value: dt.datetime | None) -> dt.datetime | None:
    """
    Stamp UTC onto a datetime read from SQL Server.

    SQL Server ``datetime``/``datetime2`` carry no zone, so pyodbc hands back *naive* datetimes -- but
    the console's domain runs on timezone-aware UTC (``clock()`` returns ``dt.datetime.now(dt.UTC)``),
    and comparing the two raises ``TypeError: can't compare offset-naive and offset-aware datetimes``.
    Normalising here, at the one seam where DB values enter, means nothing downstream ever meets a
    naive datetime -- the alternative (patching every comparison site) leaves the next new column
    holding the same landmine. An already-aware value (the fakes in tests) passes through unchanged.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.UTC)
    return value.astimezone(dt.UTC)


@dataclass(frozen=True, slots=True)
class UserRow:
    user_id: str
    username: str
    display_name: str
    role: str
    is_enabled: bool
    must_change_password: bool
    failed_attempts: int
    locked_until_utc: dt.datetime | None
    last_login_utc: dt.datetime | None
    created_utc: dt.datetime | None

    @property
    def is_locked(self) -> bool:
        if self.locked_until_utc is None:
            return False
        return self.locked_until_utc > dt.datetime.now(dt.UTC)


@dataclass(frozen=True, slots=True)
class SessionRow:
    user_id: str
    username: str
    display_name: str
    role: str
    is_enabled: bool
    must_change_password: bool
    csrf_secret: bytes
    created_utc: dt.datetime
    expires_utc: dt.datetime


@dataclass(frozen=True, slots=True)
class DeviceRow:
    serial: str
    device_name: str
    enabled: bool
    machine_code: str
    machine_id: int | None
    machine_name: str
    machine_ip: str
    firmware: str
    platform: str
    push_version: str
    last_seen_utc: dt.datetime | None
    contact_count: int
    last_ip: str
    minutes_since_contact: int | None
    state: str
    punches_last_24h: int
    pending_commands: int
    #: multi-device-employee-sync. Empty string for a NULL ADMS_DEVICE.SyncGroup -- the same
    #: "nullable in SQL, non-optional in Python" convention every other field on this row already
    #: uses. Empty means this device never exchanges anything through Roster_Sync (see
    #: adms.models.DeviceRegistration.sync_group's own docstring for the same convention on the
    #: collector side).
    sync_group: str = ""
    #: How many Roster_Versions behind this device's own group max it is, or ``None`` when it has
    #: no SyncGroup (there is no group max to be behind). Sourced from
    #: vw_ADMS_RosterSyncStatus.PinsOwed -- a version-count gap, not a literal PIN count; see that
    #: view's own comment for why. ``0`` means fully caught up, not "no data available" -- the two
    #: are told apart by this field being ``None`` only when sync_group is empty.
    roster_pins_owed: int | None = None


@dataclass(frozen=True, slots=True)
class RosterSyncRow:
    """One row of ``vw_ADMS_RosterSyncStatus``: a Linked, Enabled_Device with a Sync_Group, its
    Backfill cursor, and how far behind its own group's current version it is."""

    serial: str
    device_name: str
    sync_group: str
    roster_sync_stamp: int
    group_max_version: int
    pins_owed: int


@dataclass(frozen=True, slots=True)
class DeletionEventRow:
    """
    One propagated deletion, for the operator-facing delete fan-out audit trail (ISO 27001
    traceability). Sourced from ``ADMS_DEVICE_ROSTER_VERSION`` rows flagged ``IsDeleted = 1``,
    joined back to the command it produced in ``ADMS_COMMAND`` where one is still on record --
    the version row is the durable fact ("PIN N was deleted in group G at time T"), the command
    rows are best-effort delivery evidence that can legitimately be gone (purged, or never
    recorded if reconciliation ran before this page existed).
    """

    pin: int
    sync_group: str
    roster_version: int
    updated_utc: dt.datetime
    commands_enqueued: int


@dataclass(frozen=True, slots=True)
class AuditRow:
    when_utc: dt.datetime
    username: str
    action: str
    target: str
    detail: str
    ip: str
    succeeded: bool


#: ``NHANVIEN.PhanQuyen`` value that means "device administrator" on the firmware in the field. The
#: ``UserPrivilege`` enum names 14 for Administrator, but this old firmware reads a write of 14 back as
#: 3, and existing data already holds many priv=3 rows that are confirmed admins. Grant writes 3; revoke
#: writes 0 (plain user).
_PHANQUYEN_ADMIN = 3
_PHANQUYEN_USER = 0

#: When an employee has no biometric row at all, a device password is stored on a placeholder
#: ``dbo.TEMPLATE`` row. ``_group_by_pin`` (db/templates.py) drops rows whose ``FingerTemplate`` is
#: empty, so the placeholder must carry a non-empty sentinel or the next device→DB sync would delete
#: it — taking the password with it. ``FingerID`` 9 is the least-used real index; documented, not magic.
_PWD_ONLY_SENTINEL = "PWDONLY"
_PWD_ONLY_FINGER_ID = 9


@dataclass(frozen=True, slots=True)
class EmployeeRow:
    """An employee looked up by PIN, showing enough state to grant or revoke device-admin rights."""

    pin: int
    name: str
    card: str
    privilege: int
    is_enabled: bool

    @property
    def is_admin(self) -> bool:
        return self.privilege == _PHANQUYEN_ADMIN


@dataclass(frozen=True, slots=True)
class GrantResult:
    """What :meth:`AdminStore.set_employee_admin` did, so the UI can report it precisely."""

    templates_updated: int
    placeholder_created: bool
    devices_queued: int


class AdminStore:
    """Everything the console reads and writes."""

    __slots__ = ("_factory", "_log")

    def __init__(self, factory: ConnectionFactory, log=None) -> None:
        self._factory = factory
        self._log = log

    # ── internals ────────────────────────────────────────────────────────────────────────

    def _rows(self, sql: str, params: tuple = ()) -> list:
        try:
            cursor = self._factory.get().cursor()
            try:
                cursor.execute(sql, params)
                return cursor.fetchall()
            finally:
                cursor.close()
        except AttendanceDbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AttendanceDbError("An admin console query failed.") from exc

    def _row(self, sql: str, params: tuple = ()):
        rows = self._rows(sql, params)
        return rows[0] if rows else None

    # ── users ────────────────────────────────────────────────────────────────────────────

    #: The user columns, joined to the role through ``APP_USER_ROLE``/``APP_ROLE``. ``LEFT JOIN`` so a
    #: user with no role row still appears (its ``role`` maps to '' and reads as no capability) rather
    #: than vanishing. System A column names on the DB side; the mapper renames them to the domain.
    _USER_SELECT = """
        SELECT u.UserId, u.Username, u.FullName, r.RoleName, u.IsActive, u.MustChangePassword,
               u.FailedLoginCount, u.LockoutUntilUtc, u.LastLoginUtc, u.CreatedUtc
          FROM dbo.APP_USER u
          LEFT JOIN dbo.APP_USER_ROLE ur ON ur.UserId = u.UserId
          LEFT JOIN dbo.APP_ROLE r ON r.RoleId = ur.RoleId
    """

    @staticmethod
    def _to_user(row) -> UserRow:
        return UserRow(
            user_id=str(row[0]),
            username=row[1],
            display_name=row[2] or "",
            role=_ROLE_DB_TO_DOMAIN.get(row[3], ""),
            is_enabled=bool(row[4]),
            must_change_password=bool(row[5]),
            failed_attempts=int(row[6]),
            locked_until_utc=_utc(row[7]),
            last_login_utc=_utc(row[8]),
            created_utc=_utc(row[9]),
        )

    def find_user(self, username: str) -> UserRow | None:
        row = self._row(f"{self._USER_SELECT} WHERE u.Username = ?", (username,))
        return self._to_user(row) if row else None

    def get_user(self, user_id: str) -> UserRow | None:
        row = self._row(f"{self._USER_SELECT} WHERE u.UserId = ?", (user_id,))
        return self._to_user(row) if row else None

    def list_users(self) -> list[UserRow]:
        rows = self._rows(f"{self._USER_SELECT} ORDER BY u.Username")
        return [self._to_user(r) for r in rows]

    def count_enabled_admins(self) -> int:
        """
        Used to refuse the last administrator being disabled, demoted or deleted.

        Without this the console can be locked out of itself, and recovering means hand-editing
        ``APP_USER`` with a SQL client -- exactly the situation the console exists to avoid.
        """
        row = self._row(
            """
            SELECT COUNT(*)
              FROM dbo.APP_USER u
              JOIN dbo.APP_USER_ROLE ur ON ur.UserId = u.UserId
              JOIN dbo.APP_ROLE r ON r.RoleId = ur.RoleId
             WHERE r.RoleName = 'Admin' AND u.IsActive = 1
            """
        )
        return int(row[0]) if row else 0

    def password_material(self, user_id: str) -> tuple[bytes, bytes, int] | None:
        """``(salt, hash, iterations)``. Separate from :meth:`get_user` so the hash is only ever
        loaded on the sign-in path, and never lives in an object the templates can reach."""
        row = self._row(
            "SELECT PasswordSalt, PasswordHash, KdfIterations FROM dbo.APP_USER WHERE UserId = ?",
            (user_id,),
        )
        if row is None:
            return None
        return bytes(row[0]), bytes(row[1]), int(row[2])

    def create_user(
        self,
        *,
        username: str,
        display_name: str,
        role: str,
        salt: bytes,
        password_hash: bytes,
        iterations: int,
        must_change_password: bool,
        created_by: str,
    ) -> str:
        """
        Insert the user and its role join in one transaction, returning the new GUID.

        ``UserId`` is a client-generated ``uniqueidentifier`` (not an identity column), so the id is
        known before the insert; ``OUTPUT INSERTED.UserId`` confirms the row landed. ``created_by`` is
        recorded in the audit trail by the caller, not stored on the row -- the ``APP_USER`` table
        has no such column.
        """
        role_db = _ROLE_DOMAIN_TO_DB.get(role)
        if role_db is None:
            raise AttendanceDbError(f"Unknown role {role!r}.")
        new_id = str(uuid.uuid4())
        with transaction(self._factory, what="create a console user") as cursor:
            cursor.execute(
                """
                INSERT INTO dbo.APP_USER
                    (UserId, Username, FullName, PasswordHash, PasswordSalt, KdfAlgorithm,
                     KdfIterations, IsActive, MustChangePassword, FailedLoginCount, CreatedUtc)
                OUTPUT INSERTED.UserId
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, 0, SYSUTCDATETIME())
                """,
                (
                    new_id,
                    username,
                    display_name[:400],
                    password_hash,
                    salt,
                    _KDF_ALGORITHM,
                    iterations,
                    1 if must_change_password else 0,
                ),
            )
            row = cursor.fetchone()
            if row is None or row[0] is None:
                raise AttendanceDbError("Created the user but could not read back its id.")
            created_id = str(row[0])
            cursor.execute(
                """
                INSERT INTO dbo.APP_USER_ROLE (UserId, RoleId)
                SELECT ?, RoleId FROM dbo.APP_ROLE WHERE RoleName = ?
                """,
                (created_id, role_db),
            )
            return created_id

    def set_password(
        self, user_id: str, salt: bytes, password_hash: bytes, iterations: int, must_change: bool
    ) -> None:
        """
        Replace the password and clear the lockout counters.

        Clearing ``FailedAttempts``/``LockedUntilUtc`` here is the point: a legitimate user who was
        locked out by someone else's guessing gets back in by changing their password, without waiting
        for the window or asking an administrator.
        """
        with transaction(self._factory, what="set a console password") as cursor:
            cursor.execute(
                """
                UPDATE dbo.APP_USER
                   SET PasswordSalt = ?, PasswordHash = ?, KdfIterations = ?, KdfAlgorithm = ?,
                       MustChangePassword = ?, FailedLoginCount = 0, LockoutUntilUtc = NULL
                 WHERE UserId = ?
                """,
                (salt, password_hash, iterations, _KDF_ALGORITHM, 1 if must_change else 0, user_id),
            )

    def update_user(self, user_id: str, *, display_name: str, role: str, is_enabled: bool) -> None:
        """Update the profile fields and re-point the single role join row to the chosen role."""
        role_db = _ROLE_DOMAIN_TO_DB.get(role)
        if role_db is None:
            raise AttendanceDbError(f"Unknown role {role!r}.")
        with transaction(self._factory, what="update a console user") as cursor:
            cursor.execute(
                "UPDATE dbo.APP_USER SET FullName = ?, IsActive = ? WHERE UserId = ?",
                (display_name[:400], 1 if is_enabled else 0, user_id),
            )
            # One role per user in this console: clear then set, so a role change never leaves two.
            cursor.execute("DELETE FROM dbo.APP_USER_ROLE WHERE UserId = ?", (user_id,))
            cursor.execute(
                """
                INSERT INTO dbo.APP_USER_ROLE (UserId, RoleId)
                SELECT ?, RoleId FROM dbo.APP_ROLE WHERE RoleName = ?
                """,
                (user_id, role_db),
            )

    def delete_user(self, user_id: str) -> None:
        """Sessions and the role join go first: both FK to APP_USER, so the order is not optional."""
        with transaction(self._factory, what="delete a console user") as cursor:
            cursor.execute("DELETE FROM dbo.APP_SESSION WHERE UserId = ?", (user_id,))
            cursor.execute("DELETE FROM dbo.APP_USER_ROLE WHERE UserId = ?", (user_id,))
            cursor.execute("DELETE FROM dbo.APP_USER WHERE UserId = ?", (user_id,))

    def record_login_success(self, user_id: str, now: dt.datetime, ip: str) -> None:
        # ``ip`` is accepted for a uniform call site but not stored: the APP_USER table has no
        # LastLoginIp column. The signing-in address is captured on the session row instead.
        with transaction(self._factory, what="record a successful sign-in") as cursor:
            cursor.execute(
                """
                UPDATE dbo.APP_USER
                   SET LastLoginUtc = ?, FailedLoginCount = 0, LockoutUntilUtc = NULL
                 WHERE UserId = ?
                """,
                (now, user_id),
            )

    def record_login_failure(self, user_id: str, locked_until: dt.datetime | None) -> int:
        """Increment the failure count and apply a lockout. Returns the new count."""
        with transaction(self._factory, what="record a failed sign-in") as cursor:
            cursor.execute(
                """
                UPDATE dbo.APP_USER
                   SET FailedLoginCount = FailedLoginCount + 1,
                       LockoutUntilUtc  = ?
                 WHERE UserId = ?
                """,
                (locked_until, user_id),
            )
            cursor.execute("SELECT FailedLoginCount FROM dbo.APP_USER WHERE UserId = ?", (user_id,))
            row = cursor.fetchone()
            return int(row[0]) if row else 0

    def unlock_user(self, user_id: str) -> None:
        with transaction(self._factory, what="unlock a console user") as cursor:
            cursor.execute(
                "UPDATE dbo.APP_USER SET FailedLoginCount = 0, LockoutUntilUtc = NULL WHERE UserId = ?",
                (user_id,),
            )

    # ── sessions ─────────────────────────────────────────────────────────────────────────

    def create_session(
        self,
        *,
        token_hash: bytes,
        user_id: str,
        expires_utc: dt.datetime,
        ip: str,
        user_agent: str,
        csrf_secret: bytes,
    ) -> None:
        with transaction(self._factory, what="open a console session") as cursor:
            cursor.execute(
                """
                INSERT INTO dbo.APP_SESSION
                    (TokenHash, UserId, ExpiresUtc, Ip, UserAgent, CsrfSecret)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (token_hash, user_id, expires_utc, ip[:64], user_agent[:256], csrf_secret),
            )

    def load_session(self, token_hash: bytes) -> SessionRow | None:
        """
        The session and its user in one round trip.

        ``IsEnabled`` comes along so a disabled account's existing sessions stop working immediately
        rather than lasting until they expire -- disabling someone has to take effect now.
        """
        row = self._row(
            """
            SELECT s.UserId, u.Username, u.FullName, r.RoleName, u.IsActive,
                   u.MustChangePassword, s.CsrfSecret, s.CreatedUtc, s.ExpiresUtc
              FROM dbo.APP_SESSION s
              JOIN dbo.APP_USER u ON u.UserId = s.UserId
              LEFT JOIN dbo.APP_USER_ROLE ur ON ur.UserId = u.UserId
              LEFT JOIN dbo.APP_ROLE r ON r.RoleId = ur.RoleId
             WHERE s.TokenHash = ?
            """,
            (token_hash,),
        )
        if row is None:
            return None
        return SessionRow(
            user_id=str(row[0]),
            username=row[1],
            display_name=row[2] or "",
            role=_ROLE_DB_TO_DOMAIN.get(row[3], ""),
            is_enabled=bool(row[4]),
            must_change_password=bool(row[5]),
            csrf_secret=bytes(row[6]),
            created_utc=_utc(row[7]),
            expires_utc=_utc(row[8]),
        )

    def touch_session(self, token_hash: bytes, expires_utc: dt.datetime, now: dt.datetime) -> None:
        with transaction(self._factory, what="refresh a console session") as cursor:
            cursor.execute(
                "UPDATE dbo.APP_SESSION SET ExpiresUtc = ?, LastSeenUtc = ? WHERE TokenHash = ?",
                (expires_utc, now, token_hash),
            )

    def delete_session(self, token_hash: bytes) -> None:
        with transaction(self._factory, what="close a console session") as cursor:
            cursor.execute("DELETE FROM dbo.APP_SESSION WHERE TokenHash = ?", (token_hash,))

    def delete_sessions_for_user(self, user_id: str) -> int:
        """Sign a user out everywhere. Used on password change, on disable, and by an admin."""
        with transaction(self._factory, what="close all sessions for a user") as cursor:
            cursor.execute("DELETE FROM dbo.APP_SESSION WHERE UserId = ?", (user_id,))
            return cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else 0

    def purge_expired_sessions(self) -> int:
        with transaction(self._factory, what="purge expired sessions") as cursor:
            cursor.execute("DELETE FROM dbo.APP_SESSION WHERE ExpiresUtc < SYSUTCDATETIME()")
            return cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else 0

    def active_sessions(self) -> list[dict]:
        rows = self._rows(
            """
            SELECT u.Username, u.FullName, s.Ip, s.UserAgent, s.CreatedUtc, s.LastSeenUtc,
                   s.ExpiresUtc, s.UserId
              FROM dbo.APP_SESSION s
              JOIN dbo.APP_USER u ON u.UserId = s.UserId
             WHERE s.ExpiresUtc >= SYSUTCDATETIME()
             ORDER BY s.LastSeenUtc DESC
            """
        )
        return [
            {
                "username": r[0],
                "display_name": r[1] or "",
                "ip": r[2] or "",
                "user_agent": r[3] or "",
                "created_utc": _utc(r[4]),
                "last_seen_utc": _utc(r[5]),
                "expires_utc": _utc(r[6]),
                "user_id": str(r[7]),
            }
            for r in rows
        ]

    # ── employees (device-admin rights) ──────────────────────────────────────────────────

    def get_employee(self, pin: int) -> EmployeeRow | None:
        """
        The one employee whose ``MaChamCong`` is ``pin``, or ``None``.

        ``name`` prefers ``TenChamCong`` (the device enroll name) and falls back to ``TenNhanVien``
        when it is blank, matching how the desktop app resolves a display name.
        """
        row = self._row(
            f"""
            SELECT MaChamCong, TenChamCong, TenNhanVien, MaThe, PhanQuyen, UserEnable
              FROM {TABLE_EMPLOYEES} WHERE MaChamCong = ?
            """,
            (pin,),
        )
        if row is None:
            return None
        name = (row[1] or "").strip() or (row[2] or "").strip()
        return EmployeeRow(
            pin=int(row[0]),
            name=name,
            card=(row[3] or "").strip(),
            privilege=int(row[4]) if row[4] not in (None, "") else _PHANQUYEN_USER,
            is_enabled=parse_enabled(row[5]),
        )

    @staticmethod
    def _count_rows(cursor, table: str, pin: int) -> int:
        """How many rows ``table`` holds for ``pin``, read inside the caller's transaction."""
        cursor.execute(f"SELECT COUNT(*) FROM {table} WHERE MaChamCong = ?", (pin,))
        row = cursor.fetchone()
        return int(row[0]) if row and row[0] is not None else 0

    def _enabled_serials(self, cursor) -> list[str]:
        """Serials of every enabled device, read inside the caller's transaction."""
        cursor.execute(f"SELECT SerialNumber FROM {TABLE_ADMS_DEVICE} WHERE Enabled = 1")
        return [r[0] for r in cursor.fetchall()]

    def set_employee_admin(
        self,
        pin: int,
        *,
        is_admin: bool,
        password: int | None,
        name: str,
        card: str,
        created_by: str,
    ) -> GrantResult:
        """
        Persist a device-admin change to ATTENDANCEDB and queue it to every enabled device, atomically.

        One transaction does three things: rewrite ``NHANVIEN.PhanQuyen`` (3 to grant, 0 to revoke);
        optionally set the device unlock password (``enPassword``) on the employee's biometric rows,
        creating a sentinel placeholder row when they have none; and enqueue one ``DATA UPDATE USER``
        per enabled device so the hardware applies the change without a manual re-push.

        ``password`` is a numeric device password already validated by the caller, or ``None`` to
        leave any existing password untouched. It is never logged and never placed in an audit row.
        """
        privilege = _PHANQUYEN_ADMIN if is_admin else _PHANQUYEN_USER
        templates_updated = 0
        placeholder_created = False

        with transaction(self._factory, what="set an employee's device-admin rights") as cursor:
            cursor.execute(
                f"UPDATE {TABLE_EMPLOYEES} SET PhanQuyen = ? WHERE MaChamCong = ?",
                (privilege, pin),
            )

            if password is not None:
                # Count the employee's biometric rows first, so the branch does not depend on the
                # driver's ``rowcount`` (which the test recorder does not model). One scalar per table.
                finger_rows = self._count_rows(cursor, TABLE_FINGER, pin)
                face_rows = self._count_rows(cursor, TABLE_FACE, pin)
                templates_updated = finger_rows + face_rows
                if finger_rows:
                    cursor.execute(
                        f"UPDATE {TABLE_FINGER} SET enPassword = ? WHERE MaChamCong = ?", (password, pin)
                    )
                if face_rows:
                    cursor.execute(
                        f"UPDATE {TABLE_FACE} SET enPassword = ? WHERE MaChamCong = ?", (password, pin)
                    )
                if templates_updated == 0:
                    # No biometric row to carry the password: store it on a sentinel placeholder that
                    # _group_by_pin never treats as empty, so a later device→DB sync leaves it alone.
                    cursor.execute(
                        f"""
                        INSERT INTO {TABLE_FINGER}
                            (MaChamCong, FingerID, FingerTemplate, Flag, FingerVersion,
                             EnrollNumber, EnrollName, Privilige, enPassword, EMachineNumber)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            pin, _PWD_ONLY_FINGER_ID, _PWD_ONLY_SENTINEL, 1, FINGER_VERSION,
                            pin, "", privilege, password, 0,
                        ),
                    )
                    placeholder_created = True

            serials = self._enabled_serials(cursor)
            body = commands.update_user(
                DeviceUser(
                    pin=str(pin),
                    name=name,
                    # raw int: 3 is outside UserPrivilege, and update_user only int()s it
                    privilege=privilege,  # type: ignore[arg-type]
                    password="" if password is None else str(password),
                    card=card,
                )
            )
            for serial in serials:
                cursor.execute(
                    """
                    INSERT INTO dbo.ADMS_COMMAND (SerialNumber, CommandText, Status, CreatedBy, CreatedUtc)
                    VALUES (?, ?, 'Pending', ?, SYSUTCDATETIME())
                    """,
                    (serial, body, created_by[:64]),
                )

        return GrantResult(
            templates_updated=templates_updated,
            placeholder_created=placeholder_created,
            devices_queued=len(serials),
        )

    # ── audit ────────────────────────────────────────────────────────────────────────────

    def audit(
        self,
        *,
        username: str,
        action: str,
        target: str = "",
        detail: str = "",
        ip: str = "",
        succeeded: bool = True,
    ) -> None:
        """
        Append an audit row.

        Never raises: an audit write that fails must not also fail the operation the user asked for,
        and the alternative -- refusing the action -- would make a full disk look like a permissions
        problem. Failures are logged instead.
        """
        try:
            with transaction(self._factory, what="write an audit entry") as cursor:
                cursor.execute(
                    """
                    INSERT INTO dbo.APP_AUDIT (Username, Action, Target, Detail, Ip, Succeeded)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        username[:64],
                        action[:64],
                        target[:128],
                        detail[:1000],
                        ip[:64],
                        1 if succeeded else 0,
                    ),
                )
        except Exception as exc:  # noqa: BLE001
            if self._log is not None:
                self._log.warn("Could not write an audit entry.", exc, action=action)

    def recent_audit(self, limit: int = 200) -> list[AuditRow]:
        rows = self._rows(
            """
            SELECT TOP (?) WhenUtc, Username, Action, Target, Detail, Ip, Succeeded
              FROM dbo.APP_AUDIT ORDER BY AuditId DESC
            """,
            (max(1, min(limit, 1000)),),
        )
        return [
            AuditRow(
                when_utc=_utc(r[0]),
                username=r[1] or "",
                action=r[2] or "",
                target=r[3] or "",
                detail=r[4] or "",
                ip=r[5] or "",
                succeeded=bool(r[6]),
            )
            for r in rows
        ]

    # ── devices ──────────────────────────────────────────────────────────────────────────

    def devices(self) -> list[DeviceRow]:
        """
        Every registered device, joined to its Roster_Sync status when it has one.

        LEFT JOIN, not a second round trip: ``vw_ADMS_RosterSyncStatus`` (multi-device-employee-
        sync) already scopes itself to ``Enabled = 1 AND SyncGroup IS NOT NULL``, so a device with
        no group -- the common case for anything outside the feature's own opt-in list -- simply
        has no matching row and reads as ``sync_group=''``/``roster_pins_owed=None`` below, exactly
        matching the "no group means inert" convention the collector side already uses.
        """
        rows = self._rows(
            """
            SELECT d.SerialNumber, d.DeviceName, d.Enabled, d.MaMCC, d.MaSoMay, d.MachineName,
                   d.MachineIp, d.FirmwareVersion, d.Platform, d.PushVersion, d.LastSeenUtc,
                   d.ContactCount, d.LastIp, d.MinutesSinceContact, d.DeviceState,
                   d.PunchesLast24h, d.PendingCommands,
                   rs.SyncGroup, rs.PinsOwed
              FROM dbo.vw_APP_DeviceOverview d
              LEFT JOIN dbo.vw_ADMS_RosterSyncStatus rs ON rs.SerialNumber = d.SerialNumber
             ORDER BY CASE d.DeviceState
                        WHEN 'Silent'     THEN 0
                        WHEN 'Not linked' THEN 1
                        WHEN 'Never seen' THEN 2
                        WHEN 'Online'     THEN 3
                        ELSE 4 END,
                      d.SerialNumber
            """
        )
        # Ordered by how much attention the row needs, not alphabetically: a Silent device is the one
        # an operator opened this page to find.
        return [
            DeviceRow(
                serial=r[0],
                device_name=r[1] or "",
                enabled=bool(r[2]),
                machine_code=(r[3] or "").strip(),
                machine_id=int(r[4]) if r[4] is not None else None,
                machine_name=(r[5] or "").strip(),
                machine_ip=(r[6] or "").strip(),
                firmware=r[7] or "",
                platform=r[8] or "",
                push_version=r[9] or "",
                last_seen_utc=_utc(r[10]),
                contact_count=int(r[11] or 0),
                last_ip=r[12] or "",
                minutes_since_contact=int(r[13]) if r[13] is not None else None,
                state=r[14] or "",
                punches_last_24h=int(r[15] or 0),
                pending_commands=int(r[16] or 0),
                sync_group=(r[17] or "").strip(),
                roster_pins_owed=int(r[18]) if r[18] is not None else None,
            )
            for r in rows
        ]

    def device(self, serial: str) -> DeviceRow | None:
        return next((d for d in self.devices() if d.serial == serial), None)

    # ── multi-device-employee-sync: Roster_Sync status and delete fan-out audit ───────────

    def roster_sync_status(self) -> list[RosterSyncRow]:
        """
        Every row of ``vw_ADMS_RosterSyncStatus`` -- one per Enabled, Linked_Device with a
        non-empty ``SyncGroup``. Ordered by how far behind a device is, so a device silently
        falling behind (Fan_Out missed it, and it has not yet been Backfilled) is the one an
        operator sees first, mirroring :meth:`devices`'s own "attention first" ordering.
        """
        rows = self._rows(
            """
            SELECT SerialNumber, DeviceName, SyncGroup, RosterSyncStamp, GroupMaxVersion, PinsOwed
              FROM dbo.vw_ADMS_RosterSyncStatus
             ORDER BY PinsOwed DESC, SyncGroup, SerialNumber
            """
        )
        return [
            RosterSyncRow(
                serial=r[0],
                device_name=r[1] or "",
                sync_group=(r[2] or "").strip(),
                roster_sync_stamp=int(r[3] or 0),
                group_max_version=int(r[4] or 0),
                pins_owed=int(r[5] or 0),
            )
            for r in rows
        ]

    def recent_deletions(self, limit: int = 100) -> list[DeletionEventRow]:
        """
        Recently propagated user deletions (ISO 27001 traceability), newest first.

        ``ADMS_DEVICE_ROSTER_VERSION`` rows flagged ``IsDeleted = 1`` are the durable record of
        "PIN N was deleted from Sync_Group G, at version V, at time T" -- see
        adms.db.roster_sync's own module docstring for why that flag has to travel with the
        version snapshot rather than being inferred from NHANVIEN's current state. The enqueued
        count is a best-effort cross-reference against ADMS_COMMAND (``DATA DELETE USERINFO
        PIN=<pin>``), which can legitimately read 0 for an old row whose commands were already
        claimed and later purged -- that is a delivery-evidence gap, not a sign the deletion
        itself did not happen.
        """
        rows = self._rows(
            """
            SELECT TOP (?) v.Pin, v.SyncGroup, v.RosterVersion, v.UpdatedUtc,
                   (SELECT COUNT(*) FROM dbo.ADMS_COMMAND c
                     WHERE c.CommandText = 'DATA DELETE USERINFO PIN=' + CAST(v.Pin AS NVARCHAR(20)))
                     AS CommandsEnqueued
              FROM dbo.ADMS_DEVICE_ROSTER_VERSION v
             WHERE v.IsDeleted = 1
             ORDER BY v.UpdatedUtc DESC
            """,
            (max(1, min(limit, 500)),),
        )
        return [
            DeletionEventRow(
                pin=int(r[0]),
                sync_group=(r[1] or "").strip(),
                roster_version=int(r[2]),
                updated_utc=_utc(r[3]),
                commands_enqueued=int(r[4] or 0),
            )
            for r in rows
        ]

    def set_device_enabled(self, serial: str, enabled: bool) -> None:
        with transaction(self._factory, what="change a device's enabled flag") as cursor:
            cursor.execute(
                "UPDATE dbo.ADMS_DEVICE SET Enabled = ? WHERE SerialNumber = ?",
                (1 if enabled else 0, serial),
            )

    def link_device(self, serial: str, machine_code: str) -> None:
        with transaction(self._factory, what="link a device to a machine") as cursor:
            cursor.execute(
                "UPDATE dbo.ADMS_DEVICE SET MaMCC = ? WHERE SerialNumber = ?",
                (machine_code or None, serial),
            )

    def machines(self) -> list[dict]:
        """
        ``MAYCHAMCONG`` rows, for the link dropdown.

        ``IDMCC`` is included and shown in the UI because it is *not* unique in this database -- ten of
        eleven machines share ``1`` -- so an operator picking a machine needs to see the name, not just
        the id, to know what they chose.
        """
        rows = self._rows(
            "SELECT MaMCC, TenMCC, IDMCC, DiaChiIP, TrangThai FROM MAYCHAMCONG ORDER BY MaMCC"
        )
        return [
            {
                "code": (r[0] or "").strip(),
                "name": (r[1] or "").strip(),
                "numeric_id": int(r[2]) if r[2] is not None else None,
                "ip": (r[3] or "").strip(),
                "active": bool(r[4]),
            }
            for r in rows
        ]

    # ── commands ─────────────────────────────────────────────────────────────────────────

    def enqueue_command(self, serial: str, body: str, created_by: str) -> int:
        sql = """
            INSERT INTO dbo.ADMS_COMMAND (SerialNumber, CommandText, Status, CreatedBy, CreatedUtc)
            VALUES (?, ?, 'Pending', ?, SYSUTCDATETIME());
            SELECT CAST(SCOPE_IDENTITY() AS INT);
        """
        with transaction(self._factory, what="queue a device command") as cursor:
            cursor.execute(sql, (serial, body, created_by[:64]))
            while cursor.description is None:
                if not cursor.nextset():
                    raise AttendanceDbError("Queued the command but could not read back its id.")
            row = cursor.fetchone()
            if row is None or row[0] is None:
                raise AttendanceDbError("Queued the command but could not read back its id.")
            return int(row[0])

    def commands(self, serial: str | None = None, limit: int = 100) -> list[dict]:
        capped = max(1, min(limit, 500))
        if serial:
            rows = self._rows(
                """
                SELECT TOP (?) CommandId, SerialNumber, CommandText, Status, ReturnCode, ReturnCmd,
                       CreatedBy, CreatedUtc, SentUtc, AckedUtc
                  FROM dbo.ADMS_COMMAND WHERE SerialNumber = ? ORDER BY CommandId DESC
                """,
                (capped, serial),
            )
        else:
            rows = self._rows(
                """
                SELECT TOP (?) CommandId, SerialNumber, CommandText, Status, ReturnCode, ReturnCmd,
                       CreatedBy, CreatedUtc, SentUtc, AckedUtc
                  FROM dbo.ADMS_COMMAND ORDER BY CommandId DESC
                """,
                (capped,),
            )
        return [
            {
                "id": int(r[0]),
                "serial": r[1],
                "text": r[2] or "",
                "status": r[3] or "",
                "return_code": r[4],
                "return_cmd": r[5] or "",
                "created_by": r[6] or "",
                "created_utc": _utc(r[7]),
                "sent_utc": _utc(r[8]),
                "acked_utc": _utc(r[9]),
            }
            for r in rows
        ]

    def cancel_command(self, command_id: int) -> bool:
        """
        Remove a command that has not been dispatched yet.

        Scoped to ``Status = 'Pending'``: once the collector has handed a command to a device there is
        no recalling it, and pretending otherwise in the UI would be worse than refusing.
        """
        with transaction(self._factory, what="cancel a queued command") as cursor:
            cursor.execute(
                "DELETE FROM dbo.ADMS_COMMAND WHERE CommandId = ? AND Status = 'Pending'",
                (command_id,),
            )
            return bool(cursor.rowcount and cursor.rowcount > 0)

    # ── activity ─────────────────────────────────────────────────────────────────────────

    def summary(self) -> dict:
        """
        Dashboard counters, in one round trip rather than six.

        The three ``roster_*``/``deletions_24h`` counters are always computed (unlike every device
        query above, they do not depend on any device having a ``SyncGroup``) so the dashboard can
        show a calm "0" rather than needing a separate "is Roster_Sync even on" check -- the
        underlying tables exist unconditionally once ``adms-schema.sql`` has run, whether or not
        any device is currently opted in.
        """
        row = self._row(
            """
            SELECT
              (SELECT COUNT(*) FROM dbo.ADMS_DEVICE)                                        AS devices,
              (SELECT COUNT(*) FROM dbo.ADMS_DEVICE WHERE Enabled = 1)                      AS enabled,
              (SELECT COUNT(*) FROM dbo.vw_APP_DeviceOverview WHERE DeviceState = 'Online')  AS online,
              (SELECT COUNT(*) FROM dbo.vw_APP_DeviceOverview WHERE DeviceState = 'Silent')  AS silent,
              (SELECT COUNT(*) FROM dbo.vw_APP_DeviceOverview WHERE DeviceState = 'Not linked') AS unlinked,
              (SELECT COUNT(*) FROM dbo.ADMS_ATTLOG_RAW
                WHERE ReceivedUtc > DATEADD(DAY, -1, SYSUTCDATETIME()))                      AS punches_24h,
              (SELECT COUNT(*) FROM dbo.ADMS_COMMAND WHERE Status = 'Pending')               AS pending_cmds,
              (SELECT COUNT(*) FROM dbo.vw_ADMS_StuckCommands)                               AS stuck_cmds,
              (SELECT COUNT(*) FROM dbo.vw_ADMS_UnprojectedPunches)                          AS unprojected,
              (SELECT COUNT(*) FROM dbo.vw_ADMS_NonNumericPins)                              AS bad_pins,
              (SELECT COUNT(*) FROM dbo.vw_ADMS_RosterSyncStatus)                            AS roster_devices,
              (SELECT COUNT(*) FROM dbo.vw_ADMS_RosterSyncStatus WHERE PinsOwed > 0)         AS roster_behind,
              (SELECT COUNT(*) FROM dbo.ADMS_DEVICE_ROSTER_VERSION WHERE IsDeleted = 1
                AND UpdatedUtc > DATEADD(DAY, -1, SYSUTCDATETIME()))                         AS deletions_24h
            """
        )
        keys = (
            "devices", "enabled", "online", "silent", "unlinked",
            "punches_24h", "pending_cmds", "stuck_cmds", "unprojected", "bad_pins",
            "roster_devices", "roster_behind", "deletions_24h",
        )
        return dict(zip(keys, [int(v or 0) for v in row], strict=True)) if row else dict.fromkeys(keys, 0)

    def recent_punches(self, limit: int = 100, serial: str | None = None) -> list[dict]:
        capped = max(1, min(limit, 500))
        if serial:
            rows = self._rows(
                """
                SELECT TOP (?) SerialNumber, Pin, PunchTime, Status, Verify, WorkCode, ReceivedUtc
                  FROM dbo.ADMS_ATTLOG_RAW WHERE SerialNumber = ? ORDER BY Id DESC
                """,
                (capped, serial),
            )
        else:
            rows = self._rows(
                """
                SELECT TOP (?) SerialNumber, Pin, PunchTime, Status, Verify, WorkCode, ReceivedUtc
                  FROM dbo.ADMS_ATTLOG_RAW ORDER BY Id DESC
                """,
                (capped,),
            )
        return [
            {
                "serial": r[0],
                "pin": r[1],
                "punch_time": _utc(r[2]),
                "status": int(r[3] or 0),
                "verify": int(r[4] if r[4] is not None else -1),
                "work_code": int(r[5] or 0),
                "received_utc": _utc(r[6]),
            }
            for r in rows
        ]

    def recent_uploads(self, limit: int = 100) -> list[dict]:
        rows = self._rows(
            """
            SELECT TOP (?) SerialNumber, TableName, RecordCount, LEN(Body) AS BodyLen, ReceivedUtc
              FROM dbo.ADMS_PUSH_LOG ORDER BY Id DESC
            """,
            (max(1, min(limit, 500)),),
        )
        return [
            {
                "serial": r[0],
                "table": r[1],
                "records": int(r[2] or 0),
                "body_len": int(r[3] or 0),
                "received_utc": _utc(r[4]),
            }
            for r in rows
        ]

    def unparsed(self, limit: int = 100) -> list[dict]:
        rows = self._rows(
            """
            SELECT TOP (?) SerialNumber, TableName, RawLine, ReceivedUtc
              FROM dbo.ADMS_UNPARSED ORDER BY Id DESC
            """,
            (max(1, min(limit, 500)),),
        )
        return [
            {"serial": r[0], "table": r[1], "line": r[2], "received_utc": _utc(r[3])} for r in rows
        ]
