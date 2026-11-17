"""
Authentication for the admin console: password hashing, sessions, CSRF.

Pure functions plus small value types. Nothing here touches the database or HTTP; the store lives in
:mod:`adms.admin.store` and the wiring in :mod:`adms.admin.app`. That separation is what lets the
security-critical arithmetic be exercised directly.

Choices, and why
----------------
**PBKDF2-HMAC-SHA256, 600,000 iterations, 32-byte per-user salt.** Copied from the desktop tool's
``APP_USER`` rather than reinvented, so an operator moving between the two systems meets one scheme.
Argon2id would be a stronger choice on merit, but it needs a compiled dependency, and this service's
entire dependency list is otherwise ``pyodbc`` plus ``waitress`` -- a deliberate property on a host
where a C toolchain may not exist. PBKDF2 at 600k iterations is in the same range as OWASP's current
guidance and is available in the standard library.

The iteration count is stored per user, so it can be raised later and existing hashes upgraded on next
sign-in instead of being invalidated.

**Session tokens are random, not signed.** 32 bytes from ``secrets``, and only the SHA-256 of the token
is stored. A signed stateless cookie would need no table, and was rejected because it cannot be
revoked: when someone leaves or a laptop goes missing, an administrator has to be able to end that
session immediately, and deleting a row does that. Storing the hash rather than the token means a
database backup does not hand over live sessions.

**CSRF uses a per-session secret**, not one global key, so a token lifted from one session cannot be
replayed against another.

**Constant-time comparison everywhere** a secret is checked, and the password hash is computed even for
usernames that do not exist -- otherwise the response time answers "is this a real account?" for free.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import secrets
from dataclasses import dataclass

__all__ = [
    "PBKDF2_ITERATIONS",
    "SALT_BYTES",
    "HASH_BYTES",
    "TOKEN_BYTES",
    "SESSION_IDLE_TIMEOUT",
    "SESSION_ABSOLUTE_TIMEOUT",
    "MAX_FAILED_ATTEMPTS",
    "LOCKOUT_DURATION",
    "Role",
    "Principal",
    "hash_password",
    "verify_password",
    "new_salt",
    "new_session_token",
    "token_hash",
    "new_csrf_secret",
    "csrf_token",
    "verify_csrf_token",
    "password_problems",
    "lockout_until",
]

#: Matches the desktop tool's APP_USER. Raise it in future by bumping this constant: existing users keep
#: working because each row stores the count it was hashed with, and is re-hashed on next sign-in.
PBKDF2_ITERATIONS = 600_000
#: 16 bytes (128 bits), because ``APP_USER.PasswordSalt`` is ``varbinary(16)``. Hashing is
#: salt-length-agnostic, so existing 16-byte hashes verify unchanged and new passwords fit the column.
SALT_BYTES = 16
HASH_BYTES = 32
TOKEN_BYTES = 32

#: Sliding window: a session dies this long after its last request.
SESSION_IDLE_TIMEOUT = dt.timedelta(hours=8)
#: Hard ceiling measured from creation, so staying active cannot keep one session alive indefinitely.
#: A stolen cookie is therefore useful for at most this long even if the thief keeps it warm.
SESSION_ABSOLUTE_TIMEOUT = dt.timedelta(days=7)

#: Failed sign-ins before the account is locked. Low enough to stop online guessing, high enough that
#: an ordinary typo does not summon an administrator.
MAX_FAILED_ATTEMPTS = 8
#: Lockout is a timestamp, not a flag, so it expires by itself. A permanent lock turns every
#: mistyped password into a support ticket, which pushes people towards weaker passwords.
LOCKOUT_DURATION = dt.timedelta(minutes=15)


class Role:
    """
    The three roles, and the permission checks that use them.

    Boundaries are drawn around blast radius rather than job title. The operator/admin split exists
    specifically because ``CLEAR DATA`` on a device is irreversible and erases the users and templates
    held on the hardware itself. Bringing a new device online does not require that, so the two are
    kept apart.
    """

    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"

    ALL = (VIEWER, OPERATOR, ADMIN)

    #: Ascending authority. Used only for the "at least this role" test; anything finer grained is
    #: expressed as an explicit capability below.
    _RANK = {VIEWER: 0, OPERATOR: 1, ADMIN: 2}

    @classmethod
    def is_valid(cls, role: str) -> bool:
        return role in cls._RANK

    @classmethod
    def at_least(cls, role: str, minimum: str) -> bool:
        return cls._RANK.get(role, -1) >= cls._RANK.get(minimum, 99)


@dataclass(frozen=True, slots=True)
class Principal:
    """The signed-in user, as the request handlers see them."""

    user_id: str
    username: str
    display_name: str
    role: str
    must_change_password: bool
    csrf_secret: bytes

    # ── Capabilities ─────────────────────────────────────────────────────────────────────
    # Named for what they permit rather than for a role, so a handler reads as a statement about the
    # action and a future fourth role does not mean editing every handler.

    @property
    def can_view(self) -> bool:
        return Role.is_valid(self.role)

    @property
    def can_operate(self) -> bool:
        """Enable, disable and link devices; queue non-destructive commands."""
        return Role.at_least(self.role, Role.OPERATOR)

    @property
    def can_administer(self) -> bool:
        """Manage console users, and end other people's sessions."""
        return self.role == Role.ADMIN

    @property
    def can_send_destructive_command(self) -> bool:
        """
        Queue a command that destroys data on the device (``CLEAR DATA``, ``CLEAR LOG``).

        Admin only, and separate from :attr:`can_operate` on purpose: these are the only actions the
        console can take whose effect is irreversible and happens outside this database.
        """
        return self.role == Role.ADMIN


# ── Passwords ────────────────────────────────────────────────────────────────────────────


def new_salt() -> bytes:
    return secrets.token_bytes(SALT_BYTES)


def hash_password(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """
    Derive the stored hash. NFC-normalised first so a password typed on a different keyboard layout,
    or pasted from a different editor, still matches -- Vietnamese input methods can produce either
    composed or decomposed forms for the same visible characters.
    """
    import unicodedata

    normalised = unicodedata.normalize("NFC", password).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", normalised, salt, iterations, dklen=HASH_BYTES)


def verify_password(password: str, salt: bytes, expected: bytes, iterations: int) -> bool:
    """
    Check a password in constant time with respect to the hash contents.

    ``compare_digest`` rather than ``==``: an early-exit comparison leaks how many leading bytes
    matched, which is enough to reconstruct a hash byte by byte given enough attempts.
    """
    return hmac.compare_digest(hash_password(password, salt, iterations), expected)


def password_problems(password: str, username: str = "") -> list[str]:
    """
    Return human-readable reasons a password is unacceptable; empty means acceptable.

    Length is the requirement that carries the weight, so the floor is 12 rather than 8, and there is
    deliberately no "must contain a symbol" rule -- composition rules push people towards
    ``Password1!`` and are worse than length alone. The rest of the checks are aimed at the specific
    failure modes seen in practice: reusing the username, and the handful of passwords that appear at
    the top of every breach corpus.
    """
    problems: list[str] = []

    if len(password) < 12:
        problems.append("Must be at least 12 characters.")
    if len(password) > 200:
        # Bounded because PBKDF2 cost is paid on the server: an unbounded password is a cheap way to
        # make someone else's CPU do 600,000 iterations over a megabyte.
        problems.append("Must be at most 200 characters.")
    if password.strip() != password:
        problems.append("Must not begin or end with a space.")
    if username and username.lower() in password.lower():
        problems.append("Must not contain the username.")

    common = {
        "password", "123456", "12345678", "qwerty", "111111", "123123",
        "admin", "administrator", "letmein", "welcome", "matkhau", "password123",
    }
    if password.lower() in common:
        problems.append("This password is too common.")

    return problems


def lockout_until(now: dt.datetime, failed_attempts: int) -> dt.datetime | None:
    """
    When the account should stay locked until, or ``None`` if it should not be locked.

    Called with the count *after* the failure was recorded.
    """
    if failed_attempts < MAX_FAILED_ATTEMPTS:
        return None
    return now + LOCKOUT_DURATION


# ── Sessions ─────────────────────────────────────────────────────────────────────────────


def new_session_token() -> str:
    """
    A fresh session token for the cookie. URL-safe base64 of 32 random bytes.

    ``secrets``, not ``random``: the latter is a Mersenne Twister seeded predictably enough that
    observing a few outputs reveals the rest.
    """
    return secrets.token_urlsafe(TOKEN_BYTES)


def token_hash(token: str) -> bytes:
    """
    What actually gets stored. Plain SHA-256 with no salt, deliberately: the token is 32 bytes of
    entropy, so there is nothing to brute-force and a per-row salt would only prevent the indexed
    lookup this is on the hot path for.
    """
    return hashlib.sha256(token.encode("utf-8")).digest()


def new_csrf_secret() -> bytes:
    return secrets.token_bytes(32)


def csrf_token(secret: bytes) -> str:
    """
    Mint a CSRF token from the session's secret.

    ``<random>.<hmac>``: the random half makes each token unique so it can be embedded in several
    forms on one page without becoming a fingerprint, and the HMAC half is what proves it came from
    this session. Verification needs no server-side state beyond the secret already loaded with the
    session.
    """
    nonce = secrets.token_urlsafe(16)
    mac = hmac.new(secret, nonce.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{nonce}.{mac}"


def verify_csrf_token(secret: bytes, token: str) -> bool:
    """Check a CSRF token against the session secret, in constant time."""
    if not token or "." not in token:
        return False
    nonce, _, mac = token.partition(".")
    if not nonce or not mac:
        return False
    expected = hmac.new(secret, nonce.encode("ascii"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, mac)


def session_deadlines(now: dt.datetime) -> tuple[dt.datetime, dt.datetime]:
    """``(expires_utc, absolute_deadline)`` for a session created now."""
    return now + SESSION_IDLE_TIMEOUT, now + SESSION_ABSOLUTE_TIMEOUT


def is_session_live(
    now: dt.datetime, created_utc: dt.datetime, expires_utc: dt.datetime
) -> bool:
    """
    Both deadlines must hold: the sliding idle window AND the absolute ceiling measured from creation.

    The absolute check is what stops a stolen cookie being renewed indefinitely by a script that just
    keeps requesting a page.
    """
    if now >= expires_utc:
        return False
    return now < created_utc + SESSION_ABSOLUTE_TIMEOUT
