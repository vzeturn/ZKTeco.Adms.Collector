"""
Configuration.

Everything is an environment variable except the one thing that must not be handed to this process as
plain configuration text: the SQL connection string.

Two hosting models, two secure sources -- ``resolve_connection_string`` does not know or care which:

* **On-premises IIS.** The string is DPAPI-encrypted in the registry (:mod:`adms.dbconfig`), because an
  environment variable set in ``web.config`` is a plaintext file sitting in the site folder that a
  redeploy overwrites and a backup copies. The desktop pull tool takes the same stance with HKCU.
* **Containers.** The string arrives via ``ADMS_SQL_CONNECTION``, injected by the orchestrator from
  its secret store into the container's environment at launch, rather than being baked into the
  image or a plain configuration file. That is the container-native equivalent of the DPAPI blob.

Either way the rule is the same: the connection string never appears in source, in a log line, or in an
exception message. ``ADMS_SQL_CONNECTION`` is documented as a "development escape hatch" below only in
the sense that setting it *by hand* in a shell is a development habit -- letting an orchestrator's
secret injection populate the same variable is the normal path for that hosting model, not a workaround.
"""

from __future__ import annotations

import datetime as dt
import json
import os
from dataclasses import dataclass, field

from .errors import ConfigError
from .protocol.handshake import DEFAULT_TRANS_FLAG

__all__ = ["Settings", "load_settings", "resolve_connection_string", "reset_cache"]


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _env_int(name: str, default: int) -> int:
    raw = _env(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc


def _env_fraction(name: str, default: float) -> float:
    """A float in [0, 1] -- a sample rate. Out of range is a deployment mistake, so it fails fast."""
    raw = _env(name)
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number between 0 and 1, got {raw!r}") from exc
    if not 0.0 <= value <= 1.0:
        raise ConfigError(f"{name} must be between 0 and 1, got {raw!r}")
    return value


def _env_int_tuple(name: str) -> tuple[int, ...]:
    """
    Parse a comma-separated list of integers. Blank (unset) returns an empty tuple, which is the
    "fully disabled" state ``roster_sync_delete_opcodes`` relies on -- a caller checks
    ``if settings.roster_sync_delete_opcodes:`` rather than needing a separate enabled flag.

    A malformed entry raises, the same as every other typed setting here: a typo'd OpCode is a
    deployment mistake worth failing fast on, not one to silently drop and run with fewer
    OpCodes recognised than the operator intended.
    """
    raw = _env(name)
    if not raw:
        return ()
    try:
        return tuple(int(part.strip()) for part in raw.split(",") if part.strip())
    except ValueError as exc:
        raise ConfigError(f"{name} must be a comma-separated list of integers, got {raw!r}") from exc


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name).lower()
    if not raw:
        return default
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"{name} must be a boolean, got {raw!r}")


@dataclass(frozen=True, slots=True)
class Settings:
    """Resolved configuration for one worker process."""

    # ── Database ──────────────────────────────────────────────────────────────────────────
    #: Registry sub-key holding the DPAPI-protected connection string. Overridable so a test can
    #: point at an isolated key instead of the real configuration.
    registry_subkey: str = r"SOFTWARE\AdmsCollector\AttendanceDb"
    #: Local-development only. When set it wins over the registry, which is why the deployment
    #: instructions never mention it.
    sql_connection: str = ""
    odbc_driver: str = "ODBC Driver 18 for SQL Server"
    sql_login_timeout: int = 10
    sql_query_timeout: int = 25
    #: Skip TLS certificate validation. Default False, so the certificate IS validated. The target is
    #: an Amazon RDS instance presenting an RDS CA certificate whose root is not in the Windows store
    #: by default -- run ``deploy/import-rds-ca.ps1`` once. Only enable this for a server with a
    #: self-signed certificate; it leaves the connection encrypted but unauthenticated.
    trust_server_certificate: bool = False

    # ── Authorisation ─────────────────────────────────────────────────────────────────────
    #: Optional secret URL segment the device must carry (configure the device path as
    #: ``/<secret>/iclock``). Weak by nature -- it travels in plaintext HTTP and lands in the IIS
    #: access log -- but it is the only credential-shaped field the protocol has room for.
    path_secret: str = ""
    #: When true, an unknown serial is recorded as a *disabled* row so an operator can see and link
    #: it. Never grants access. Reasonable to leave on for a site-local, device-only network segment;
    #: leave off if the site is reachable more broadly.
    auto_register_devices: bool = False

    # ── Behaviour ─────────────────────────────────────────────────────────────────────────
    archive_raw_bodies: bool = True
    #: Cap on raw body text archived per request. Photo and template uploads reach megabytes; past a
    #: point the archive costs more than it explains.
    archive_body_limit: int = 64_000
    max_commands_per_poll: int = 10
    #: Site offset from UTC, used for local wall-clock timestamps in audit fields. On an on-premises
    #: Windows host the machine clock is normally already site-local, but this stays explicit so the
    #: value does not silently change if the server is ever moved or re-imaged in another zone.
    utc_offset_hours: int = 7

    # ── Auto-enrolment ────────────────────────────────────────────────────────────────────
    #: When a punch arrives from a PIN with no NHANVIEN row, queue a request to the device for that
    #: user's record (and fingerprints), so the roster fills itself from what the devices already know.
    #: On by default: an unattributable punch is a problem that fixes itself far more reliably than it
    #: gets noticed.
    enroll_query_enabled: bool = True
    #: Also ask for fingerprint templates, not just the user record. This is what makes dbo.TEMPLATE
    #: recoverable without re-enrolling anyone -- the hardware holds the enrolment data and can be asked
    #: again. Costs one extra command and one extra upload per new person.
    enroll_query_include_fingerprints: bool = True
    #: How long before the same device is asked about the same PIN again. Counts commands in any
    #: status, so a device that cannot answer is not asked forever.
    enroll_query_cooldown: dt.timedelta = dt.timedelta(hours=6)
    #: Cap per ATTLOG batch. A device back from a long outage can carry hundreds of unknown PINs;
    #: queuing all of them at once would swamp its command channel. The remainder is picked up on later
    #: batches.
    enroll_query_max_per_batch: int = 25
    #: Overrides the DATA QUERY wording for the user-record enrolment request. Blank means the default,
    #: 'DATA QUERY USERINFO PIN={pin}'. This exists because the accepted table token differs across
    #: firmware builds and this is the one part of the enrolment path not verified against hardware --
    #: so a site must be able to correct it by configuration rather than by a code change. The symptom
    #: that sends an operator here is a negative ADMS_COMMAND.ReturnCode after the first attempt: the
    #: device rejected the wording, not the PIN. Free text on purpose -- validating against a whitelist
    #: would assume we know what a given build accepts, which is exactly what we do not know.
    query_userinfo_command: str = ""
    #: Same, for the fingerprint request. Blank means 'DATA QUERY FINGERTMP PIN={pin}'.
    query_fingertmp_command: str = ""

    # ── Handshake ─────────────────────────────────────────────────────────────────────────
    # ── Roster sync (multi-device-employee-sync) ─────────────────────────────────────────────
    #: Default off: with this false, AdmsService.roster_sync is None (see composition.py) and no
    #: request path calls a Roster_Sync method at all -- the feature costs nothing beyond an idle
    #: `if` when off, matching enroll_query_enabled's own contract.
    roster_sync_enabled: bool = False
    #: The most Push_Commands enqueued for one target device in one triggering request (Fan_Out)
    #: or one triggering contact (Backfill). Same rationale as enroll_query_max_per_batch: a
    #: device returning from a long outage, or a first Backfill, must not be handed an unbounded
    #: burst of commands.
    roster_sync_max_commands_per_cycle: int = 25
    #: How long a device in a Sync_Group may go without contact before its next contact triggers
    #: a Backfill rather than relying on Fan_Out alone to have kept it current.
    roster_sync_backfill_silence_hours: int = 24
    #: Face template propagation (`DATA UPDATE BIODATA`) is NOT verified against real firmware --
    #: no face template has been used to test it. Off by default; flipping it
    #: once verified requires no other code change.
    roster_sync_push_faces: bool = False
    #: Master switch for delete fan-out (both triggers below). Off by default, matching
    #: roster_sync_enabled's own posture: the feature costs nothing beyond an idle `if` when off.
    roster_sync_fanout_deletes: bool = False
    #: DB-side delete detection: comma-separated list of PINs is never configured here -- this is
    #: a behaviour switch, not data. When true and roster_sync_fanout_deletes is true, each
    #: request's Backfill/reconcile pass also checks whether any PIN this Sync_Group previously
    #: pushed has since lost its NHANVIEN row, and fans out a delete for it. Safe to enable by
    #: default alongside roster_sync_fanout_deletes: it reads ADMS_DEVICE_ROSTER_VERSION and
    #: NHANVIEN only, both already-owned/locked tables this service already reads elsewhere, and a
    #: PIN genuinely deleted from NHANVIEN can only mean an operator or the desktop app removed it
    #: intentionally.
    roster_sync_reconcile_deletes: bool = True
    #: Device-side OPLOG delete detection: which numeric OPLOG OpCode(s) mean "this user was
    #: deleted on the device", comma-separated (e.g. "5" or "5,9"). Empty (the default) means this
    #: trigger is fully disabled regardless of roster_sync_fanout_deletes -- unlike the DB-side
    #: trigger, the OpCode-to-"delete" mapping for this vendor's OPLOG grammar has not been
    #: confirmed against a device (no captured ADMS_OPERLOG row for an on-device delete
    #: at the time this was written). Guessing a value here is not a safe default: an incorrect
    #: OpCode could fan out a delete nothing asked for, wiping biometrics on every other device in
    #: the group, and that is not reversible. Populate this only after triggering a real delete on
    #: one device, reading its OpCode back from ADMS_OPERLOG, and confirming it there.
    roster_sync_delete_opcodes: tuple[int, ...] = ()

    server_version: str = "2.4.1"
    #: ``getrequest`` poll interval in seconds -- also the worst-case latency of a queued command.
    #: No longer a cost lever now that this is self-hosted, so it can stay short.
    poll_delay: int = 10
    #: How long the device waits after a non-2xx reply before retrying. The backstop that keeps
    #: unacknowledged punches on the device during an outage.
    error_delay: int = 30
    trans_times: str = "00:00;14:00"
    trans_interval: int = 1
    trans_flag: str = DEFAULT_TRANS_FLAG
    realtime: bool = True
    log_level: str = "INFO"
    #: Directory for the rolling log file. Empty means log to stdout only, which is what
    #: AspNetCoreModuleV2 captures into its own stdout log.
    log_dir: str = ""

    # ── Error reporting (Sentry) ──────────────────────────────────────────────────────────
    #: Sentry DSN. Empty (the default) means error reporting is off and sentry_sdk is never
    #: imported. A DSN only lets a client *submit* events to one project, so it is configuration,
    #: not a credential -- but it still comes from the host's configuration, never from source.
    sentry_dsn: str = ""
    sentry_environment: str = "production"
    #: Share of requests traced for performance. Kept small: the free plan's quota is the limit,
    #: and a device fleet polling every few seconds would spend it in hours at 1.0.
    sentry_traces_sample_rate: float = 0.02
    extra_options: dict[str, str] = field(default_factory=dict)


def load_settings() -> Settings:
    """Build :class:`Settings` from the environment."""
    extra_raw = _env("ADMS_EXTRA_OPTIONS")
    extra: dict[str, str] = {}
    if extra_raw:
        try:
            parsed = json.loads(extra_raw)
        except json.JSONDecodeError as exc:
            raise ConfigError("ADMS_EXTRA_OPTIONS must be a JSON object.") from exc
        if not isinstance(parsed, dict):
            raise ConfigError("ADMS_EXTRA_OPTIONS must be a JSON object.")
        extra = {str(k): str(v) for k, v in parsed.items()}

    return Settings(
        registry_subkey=_env("ADMS_REGISTRY_SUBKEY", r"SOFTWARE\AdmsCollector\AttendanceDb"),
        sql_connection=_env("ADMS_SQL_CONNECTION"),
        odbc_driver=_env("ADMS_ODBC_DRIVER", "ODBC Driver 18 for SQL Server"),
        sql_login_timeout=_env_int("ADMS_SQL_LOGIN_TIMEOUT", 10),
        sql_query_timeout=_env_int("ADMS_SQL_QUERY_TIMEOUT", 25),
        trust_server_certificate=_env_bool("ADMS_SQL_TRUST_SERVER_CERT", False),
        path_secret=_env("ADMS_PATH_SECRET"),
        auto_register_devices=_env_bool("ADMS_AUTO_REGISTER_DEVICES", False),
        archive_raw_bodies=_env_bool("ADMS_ARCHIVE_RAW_BODIES", True),
        archive_body_limit=_env_int("ADMS_ARCHIVE_BODY_LIMIT", 64_000),
        max_commands_per_poll=_env_int("ADMS_MAX_COMMANDS_PER_POLL", 10),
        utc_offset_hours=_env_int("ADMS_UTC_OFFSET_HOURS", 7),
        enroll_query_enabled=_env_bool("ADMS_ENROLL_QUERY_ENABLED", True),
        enroll_query_include_fingerprints=_env_bool("ADMS_ENROLL_QUERY_FINGERPRINTS", True),
        enroll_query_cooldown=dt.timedelta(hours=_env_int("ADMS_ENROLL_QUERY_COOLDOWN_HOURS", 6)),
        enroll_query_max_per_batch=_env_int("ADMS_ENROLL_QUERY_MAX_PER_BATCH", 25),
        query_userinfo_command=_env("ADMS_QUERY_USERINFO_COMMAND"),
        query_fingertmp_command=_env("ADMS_QUERY_FINGERTMP_COMMAND"),
        roster_sync_enabled=_env_bool("ADMS_ROSTER_SYNC_ENABLED", False),
        roster_sync_max_commands_per_cycle=_env_int("ADMS_ROSTER_SYNC_MAX_COMMANDS_PER_CYCLE", 25),
        roster_sync_backfill_silence_hours=_env_int("ADMS_ROSTER_SYNC_BACKFILL_SILENCE_HOURS", 24),
        roster_sync_push_faces=_env_bool("ADMS_ROSTER_SYNC_PUSH_FACES", False),
        roster_sync_fanout_deletes=_env_bool("ADMS_ROSTER_SYNC_FANOUT_DELETES", False),
        roster_sync_reconcile_deletes=_env_bool("ADMS_ROSTER_SYNC_RECONCILE_DELETES", True),
        roster_sync_delete_opcodes=_env_int_tuple("ADMS_ROSTER_SYNC_DELETE_OPCODES"),
        server_version=_env("ADMS_SERVER_VERSION", "2.4.1"),
        poll_delay=_env_int("ADMS_POLL_DELAY", 10),
        error_delay=_env_int("ADMS_ERROR_DELAY", 30),
        trans_times=_env("ADMS_TRANS_TIMES", "00:00;14:00"),
        trans_interval=_env_int("ADMS_TRANS_INTERVAL", 1),
        trans_flag=_env("ADMS_TRANS_FLAG", DEFAULT_TRANS_FLAG),
        realtime=_env_bool("ADMS_REALTIME", True),
        log_level=_env("ADMS_LOG_LEVEL", "INFO").upper(),
        log_dir=_env("ADMS_LOG_DIR"),
        sentry_dsn=_env("ADMS_SENTRY_DSN"),
        sentry_environment=_env("ADMS_SENTRY_ENVIRONMENT", "production"),
        sentry_traces_sample_rate=_env_fraction("ADMS_SENTRY_TRACES_SAMPLE_RATE", 0.02),
        extra_options=extra,
    )


#: Cached per worker process. Reading the registry and decrypting is cheap, but it is pointless work
#: on every request, and caching keeps the plaintext in exactly one place.
_connection_string: str | None = None


def resolve_connection_string(settings: Settings) -> str:
    """
    Return the ODBC connection string.

    Order: ``ADMS_SQL_CONNECTION`` first, then the DPAPI-protected registry value.

    ``ADMS_SQL_CONNECTION`` is not read from disk here -- it is whatever the process environment
    already holds by the time this runs, regardless of how it got there. In a container that is a
    secret injected by the orchestrator before the container's entrypoint starts; on a developer's laptop it is a value exported by hand. This function cannot
    tell the two apart, and does not need to: both are "the environment already has it", which is why
    the registry fallback below only ever runs on the on-premises IIS hosting model, where
    ``ADMS_SQL_CONNECTION`` is never set.

    Raises :class:`~adms.errors.ConfigError` if neither is present. The message names the registry key
    and the script that writes it, and never any part of the value itself. On a host with no registry
    at all (Linux containers), that fallback simply is not importable -- see the ``ImportError`` guard below --
    so a missing ``ADMS_SQL_CONNECTION`` there fails with a clearer, platform-appropriate message
    instead of an unrelated ``winreg`` import error.
    """
    global _connection_string
    if _connection_string:
        return _connection_string

    if settings.sql_connection:
        _connection_string = settings.sql_connection
        return _connection_string

    try:
        from .dbconfig import DbConnectionStore
    except ImportError as exc:
        # dbconfig imports winreg, which does not exist off Windows. Reaching this branch on a
        # container host means ADMS_SQL_CONNECTION was not set -- almost always a missing
        # secret or environment entry -- so say that rather than surfacing a confusing
        # "No module named 'winreg'" from a platform this deployment was never going to run the
        # registry fallback on anyway.
        raise ConfigError(
            "No database configuration. ADMS_SQL_CONNECTION is not set, and the DPAPI/registry "
            "fallback is only available on Windows. In a container, inject "
            "ADMS_SQL_CONNECTION from your orchestrator's secret store."
        ) from exc

    stored = DbConnectionStore(settings.registry_subkey).load()
    if not stored:
        raise ConfigError(
            f"No database configuration. Expected a DPAPI-protected connection string in "
            f"HKLM\\{settings.registry_subkey}\\ConnectionString -- run "
            "deploy/set-db-connection.ps1 on this host."
        )

    _connection_string = stored
    return _connection_string


def reset_cache() -> None:
    """Drop the cached connection string. For tests, and after rotating the stored credential."""
    global _connection_string
    _connection_string = None


def build_connection_string(
    *,
    host: str,
    database: str,
    username: str,
    password: str,
    port: str = "1433",
    settings: Settings | None = None,
) -> str:
    """
    Assemble an ODBC connection string from parts.

    Used by ``deploy/set-db-connection.ps1`` so an operator supplies fields rather than hand-writing a
    DSN and getting a subtle option wrong.

    ``host`` should be a DNS name, not an IP: a database server can be reachable both
    publicly and privately, and a hostname lets DNS decide which. Pinning an IP freezes that choice.

    ``Encrypt=yes`` is set unconditionally. A server may accept unencrypted sessions (for example RDS
    with ``rds.force_ssl = 0``), meaning the client is the only thing that can insist, and this
    connection may cross the internet.
    """
    resolved = settings or Settings()
    trust = "yes" if resolved.trust_server_certificate else "no"
    return (
        f"DRIVER={{{resolved.odbc_driver}}};"
        f"SERVER={host},{port};"
        f"DATABASE={database};"
        f"UID={username};"
        f"PWD={password};"
        f"Encrypt=yes;TrustServerCertificate={trust};"
        f"Connection Timeout={resolved.sql_login_timeout};"
    )
