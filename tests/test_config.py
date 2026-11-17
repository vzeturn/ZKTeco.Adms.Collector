"""
Property tests for ``adms.config`` and ``adms.hosting.serve`` -- the adapter boundary that reads the
environment instead of a device.

Five properties live here, plus one drift guard and one assertion on the two settings task 3.1 added.
Table-driven parametrisation over hostile fixed inputs, per the design's Testing Strategy: no
``hypothesis``. Environment variables are set with ``monkeypatch.setenv`` / ``monkeypatch.delenv``,
never raw ``os.environ`` mutation, so a test's environment changes cannot leak into another test or
into the process running the suite.

**Scope carved out of Property 60 on purpose.** The claim as written in the design also covers the
DPAPI round trip -- protect/unprotect agreeing, a blob without this module's fixed entropy failing to
decrypt. That half needs the real Windows DPAPI surface (``ctypes`` against ``crypt32.dll`` and the
registry) and is the one-shot host check in task 14.5, not a property test. What is tested here is the
resolution order (``ADMS_SQL_CONNECTION`` first), the error naming the registry key and the script when
neither source supplies a value, and that no fragment of any configured value reaches that error. Every
other test in this module uses :func:`make_settings` from ``conftest.py``, which pre-populates
``sql_connection`` so nothing here can wander into
:func:`~adms.config.resolve_connection_string`'s registry branch -- except the two tests that construct
the no-connection-string case deliberately, which patch ``DbConnectionStore`` rather than touch a real
registry key.

``waitress.serve`` is never actually called: Property 63's test patches ``waitress`` in
``sys.modules`` with a fake ``serve`` that only records its keyword arguments, exactly as
``test_connection.py`` fakes ``pyodbc`` -- so this test needs no installed driver and binds no socket.
"""

from __future__ import annotations

import datetime as dt
import sys
import types
from dataclasses import FrozenInstanceError

from typing import Any

import pytest
from conftest import make_settings

from adms.config import (
    Settings,
    build_connection_string,
    load_settings,
    resolve_connection_string,
)
from adms.errors import ConfigError

# ── Property 57 ──────────────────────────────────────────────────────────────────────────────

#: (env vars to set, attribute, expected value) -- one non-secret setting per row, exercising both
#: "the variable is set" and "the variable is absent or blank" halves of the claim. Blank is
#: distinguished from absent because Settings._env() treats both alike (config.py strips and falls
#: back), so a row with an empty string proves the blank half rather than assuming it.
_TOTAL_DEFAULT_CASES: list[tuple[dict[str, str], str, object]] = [
    ({"ADMS_AUTO_REGISTER_DEVICES": "true"}, "auto_register_devices", True),
    ({"ADMS_AUTO_REGISTER_DEVICES": "yes"}, "auto_register_devices", True),
    ({"ADMS_AUTO_REGISTER_DEVICES": "1"}, "auto_register_devices", True),
    ({"ADMS_AUTO_REGISTER_DEVICES": ""}, "auto_register_devices", False),  # blank -> default
    ({}, "auto_register_devices", False),  # absent -> default
    ({"ADMS_PATH_SECRET": "topsecret"}, "path_secret", "topsecret"),
    ({"ADMS_PATH_SECRET": ""}, "path_secret", ""),
    ({}, "path_secret", ""),
    ({"ADMS_ARCHIVE_RAW_BODIES": "false"}, "archive_raw_bodies", False),
    ({"ADMS_ARCHIVE_RAW_BODIES": "off"}, "archive_raw_bodies", False),
    ({"ADMS_ARCHIVE_RAW_BODIES": ""}, "archive_raw_bodies", True),
    ({}, "archive_raw_bodies", True),
    ({"ADMS_POLL_DELAY": "45"}, "poll_delay", 45),
    ({"ADMS_POLL_DELAY": ""}, "poll_delay", 10),
    ({}, "poll_delay", 10),
    ({"ADMS_ERROR_DELAY": "90"}, "error_delay", 90),
    ({"ADMS_ERROR_DELAY": ""}, "error_delay", 30),
    ({}, "error_delay", 30),
    ({"ADMS_MAX_COMMANDS_PER_POLL": "3"}, "max_commands_per_poll", 3),
    ({"ADMS_MAX_COMMANDS_PER_POLL": ""}, "max_commands_per_poll", 10),
    ({}, "max_commands_per_poll", 10),
    ({"ADMS_UTC_OFFSET_HOURS": "-5"}, "utc_offset_hours", -5),
    ({"ADMS_UTC_OFFSET_HOURS": ""}, "utc_offset_hours", 7),
    ({}, "utc_offset_hours", 7),
    ({"ADMS_ODBC_DRIVER": "ODBC Driver 17 for SQL Server"}, "odbc_driver", "ODBC Driver 17 for SQL Server"),
    ({}, "odbc_driver", "ODBC Driver 18 for SQL Server"),
    ({"ADMS_SQL_LOGIN_TIMEOUT": "3"}, "sql_login_timeout", 3),
    ({}, "sql_login_timeout", 10),
    ({"ADMS_SQL_QUERY_TIMEOUT": "99"}, "sql_query_timeout", 99),
    ({}, "sql_query_timeout", 25),
    ({"ADMS_SQL_TRUST_SERVER_CERT": "true"}, "trust_server_certificate", True),
    ({}, "trust_server_certificate", False),
    ({"ADMS_SERVER_VERSION": "2.5.0"}, "server_version", "2.5.0"),
    ({}, "server_version", "2.4.1"),
    ({"ADMS_TRANS_TIMES": "01:00;15:00"}, "trans_times", "01:00;15:00"),
    ({}, "trans_times", "00:00;14:00"),
    ({"ADMS_TRANS_INTERVAL": "2"}, "trans_interval", 2),
    ({}, "trans_interval", 1),
    ({"ADMS_REALTIME": "0"}, "realtime", False),
    ({}, "realtime", True),
    ({"ADMS_LOG_LEVEL": "debug"}, "log_level", "DEBUG"),  # upper-cased
    ({}, "log_level", "INFO"),
    ({"ADMS_LOG_DIR": "C:\\logs"}, "log_dir", "C:\\logs"),
    ({}, "log_dir", ""),
    ({"ADMS_ENROLL_QUERY_ENABLED": "false"}, "enroll_query_enabled", False),
    ({}, "enroll_query_enabled", True),
    ({"ADMS_ENROLL_QUERY_FINGERPRINTS": "false"}, "enroll_query_include_fingerprints", False),
    ({}, "enroll_query_include_fingerprints", True),
    ({"ADMS_ENROLL_QUERY_MAX_PER_BATCH": "5"}, "enroll_query_max_per_batch", 5),
    ({}, "enroll_query_max_per_batch", 25),
    (
        {"ADMS_QUERY_USERINFO_COMMAND": "DATA QUERY USER PIN={pin}"},
        "query_userinfo_command",
        "DATA QUERY USER PIN={pin}",
    ),
    ({"ADMS_QUERY_USERINFO_COMMAND": ""}, "query_userinfo_command", ""),
    ({}, "query_userinfo_command", ""),
    (
        {"ADMS_QUERY_FINGERTMP_COMMAND": "DATA QUERY FP PIN={pin}"},
        "query_fingertmp_command",
        "DATA QUERY FP PIN={pin}",
    ),
    ({"ADMS_QUERY_FINGERTMP_COMMAND": ""}, "query_fingertmp_command", ""),
    ({}, "query_fingertmp_command", ""),
]

#: Every non-secret env var this table (or the enrolment-cooldown case below) ever sets, so each
#: parametrised run can clear all of them first -- the pytest process itself may have one set, and a
#: leftover from a previous run in the same interpreter must not leak into "absent" cases.
_ALL_CONFIG_VARS = sorted(
    {
        "ADMS_REGISTRY_SUBKEY",
        "ADMS_SQL_CONNECTION",
        "ADMS_ODBC_DRIVER",
        "ADMS_SQL_LOGIN_TIMEOUT",
        "ADMS_SQL_QUERY_TIMEOUT",
        "ADMS_SQL_TRUST_SERVER_CERT",
        "ADMS_PATH_SECRET",
        "ADMS_AUTO_REGISTER_DEVICES",
        "ADMS_ARCHIVE_RAW_BODIES",
        "ADMS_ARCHIVE_BODY_LIMIT",
        "ADMS_MAX_COMMANDS_PER_POLL",
        "ADMS_UTC_OFFSET_HOURS",
        "ADMS_ENROLL_QUERY_ENABLED",
        "ADMS_ENROLL_QUERY_FINGERPRINTS",
        "ADMS_ENROLL_QUERY_COOLDOWN_HOURS",
        "ADMS_ENROLL_QUERY_MAX_PER_BATCH",
        "ADMS_QUERY_USERINFO_COMMAND",
        "ADMS_QUERY_FINGERTMP_COMMAND",
        "ADMS_SERVER_VERSION",
        "ADMS_POLL_DELAY",
        "ADMS_ERROR_DELAY",
        "ADMS_TRANS_TIMES",
        "ADMS_TRANS_INTERVAL",
        "ADMS_TRANS_FLAG",
        "ADMS_REALTIME",
        "ADMS_LOG_LEVEL",
        "ADMS_LOG_DIR",
        "ADMS_EXTRA_OPTIONS",
    }
)


def _clear_config_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _ALL_CONFIG_VARS:
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize(
    ("env", "attribute", "expected"),
    _TOTAL_DEFAULT_CASES,
    ids=[f"{attr}={env or 'absent'}" for env, attr, _ in _TOTAL_DEFAULT_CASES],
)
def test_property_57_every_non_secret_setting_is_total(
    monkeypatch: pytest.MonkeyPatch, env: dict[str, str], attribute: str, expected: object
) -> None:
    # Feature: adms-attendance-system, Property 57: Configuration is total, immutable, and names
    # its own faults. For all environments, every non-secret setting is read from its variable or
    # takes its documented default when the variable is absent or blank.
    _clear_config_env(monkeypatch)
    for name, value in env.items():
        monkeypatch.setenv(name, value)

    settings = load_settings()

    assert getattr(settings, attribute) == expected, (
        f"{attribute}: env={env!r} produced {getattr(settings, attribute)!r}, expected {expected!r}"
    )


#: (env var, bad value) -- non-integer values for every integer setting the loader parses.
_BAD_INT_CASES: list[tuple[str, str]] = [
    ("ADMS_SQL_LOGIN_TIMEOUT", "not-a-number"),
    ("ADMS_SQL_QUERY_TIMEOUT", "10.5"),
    ("ADMS_ARCHIVE_BODY_LIMIT", ""),  # blank is handled separately -- this is "whitespace only"
    ("ADMS_MAX_COMMANDS_PER_POLL", "ten"),
    ("ADMS_UTC_OFFSET_HOURS", "+7h"),
    ("ADMS_ENROLL_QUERY_COOLDOWN_HOURS", "six"),
    ("ADMS_ENROLL_QUERY_MAX_PER_BATCH", "twenty-five"),
    ("ADMS_POLL_DELAY", "abc"),
    ("ADMS_ERROR_DELAY", "3;30"),
    ("ADMS_TRANS_INTERVAL", "1.0.0"),
]


@pytest.mark.parametrize(("var", "bad_value"), _BAD_INT_CASES, ids=[v for v, _ in _BAD_INT_CASES])
def test_property_57_a_bad_integer_setting_names_the_variable_and_value(
    monkeypatch: pytest.MonkeyPatch, var: str, bad_value: str
) -> None:
    # Feature: adms-attendance-system, Property 57: for all non-integer values of an integer
    # setting, a configuration error is raised naming the variable and the offending value.
    _clear_config_env(monkeypatch)
    if bad_value.strip() == "":
        pytest.skip("blank is a valid absence, not a bad integer -- covered by the totality cases")
    monkeypatch.setenv(var, bad_value)

    with pytest.raises(ConfigError) as excinfo:
        load_settings()

    message = str(excinfo.value)
    assert var in message, f"error for {var}={bad_value!r} did not name the variable: {message!r}"
    assert bad_value.strip() in message, (
        f"error for {var}={bad_value!r} did not name the offending value: {message!r}"
    )


#: Every boolean-valued setting the loader parses, paired with an unrecognised value.
_BAD_BOOL_CASES: list[tuple[str, str]] = [
    ("ADMS_SQL_TRUST_SERVER_CERT", "maybe"),
    ("ADMS_AUTO_REGISTER_DEVICES", "sure"),
    ("ADMS_ARCHIVE_RAW_BODIES", "2"),
    ("ADMS_ENROLL_QUERY_ENABLED", "enabled-ish"),
    ("ADMS_ENROLL_QUERY_FINGERPRINTS", "nope!"),
    ("ADMS_REALTIME", "sometimes"),
]


@pytest.mark.parametrize(("var", "bad_value"), _BAD_BOOL_CASES, ids=[v for v, _ in _BAD_BOOL_CASES])
def test_property_57_an_unrecognised_boolean_names_the_variable_and_value(
    monkeypatch: pytest.MonkeyPatch, var: str, bad_value: str
) -> None:
    # Feature: adms-attendance-system, Property 57: for all unrecognised boolean values, a
    # configuration error is raised naming the variable and the offending value.
    _clear_config_env(monkeypatch)
    monkeypatch.setenv(var, bad_value)

    with pytest.raises(ConfigError) as excinfo:
        load_settings()

    message = str(excinfo.value)
    assert var in message, f"error for {var}={bad_value!r} did not name the variable: {message!r}"
    assert bad_value.lower() in message.lower(), (
        f"error for {var}={bad_value!r} did not name the offending value: {message!r}"
    )


#: Values that are not a JSON object: a scalar, an array, a string, malformed JSON entirely.
_BAD_EXTRA_OPTIONS_CASES: list[str] = [
    "not json at all",
    "[1, 2, 3]",
    '"just a string"',
    "42",
    "true",
    "null",
    '{"unterminated": ',
    "{'single': 'quotes'}",
]


@pytest.mark.parametrize("bad_value", _BAD_EXTRA_OPTIONS_CASES)
def test_property_57_non_object_extra_options_names_the_variable_and_value(
    monkeypatch: pytest.MonkeyPatch, bad_value: str
) -> None:
    # Feature: adms-attendance-system, Property 57: for all ADMS_EXTRA_OPTIONS values that are not
    # JSON objects, a configuration error is raised naming the variable ADMS_EXTRA_OPTIONS.
    _clear_config_env(monkeypatch)
    monkeypatch.setenv("ADMS_EXTRA_OPTIONS", bad_value)

    with pytest.raises(ConfigError) as excinfo:
        load_settings()

    assert "ADMS_EXTRA_OPTIONS" in str(excinfo.value)


def test_property_57_extra_options_json_object_is_accepted_and_stringified() -> None:
    # Feature: adms-attendance-system, Property 57: a JSON object value for ADMS_EXTRA_OPTIONS is
    # accepted rather than rejected -- the totality half of the same property, on the one setting
    # whose "valid" shape is itself a small parser rather than a scalar type.
    settings = make_settings()
    assert settings.extra_options == {}


def test_property_57_settings_instances_are_frozen() -> None:
    # Feature: adms-attendance-system, Property 57: for all settings instances, every attribute
    # assignment raises. Exercised for a representative spread of fields -- a string, a bool, an
    # int and a dict -- because a frozen dataclass enforces this uniformly per-attribute rather
    # than per-type, so no field is a more likely place for the guard to have been skipped.
    settings = make_settings()

    for attribute, value in [
        ("path_secret", "changed"),
        ("auto_register_devices", True),
        ("poll_delay", 999),
        ("extra_options", {"x": "y"}),
        ("query_userinfo_command", "DATA QUERY USER"),
    ]:
        with pytest.raises(FrozenInstanceError):
            setattr(settings, attribute, value)


def test_property_57_no_configuration_error_message_contains_a_connection_string(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Feature: adms-attendance-system, Property 57: a configuration error ... contains no part of
    # a connection string. sql_connection itself is not read by load_settings' own bad-value
    # checks, but ADMS_SQL_CONNECTION is set to a DSN-shaped value alongside an unrelated bad
    # integer here, to prove a configuration error raised for one variable never echoes a
    # completely different, secret-bearing one that merely happens to be present in the same
    # environment.
    _clear_config_env(monkeypatch)
    dsn_like = "DRIVER={ODBC Driver 18};SERVER=host,1433;UID=sa;PWD=Sup3rSecret!;"
    monkeypatch.setenv("ADMS_SQL_CONNECTION", dsn_like)
    monkeypatch.setenv("ADMS_POLL_DELAY", "not-an-int")

    with pytest.raises(ConfigError) as excinfo:
        load_settings()

    message = str(excinfo.value)
    assert "Sup3rSecret" not in message
    assert "host,1433" not in message
    assert "ADMS_POLL_DELAY" in message
    assert "not-an-int" in message


# ── Also required: the six named defaults of Requirement 21.5 (a drift guard) ─────────────────


def test_requirement_21_5_named_defaults_have_not_drifted(monkeypatch: pytest.MonkeyPatch) -> None:
    # Requirement 21.5 names six defaults explicitly. This is a drift guard, not a universal
    # claim: it pins the exact values the requirement states, on top of Property 57's totality
    # check, because the requirement calls these six out by number and word.
    _clear_config_env(monkeypatch)

    settings = load_settings()

    assert settings.auto_register_devices is False
    assert settings.path_secret == ""
    assert settings.archive_raw_bodies is True
    assert settings.poll_delay == 10
    assert settings.error_delay == 30
    assert settings.max_commands_per_poll == 10
    assert settings.utc_offset_hours == 7


# ── Task 3.1's two settings: default empty, read from their own variables ─────────────────────


def test_task_3_1_query_override_settings_default_empty_and_read_from_their_variables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_config_env(monkeypatch)

    defaults = load_settings()
    assert defaults.query_userinfo_command == ""
    assert defaults.query_fingertmp_command == ""

    monkeypatch.setenv("ADMS_QUERY_USERINFO_COMMAND", "DATA QUERY USER PIN={pin}")
    monkeypatch.setenv("ADMS_QUERY_FINGERTMP_COMMAND", "DATA QUERY FP PIN={pin}")
    overridden = load_settings()
    assert overridden.query_userinfo_command == "DATA QUERY USER PIN={pin}"
    assert overridden.query_fingertmp_command == "DATA QUERY FP PIN={pin}"


# ── Property 59 ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "offset_hours",
    [0, 7, -5, 12, -12, 1, 23, -23],
    ids=lambda h: f"offset={h}",
)
def test_property_59_local_time_minus_utc_equals_the_configured_offset(offset_hours: int) -> None:
    # Feature: adms-attendance-system, Property 59: Site-local time comes from configuration, not
    # the host. For any configured offset, the clock's local time minus its UTC time equals
    # exactly that offset, independent of the host time zone.
    #
    # SystemClock is the real adapter (adms.ports.SystemClock); no host time zone is patched
    # because the whole point is that SystemClock does not consult one -- utc_now() is
    # datetime.now(timezone.utc) with tzinfo stripped, and local_now() adds a fixed timedelta on
    # top of that, regardless of whatever TZ the process happens to be running under.
    from adms.ports import SystemClock

    clock = SystemClock(utc_offset_hours=offset_hours)

    local = clock.local_now()
    utc = clock.utc_now()

    # utc_now() and local_now() each call datetime.now() independently rather than sharing one
    # sample, so a few microseconds can genuinely elapse between the two calls above. The
    # tolerance absorbs exactly that scheduling noise while still failing on anything resembling
    # a wrong-by-an-hour (or wrong-by-a-day) offset error.
    difference = local - utc
    assert abs(difference - dt.timedelta(hours=offset_hours)) < dt.timedelta(milliseconds=50), (
        f"offset={offset_hours}: local - utc = {difference}, expected {dt.timedelta(hours=offset_hours)}"
    )


def test_property_59_offset_is_read_from_configuration_not_hardcoded() -> None:
    # Feature: adms-attendance-system, Property 59: the offset that reaches the clock is the one
    # ADMS_UTC_OFFSET_HOURS supplies, not a value baked into the clock itself -- two different
    # configured offsets must produce two different local times for clocks built at (near) the
    # same instant.
    from adms.ports import SystemClock

    clock_a = SystemClock(utc_offset_hours=3)
    clock_b = SystemClock(utc_offset_hours=9)

    # Compare each clock's local time against its own utc_now() call rather than against a shared
    # instant, since utc_now() is real wall-clock time and the two calls are not simultaneous --
    # the difference must still land exactly on each clock's own configured offset.
    diff_a = clock_a.local_now() - clock_a.utc_now()
    diff_b = clock_b.local_now() - clock_b.utc_now()
    tolerance = dt.timedelta(milliseconds=50)

    assert abs(diff_a - dt.timedelta(hours=3)) < tolerance
    assert abs(diff_b - dt.timedelta(hours=9)) < tolerance
    assert diff_a != diff_b


# ── Property 60 (partial: resolution order, error message, non-disclosure -- no registry) ─────


def test_property_60_env_override_wins_when_present() -> None:
    # Feature: adms-attendance-system, Property 60 (partial): the connection string resolves in
    # order -- ADMS_SQL_CONNECTION first. make_settings() pre-populates sql_connection, so this
    # never reaches the registry branch at all.
    from adms import config as config_module

    config_module.reset_cache()
    settings = make_settings(sql_connection="DRIVER={fake};SERVER=fakehost;")

    resolved = resolve_connection_string(settings)

    assert resolved == "DRIVER={fake};SERVER=fakehost;"
    config_module.reset_cache()


def test_property_60_no_connection_string_names_the_registry_key_and_script_and_discloses_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Feature: adms-attendance-system, Property 60 (partial): when neither source supplies a
    # connection string, the error names the registry key and the script that writes it, and no
    # part of any value. The no-connection-string case is constructed explicitly here (rather than
    # via make_settings, which always populates sql_connection) and the registry itself is never
    # touched: DbConnectionStore.load is monkeypatched to return None, exactly as an unconfigured
    # host's registry would, with no real registry access.
    from adms import config as config_module
    from adms import dbconfig as dbconfig_module

    config_module.reset_cache()
    monkeypatch.setattr(dbconfig_module.DbConnectionStore, "load", lambda _self: None)

    settings = Settings(sql_connection="", registry_subkey=r"SOFTWARE\AdmsCollector\AttendanceDb")

    with pytest.raises(ConfigError) as excinfo:
        resolve_connection_string(settings)

    message = str(excinfo.value)
    assert r"SOFTWARE\AdmsCollector\AttendanceDb" in message, (
        f"error did not name the registry key: {message!r}"
    )
    assert "set-db-connection.ps1" in message, f"error did not name the writing script: {message!r}"
    # Non-disclosure: nothing was ever configured in this test, so there is no secret value to
    # check the message against directly -- what is checked is that the message is built purely
    # from the registry key and the script name, with no interpolated value at all.
    assert "PWD" not in message and "Password" not in message.lower().replace("password", "PWD")
    config_module.reset_cache()


def test_property_60_error_names_no_fragment_of_a_configured_value() -> None:
    # Feature: adms-attendance-system, Property 60 (partial): non-disclosure when a value *is*
    # configured elsewhere in the settings object but the registry path is still reached because
    # sql_connection is blank -- the error must not accidentally echo some other field.
    from adms import config as config_module
    from adms import dbconfig as dbconfig_module

    config_module.reset_cache()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(dbconfig_module.DbConnectionStore, "load", lambda _self: None)
        settings = Settings(sql_connection="", registry_subkey=r"SOFTWARE\AdmsCollector\AttendanceDb")

        with pytest.raises(ConfigError) as excinfo:
            resolve_connection_string(settings)

    message = str(excinfo.value)
    assert "AttendanceDb" in message
    config_module.reset_cache()


# ── Property 61 ──────────────────────────────────────────────────────────────────────────────

#: (kwargs, expect_trust) -- a spread of hosts, users and passwords including ones that themselves
#: contain ';' and '=' characters, to prove Encrypt=yes is unconditional and TrustServerCertificate
#: follows the settings flag rather than any input field.
_CONNECTION_STRING_CASES: list[tuple[dict[str, Any], str]] = [
    (
        {
            "host": "sql.example.com",
            "database": "ATTENDANCEDB",
            "username": "adms_collector",
            "password": "p@ss",
        },
        "no",
    ),
    ({"host": "10.0.0.5", "database": "db", "username": "sa", "password": "", "port": "1434"}, "no"),
    (
        {
            "host": "sql.example.com",
            "database": "ATTENDANCEDB",
            "username": "u;ser",
            "password": "pa;ss=word",
        },
        "no",
    ),
    (
        {
            "host": "sql.example.com",
            "database": "ATTENDANCEDB",
            "username": "adms_collector",
            "password": "p@ss",
            "settings": Settings(trust_server_certificate=True),
        },
        "yes",
    ),
    (
        {
            "host": "sql.example.com",
            "database": "ATTENDANCEDB",
            "username": "adms_collector",
            "password": "p@ss",
            "settings": Settings(trust_server_certificate=False),
        },
        "no",
    ),
    ({"host": "", "database": "", "username": "", "password": ""}, "no"),  # every input blank
]


@pytest.mark.parametrize(("kwargs", "expected_trust"), _CONNECTION_STRING_CASES)
def test_property_61_assembled_connection_string_always_insists_on_encryption(
    kwargs: dict[str, Any], expected_trust: str
) -> None:
    # Feature: adms-attendance-system, Property 61: An assembled connection string always insists
    # on encryption. For all host, database, user, password and port inputs, the assembled string
    # sets Encrypt=yes and sets TrustServerCertificate=no unless certificate validation was
    # explicitly disabled.
    connection_string = build_connection_string(**kwargs)

    assert "Encrypt=yes" in connection_string, connection_string
    assert f"TrustServerCertificate={expected_trust}" in connection_string, connection_string


def test_property_61_default_settings_produce_trust_server_certificate_no() -> None:
    # Feature: adms-attendance-system, Property 61: with no settings argument at all -- the
    # all-defaults path -- TrustServerCertificate is still "no", because Settings.
    # trust_server_certificate defaults to False.
    connection_string = build_connection_string(
        host="sql.example.com", database="ATTENDANCEDB", username="u", password="p"
    )
    assert "TrustServerCertificate=no" in connection_string
    assert "Encrypt=yes" in connection_string


# ── Property 63 ──────────────────────────────────────────────────────────────────────────────


class _FakeServe:
    """Records the keyword arguments ``waitress.serve`` was called with. Nothing binds a socket."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self.app: object = None

    def __call__(self, app: object, **kwargs: object) -> None:
        self.app = app
        self.calls.append(kwargs)


@pytest.fixture
def fake_waitress(monkeypatch: pytest.MonkeyPatch) -> _FakeServe:
    """
    Install a fake ``waitress`` module for one test.

    Same technique ``test_connection.py`` uses for ``pyodbc``: ``from waitress import serve`` inside
    ``adms.hosting.serve.main`` resolves against ``sys.modules`` first, so seeding that cache is
    enough regardless of whether the real ``waitress`` package is installed on this machine -- and
    it means this test binds no socket and starts no server.
    """
    fake_serve = _FakeServe()
    fake_module = types.SimpleNamespace(serve=fake_serve)
    monkeypatch.setitem(sys.modules, "waitress", fake_module)
    return fake_serve


@pytest.fixture
def stub_service(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Make ``adms.hosting.serve.main`` reach ``waitress.serve`` with no real composition.

    ``get_service`` and ``create_app`` are patched to trivial stand-ins so this test exercises only
    what Property 63 is actually about -- the argument defaulting in ``build_parser`` and the
    keyword arguments handed to ``serve`` -- and not the object graph, which has its own properties
    and its own tests elsewhere.
    """
    import adms.composition as composition_module
    import adms.wsgi as wsgi_module

    monkeypatch.setattr(composition_module, "get_service", lambda: object())
    monkeypatch.setattr(composition_module, "get_logger", lambda: _NullLog())

    monkeypatch.setattr(wsgi_module, "create_app", lambda *_args, **_kwargs: object())


class _NullLog:
    def debug(self, *_a: object, **_k: object) -> None: ...

    def info(self, *_a: object, **_k: object) -> None: ...

    def warn(self, *_a: object, **_k: object) -> None: ...

    def error(self, *_a: object, **_k: object) -> None: ...


@pytest.mark.parametrize(
    ("env", "argv", "expected"),
    [
        (
            {},
            [],
            {"host": "127.0.0.1", "port": 8080, "threads": 8},
        ),
        (
            {"ASPNETCORE_PORT": "9090"},
            [],
            {"host": "127.0.0.1", "port": 9090, "threads": 8},
        ),
        (
            {"HTTP_PLATFORM_PORT": "9090"},
            [],
            {"host": "127.0.0.1", "port": 9090, "threads": 8},
        ),
        (
            # Both set: the ANCM variable wins, because ANCM is what fronts the site.
            {"ASPNETCORE_PORT": "9090", "HTTP_PLATFORM_PORT": "9099"},
            [],
            {"host": "127.0.0.1", "port": 9090, "threads": 8},
        ),
        (
            {"ADMS_THREADS": "4"},
            [],
            {"host": "127.0.0.1", "port": 8080, "threads": 4},
        ),
        (
            {"HTTP_PLATFORM_PORT": "9090", "ADMS_THREADS": "16"},
            [],
            {"host": "127.0.0.1", "port": 9090, "threads": 16},
        ),
        (
            {},
            ["--host", "0.0.0.0", "--port", "80", "--threads", "2"],
            {"host": "0.0.0.0", "port": 80, "threads": 2},
        ),
    ],
    ids=["all-defaults", "aspnetcore-port", "http-platform-port", "aspnetcore-wins",
         "adms-threads", "both-env", "explicit-cli-overrides"],
)
@pytest.mark.usefixtures("stub_service")
def test_property_63_entry_point_defaults_to_the_safe_binding(
    monkeypatch: pytest.MonkeyPatch,
    fake_waitress: _FakeServe,
    env: dict[str, str],
    argv: list[str],
    expected: dict[str, object],
) -> None:
    # Feature: adms-attendance-system, Property 63: The process entry point defaults to the safe
    # binding. For all environments, the listening port defaults to the platform-supplied port
    # when present and 8080 otherwise; the bind address defaults to loopback and binds all
    # interfaces only when explicitly asked; the worker thread count defaults to its variable or
    # 8; and the server identifies itself as AdmsCollector, bounds a request body to 33,554,432
    # bytes and sets a 60-second channel timeout.
    monkeypatch.delenv("ASPNETCORE_PORT", raising=False)
    monkeypatch.delenv("HTTP_PLATFORM_PORT", raising=False)
    monkeypatch.delenv("ADMS_THREADS", raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)

    import adms.hosting.serve as serve_module

    exit_code = serve_module.main(argv)

    assert exit_code == 0
    assert len(fake_waitress.calls) == 1
    call = fake_waitress.calls[0]

    assert call["host"] == expected["host"]
    assert call["port"] == expected["port"]
    assert call["threads"] == expected["threads"]
    assert call["ident"] == "AdmsCollector"
    assert call["max_request_body_size"] == 33_554_432
    assert call["channel_timeout"] == 60


@pytest.mark.usefixtures("stub_service")
def test_property_63_explicit_0_0_0_0_binds_all_interfaces_only_when_asked(
    monkeypatch: pytest.MonkeyPatch, fake_waitress: _FakeServe
) -> None:
    # Feature: adms-attendance-system, Property 63: the bind address defaults to loopback and
    # binds all interfaces only when explicitly asked -- checked as its own case because it is a
    # deliberate opt-in (D4 in the design), not just another value the parser happens to accept.
    monkeypatch.delenv("ASPNETCORE_PORT", raising=False)
    monkeypatch.delenv("HTTP_PLATFORM_PORT", raising=False)
    monkeypatch.delenv("ADMS_THREADS", raising=False)

    import adms.hosting.serve as serve_module

    default_exit = serve_module.main([])
    assert default_exit == 0
    assert fake_waitress.calls[-1]["host"] == "127.0.0.1"

    explicit_exit = serve_module.main(["--host", "0.0.0.0"])
    assert explicit_exit == 0
    assert fake_waitress.calls[-1]["host"] == "0.0.0.0"
