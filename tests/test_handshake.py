"""
Property tests for ``adms.protocol.handshake.build_handshake`` -- the handshake body's exact wire
shape -- and for Property 11's registration-offset half, re-verified now that task 4.2 has landed.

Three properties live here, each implemented by exactly one test function.

Property 10 is pure and belongs entirely to ``build_handshake``: the first line is string-matched
by firmware, so its text is exact; both stamp vocabularies are emitted so one server serves a mixed
estate without sniffing versions; the fixed parameter keys are all present; and every configured
extra option is appended.

Property 11 has two halves, both asserted inside its one test. The ``Realtime`` half is pure and
checked against ``build_handshake`` directly. The registration-offset half is deliberately checked
one layer up, through ``AdmsService._handshake`` via the fake graph, rather than only against
``build_handshake``: the defect this half exists to catch -- ``AdmsService._handshake`` always
passing ``settings.utc_offset_hours`` and so making ``ADMS_DEVICE.TimeZoneOffset`` dead in
production (V2) -- was in the *caller*, not the builder. ``build_handshake``'s own fallback (use
the registration's stored offset when no explicit offset is supplied) was already correct before
task 4.2; the fix was the one argument at the call site, and only a test that drives the call site
can regress-guard it. Task 4.2 chose Option A: pass ``None`` so the per-device value wins.

Property 12 is pure: no fixed line sets a device clock, and the body is never ``OK: <n>`` shaped --
across the same combinations Property 10 exercises.
"""

from __future__ import annotations

import re
from typing import Any

import pytest
from conftest import make_settings

from adms.models import DeviceRegistration
from adms.protocol.handshake import DEFAULT_TRANS_FLAG, build_handshake

# ── Shared parsing helper ────────────────────────────────────────────────────────────────────


def _parse_handshake(body: str) -> tuple[str, dict[str, str]]:
    """
    Split a handshake body into its first line and its ``Key=Value`` fields.

    Splitting on the literal ``"\\r\\n"`` rather than a line-splitting helper is deliberate: the
    property under test *is* the separator, so the test must not go through code that would
    tolerate a bare ``\\n`` and hide a regression.
    """
    assert "\r\n" in body, f"body carries no CRLF at all: {body!r}"
    parts = body.split("\r\n")
    assert parts[-1] == "", (
        f"body does not terminate its last line with CRLF -- split on '\\r\\n' left a non-empty "
        f"tail {parts[-1]!r}"
    )
    lines = parts[:-1]
    assert lines, f"body produced no lines at all: {body!r}"

    # No residual bare '\n' or '\r' anywhere once every '\r\n' pair is removed -- proves every
    # separator in the body really was a CRLF pair, not a mix.
    residual = body.replace("\r\n", "")
    assert "\n" not in residual and "\r" not in residual, (
        f"body contains a line separator that is not a full CRLF pair: {body!r}"
    )

    first, *rest = lines
    fields: dict[str, str] = {}
    for line in rest:
        key, sep, value = line.partition("=")
        assert sep == "=", f"line {line!r} is not of the form Key=Value"
        fields[key] = value
    return first, fields


# ── Property 10 ──────────────────────────────────────────────────────────────────────────────

#: One case per row: a registration's stamp/offset state, the build_handshake overrides to apply,
#: and the extra options to configure. Deliberately varied rather than one blessed case, because
#: the property is a claim about the shape for *any* registration and *any* settings. Reused by
#: Property 12 below, since both properties are claims about the same shape for the same inputs.
_HANDSHAKE_SHAPE_CASES: list[dict[str, Any]] = [
    {
        "id": "defaults, zero stamps",
        "registration": {
            "serial": "CJXX204960333",
            "attlog_stamp": "0",
            "operlog_stamp": "0",
            "attphoto_stamp": "0",
        },
        "build_kwargs": {},
        "extra": {},
    },
    {
        "id": "nonzero, distinct stamps and a registration-stored offset",
        "registration": {
            "serial": "CJXX204960333",
            "attlog_stamp": "12345",
            "operlog_stamp": "67890",
            "attphoto_stamp": "111",
            "timezone_offset": 3,
        },
        "build_kwargs": {},
        "extra": {},
    },
    {
        "id": "every handshake parameter overridden from its default",
        "registration": {"serial": "CJXX204960333"},
        "build_kwargs": {
            "server_version": "9.9.9",
            "delay": 99,
            "error_delay": 15,
            "trans_times": "06:00;18:00",
            "trans_interval": 5,
            "trans_flag": "TransData AttLog OpLog",
            "realtime": False,
            "encrypt": True,
            "timezone_offset": 11,
        },
        "extra": {},
    },
    {
        "id": "extra options appended, including a value that itself contains '='",
        "registration": {"serial": "CJXX204960333"},
        "build_kwargs": {},
        "extra": {"PhotoFuncOn": "1", "Note": "a=b=c", "MultiBioDataSupport": "1:0,2:1,7:0,15:1"},
    },
    {
        "id": "a hostile serial: unicode, punctuation, and a tab",
        "registration": {"serial": "CJ-\u90ae-99*()\t&"},
        "build_kwargs": {},
        "extra": {},
    },
    {
        "id": "an empty extra-options mapping is the same as None",
        "registration": {"serial": "CJXX204960333"},
        "build_kwargs": {},
        "extra": None,
    },
]

#: The fixed parameter keys every handshake must carry, regardless of registration or settings.
_FIXED_KEYS = {
    "Stamp",
    "OpStamp",
    "PhotoStamp",
    "ATTLOGStamp",
    "OPERLOGStamp",
    "ATTPHOTOStamp",
    "ErrorDelay",
    "Delay",
    "TransTimes",
    "TransInterval",
    "TransFlag",
    "TimeZone",
    "Realtime",
    "Encrypt",
    "ServerVer",
}


@pytest.mark.parametrize("case", _HANDSHAKE_SHAPE_CASES, ids=[c["id"] for c in _HANDSHAKE_SHAPE_CASES])
def test_property_10_handshake_body_has_exactly_the_shape_firmware_string_matches(
    case: dict[str, Any],
) -> None:
    # Feature: adms-attendance-system, Property 10: The handshake body has exactly the shape
    # firmware string-matches. Exact first line "GET OPTION FROM: <serial>", CRLF-joined including
    # the final line, both stamp vocabularies present carrying the registration's stored values,
    # every fixed parameter key present, and every configured extra option appended as Key=Value.
    registration = DeviceRegistration(enabled=True, **case["registration"])
    body = build_handshake(registration, extra=case["extra"], **case["build_kwargs"])

    first_line, fields = _parse_handshake(body)

    assert first_line == f"GET OPTION FROM: {registration.serial}", (
        f"{case['id']}: the first line is string-matched by firmware and must be exact"
    )

    # Both stamp vocabularies, carrying the registration's own stored values.
    for key in ("Stamp", "ATTLOGStamp"):
        assert fields[key] == registration.attlog_stamp, f"{case['id']}: {key}"
    for key in ("OpStamp", "OPERLOGStamp"):
        assert fields[key] == registration.operlog_stamp, f"{case['id']}: {key}"
    for key in ("PhotoStamp", "ATTPHOTOStamp"):
        assert fields[key] == registration.attphoto_stamp, f"{case['id']}: {key}"

    # Every fixed parameter key is present at all, whatever this case configured.
    assert set(fields) >= _FIXED_KEYS, f"{case['id']}: missing {_FIXED_KEYS - set(fields)}"

    # And each carries what was asked for, defaulted where the case did not override it.
    build_kwargs = case["build_kwargs"]
    assert fields["ErrorDelay"] == str(build_kwargs.get("error_delay", 30))
    assert fields["Delay"] == str(build_kwargs.get("delay", 10))
    assert fields["TransTimes"] == build_kwargs.get("trans_times", "00:00;14:00")
    assert fields["TransInterval"] == str(build_kwargs.get("trans_interval", 1))
    assert fields["TransFlag"] == build_kwargs.get("trans_flag", DEFAULT_TRANS_FLAG)
    explicit_tz = build_kwargs.get("timezone_offset")
    expected_tz = registration.timezone_offset if explicit_tz is None else explicit_tz
    assert fields["TimeZone"] == str(expected_tz)
    assert fields["Realtime"] == ("1" if build_kwargs.get("realtime", True) else "0")
    assert fields["Encrypt"] == ("1" if build_kwargs.get("encrypt", False) else "0")
    assert fields["ServerVer"] == build_kwargs.get("server_version", "2.4.1")

    # Every configured extra option, appended verbatim as its own Key=Value line.
    for key, value in (case["extra"] or {}).items():
        assert fields[key] == value, f"{case['id']}: extra option {key!r} did not survive verbatim"


# ── Property 11 ──────────────────────────────────────────────────────────────────────────────


def test_property_11_realtime_and_timezone_are_emitted_from_configuration(fake: Any, wire: Any) -> None:
    # Feature: adms-attendance-system, Property 11: Real-time upload and the time zone are emitted
    # from configuration. Realtime=1 appears iff real-time upload is configured; and the emitted
    # TimeZone equals the explicitly supplied offset when one is given and the registration's
    # stored offset otherwise -- the registration-offset half re-verified through
    # AdmsService._handshake via the fake graph, since task 4.2's defect (V2) was in the caller,
    # not in build_handshake itself.

    # -- Realtime half, build_handshake level, table-driven over both settings --
    plain_registration = DeviceRegistration(serial="CJXX204960333", enabled=True)
    for realtime in (True, False):
        body = build_handshake(plain_registration, realtime=realtime)
        _, fields = _parse_handshake(body)
        assert fields["Realtime"] == ("1" if realtime else "0"), f"realtime={realtime}"

    # -- Time-zone half, build_handshake level: an explicit offset wins over the registration's
    #    stored value, and omitting it falls through to whatever the registration stored. This is
    #    build_handshake's own fallback, which was already correct before task 4.2 -- the defect
    #    was that AdmsService._handshake never exercised the "omitted" branch in production.
    offset_registration = DeviceRegistration(serial="CJXX204960333", enabled=True, timezone_offset=3)
    explicit_body = build_handshake(offset_registration, timezone_offset=11)
    _, explicit_fields = _parse_handshake(explicit_body)
    assert explicit_fields["TimeZone"] == "11", "an explicit offset must win over the stored one"

    fallback_body = build_handshake(offset_registration, timezone_offset=None)
    _, fallback_fields = _parse_handshake(fallback_body)
    assert fallback_fields["TimeZone"] == "3", "omitting the offset must fall back to the stored one"

    # -- Time-zone half, service level: the half that could not be written until task 4.2's
    #    decision landed. Two registrations, two different stored offsets, one shared global
    #    setting that matches neither, driven through AdmsService._handshake via the fake graph --
    #    not build_handshake directly -- because a test against build_handshake alone cannot see
    #    the call site where the defect lived, and would have stayed green throughout V2's
    #    lifetime as a live production defect.
    settings = make_settings(utc_offset_hours=9)  # deliberately neither 3 nor 11
    serial_a, serial_b = "TZOFFSET0003", "TZOFFSET0011"
    registration_a = DeviceRegistration(
        serial=serial_a, enabled=True, machine_code="MCCA0001", machine_id=21, timezone_offset=3
    )
    registration_b = DeviceRegistration(
        serial=serial_b, enabled=True, machine_code="MCCB0001", machine_id=22, timezone_offset=11
    )
    service, _stores = fake(settings=settings, devices=[registration_a, registration_b])

    response_a = service.handle(wire.handshake(serial_a))
    response_b = service.handle(wire.handshake(serial_b))

    assert response_a.status == 200
    assert response_b.status == 200
    _, fields_a = _parse_handshake(response_a.body)
    _, fields_b = _parse_handshake(response_b.body)

    assert fields_a["TimeZone"] == "3", "registration A's own stored offset must win"
    assert fields_b["TimeZone"] == "11", "registration B's own stored offset must win"
    # Neither answer is the global setting -- the failure mode this guards against is both devices
    # silently collapsing onto Settings.utc_offset_hours, which is exactly what V2 was.
    assert fields_a["TimeZone"] != str(settings.utc_offset_hours)
    assert fields_b["TimeZone"] != str(settings.utc_offset_hours)


# ── Property 12 ──────────────────────────────────────────────────────────────────────────────

#: Keys that would rewrite a device's clock, in every casing/spelling a reader might reasonably
#: expect the vendor protocol to use. None of these may appear among the handshake's own fixed
#: lines, for any registration, settings or extra-options combination -- Requirement 3.7's whole
#: point is that connecting to this service never moves a device's clock.
_CLOCK_KEY_CANDIDATES = {"currenttime", "date", "time", "datetime", "settime"}

#: The count-shaped body a handshake must never produce. Firmware reads a counted reply to a
#: handshake as an absence of configuration.
_OK_COUNT_PATTERN = re.compile(r"^OK: -?\d+$")


@pytest.mark.parametrize("case", _HANDSHAKE_SHAPE_CASES, ids=[c["id"] for c in _HANDSHAKE_SHAPE_CASES])
def test_property_12_a_handshake_never_sets_a_clock_or_carries_a_count(case: dict[str, Any]) -> None:
    # Feature: adms-attendance-system, Property 12: A handshake never sets a device clock and
    # never carries a count. For any registration, settings and set of extra options, no emitted
    # line sets the device clock; and the response body is never of the form OK: <n>.
    registration = DeviceRegistration(enabled=True, **case["registration"])
    body = build_handshake(registration, extra=case["extra"], **case["build_kwargs"])
    _, fields = _parse_handshake(body)

    # Only the keys this case's own extra options introduced are excluded -- an operator's own
    # configuration is not what this property is about. Every key the *design* emits on its own,
    # for every case in the shared table, must not be a clock-setting key.
    extra_keys = {k.lower() for k in (case["extra"] or {})}
    fixed_keys_present = {k.lower() for k in fields} - extra_keys
    offending = fixed_keys_present & _CLOCK_KEY_CANDIDATES
    assert not offending, f"{case['id']}: handshake emitted a clock-setting key: {offending}"

    assert not _OK_COUNT_PATTERN.match(body.strip()), f"{case['id']}: body was OK: <n> shaped"
    assert body.strip() != "OK", f"{case['id']}: body was bare OK"
