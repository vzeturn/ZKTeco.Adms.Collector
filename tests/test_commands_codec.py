"""
Tests for ``adms.protocol.commands`` -- the command-downlink codec: rendering a ``getrequest``
reply and parsing a ``devicecmd`` acknowledgement.

Two properties live here, both about tolerance in one direction and exactness in the other:

* **Property 42** says the *render* half must be exact -- one ``C:<id>:<body>`` line per command,
  CRLF-joined and CRLF-terminated, and ``OK`` (never a zero-length body) for an empty queue -- while
  the *parse* half must be lenient about everything firmware actually sends, and strict about exactly
  one thing: a missing ``Return`` is always a failure, never a silent success.
* **Property 45** says the clock command's packed integer encoding is an exact, reversible bijection
  under the vendor's own (31-day-month) arithmetic, and that this command is issued only explicitly --
  never folded into the handshake, which would rewrite a device's clock on every connection.

``task 3.1``'s ``query_user_info`` / ``query_fingerprints`` / ``_render_query`` are template-rendering
helpers, not codec concerns, and are covered by Property 55 in ``test_service_enrolment.py`` (task
10.5) -- out of scope here.

No service, no adapters, no database -- ``render_commands``, ``parse_acks`` and ``set_time`` are pure
functions, so every case below is a value in and a value out.
"""

from __future__ import annotations

import datetime as dt
from typing import NamedTuple

import pytest

from adms.models import CommandAck, DeviceCommand, DeviceRegistration
from adms.protocol.commands import parse_acks, render_commands, set_time
from adms.protocol.handshake import build_handshake

# ── Property 42: Commands render exactly, and acknowledgements are parsed tolerantly ────────

# ---- Rendering ---------------------------------------------------------------------------------

_RENDER_CASES: tuple[tuple[str, list[DeviceCommand], str], ...] = (
    ("empty queue renders OK, never a zero-length body", [], "OK"),
    ("one command, CRLF-terminated", [DeviceCommand(1, "CHECK")], "C:1:CHECK\r\n"),
    (
        "several commands, CRLF-joined, order preserved, each CRLF-terminated",
        [DeviceCommand(1, "CHECK"), DeviceCommand(2, "REBOOT"), DeviceCommand(3, "INFO")],
        "C:1:CHECK\r\nC:2:REBOOT\r\nC:3:INFO\r\n",
    ),
    (
        "a body containing spaces and '=' is rendered verbatim, not re-escaped",
        [DeviceCommand(42, "SET OPTIONS DateTime=821382000")],
        "C:42:SET OPTIONS DateTime=821382000\r\n",
    ),
    (
        "a large id and an empty command body still render exactly",
        [DeviceCommand(999999, "")],
        "C:999999:\r\n",
    ),
    (
        "queue order is emitted as given, not sorted by id",
        [DeviceCommand(50, "B"), DeviceCommand(7, "A")],
        "C:50:B\r\nC:7:A\r\n",
    ),
)
_RENDER_IDS = [c[0] for c in _RENDER_CASES]


@pytest.mark.parametrize(("case_id", "commands", "expected"), _RENDER_CASES, ids=_RENDER_IDS)
def test_render_commands_renders_exactly(case_id: str, commands: list[DeviceCommand], expected: str) -> None:
    # Feature: adms-attendance-system, Property 42: Commands render exactly, and acknowledgements
    # are parsed tolerantly -- for any list of claimed commands, the rendered body is one
    # C:<id>:<body> line per command joined and terminated with CRLF, and the empty list renders
    # OK rather than a zero-length body, because some firmware reads a zero-length response as a
    # connection failure and backs off as if the server were down.
    result = render_commands(commands)
    assert result == expected, f"{case_id}: got {result!r}"
    if commands:
        assert result != "", f"{case_id}: a non-empty queue must never render a zero-length body"
    else:
        assert result == "OK" and len(result) > 0, f"{case_id}: empty queue must render 'OK', not ''"


# ---- Acking -------------------------------------------------------------------------------------


class ExpectedAck(NamedTuple):
    command_id: int
    return_code: int
    command: str
    succeeded: bool


_PARSE_CASES: tuple[tuple[str, str, list[ExpectedAck]], ...] = (
    (
        "one ack, all fields present, non-negative Return is success",
        "ID=1&Return=0&CMD=CHECK",
        [ExpectedAck(1, 0, "CHECK", True)],
    ),
    (
        "one ack per line",
        "ID=1&Return=0&CMD=CHECK\nID=2&Return=-1&CMD=REBOOT",
        [ExpectedAck(1, 0, "CHECK", True), ExpectedAck(2, -1, "REBOOT", False)],
    ),
    (
        "several acks joined by & on one line -- a new ack starts at each ID=",
        "ID=1&Return=0&CMD=CHECK&ID=2&Return=5&CMD=INFO",
        [ExpectedAck(1, 0, "CHECK", True), ExpectedAck(2, 5, "INFO", True)],
    ),
    (
        "three acks chained by &, the last missing Return entirely -- still a failure, not success",
        "ID=5&Return=0&ID=6&Return=0&ID=7&CMD=REBOOT",
        [
            ExpectedAck(5, 0, "", True),
            ExpectedAck(6, 0, "", True),
            ExpectedAck(7, -1, "REBOOT", False),
        ],
    ),
    ("an empty body yields no acks, and raises nothing", "", []),
    ("a whitespace-only body yields no acks", "   \n\n  \t \n", []),
    (
        "a fragment with no ID at all is skipped without raising",
        "Foo=bar&Baz=qux",
        [],
    ),
    (
        "a negative id is skipped -- never surfaced as an ack to act on",
        "ID=-7&Return=0&CMD=CHECK",
        [],
    ),
    (
        "ID= with no value at all is skipped (parses to the -1 default, then filtered as negative)",
        "ID=&Return=0&CMD=CHECK",
        [],
    ),
    (
        "a missing Return is recorded as failure, never success, even with CMD present",
        "ID=3&CMD=REBOOT",
        [ExpectedAck(3, -1, "REBOOT", False)],
    ),
    (
        "a missing CMD defaults to an empty command name, independent of Return",
        "ID=4&Return=0",
        [ExpectedAck(4, 0, "", True)],
    ),
    (
        "unparseable junk fragments alongside a valid ack are skipped, not fatal",
        "garbage&&&more=junk&ID=8&Return=2&CMD=INFO",
        [ExpectedAck(8, 2, "INFO", True)],
    ),
    (
        "mixed valid and invalid acks across two lines",
        "ID=9&Return=1&CMD=CHECK\nFoo=bar\nID=-1&Return=0\nID=10&CMD=INFO",
        [ExpectedAck(9, 1, "CHECK", True), ExpectedAck(10, -1, "INFO", False)],
    ),
)
_PARSE_IDS = [c[0] for c in _PARSE_CASES]


@pytest.mark.parametrize(("case_id", "body", "expected"), _PARSE_CASES, ids=_PARSE_IDS)
def test_parse_acks_is_tolerant(case_id: str, body: str, expected: list[ExpectedAck]) -> None:
    # Feature: adms-attendance-system, Property 42: Commands render exactly, and acknowledgements
    # are parsed tolerantly -- for any acknowledgement body (one per line, several joined by &,
    # empty, or containing fragments with no ID or a negative id), a new acknowledgement starts at
    # each ID=, unparseable fragments are skipped without raising, a missing Return is recorded as
    # failure, a Return of zero or more as success, and an empty body yields no acks (which is what
    # lets the service answer 200 OK for it).
    acks = parse_acks(body)

    assert len(acks) == len(expected), f"{case_id}: got {acks!r}"
    for ack, want in zip(acks, expected, strict=True):
        assert isinstance(ack, CommandAck)
        assert ack.command_id == want.command_id, f"{case_id}: {ack!r}"
        assert ack.return_code == want.return_code, f"{case_id}: {ack!r}"
        assert ack.command == want.command, f"{case_id}: {ack!r}"
        assert ack.succeeded is want.succeeded, f"{case_id}: {ack!r}"


def test_a_missing_return_is_never_marked_done() -> None:
    # Feature: adms-attendance-system, Property 42: a missing Return is recorded as failure -- never
    # success -- so a command is never marked Done on an acknowledgement that never said so. Stated
    # once more, directly, because this is the clause the property exists to protect.
    (ack,) = parse_acks("ID=1&CMD=REBOOT")
    assert ack.return_code == -1
    assert ack.succeeded is False


# ── Property 45: The clock command's packed encoding round-trips ────────────────────────────

#: The vendor's packed form, copied here from ``commands._zk_datetime``'s own docstring rather than
#: imported: a property that reads its expectation from the code under test cannot fail when that
#: code changes. It deliberately assumes every month has 31 days.
def _encode_reference(when: dt.datetime) -> int:
    days = ((when.year - 2000) * 12 * 31) + ((when.month - 1) * 31) + (when.day - 1)
    return days * 86400 + when.hour * 3600 + when.minute * 60 + when.second


def _decode_reference(value: int) -> dt.datetime:
    """
    The exact inverse of ``_encode_reference``, under the same 31-day-month assumption.

    Not a real calendar decoder -- day 1..31 in *every* month, whether or not that month really has
    31 days -- which is exactly what makes the round trip hold even though the packed form does not
    match a real calendar: encoding and decoding share one assumption, so they cancel.
    """
    seconds = value % 60
    value //= 60
    minutes = value % 60
    value //= 60
    hours = value % 24
    days = value // 24

    months_total = days // 31
    day = days % 31 + 1
    year = 2000 + months_total // 12
    month = months_total % 12 + 1
    return dt.datetime(year, month, day, hours, minutes, seconds)


#: Dates chosen specifically to exercise months that do *not* really have 31 days -- a 28-day
#: February, a leap-year 29-day February, and a 30-day April -- alongside a genuine 31-day month as
#: the baseline, so the round trip is confirmed to hold regardless of what the real calendar allows.
_ROUND_TRIP_DATES: tuple[tuple[str, dt.datetime], ...] = (
    ("28-day February (non-leap year), midnight", dt.datetime(2026, 2, 28, 0, 0, 0)),
    ("29-day February (leap year), last second of the day", dt.datetime(2024, 2, 29, 23, 59, 59)),
    ("30-day April, an arbitrary mid-day time", dt.datetime(2026, 4, 30, 12, 30, 45)),
    ("31-day January, the baseline the packing assumes everywhere", dt.datetime(2026, 1, 31, 8, 0, 0)),
    ("year offset zero (2000-01-01)", dt.datetime(2000, 1, 1, 0, 0, 0)),
    ("far-future 31-day December, last second of the day", dt.datetime(2035, 12, 31, 23, 59, 59)),
    ("30-day June, first second of the day", dt.datetime(2026, 6, 1, 0, 0, 1)),
)
_ROUND_TRIP_IDS = [c[0] for c in _ROUND_TRIP_DATES]


@pytest.mark.parametrize(("case_id", "when"), _ROUND_TRIP_DATES, ids=_ROUND_TRIP_IDS)
def test_clock_command_packed_encoding_round_trips(case_id: str, when: dt.datetime) -> None:
    # Feature: adms-attendance-system, Property 45: The clock command's packed encoding round-trips
    # -- for any naive local datetime, the encoded integer decodes back to that datetime under the
    # vendor's formula. Dates are drawn from 28/29/30-day months specifically, to confirm the
    # packing/unpacking is internally consistent even though the packed form does not match a real
    # calendar (it assumes every month has 31 days).
    command_body = set_time(when)
    expected_packed = _encode_reference(when)

    assert command_body == f"SET OPTIONS DateTime={expected_packed}", f"{case_id}: got {command_body!r}"

    packed_text = command_body.removeprefix("SET OPTIONS DateTime=")
    packed = int(packed_text)
    assert packed == expected_packed, f"{case_id}"

    decoded = _decode_reference(packed)
    assert decoded == when, f"{case_id}: encoded {packed} decoded back to {decoded!r}, expected {when!r}"


def test_clock_command_is_issued_only_explicitly_never_inside_a_handshake() -> None:
    # Feature: adms-attendance-system, Property 45: the command is emitted only as an explicit
    # command, never as part of a handshake -- checked by confirming no handshake body, across a
    # spread of registrations and settings, contains the clock-setting command's shape at all.
    registrations = (
        DeviceRegistration(serial="CJXX204960333"),
        DeviceRegistration(serial="CJXX999999999", machine_id=7, timezone_offset=9),
        DeviceRegistration(serial="UNLINKED0001", enabled=True),
    )
    for registration in registrations:
        body = build_handshake(registration, extra={"Foo": "Bar", "DateTimeHint": "not-the-command"})
        assert "SET OPTIONS DateTime=" not in body, f"serial={registration.serial}: {body!r}"
        assert "SET OPTIONS" not in body, f"serial={registration.serial}: {body!r}"
