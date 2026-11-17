"""
``protocol.attlog.parse_attlog`` -- the punch parser, and the only place the acknowledged count is
decided from.

One property lives here. Everything else about ``ATTLOG`` -- what gets written, whether a retry is
idempotent, whether the archive precedes the projection -- belongs to the service layer
(``test_service_attlog.py``) and is out of scope for a module that does no I/O at all.
"""

from __future__ import annotations

from typing import NamedTuple

import generators as gen
import pytest

from adms.models import VerifyMode
from adms.protocol.attlog import parse_attlog
from adms.protocol.text import split_lines


class LineCase(NamedTuple):
    """One line of a fixture body, and what the property says must happen to it."""

    #: The line exactly as a device would send it. No leading or trailing whitespace of its own, so
    #: ``split_lines`` cannot alter it and a test failure names the input verbatim.
    text: str
    #: Whether this line must land in ``logs`` (True) or ``rejected`` (False).
    accept: bool
    #: The PIN a passing line must parse to, when worth pinning down. ``None`` means "accepted, but
    #: this case is not about which PIN came out".
    pin: str | None = None


def _case(case_id: str, lines: list[LineCase], *, body: str | None = None) -> tuple[str, str, list[LineCase]]:
    """
    Build one parametrised case.

    ``body`` defaults to the lines joined with ``\\n``, which is right for every case that is *about*
    specific lines. The two structural cases (an empty body, a body of only blanks) supply ``body``
    directly with an empty ``lines`` list, because there is nothing line-shaped to name.
    """
    return case_id, ("\n".join(line.text for line in lines) if body is None else body), lines


#: Dead-clock strings a device with a broken real-time clock actually emits. Blank entries in
#: ``generators.DEAD_CLOCK_STAMPS`` are for ``parse_timestamp``'s own totality test and are skipped
#: here: a line reduced to nothing but a PIN and whitespace is a structural case, not a timestamp one.
_DEAD_CLOCK_STAMPS = [s for s in gen.DEAD_CLOCK_STAMPS if s.strip()]

CASES: list[tuple[str, str, list[LineCase]]] = [
    _case(
        "positional layout, full seven-field arity",
        [LineCase("501\t2026-08-07 08:00:05\t1\t1\t3\tR1\tR2", True, pin="501")],
    ),
    _case(
        "positional layout, minimal two-field arity -- only PIN and timestamp are guaranteed",
        [LineCase("502\t2026-08-07 08:01:00", True, pin="502")],
    ),
    _case(
        "positional layout, 8-field arity with the 2020 health-screening mask flag",
        [LineCase("503\t2026-08-07 08:02:00\t0\t1\t0\t\t\t0", True, pin="503")],
    ),
    _case(
        "positional layout, 9-field arity with the mask flag and temperature",
        [LineCase("504\t2026-08-07 08:03:00\t0\t1\t0\t\t\t0\t36.5", True, pin="504")],
    ),
    _case(
        "positional layout, arity far beyond any documented field -- never validated, only defaulted",
        [LineCase("510\t2026-08-07 08:10:00\tX\tY\tZ\tA\tB\tC\tD\tE\tF\tG", True, pin="510")],
    ),
    _case(
        "key=value layout, pin taken from the PIN key",
        [LineCase("PIN=505\tTime=2026-08-07 08:04:00\tStatus=1\tVerify=1", True, pin="505")],
    ),
    _case(
        "key=value layout, alternate key spellings (UserID / CheckTime)",
        [LineCase("UserID=506\tCheckTime=2026-08-07 08:05:00", True, pin="506")],
    ),
    _case(
        "key=value layout, no pin key present at all -- rejected",
        [LineCase("Foo=1\tBar=2", False)],
    ),
    _case(
        "key=value layout, a pin key present but blank -- rejected",
        [LineCase("PIN= \tTime=2026-08-07 08:08:00", False)],
    ),
    _case(
        "key=value layout, pin present but no timestamp key at all -- rejected",
        [LineCase("PIN=508\tFoo=1", False)],
    ),
    _case(
        "positional layout, pin present but the timestamp field is not parseable -- rejected",
        [LineCase("507\tnot-a-timestamp\t0\t1", False)],
    ),
    _case(
        "positional layout, a bare token with no timestamp field at all -- rejected",
        [LineCase("PINONLYNOEQUALS", False)],
    ),
    _case(
        "both layouts within one body, the switch decided independently per line",
        [
            LineCase("501\t2026-08-07 08:00:05\t1\t1\t3\tR1\tR2", True, pin="501"),
            LineCase("PIN=505\tTime=2026-08-07 08:04:00", True, pin="505"),
            LineCase("507\tnot-a-timestamp", False),
            LineCase("Foo=1\tBar=2", False),
            LineCase("UserID=506\tCheckTime=2026-08-07 08:05:00", True, pin="506"),
        ],
    ),
    _case("empty body -- zero lines, zero of either list", [], body=""),
    _case(
        "a body of only blank lines and whitespace -- discarded before parsing ever sees them",
        [],
        body="\n\n   \n\t\n\r\n   \t  \n",
    ),
    *(
        _case(
            f"positional layout, dead-clock timestamp {stamp!r} -- rejected, never a punch",
            [LineCase(f"509\t{stamp}", False)],
        )
        for stamp in _DEAD_CLOCK_STAMPS
    ),
]


@pytest.mark.parametrize("case_id, body, lines", CASES, ids=[c[0] for c in CASES])
def test_attlog_parsing_accounts_for_every_line_and_rejects_exactly_the_unusable_ones(
    case_id: str, body: str, lines: list[LineCase]
) -> None:
    # Feature: adms-attendance-system, Property 21: ATTLOG parsing accounts for every line, and
    # rejects exactly the unusable ones. len(logs) + len(rejected) == len(split_lines(body)) for any
    # body, and a line is rejected iff it yields no non-empty PIN or no parseable timestamp -- asserted
    # on every hostile case below, not on one chosen case, because that identity is what makes the
    # acknowledged count honest.
    raw_lines = split_lines(body)
    assert raw_lines == [line.text for line in lines], (
        f"{case_id}: a fixture line was altered by split_lines -- the case no longer tests what its "
        f"name says. Expected {[line.text for line in lines]!r}, got {raw_lines!r}"
    )

    logs, rejected = parse_attlog(body)

    # The accounting identity itself: nothing is gained or lost, for every body in this table.
    assert len(logs) + len(rejected) == len(raw_lines), (
        f"{case_id}: {len(logs)} logs + {len(rejected)} rejected != {len(raw_lines)} non-blank lines"
    )

    expected_logs = sum(1 for line in lines if line.accept)
    expected_rejected = sum(1 for line in lines if not line.accept)
    assert len(logs) == expected_logs, f"{case_id}: expected {expected_logs} usable line(s)"
    assert len(rejected) == expected_rejected, f"{case_id}: expected {expected_rejected} rejected line(s)"

    # Order within both lists is arrival order (the parser's own postcondition), and classification is
    # exactly the rejected-iff rule -- checked together by walking the fixture and both outputs in lock
    # step, so a line landing in the wrong list is reported by name rather than by count alone.
    log_iter = iter(logs)
    rejected_iter = iter(rejected)
    for line in lines:
        if line.accept:
            log = next(log_iter, None)
            assert log is not None, f"{case_id}: {line.text!r} was expected among the usable logs"
            assert log.pin != "", f"{case_id}: {line.text!r} produced an empty PIN despite being usable"
            assert log.timestamp is not None
            if line.pin is not None:
                assert log.pin == line.pin, f"{case_id}: {line.text!r} parsed pin {log.pin!r}"
        else:
            rej = next(rejected_iter, None)
            assert rej == line.text, f"{case_id}: expected {line.text!r} among the rejected lines"

    assert next(log_iter, None) is None, f"{case_id}: more logs were produced than the fixture expects"
    assert next(rejected_iter, None) is None, f"{case_id}: more rejected lines than the fixture expects"


def test_attlog_fields_beyond_the_timestamp_are_defaulted_never_validated() -> None:
    # Feature: adms-attendance-system, Property 21: every field after the timestamp is either the
    # parsed value or its declared default -- arity is never validated, so a line with unparseable
    # junk in every trailing field, or far more fields than any layout documents, is still usable.
    line = "510\t2026-08-07 08:10:00\tX\tY\tZ\tA\tB\tC\tD\tE\tF\tG"
    logs, rejected = parse_attlog(line)

    assert rejected == []
    assert len(logs) == 1
    log = logs[0]
    assert log.pin == "510"
    # status ("X") and work_code ("Z") do not parse as integers, so each falls back to its default
    # rather than rejecting the line or raising.
    assert log.status == 0
    assert log.work_code == 0
    # verify ("Y") does not parse as a VerifyMode code, so it falls back to OTHER rather than raising.
    assert log.verify == VerifyMode.OTHER
    # reserved1/reserved2 take whatever sits at their positions; everything past them is ignored
    # outright, which is the whole point of "arity beyond two is never validated".
    assert log.reserved1 == "A"
    assert log.reserved2 == "B"
