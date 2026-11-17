"""
Tests for ``adms.protocol.operlog.parse_operlog``.

Two properties live here. Property 35 is about the parser's *shape*: every non-blank line in an
``OPERLOG`` body lands in exactly one of the seven recognised kinds or in ``unparsed``, the totals
always add up, and an ``OPLOG`` line's timestamp and op code are found by content rather than by
position -- firmware disagrees about where the operator PIN and the timestamp sit relative to each
other. Property 37 is about the ``USER`` line's three defaults, each of which exists to avoid a
specific harm if it guesses wrong: ``Card`` falling back to ``ViceCard`` only when empty, an absent
enabled flag meaning enabled, and an unrecognised privilege mapping to the lowest one rather than the
highest.

No service, no adapters, no database -- ``parse_operlog`` is pure, so every case here is a body in and
a :class:`~adms.models.PushBatch` out.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable

import pytest

from adms.models import PushBatch, UserPrivilege
from adms.protocol.operlog import parse_operlog

# ── Shared bodies ────────────────────────────────────────────────────────────────────────────

#: Creating a user on a device uploads exactly this shape in one POST: the roster line, its
#: fingerprint and the device's own audit breadcrumb for the enrolment. This is the normal case the
#: design calls out, not an edge case -- and it carries blank lines on either side and in the middle,
#: which a device-generated body routinely does and which must not be counted.
NORMAL_MIXED_BODY = "\n".join(
    [
        "",
        "USER\tPIN=1001\tName=Nguyen Van A\tPri=0\tCard=88001122\tVerify=1\tEnable=1",
        "",
        "FP\tPIN=1001\tFID=0\tSize=512\tValid=1\tTMP=QklPRklOR0VS",
        "OPLOG\t3\t9999\t2026-08-07 08:00:00\t0\ta\tb\tc",
        "",
    ]
)

#: One line of each of the seven recognised tags. USERPIC and BIOPHOTO both classify as photos, so
#: seven lines produce six non-empty kinds and a photos count of two -- the total must still be seven.
ALL_SEVEN_KINDS_BODY = "\n".join(
    [
        "USER\tPIN=1101\tName=Test User\tPri=0\tCard=1\tEnable=1",
        "FP\tPIN=1101\tFID=0\tSize=512\tValid=1\tTMP=Zmlu",
        "FACE\tPIN=1101\tFID=0\tSIZE=1024\tVALID=1\tTMP=ZmFjZQ==",
        "BIODATA\tPin=1101\tNo=1\tIndex=0\tValid=1\tDuress=0\tType=1\tTmp=Ymlv",
        "USERPIC\tPIN=1101\tFileName=1101.jpg\tSize=100\tContent=cGljdHVyZQ==",
        "BIOPHOTO\tPIN=1101\tFileName=1101b.jpg\tSize=200\tContent=cGhvdG8=",
        "OPLOG\t3\t9999\t2026-08-07 08:00:00\t0\ta\tb\tc",
    ]
)

#: A tag no firmware family in this design is documented to send. It must become unparsed rather than
#: raise or vanish, so the acknowledged count still matches what the device believes it sent.
UNRECOGNISED_TAG_BODY = "SMS\tPIN=3001\tText=Hello"

#: The same OPLOG record with the operator PIN and the timestamp in three different relative
#: positions -- op code first in all three, matching the module's own note that "some builds put the
#: operator PIN second and the timestamp third, others swap them". The op code and operator PIN must
#: come out identical regardless of where the timestamp lands.
OPLOG_ADMIN_THEN_TIME = "OPLOG\t3\t9999\t2026-08-07 08:00:00\t0\ta\tb\tc"
OPLOG_TIME_THEN_ADMIN = "OPLOG\t3\t2026-08-07 08:00:00\t9999\t0\ta\tb\tc"
OPLOG_TIME_FIRST = "OPLOG\t2026-08-07 08:00:00\t3\t9999\t0\ta\tb\tc"

_OPLOG_TIMESTAMP = dt.datetime(2026, 8, 7, 8, 0, 0)


def _kind_counts(batch: PushBatch) -> dict[str, int]:
    return {
        "users": len(batch.users),
        "fingers": len(batch.fingers),
        "faces": len(batch.faces),
        "biodata": len(batch.biodata),
        "photos": len(batch.photos),
        "operations": len(batch.operations),
        "unparsed": len(batch.unparsed),
    }


def _non_blank_line_count(body: str) -> int:
    normalised = body.replace("\r\n", "\n").replace("\r", "\n")
    return len([line for line in normalised.split("\n") if line.strip()])


def _check_oplog_event(
    expected_op_code: int, expected_operator: str, expected_timestamp: dt.datetime, expected_raw: str
) -> Callable[[PushBatch], None]:
    def _check(batch: PushBatch) -> None:
        assert len(batch.operations) == 1
        event = batch.operations[0]
        assert event.op_code == expected_op_code
        assert event.operator_pin == expected_operator
        assert event.timestamp == expected_timestamp
        assert event.raw == expected_raw

    return _check


# ── Property 35 ──────────────────────────────────────────────────────────────────────────────

PROPERTY_35_CASES = [
    pytest.param(
        NORMAL_MIXED_BODY,
        {"users": 1, "fingers": 1, "faces": 0, "biodata": 0, "photos": 0, "operations": 1, "unparsed": 0},
        None,
        id="normal_case_user_fp_and_oplog_mixed_with_blank_lines",
    ),
    pytest.param(
        ALL_SEVEN_KINDS_BODY,
        {"users": 1, "fingers": 1, "faces": 1, "biodata": 1, "photos": 2, "operations": 1, "unparsed": 0},
        None,
        id="all_seven_recognised_kinds_one_line_each",
    ),
    pytest.param(
        UNRECOGNISED_TAG_BODY,
        {"users": 0, "fingers": 0, "faces": 0, "biodata": 0, "photos": 0, "operations": 0, "unparsed": 1},
        None,
        id="unrecognised_tag_becomes_unparsed_not_dropped_or_raised",
    ),
    pytest.param(
        OPLOG_ADMIN_THEN_TIME,
        {"users": 0, "fingers": 0, "faces": 0, "biodata": 0, "photos": 0, "operations": 1, "unparsed": 0},
        _check_oplog_event(3, "9999", _OPLOG_TIMESTAMP, OPLOG_ADMIN_THEN_TIME),
        id="oplog_operator_pin_before_timestamp",
    ),
    pytest.param(
        OPLOG_TIME_THEN_ADMIN,
        {"users": 0, "fingers": 0, "faces": 0, "biodata": 0, "photos": 0, "operations": 1, "unparsed": 0},
        _check_oplog_event(3, "9999", _OPLOG_TIMESTAMP, OPLOG_TIME_THEN_ADMIN),
        id="oplog_timestamp_before_operator_pin",
    ),
    pytest.param(
        OPLOG_TIME_FIRST,
        {"users": 0, "fingers": 0, "faces": 0, "biodata": 0, "photos": 0, "operations": 1, "unparsed": 0},
        _check_oplog_event(3, "9999", _OPLOG_TIMESTAMP, OPLOG_TIME_FIRST),
        id="oplog_timestamp_leads_every_other_field",
    ),
]


@pytest.mark.parametrize(("body", "expected_counts", "extra_check"), PROPERTY_35_CASES)
def test_property_35_operlog_classification_is_total_and_every_line_is_accounted_for(
    body: str,
    expected_counts: dict[str, int],
    extra_check: Callable[[PushBatch], None] | None,
) -> None:
    # Feature: adms-attendance-system, Property 35: OPERLOG classification is total and every line is
    # accounted for
    """
    For any OPERLOG body, every non-blank line classifies as exactly one of the seven recognised kinds
    (USER, FP, FACE, BIODATA, USERPIC, BIOPHOTO, OPLOG) or is returned unparsed, and the total equals
    the number of non-blank lines. Every OPLOG line produces an event carrying its original text, with
    the timestamp taken from the first field that parses as one and the op code from the first
    remaining field -- whatever order the firmware used for the operator PIN and the timestamp.

    **Validates: Requirements 7.2, 7.10**
    """
    batch = parse_operlog(body)

    assert _kind_counts(batch) == expected_counts
    assert batch.record_count == _non_blank_line_count(body)

    if extra_check is not None:
        extra_check(batch)


# ── Property 37 ──────────────────────────────────────────────────────────────────────────────

PROPERTY_37_CASES = [
    # Card falls back to ViceCard only when Card is empty.
    pytest.param(
        "USER\tPIN=2001\tCard=11112222\tViceCard=99998888\tName=A",
        {"card": "11112222"},
        id="card_and_vicecard_both_set_card_wins",
    ),
    pytest.param(
        "USER\tPIN=2002\tCard=\tViceCard=99998888\tName=B",
        {"card": "99998888"},
        id="card_empty_vicecard_set_vicecard_wins",
    ),
    pytest.param(
        "USER\tPIN=2003\tViceCard=77776666\tName=C",
        {"card": "77776666"},
        id="card_absent_entirely_vicecard_set_vicecard_wins",
    ),
    pytest.param(
        "USER\tPIN=2004\tName=D",
        {"card": ""},
        id="card_and_vicecard_both_absent_yields_empty_card",
    ),
    # An absent enabled flag means enabled; explicit falsy spellings mean disabled.
    pytest.param(
        "USER\tPIN=2005\tName=E",
        {"enabled": True},
        id="no_enabled_flag_at_all_defaults_to_enabled",
    ),
    pytest.param(
        "USER\tPIN=2006\tName=F\tEnable=0",
        {"enabled": False},
        id="explicit_enable_0_is_disabled",
    ),
    pytest.param(
        "USER\tPIN=2007\tName=G\tEnable=false",
        {"enabled": False},
        id="explicit_enable_false_is_disabled",
    ),
    # Privilege: the known set, plus an unrecognised value and a missing one -- both must land on the
    # lowest privilege rather than guess upward.
    pytest.param(
        "USER\tPIN=2008\tName=H\tPri=0",
        {"privilege": UserPrivilege.USER},
        id="privilege_0_is_user",
    ),
    pytest.param(
        "USER\tPIN=2009\tName=I\tPri=2",
        {"privilege": UserPrivilege.ENROLLER},
        id="privilege_2_is_enroller",
    ),
    pytest.param(
        "USER\tPIN=2010\tName=J\tPri=6",
        {"privilege": UserPrivilege.MANAGER},
        id="privilege_6_is_manager",
    ),
    pytest.param(
        "USER\tPIN=2011\tName=K\tPri=14",
        {"privilege": UserPrivilege.ADMINISTRATOR},
        id="privilege_14_is_administrator",
    ),
    pytest.param(
        "USER\tPIN=2012\tName=L\tPri=999",
        {"privilege": UserPrivilege.USER},
        id="unrecognised_privilege_falls_back_to_the_lowest_not_the_highest",
    ),
    pytest.param(
        "USER\tPIN=2013\tName=M",
        {"privilege": UserPrivilege.USER},
        id="missing_privilege_defaults_to_the_lowest",
    ),
]


@pytest.mark.parametrize(("line", "expected"), PROPERTY_37_CASES)
def test_property_37_every_default_in_the_user_path_fails_safe(
    line: str, expected: dict[str, object]
) -> None:
    # Feature: adms-attendance-system, Property 37: Every default in the USER path fails safe
    """
    For any USER line, the card is taken from Card and falls back to ViceCard only when Card is
    empty; an absent enabled flag yields enabled; and for all privilege tokens, an unrecognised value
    maps to the lowest privilege rather than guessing upward into device administration.

    **Validates: Requirements 7.5, 7.6, 7.7**
    """
    batch = parse_operlog(line)

    assert len(batch.users) == 1
    assert not batch.unparsed
    user = batch.users[0]
    for attribute, value in expected.items():
        assert getattr(user, attribute) == value, (
            f"{attribute}: expected {value!r}, got {getattr(user, attribute)!r}"
        )
