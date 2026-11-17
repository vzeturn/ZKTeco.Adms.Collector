"""
Table-driven property tests over hostile fixed inputs for session and lockout arithmetic in
:mod:`adms.admin.auth`. No hypothesis, no new dependency -- plain pytest parametrize.

Scope: only the pure functions (lockout_until, session_deadlines, is_session_live). The
store-backed half of Property 15 (loading a Principal, deleting dead rows) belongs to a
separate task and is not exercised here.

The module under test is settled and NOT modified here. All times are fixed and constructed
by hand -- never datetime.now()/utcnow() -- so results are deterministic.
"""

from __future__ import annotations

import datetime as dt

import pytest

from adms.admin.auth import (
    LOCKOUT_DURATION,
    MAX_FAILED_ATTEMPTS,
    SESSION_ABSOLUTE_TIMEOUT,
    SESSION_IDLE_TIMEOUT,
    is_session_live,
    lockout_until,
    session_deadlines,
)

BASE = dt.datetime(2026, 1, 1, 12, 0, 0)

# ── Property 14: lockout arithmetic ─────────────────────────────────────────────────────────

FAILED_ATTEMPTS_CASES = [
    pytest.param(0, id="0-well-below-threshold"),
    pytest.param(1, id="1-well-below-threshold"),
    pytest.param(7, id="7-just-below-threshold"),
    pytest.param(8, id="8-exactly-at-threshold"),
    pytest.param(9, id="9-just-above-threshold"),
    pytest.param(20, id="20-well-above-threshold"),
]


@pytest.mark.parametrize("failed_attempts", FAILED_ATTEMPTS_CASES)
def test_lockout_until_matches_threshold(failed_attempts):
    result = lockout_until(BASE, failed_attempts)
    if failed_attempts < MAX_FAILED_ATTEMPTS:
        assert result is None
    else:
        assert result == BASE + LOCKOUT_DURATION


def test_lockout_boundary_seven_is_not_locked():
    assert lockout_until(BASE, 7) is None


def test_lockout_boundary_eight_is_locked():
    assert lockout_until(BASE, 8) == BASE + dt.timedelta(minutes=15)


# ── Property 15 (pure half): a session is live only while both deadlines hold ──────────────


def test_session_deadlines_are_exactly_idle_and_absolute_offsets():
    expires, absolute = session_deadlines(BASE)
    assert expires == BASE + dt.timedelta(hours=8)
    assert absolute == BASE + dt.timedelta(days=7)
    assert expires == BASE + SESSION_IDLE_TIMEOUT
    assert absolute == BASE + SESSION_ABSOLUTE_TIMEOUT


SESSION_LIVE_CASES = [
    # now well before expiry, well within the 7d absolute ceiling -> live.
    pytest.param(
        BASE,
        BASE + dt.timedelta(hours=8),
        BASE + dt.timedelta(hours=1),
        True,
        id="now-before-both-deadlines-live",
    ),
    # now exactly equal to expires_utc -> dead. The check is `now >= expires_utc`.
    pytest.param(
        BASE,
        BASE + dt.timedelta(hours=8),
        BASE + dt.timedelta(hours=8),
        False,
        id="now-equals-expiry-boundary-dead",
    ),
    # now one microsecond after expiry -> dead. Expiry check alone is the deciding factor:
    # absolute ceiling (created+7d) is still far in the future.
    pytest.param(
        BASE,
        BASE + dt.timedelta(hours=8),
        BASE + dt.timedelta(hours=8) + dt.timedelta(microseconds=1),
        False,
        id="now-just-after-expiry-dead",
    ),
    # idle expiry was pushed far out (renewed many times), well within that expiry window, but
    # now is past created_utc + 7d -- absolute ceiling alone is the deciding factor.
    pytest.param(
        BASE,
        BASE + dt.timedelta(days=30),
        BASE + dt.timedelta(days=8),
        False,
        id="within-idle-window-but-past-absolute-ceiling-dead",
    ),
    # now strictly less than both deadlines -> live.
    pytest.param(
        BASE,
        BASE + dt.timedelta(hours=8),
        BASE + dt.timedelta(minutes=1),
        True,
        id="now-just-after-creation-live",
    ),
    # now one microsecond before expiry and one microsecond before the absolute ceiling -> live.
    pytest.param(
        BASE,
        BASE + dt.timedelta(hours=8),
        BASE + dt.timedelta(hours=8) - dt.timedelta(microseconds=1),
        True,
        id="now-just-before-expiry-live",
    ),
    # now one microsecond before the absolute ceiling but expiry was set beyond it -> live,
    # because both conditions independently hold.
    pytest.param(
        BASE,
        BASE + dt.timedelta(days=30),
        BASE + dt.timedelta(days=7) - dt.timedelta(microseconds=1),
        True,
        id="now-just-before-absolute-ceiling-live",
    ),
    # now one microsecond at/after the absolute ceiling with expiry set beyond it -> dead.
    pytest.param(
        BASE,
        BASE + dt.timedelta(days=30),
        BASE + dt.timedelta(days=7),
        False,
        id="now-equals-absolute-ceiling-dead",
    ),
    # weird clock: now is before created_utc. Both conditions still hold (now < expires_utc and
    # now < created_utc + 7d), so the session reads as live -- the functions do no clock-sanity
    # checking of their own.
    pytest.param(
        BASE,
        BASE + dt.timedelta(hours=8),
        BASE - dt.timedelta(hours=1),
        True,
        id="now-before-creation-weird-clock-live",
    ),
]


@pytest.mark.parametrize("created_utc,expires_utc,now,expected_live", SESSION_LIVE_CASES)
def test_is_session_live(created_utc, expires_utc, now, expected_live):
    assert is_session_live(now, created_utc, expires_utc) is expected_live
