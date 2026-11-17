"""
DB datetimes enter the domain as timezone-aware UTC (regression for the live console 500).

SQL Server ``datetime`` columns carry no zone, so pyodbc returns *naive* datetimes; the console's
domain runs on aware UTC (``datetime.now(dt.UTC)``). Comparing the two raised
``TypeError: can't compare offset-naive and offset-aware datetimes`` in ``is_session_live`` and 500'd
every authenticated page. ``store._utc`` normalises at the seam so nothing downstream meets a naive
value. These tests pin that seam and prove the crash it prevents is real.
"""

from __future__ import annotations

import datetime as dt

import pytest

from adms.admin import auth
from adms.admin.store import _utc


def test_naive_datetime_gains_utc() -> None:
    naive = dt.datetime(2026, 8, 14, 2, 0, 0)  # what pyodbc hands back from a datetime column
    out = _utc(naive)
    assert out is not None
    assert out.tzinfo is dt.UTC
    assert out == dt.datetime(2026, 8, 14, 2, 0, 0, tzinfo=dt.UTC)


def test_aware_datetime_is_preserved() -> None:
    # The fakes in the test suite already produce aware datetimes; they must pass through unchanged so
    # the normaliser is a no-op on already-correct input, never a double-shift.
    aware = dt.datetime(2026, 8, 14, 2, 0, 0, tzinfo=dt.UTC)
    assert _utc(aware) == aware


def test_aware_non_utc_is_converted_not_relabelled() -> None:
    # A +07:00 wall-clock instant must become the same instant in UTC, not the same digits relabelled.
    plus7 = dt.datetime(2026, 8, 14, 9, 0, 0, tzinfo=dt.timezone(dt.timedelta(hours=7)))
    assert _utc(plus7) == dt.datetime(2026, 8, 14, 2, 0, 0, tzinfo=dt.UTC)


def test_none_passes_through() -> None:
    assert _utc(None) is None


def test_is_session_live_would_crash_on_a_naive_expiry_without_normalisation() -> None:
    # The exact production failure: a naive expiry vs an aware ``now``. This documents *why* the seam
    # exists -- feed the raw pyodbc-shaped value straight in and the comparison raises.
    now = dt.datetime(2026, 8, 14, 2, 0, 0, tzinfo=dt.UTC)
    naive_expiry = dt.datetime(2026, 8, 14, 10, 0, 0)  # no tzinfo, as SQL Server returns it
    with pytest.raises(TypeError):
        auth.is_session_live(now, now, naive_expiry)


def test_is_session_live_accepts_the_normalised_value() -> None:
    # After normalisation the same instant compares cleanly and the session reads as live.
    now = dt.datetime(2026, 8, 14, 2, 0, 0, tzinfo=dt.UTC)
    created = _utc(dt.datetime(2026, 8, 14, 1, 0, 0))
    expiry = _utc(dt.datetime(2026, 8, 14, 10, 0, 0))
    assert auth.is_session_live(now, created, expiry) is True
