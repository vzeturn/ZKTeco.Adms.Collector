"""
The escaping helpers, the stylesheet constant, and time formatting (task 2.1).

These are the foundation everything else in ``ui.py`` rests on: every interpolated value passes through
``esc`` or ``esc_attr``, so if those are wrong every page is wrong. The tests are ordinary example
tests; the exhaustive hostile-input coverage is Property 1/3 in ``test_ui_escaping_property.py``.
"""

from __future__ import annotations

import datetime as dt

import pytest

from adms.admin import ui

# ── esc ──────────────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("a & b", "a &amp; b"),
        ("<script>", "&lt;script&gt;"),
        ('"quoted"', "&quot;quoted&quot;"),
        ("it's", "it&#x27;s"),
        ("<a href=\"x\" onclick='y'>&", "&lt;a href=&quot;x&quot; onclick=&#x27;y&#x27;&gt;&amp;"),
        (None, ""),
        (42, "42"),
        (True, "True"),
    ],
)
def test_esc_replaces_all_five_metacharacters(value: object, expected: str) -> None:
    assert ui.esc(value) == expected


def test_esc_none_is_empty_not_the_word_none() -> None:
    assert ui.esc(None) == ""


def test_esc_datetime_renders_without_raising() -> None:
    stamp = dt.datetime(2026, 8, 12, 9, 30, 0)
    assert "2026" in ui.esc(stamp)


@pytest.mark.parametrize("evil", ["\x00", "\r\n", "\ud800", "🙂", "\x1b[31m"])
def test_esc_never_raises_on_control_or_surrogate(evil: str) -> None:
    result = ui.esc(evil)
    assert isinstance(result, str)
    for metachar in "<>&\"'":
        assert metachar not in result or metachar not in evil


def test_esc_is_single_pass_not_double() -> None:
    # An already-escaped ampersand must not become &amp;amp; when escaped once.
    assert ui.esc("&amp;") == "&amp;amp;"  # escaping the literal string "&amp;" once
    # But escaping a raw & once yields exactly &amp;, and the visible UI never shows &amp;amp;
    assert ui.esc("&") == "&amp;"


# ── esc_attr ─────────────────────────────────────────────────────────────────────────────────


def test_esc_attr_escapes_quotes_for_attribute_context() -> None:
    assert ui.esc_attr('a "b" c') == "a &quot;b&quot; c"
    assert ui.esc_attr("a 'b' c") == "a &#x27;b&#x27; c"
    assert ui.esc_attr(None) == ""


# ── local_time ───────────────────────────────────────────────────────────────────────────────


def test_local_time_shifts_by_offset_and_states_zone() -> None:
    utc = dt.datetime(2026, 8, 12, 2, 0, 0)
    rendered = ui.local_time(utc, 7)
    assert "09:00" in rendered  # 02:00 UTC + 7h
    assert "2026-08-12" in rendered
    # The zone must be stated so the reader is not left guessing (Requirement 6.7).
    assert "+07" in rendered or "UTC+7" in rendered or "GMT+7" in rendered


def test_local_time_none_is_a_dash_not_a_crash() -> None:
    assert ui.local_time(None, 7) == "—"


# ── stylesheet ───────────────────────────────────────────────────────────────────────────────


def test_stylesheet_is_a_nonempty_string() -> None:
    assert isinstance(ui.STYLESHEET, str)
    assert len(ui.STYLESHEET) > 100


def test_stylesheet_has_no_offorigin_or_font_download() -> None:
    css = ui.STYLESHEET.lower()
    assert "@font-face" not in css
    # No off-origin resource loads. The SVG XML namespace ``xmlns="http://www.w3.org/2000/svg"`` inside a
    # data: URI is an identifier, not a fetch, and is required for the mark to render -- so the guard is
    # against a URL that would actually reach the network: a scheme followed by ``//`` and a host, or a
    # protocol-relative ``url(//...)``. A ``data:`` URI never touches the network and is allowed.
    assert "https://" not in css
    assert "http://" not in css.replace('xmlns="http://www.w3.org/2000/svg"', "")
    assert "url(//" not in css
    assert "url('//" not in css and 'url("//' not in css


def test_stylesheet_carries_the_required_features() -> None:
    css = ui.STYLESHEET
    assert "prefers-color-scheme: dark" in css
    assert ":focus-visible" in css
    assert "@media" in css  # the single-column reflow below 40rem


def test_stylesheet_etag_is_sha256_prefix_of_the_stylesheet() -> None:
    import hashlib

    expected = hashlib.sha256(ui.STYLESHEET.encode("utf-8")).hexdigest()[:16]
    assert expected == ui.STYLESHEET_ETAG
    assert len(ui.STYLESHEET_ETAG) == 16
