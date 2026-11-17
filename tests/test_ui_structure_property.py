"""
Task 2.4: property-based structure tests over every page the console renders.

Table-driven, fixed inputs (no hypothesis, no randomness): a single ``ALL_PAGES`` list of
``(name, html)`` built once at import time, then three properties are asserted against every entry.

Property 33 -- Page structure is accessible on every page: doctype, ``lang``, exactly one ``<h1>``, a
skip link that opens before any other focusable element and targets a real id, ``<main>``/``<nav>``
landmarks (nav only where the shell actually renders one -- see the note above ``_HAS_NAV``), every
real form control labelled, every table captioned with a scoped header, and forms submit via a button
rather than a link.

Property 34 -- Validation failures are announced: the messages sit in a ``role="alert"
aria-live="polite"`` region, and each rejected control on the change-password page is
``aria-invalid="true"`` with an ``aria-describedby`` pointing at a real id.

Property 7 -- Every console form (excluding sign-in, which has no session yet) carries a hidden
``csrf`` field whose value verifies against the same secret used to build the page.
"""

from __future__ import annotations

import datetime as dt
import re

import pytest

from adms.admin import auth, ui
from adms.admin.store import AuditRow, DeviceRow, UserRow

WHEN = dt.datetime(2026, 8, 12, 2, 0, 0)

SECRET = auth.new_csrf_secret()
TOKEN = auth.csrf_token(SECRET)


def _principal(role: str = auth.Role.ADMIN) -> auth.Principal:
    return auth.Principal(
        user_id=1,
        username="jane.doe",
        display_name="Jane Doe",
        role=role,
        must_change_password=False,
        csrf_secret=SECRET,
    )


def _device(**over: object) -> DeviceRow:
    base = {
        "serial": "CJXX204960333",
        "device_name": "Lobby A",
        "enabled": True,
        "machine_code": "MC01",
        "machine_id": 1,
        "machine_name": "Front Door",
        "machine_ip": "10.0.0.9",
        "firmware": "Ver 6.60",
        "platform": "ZMM220",
        "push_version": "2.4.1",
        "last_seen_utc": WHEN,
        "contact_count": 42,
        "last_ip": "10.0.0.9",
        "minutes_since_contact": 3,
        "state": "Online",
        "punches_last_24h": 17,
        "pending_commands": 1,
    }
    return DeviceRow(**{**base, **over})  # type: ignore[arg-type]


def _user(**over: object) -> UserRow:
    base = {
        "user_id": 2, "username": "minh.le", "display_name": "Le Van Minh", "role": "operator",
        "is_enabled": True, "must_change_password": False, "failed_attempts": 0,
        "locked_until_utc": None, "last_login_utc": WHEN,
        "created_utc": WHEN,
    }
    return UserRow(**{**base, **over})  # type: ignore[arg-type]


_MACHINES = [
    {"code": "MC01", "name": "Front Door", "numeric_id": 1, "ip": "10.0.0.9", "active": True},
    {"code": "MC02", "name": "Back Door", "numeric_id": 1, "ip": "10.0.0.10", "active": True},
]
_COMMANDS = [
    {"id": 5, "serial": "CJXX204960333", "text": "REBOOT", "status": "Pending",
     "return_code": None, "return_cmd": "", "created_by": "jane.doe",
     "created_utc": WHEN, "sent_utc": None, "acked_utc": None},
]
_PUNCHES = [
    {"serial": "CJXX204960333", "pin": "1001", "punch_time": WHEN, "status": 0,
     "verify": 1, "work_code": 0, "received_utc": WHEN},
]
_UPLOADS = [
    {"serial": "CJXX204960333", "table": "ATTLOG", "records": 5, "body_len": 320,
     "received_utc": WHEN},
]
_UNPARSED = [
    {"serial": "CJXX204960333", "table": "ATTLOG", "line": "<garbage line>", "received_utc": WHEN},
]
_SESSIONS = [
    {"username": "minh.le", "display_name": "Le Van Minh", "ip": "10.0.0.5",
     "user_agent": "curl/8.0", "created_utc": WHEN, "last_seen_utc": WHEN,
     "expires_utc": WHEN, "user_id": 2},
]
_AUDIT = [
    AuditRow(when_utc=WHEN, username="jane.doe", action="user.create",
             target="minh.le", detail="role=operator", ip="10.0.0.1", succeeded=True),
]

_SUMMARY = {
    "devices": 11, "enabled": 9, "online": 6, "silent": 2, "unlinked": 1,
    "punches_24h": 340, "pending_cmds": 3, "stuck_cmds": 0, "unprojected": 5, "bad_pins": 1,
}

# ── ALL_PAGES ────────────────────────────────────────────────────────────────────────────────
#
# Every page the console renders, built once with the shared SECRET/TOKEN so Property 7 can verify
# every form's csrf field against one known secret.

ALL_PAGES: list[tuple[str, str]] = [
    ("page (shell)", ui.page(title="Devices", body="<p>content</p>", principal=_principal(),
                              active="devices", csrf=TOKEN)),
    ("sign_in_page", ui.sign_in_page()),
    ("sign_in_page (error)", ui.sign_in_page(error="Incorrect username or password.",
                                              username="jane.doe")),
    ("change_password_page (voluntary, clean)",
     ui.change_password_page(problems=[], forced=False, csrf=TOKEN)),
    ("change_password_page (forced, clean)",
     ui.change_password_page(problems=[], forced=True, csrf=TOKEN)),
    ("change_password_page (voluntary, one problem)",
     ui.change_password_page(problems=["Too short."], forced=False, csrf=TOKEN)),
    ("change_password_page (forced, several problems)",
     ui.change_password_page(
         problems=["Must be at least 12 characters.", "This password is too common."],
         forced=True, csrf=TOKEN,
     )),
    ("confirm_page", ui.confirm_page(title="Delete user", prompt="Delete jane.doe?",
                                      action="/users/5/delete", hidden={"user_id": "5"},
                                      csrf=TOKEN, danger=True)),
    ("error_page", ui.error_page(status=404, heading="Not found", detail="No such page.")),
    ("dashboard", ui.dashboard(_SUMMARY, [_device()], _principal())),
    ("device_list", ui.device_list([_device()], _principal())),
    ("device_detail", ui.device_detail(_device(), _MACHINES, _COMMANDS, _PUNCHES, _principal(),
                                        TOKEN)),
    ("activity_page (punches)", ui.activity_page("punches", _PUNCHES, _UPLOADS, _UNPARSED,
                                                  _principal())),
    ("activity_page (uploads)", ui.activity_page("uploads", _PUNCHES, _UPLOADS, _UNPARSED,
                                                  _principal())),
    ("activity_page (unparsed)", ui.activity_page("unparsed", _PUNCHES, _UPLOADS, _UNPARSED,
                                                   _principal())),
    ("users_page", ui.users_page([_user()], _principal(), TOKEN)),
    ("sessions_page", ui.sessions_page(_SESSIONS, _principal(), TOKEN)),
    ("audit_page", ui.audit_page(_AUDIT, _principal())),
]

#: Pages built through ``page()`` with a real principal render a ``<nav>`` landmark (see ``_nav`` in
#: ui.py); the pre-session pages built through ``_standalone`` never do. This is the shell's real
#: guarantee, not a defect -- there is nothing to navigate to before signing in.
_HAS_NAV = {
    "page (shell)", "dashboard", "device_list", "device_detail",
    "activity_page (punches)", "activity_page (uploads)", "activity_page (unparsed)",
    "users_page", "sessions_page", "audit_page",
}

_PAGE_IDS = [name for name, _ in ALL_PAGES]


# ── Property 33: accessible structure on every page ─────────────────────────────────────────────


def test_all_pages_covers_every_kind_of_page() -> None:
    assert len(ALL_PAGES) == len(_PAGE_IDS)
    assert len(set(_PAGE_IDS)) == len(_PAGE_IDS)


@pytest.mark.parametrize("_name,html", ALL_PAGES, ids=_PAGE_IDS)
def test_page_starts_with_doctype(_name: str, html: str) -> None:
    assert html.lstrip().lower().startswith("<!doctype html>")


@pytest.mark.parametrize("_name,html", ALL_PAGES, ids=_PAGE_IDS)
def test_page_declares_language(_name: str, html: str) -> None:
    assert re.search(r'<html[^>]*\blang="[^"]+"', html) is not None


@pytest.mark.parametrize("_name,html", ALL_PAGES, ids=_PAGE_IDS)
def test_page_has_exactly_one_h1(_name: str, html: str) -> None:
    assert len(re.findall(r"<h1\b", html)) == 1


@pytest.mark.parametrize("_name,html", ALL_PAGES, ids=_PAGE_IDS)
def test_page_has_main_landmark(_name: str, html: str) -> None:
    assert "<main" in html


@pytest.mark.parametrize("name,html", ALL_PAGES, ids=_PAGE_IDS)
def test_page_has_nav_landmark_where_a_session_exists(name: str, html: str) -> None:
    # pre-session pages (sign-in, change-password, confirm, error) render no nav -- correctly, there
    # is nothing to navigate to before signing in.
    if name in _HAS_NAV:
        assert "<nav" in html


@pytest.mark.parametrize("_name,html", ALL_PAGES, ids=_PAGE_IDS)
def test_skip_link_opens_before_any_other_focusable_element(_name: str, html: str) -> None:
    skip_pos = html.find('<a class="skip-link"')
    assert skip_pos != -1, "no skip link found"
    for tag in ("<a ", "<input", "<button"):
        pos = html.find(tag, skip_pos + 1)
        assert pos == -1 or pos > skip_pos, f"{tag.strip()} opens before the skip link"


@pytest.mark.parametrize("_name,html", ALL_PAGES, ids=_PAGE_IDS)
def test_skip_link_target_exists(_name: str, html: str) -> None:
    href = re.search(r'<a class="skip-link"[^>]*\bhref="#([\w-]+)"', html)
    assert href is not None
    assert f'id="{href.group(1)}"' in html


def _real_controls(html: str) -> list[tuple[str, str]]:
    """(tag, id) for every <input>/<select>/<textarea> that has a name and is not type=hidden."""
    controls = []
    for tag_html in re.findall(r"<(?:input|select|textarea)\b[^>]*>", html):
        if 'name="' not in tag_html:
            continue
        if re.search(r'type="hidden"', tag_html):
            continue
        match = re.search(r'\bid="([^"]+)"', tag_html)
        assert match is not None, f"control missing id: {tag_html}"
        controls.append((tag_html, match.group(1)))
    return controls


@pytest.mark.parametrize("name,html", ALL_PAGES, ids=_PAGE_IDS)
def test_every_real_control_has_a_matching_label(name: str, html: str) -> None:
    for _tag_html, control_id in _real_controls(html):
        assert re.search(rf'<label[^>]*\bfor="{re.escape(control_id)}"', html), (
            f"no <label for=\"{control_id}\"> in {name}"
        )


@pytest.mark.parametrize("name,html", ALL_PAGES, ids=_PAGE_IDS)
def test_every_table_has_a_caption_and_a_scoped_header(name: str, html: str) -> None:
    for table in re.findall(r"<table\b.*?</table>", html, flags=re.DOTALL):
        assert "<caption" in table, f"a table in {name} is missing its caption"
        assert re.search(r"<th[^>]*\bscope=", table), f"a table in {name} is missing th scope"


@pytest.mark.parametrize("name,html", ALL_PAGES, ids=_PAGE_IDS)
def test_forms_that_post_to_the_console_submit_via_a_button(name: str, html: str) -> None:
    for form in re.findall(r"<form\b.*?</form>", html, flags=re.DOTALL):
        action = re.search(r'\baction="([^"]*)"', form)
        if action is None or action.group(1) == "/sign-in":
            continue
        assert "<button" in form, f"a posting form in {name} has no <button> submit"


@pytest.mark.parametrize("name,html", ALL_PAGES, ids=_PAGE_IDS)
def test_at_most_one_primary_button_per_page(name: str, html: str) -> None:
    # Visual hierarchy: a page has at most one primary (accent-filled) call to action, so the eye is not
    # split between two equal-weight buttons. device_detail once had two (Save link + Queue command);
    # this pins the fix. Zero primaries (a read-only page) is fine.
    primaries = re.findall(r'class="[^"]*\bprimary\b[^"]*"', html)
    assert len(primaries) <= 1, f"{name} has {len(primaries)} primary buttons (expected at most 1)"


@pytest.mark.parametrize("name,html", ALL_PAGES, ids=_PAGE_IDS)
def test_no_anchor_posts_to_a_console_mutation_route(name: str, html: str) -> None:
    # links navigate, they never submit: no <a href="..."> should target a known POST-only action.
    for href in re.findall(r'<a\b[^>]*\bhref="([^"]+)"', html):
        assert not href.endswith(("/delete", "/revoke", "/link", "/commands", "/change-password")), (
            f"an <a> in {name} points at a mutation route: {href}"
        )


# ── Property 34: validation failures are announced ──────────────────────────────────────────────


@pytest.mark.parametrize(
    "problems",
    [["Too short."], ["Must be at least 12 characters.", "This password is too common."]],
    ids=["one problem", "several problems"],
)
def test_change_password_problems_sit_in_a_live_alert_region(problems: list[str]) -> None:
    html = ui.change_password_page(problems=problems, forced=False, csrf=TOKEN)
    assert re.search(r'role="alert"[^>]*aria-live="polite"', html) or re.search(
        r'aria-live="polite"[^>]*role="alert"', html
    )
    for problem in problems:
        assert problem in html


@pytest.mark.parametrize(
    "problems",
    [["Too short."], ["Must be at least 12 characters.", "This password is too common."]],
    ids=["one problem", "several problems"],
)
def test_change_password_rejected_control_is_invalid_and_described(problems: list[str]) -> None:
    html = ui.change_password_page(problems=problems, forced=False, csrf=TOKEN)
    assert 'aria-invalid="true"' in html
    described = re.search(r'aria-describedby="([\w-]+)"', html)
    assert described is not None
    assert f'id="{described.group(1)}"' in html


def test_sign_in_error_sits_in_a_live_alert_region() -> None:
    html = ui.sign_in_page(error="Incorrect username or password.", username="u")
    assert re.search(r'role="alert"[^>]*aria-live="polite"', html) or re.search(
        r'aria-live="polite"[^>]*role="alert"', html
    )
    assert "Incorrect username or password." in html


# ── Property 7: every console form carries a usable csrf token ──────────────────────────────────


@pytest.mark.parametrize("name,html", ALL_PAGES, ids=_PAGE_IDS)
def test_every_posting_console_form_carries_a_verifiable_csrf_token(name: str, html: str) -> None:
    for form in re.findall(r"<form\b.*?</form>", html, flags=re.DOTALL):
        action = re.search(r'\baction="([^"]*)"', form)
        if action is None or action.group(1) == "/sign-in":
            continue  # sign-in is exempt: there is no session yet to mint a secret from
        found = re.findall(r'name="csrf_token"[^>]*value="([^"]+)"', form) + re.findall(
            r'value="([^"]+)"[^>]*name="csrf_token"', form
        )
        assert found, f"a posting form in {name} (action={action.group(1)!r}) has no csrf field"
        assert any(auth.verify_csrf_token(SECRET, value) for value in found), (
            f"csrf field in {name} does not verify against SECRET"
        )
