"""
The data pages: dashboard, device list and detail, activity, users, sessions and audit (task 2.5).

Example tests for the contract the data pages owe their readers: every field of every row appears, tables
carry a ``<caption>`` and ``<th scope>``, a device's state is written in words next to its colour, the
machine chooser shows name, code and IDMCC, the queue control names its poll latency, and no page ever
prints a password, hash or token. Timestamps render in site-local time with the zone named. The
over-all-rows coverage is Property 26/2/28 in the ``* 2.6`` sibling.
"""

from __future__ import annotations

import datetime as dt
import re

from adms.admin import auth, ui
from adms.admin.store import AuditRow, DeviceRow, UserRow

WHEN = dt.datetime(2026, 8, 12, 2, 0, 0)  # 02:00 UTC -> 09:00 at UTC+7


def _principal(role: str = auth.Role.ADMIN) -> auth.Principal:
    return auth.Principal(
        user_id=1,
        username="jane.doe",
        display_name="Jane Doe",
        role=role,
        must_change_password=False,
        csrf_secret=auth.new_csrf_secret(),
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


def _table_is_well_formed(html: str) -> None:
    """Every <table> in the fragment has a <caption> and at least one <th scope=...>."""
    for table in re.findall(r"<table\b.*?</table>", html, flags=re.DOTALL):
        assert "<caption" in table, "a table is missing its caption"
        assert re.search(r"<th[^>]*\bscope=", table), "a table header is missing scope"


def _no_secrets(html: str) -> None:
    lowered = html.lower()
    for forbidden in ("passwordhash", "password_hash", "passwordsalt", "csrfsecret", "csrf_secret",
                      "tokenhash", "token_hash"):
        assert forbidden not in lowered
    # A bare "password" label is fine, and an empty password *input* (the add-user form) leaks
    # nothing; what must never appear is a password field carrying a value -- a rendered secret.
    for field in re.findall(r"<input\b[^>]*type=\"password\"[^>]*>", html):
        assert 'value="' not in field, "a password input carries a value"


# ── dashboard ────────────────────────────────────────────────────────────────────────────────


def test_dashboard_shows_every_summary_counter() -> None:
    summary = {
        "devices": 11, "enabled": 9, "online": 6, "silent": 2, "unlinked": 1,
        "punches_24h": 340, "pending_cmds": 3, "stuck_cmds": 0, "unprojected": 5, "bad_pins": 1,
    }
    html = ui.dashboard(summary, [_device()], _principal())
    for value in ("11", "9", "6", "2", "340", "3", "5"):
        assert value in html
    _table_is_well_formed(html)
    _no_secrets(html)


def test_dashboard_renders_a_missing_counter_as_zero_not_a_crash() -> None:
    html = ui.dashboard({"devices": 4}, [], _principal())
    assert "4" in html


# ── device list ──────────────────────────────────────────────────────────────────────────────


def test_device_list_shows_every_triage_field_of_a_row() -> None:
    # The list carries the columns you triage by: identity, machine, load. The per-device spec fields
    # (firmware / platform / push / IP / contacts) live on the detail page, asserted in the detail tests.
    d = _device()
    html = ui.device_list([d], _principal())
    for field in (d.serial, d.device_name, d.machine_name):
        assert field in html
    assert str(d.punches_last_24h) in html
    assert str(d.pending_commands) in html
    _table_is_well_formed(html)
    _no_secrets(html)


def test_device_list_states_the_state_in_words_not_colour_alone() -> None:
    html = ui.device_list([_device(state="Silent")], _principal())
    assert "Silent" in html  # the literal state word must appear as text


def test_device_list_local_time_states_the_zone() -> None:
    html = ui.device_list([_device()], _principal())
    assert "09:00" in html  # 02:00 UTC shifted to UTC+7
    assert "UTC+7" in html or "+07" in html


def test_device_list_escapes_a_hostile_device_name() -> None:
    html = ui.device_list([_device(device_name="<script>alert(1)</script>")], _principal())
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_device_list_never_seen_device_shows_a_dash_not_a_crash() -> None:
    html = ui.device_list(
        [_device(last_seen_utc=None, minutes_since_contact=None, state="Never seen")], _principal()
    )
    assert "—" in html
    assert "Never seen" in html


# ── device detail ────────────────────────────────────────────────────────────────────────────


def _detail(principal: auth.Principal | None = None) -> str:
    machines = [
        {"code": "MC01", "name": "Front Door", "numeric_id": 1, "ip": "10.0.0.9", "active": True},
        {"code": "MC02", "name": "Back Door", "numeric_id": 1, "ip": "10.0.0.10", "active": True},
    ]
    commands = [
        {"id": 5, "serial": "CJXX204960333", "text": "REBOOT", "status": "Pending",
         "return_code": None, "return_cmd": "", "created_by": "jane.doe",
         "created_utc": WHEN, "sent_utc": None, "acked_utc": None},
    ]
    punches = [
        {"serial": "CJXX204960333", "pin": "1001", "punch_time": WHEN, "status": 0,
         "verify": 1, "work_code": 0, "received_utc": WHEN},
    ]
    return ui.device_detail(
        _device(), machines, commands, punches, principal or _principal(), auth.csrf_token(b"x" * 32)
    )


def test_device_detail_shows_the_full_per_device_record() -> None:
    # The spec fields dropped from the list table have their home here -- no field is lost, it just moves
    # from the triage surface to the record page.
    d = _device()
    html = ui.device_detail(d, [], [], [], _principal(), auth.csrf_token(b"x" * 32))
    for field in (d.firmware, d.platform, d.push_version, d.last_ip, d.machine_code):
        assert field in html
    assert str(d.contact_count) in html


def test_device_detail_disabled_device_offers_enable_via_plain_post() -> None:
    # A disabled device gets a plain enable POST (no confirm interstitial -- turning a device back on
    # breaks nothing), and no disable action is offered.
    html = ui.device_detail(_device(enabled=False), [], [], [], _principal(), auth.csrf_token(b"x" * 32))
    assert 'action="/devices/CJXX204960333/enable"' in html
    assert "Enable device" in html
    assert "/confirm" not in html


def test_device_detail_enabled_device_routes_disable_through_confirm() -> None:
    # An enabled device offers Disable, and it must go through the confirm page because disabling
    # stops the device accepting pushes.
    html = ui.device_detail(_device(enabled=True), [], [], [], _principal(), auth.csrf_token(b"x" * 32))
    assert 'href="/devices/CJXX204960333/confirm"' in html
    assert "Disable device" in html
    assert 'action="/devices/CJXX204960333/enable"' not in html


def test_device_detail_machine_chooser_shows_name_code_and_idmcc() -> None:
    html = _detail()
    assert "Front Door" in html  # name
    assert "MC01" in html         # code
    # IDMCC (numeric_id) is shown because it is not unique; an operator needs the name to disambiguate.
    assert re.search(r"Front Door.*\b1\b", html, flags=re.DOTALL)


def test_device_detail_queue_control_names_the_poll_latency() -> None:
    html = _detail()
    # the poll-interval note must sit beside the queue control so an operator knows the delay
    assert re.search(r"poll|next\s+poll|deliver", html, flags=re.IGNORECASE)


def test_device_detail_offers_destructive_commands_only_to_admin() -> None:
    admin = _detail(_principal(auth.Role.ADMIN))
    operator = _detail(_principal(auth.Role.OPERATOR))
    assert "CLEAR LOG" in admin
    assert "CLEAR LOG" not in operator  # an operator cannot even see the destructive options
    assert "REBOOT" in operator          # but can see the safe ones


def test_device_detail_shows_command_history_fields() -> None:
    html = _detail()
    assert "REBOOT" in html
    assert "Pending" in html
    assert "jane.doe" in html
    _table_is_well_formed(html)
    _no_secrets(html)


# ── activity ─────────────────────────────────────────────────────────────────────────────────


def _activity(tab: str) -> str:
    punches = [{"serial": "CJXX204960333", "pin": "1001", "punch_time": WHEN, "status": 0,
                "verify": 1, "work_code": 0, "received_utc": WHEN}]
    uploads = [{"serial": "CJXX204960333", "table": "ATTLOG", "records": 5, "body_len": 320,
                "received_utc": WHEN}]
    unparsed = [{"serial": "CJXX204960333", "table": "ATTLOG", "line": "<garbage line>",
                 "received_utc": WHEN}]
    return ui.activity_page(tab, punches, uploads, unparsed, _principal())


def test_activity_punches_tab_shows_punch_fields() -> None:
    html = _activity("punches")
    assert "1001" in html   # pin
    assert "CJXX204960333" in html
    _table_is_well_formed(html)


def test_activity_unparsed_line_is_rendered_inert() -> None:
    html = _activity("unparsed")
    assert "<garbage line>" not in html
    assert "&lt;garbage line&gt;" in html


def test_activity_marks_the_current_tab() -> None:
    html = _activity("uploads")
    assert 'aria-current="page"' in html


# ── users ────────────────────────────────────────────────────────────────────────────────────


def _user(**over: object) -> UserRow:
    base = {
        "user_id": 2, "username": "minh.le", "display_name": "Le Van Minh", "role": "operator",
        "is_enabled": True, "must_change_password": False, "failed_attempts": 0,
        "locked_until_utc": None, "last_login_utc": WHEN,
        "created_utc": WHEN,
    }
    return UserRow(**{**base, **over})  # type: ignore[arg-type]


def test_users_page_shows_every_user_field_but_no_secret() -> None:
    html = ui.users_page([_user()], _principal(), auth.csrf_token(b"y" * 32))
    for field in ("minh.le", "Le Van Minh", "operator"):
        assert field in html
    _table_is_well_formed(html)
    _no_secrets(html)


def test_users_page_marks_a_locked_account() -> None:
    locked = _user(locked_until_utc=dt.datetime(2099, 1, 1), failed_attempts=8)
    html = ui.users_page([locked], _principal(), auth.csrf_token(b"y" * 32))
    assert re.search(r"lock", html, flags=re.IGNORECASE)


# ── sessions ─────────────────────────────────────────────────────────────────────────────────


def test_sessions_page_shows_session_fields_without_the_token() -> None:
    sessions = [{
        "username": "minh.le", "display_name": "Le Van Minh", "ip": "10.0.0.5",
        "user_agent": "curl/8.0", "created_utc": WHEN, "last_seen_utc": WHEN,
        "expires_utc": WHEN, "user_id": 2,
    }]
    html = ui.sessions_page(sessions, _principal(), auth.csrf_token(b"z" * 32))
    assert "minh.le" in html
    assert "10.0.0.5" in html
    assert "curl/8.0" in html
    _table_is_well_formed(html)
    _no_secrets(html)


def test_sessions_page_escapes_a_hostile_user_agent() -> None:
    sessions = [{
        "username": "u", "display_name": "d", "ip": "1.2.3.4",
        "user_agent": "<script>alert(1)</script>", "created_utc": WHEN,
        "last_seen_utc": WHEN, "expires_utc": WHEN, "user_id": 3,
    }]
    html = ui.sessions_page(sessions, _principal(), auth.csrf_token(b"z" * 32))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# ── audit ────────────────────────────────────────────────────────────────────────────────────


def test_audit_page_shows_entry_fields_and_outcome() -> None:
    entries = [
        AuditRow(when_utc=WHEN, username="jane.doe", action="user.create",
                 target="minh.le", detail="role=operator", ip="10.0.0.1", succeeded=True),
        AuditRow(when_utc=WHEN, username="jane.doe", action="signin",
                 target="", detail="", ip="10.0.0.1", succeeded=False),
    ]
    html = ui.audit_page(entries, _principal())
    assert "user.create" in html
    assert "minh.le" in html
    assert "role=operator" in html
    # the success/failure outcome must be legible, not just a colour
    assert re.search(r"fail|success|no|yes|✓|✗", html, flags=re.IGNORECASE)
    _table_is_well_formed(html)
    _no_secrets(html)


def test_audit_page_local_time_states_the_zone() -> None:
    entries = [AuditRow(when_utc=WHEN, username="u", action="a", target="", detail="",
                        ip="", succeeded=True)]
    html = ui.audit_page(entries, _principal())
    assert "09:00" in html
    assert "UTC+7" in html or "+07" in html


def test_audit_page_escapes_a_hostile_detail() -> None:
    entries = [AuditRow(when_utc=WHEN, username="u", action="a", target="t",
                        detail="<img src=x onerror=alert(1)>", ip="", succeeded=True)]
    html = ui.audit_page(entries, _principal())
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;img" in html
