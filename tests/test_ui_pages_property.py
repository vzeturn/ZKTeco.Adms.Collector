"""
Property tests for the admin console's data pages (task 2.6): fixed hostile-input tables, not
hypothesis. Three properties, table-driven:

  P26 - every field of every listed row appears in the rendered page.
  P2  - no value that arrived from the device network survives as markup; it is always escaped.
  P28 - timestamps render in site-local time with the zone stated, and a missing timestamp is an
        em dash, not a crash.

Reuses the ``_principal``/``_device``/``_user`` helpers and dict shapes from ``test_ui_pages.py``.
"""

from __future__ import annotations

import datetime as dt
import re

import pytest

from adms.admin import auth, ui
from adms.admin.store import AuditRow, DeviceRow, UserRow

WHEN = dt.datetime(2026, 8, 12, 2, 0, 0)  # 02:00 UTC


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


def _user(**over: object) -> UserRow:
    base = {
        "user_id": 2, "username": "minh.le", "display_name": "Le Van Minh", "role": "operator",
        "is_enabled": True, "must_change_password": False, "failed_attempts": 0,
        "locked_until_utc": None, "last_login_utc": WHEN,
        "created_utc": WHEN,
    }
    return UserRow(**{**base, **over})  # type: ignore[arg-type]


# ── Property 26: every field of every listed row appears ───────────────────────────────────────


def test_property26_device_list_shows_every_sentinel_field() -> None:
    d = _device(
        serial="SERIAL_SENTINEL",
        device_name="NAME_SENTINEL",
        machine_name="MACH_SENTINEL",
        machine_code="CODE_SENTINEL",
        firmware="FW_SENTINEL",
        platform="PLAT_SENTINEL",
        push_version="PUSH_SENTINEL",
        last_ip="IP_SENTINEL",
        contact_count=13579,
        punches_last_24h=98765,
        pending_commands=24680,
    )
    # The list is a triage surface -- identity, state, recency, load. It shows the columns you scan by.
    list_html = ui.device_list([d], _principal())
    for sentinel in ("SERIAL_SENTINEL", "NAME_SENTINEL", "MACH_SENTINEL", "98765", "24680"):
        assert sentinel in list_html
    # The per-device facts (machine code, firmware, platform, push, IP, contacts) live on the detail
    # page, so no field is lost -- it just has one home. Assert each appears there.
    detail_html = ui.device_detail(d, [], [], [], _principal(), auth.csrf_token(b"x" * 32))
    for sentinel in (
        "CODE_SENTINEL", "FW_SENTINEL", "PLAT_SENTINEL", "PUSH_SENTINEL", "IP_SENTINEL", "13579",
    ):
        assert sentinel in detail_html


def test_property26_device_detail_shows_every_command_history_sentinel() -> None:
    commands = [
        {"id": 112233, "serial": "S1", "text": "TEXT_SENTINEL", "status": "STATUS_SENTINEL",
         "return_code": None, "return_cmd": "", "created_by": "CREATEDBY_SENTINEL",
         "created_utc": WHEN, "sent_utc": None, "acked_utc": None},
    ]
    html = ui.device_detail(_device(), [], commands, [], _principal(), auth.csrf_token(b"x" * 32))
    for sentinel in ("112233", "TEXT_SENTINEL", "STATUS_SENTINEL", "CREATEDBY_SENTINEL"):
        assert sentinel in html


@pytest.mark.parametrize(
    ("tab", "punches", "uploads", "unparsed", "sentinels"),
    [
        (
            "punches",
            [{"serial": "SER_SENTINEL", "pin": "PIN_SENTINEL", "punch_time": WHEN,
              "status": 7, "verify": 3, "work_code": 0, "received_utc": WHEN}],
            [],
            [],
            ("SER_SENTINEL", "PIN_SENTINEL", "7", "3"),
        ),
        (
            "uploads",
            [],
            [{"serial": "SER_SENTINEL", "table": "TABLE_SENTINEL", "records": 4321,
              "body_len": 8642, "received_utc": WHEN}],
            [],
            ("SER_SENTINEL", "TABLE_SENTINEL", "4321", "8642"),
        ),
        (
            "unparsed",
            [],
            [],
            [{"serial": "SER_SENTINEL", "table": "TABLE_SENTINEL", "line": "LINE_SENTINEL",
              "received_utc": WHEN}],
            ("SER_SENTINEL", "TABLE_SENTINEL", "LINE_SENTINEL"),
        ),
    ],
    ids=["punches-tab", "uploads-tab", "unparsed-tab"],
)
def test_property26_activity_tabs_show_every_sentinel_field(
    tab: str, punches: list[dict], uploads: list[dict], unparsed: list[dict], sentinels: tuple[str, ...]
) -> None:
    html = ui.activity_page(tab, punches, uploads, unparsed, _principal())
    for sentinel in sentinels:
        assert sentinel in html


def test_property26_users_page_shows_every_sentinel_field() -> None:
    u = _user(
        username="USERNAME_SENTINEL",
        display_name="DISPLAYNAME_SENTINEL",
        role="ROLE_SENTINEL",
    )
    html = ui.users_page([u], _principal(), auth.csrf_token(b"y" * 32))
    for sentinel in ("USERNAME_SENTINEL", "DISPLAYNAME_SENTINEL", "ROLE_SENTINEL"):
        assert sentinel in html


def test_property26_sessions_page_shows_every_sentinel_field() -> None:
    sessions = [{
        "username": "USERNAME_SENTINEL", "display_name": "DISPLAYNAME_SENTINEL",
        "ip": "IP_SENTINEL", "user_agent": "AGENT_SENTINEL",
        "created_utc": WHEN, "last_seen_utc": WHEN, "expires_utc": WHEN, "user_id": 9,
    }]
    html = ui.sessions_page(sessions, _principal(), auth.csrf_token(b"z" * 32))
    for sentinel in ("USERNAME_SENTINEL", "DISPLAYNAME_SENTINEL", "IP_SENTINEL", "AGENT_SENTINEL"):
        assert sentinel in html


def test_property26_audit_page_shows_every_sentinel_field() -> None:
    entries = [
        AuditRow(when_utc=WHEN, username="USERNAME_SENTINEL", action="ACTION_SENTINEL",
                 target="TARGET_SENTINEL", detail="DETAIL_SENTINEL", ip="IP_SENTINEL",
                 succeeded=True),
    ]
    html = ui.audit_page(entries, _principal())
    for sentinel in (
        "USERNAME_SENTINEL", "ACTION_SENTINEL", "TARGET_SENTINEL", "DETAIL_SENTINEL", "IP_SENTINEL",
    ):
        assert sentinel in html


# ── Property 2: hostile payloads never survive as markup ───────────────────────────────────────

_PAYLOADS = (
    ("<script>alert(1)</script>", "&lt;script&gt;"),
    ('"><img src=x onerror=alert(1)>', "&lt;img"),
    ("'><svg onload=alert(1)>", "&lt;svg"),
    ("</td><script>", "&lt;script&gt;"),
)


def _assert_neutralized(html: str, payload: str, escaped_marker: str) -> None:
    assert payload not in html
    assert escaped_marker in html


def _render_device_field(field: str, device: DeviceRow) -> str:
    """Render whichever page owns ``field``. The device list is a triage surface (identity, state,
    recency, load); the per-device facts -- firmware, platform, push version, IP -- live on the detail
    page. XSS neutralisation must hold on whichever page actually prints the value."""
    list_fields = {"serial", "device_name", "machine_name", "machine_code"}
    if field in list_fields:
        return ui.device_list([device], _principal())
    return ui.device_detail(device, [], [], [], _principal(), auth.csrf_token(b"x" * 32))


@pytest.mark.parametrize(
    ("field", "payload", "escaped"),
    [(field, payload, escaped) for field in ("device_name", "firmware", "platform", "push_version")
     for payload, escaped in _PAYLOADS],
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_property2_device_field_payloads_are_escaped(field: str, payload: str, escaped: str) -> None:
    device = _device(**{field: payload})
    html = _render_device_field(field, device)
    _assert_neutralized(html, payload, escaped)


@pytest.mark.parametrize(("payload", "escaped"), _PAYLOADS)
def test_property2_command_text_payload_is_escaped(payload: str, escaped: str) -> None:
    commands = [
        {"id": 1, "serial": "S1", "text": payload, "status": "Pending",
         "return_code": None, "return_cmd": "", "created_by": "u",
         "created_utc": WHEN, "sent_utc": None, "acked_utc": None},
    ]
    html = ui.device_detail(_device(), [], commands, [], _principal(), auth.csrf_token(b"x" * 32))
    _assert_neutralized(html, payload, escaped)


@pytest.mark.parametrize(("payload", "escaped"), _PAYLOADS)
def test_property2_unparsed_raw_line_payload_is_escaped(payload: str, escaped: str) -> None:
    unparsed = [{"serial": "S1", "table": "ATTLOG", "line": payload, "received_utc": WHEN}]
    html = ui.activity_page("unparsed", [], [], unparsed, _principal())
    _assert_neutralized(html, payload, escaped)


@pytest.mark.parametrize(("payload", "escaped"), _PAYLOADS)
def test_property2_session_user_agent_payload_is_escaped(payload: str, escaped: str) -> None:
    sessions = [{
        "username": "u", "display_name": "d", "ip": "1.2.3.4", "user_agent": payload,
        "created_utc": WHEN, "last_seen_utc": WHEN, "expires_utc": WHEN, "user_id": 3,
    }]
    html = ui.sessions_page(sessions, _principal(), auth.csrf_token(b"z" * 32))
    _assert_neutralized(html, payload, escaped)


# ── Property 28: site-local time with the zone stated ───────────────────────────────────────────

_OFFSETS = (0, 7, -5, 5)


def _expected_local(offset_hours: int) -> tuple[str, str]:
    """(HH:MM, zone label) for WHEN shifted by offset_hours."""
    shifted = WHEN + dt.timedelta(hours=offset_hours)
    sign = "+" if offset_hours >= 0 else "-"
    zone = f"UTC{sign}{abs(offset_hours)}"
    return f"{shifted:%H:%M}", zone


@pytest.mark.parametrize("offset", _OFFSETS, ids=[f"offset={o}" for o in _OFFSETS])
def test_property28_device_list_local_time_and_zone(offset: int) -> None:
    html = ui.device_list([_device()], _principal(), offset_hours=offset)
    hhmm, zone = _expected_local(offset)
    assert hhmm in html
    assert zone in html
    if offset == -5:
        assert "2026-08-11" in html  # crosses to the previous day


@pytest.mark.parametrize("offset", _OFFSETS, ids=[f"offset={o}" for o in _OFFSETS])
def test_property28_audit_page_local_time_and_zone(offset: int) -> None:
    entries = [AuditRow(when_utc=WHEN, username="u", action="a", target="", detail="",
                        ip="", succeeded=True)]
    html = ui.audit_page(entries, _principal(), offset_hours=offset)
    hhmm, zone = _expected_local(offset)
    assert hhmm in html
    assert zone in html
    if offset == -5:
        assert "2026-08-11" in html


@pytest.mark.parametrize("offset", _OFFSETS, ids=[f"offset={o}" for o in _OFFSETS])
def test_property28_activity_punches_local_time_and_zone(offset: int) -> None:
    punches = [{"serial": "S1", "pin": "1", "punch_time": WHEN, "status": 0, "verify": 1,
                "work_code": 0, "received_utc": WHEN}]
    html = ui.activity_page("punches", punches, [], [], _principal(), offset_hours=offset)
    hhmm, zone = _expected_local(offset)
    assert hhmm in html
    assert zone in html
    if offset == -5:
        assert "2026-08-11" in html


def test_property28_none_timestamp_renders_as_dash_without_raising() -> None:
    device = _device(last_seen_utc=None, minutes_since_contact=None, state="Never seen")
    html = ui.device_list([device], _principal())
    assert "—" in html
    # The empty timestamp renders as the em-dash in its own cell (the cell also carries a data-label
    # for the mobile card layout), rather than raising.
    assert re.search(r'<td data-label="Last seen">—</td>', html)
