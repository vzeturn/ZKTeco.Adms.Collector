"""
The read-only handlers (task 6.1): GET /, /devices, /devices/{serial}, /activity, /audit.

These pages only read. What matters at the handler seam -- the page bodies themselves are covered in
``test_ui_pages.py`` -- is that each renders, that the order the store returned survives to the page
(the handler never re-sorts), that an unknown serial is a 404, and that the activity tab selection is
total: any tab value, including a missing or unknown one, resolves to a real stream, never an error.
"""

from __future__ import annotations

import datetime as dt

from tests.conftest import WsgiClient

from adms.admin import auth
from adms.admin.store import DeviceRow
from adms.config import Settings

WHEN = dt.datetime(2026, 8, 12, 2, 0, 0, tzinfo=dt.UTC)


def _device(serial: str, **over: object) -> DeviceRow:
    base = {
        "serial": serial, "device_name": f"dev-{serial}", "enabled": True, "machine_code": "MC01",
        "machine_id": 1, "machine_name": "Front Door", "machine_ip": "10.0.0.9",
        "firmware": "Ver 6.60", "platform": "ZMM220", "push_version": "2.4.1", "last_seen_utc": WHEN,
        "contact_count": 42, "last_ip": "10.0.0.9", "minutes_since_contact": 3, "state": "Online",
        "punches_last_24h": 17, "pending_commands": 1,
    }
    return DeviceRow(**{**base, **over})  # type: ignore[arg-type]


def _client(store, role: str = "admin") -> WsgiClient:
    from adms.admin.app import create_app

    app = create_app(store, settings=Settings(), clock=lambda: WHEN)
    u = store.add_user(username="u", role=role, password="pw")
    token = auth.new_session_token()
    store.create_session(
        token_hash=auth.token_hash(token), user_id=u.user_id,
        expires_utc=WHEN + auth.SESSION_IDLE_TIMEOUT, ip="1.2.3.4", user_agent="ua",
        csrf_secret=auth.new_csrf_secret(),
    )
    c = WsgiClient(app)
    c.cookies["adms_console"] = token
    return c


# ── the pages render ─────────────────────────────────────────────────────────────────────────────


def test_dashboard_renders_the_summary_and_the_device_table(store) -> None:
    store.set_summary({"devices": 3, "online": 2})
    store.add_device(_device("AAA"))
    resp = _client(store).get("/")
    assert resp.status == 200
    assert "Dashboard" in resp.text
    assert "AAA" in resp.text


def test_devices_page_renders(store) -> None:
    store.add_device(_device("AAA"))
    resp = _client(store).get("/devices")
    assert resp.status == 200
    assert "AAA" in resp.text


def test_audit_page_renders(store) -> None:
    store.audit(username="thu", action="sign_in", ip="1.2.3.4", succeeded=True)
    resp = _client(store).get("/audit")
    assert resp.status == 200
    assert "sign_in" in resp.text


# ── the handler preserves the store's order, never re-sorts ──────────────────────────────────────


def test_device_list_keeps_the_store_order(store) -> None:
    # The store yields devices most-urgent-first, not alphabetical. Seed a deliberately un-alphabetical
    # order and assert the page renders them in that same order -- the handler must not re-sort.
    for serial in ("ZZZ", "AAA", "MMM"):
        store.add_device(_device(serial))
    text = _client(store).get("/devices").text
    positions = [text.index(s) for s in ("ZZZ", "AAA", "MMM")]
    assert positions == sorted(positions), "the device list re-sorted the store's order"


# ── an unknown serial is a 404 ────────────────────────────────────────────────────────────────────


def test_known_serial_renders_its_detail(store) -> None:
    store.add_device(_device("AAA"))
    resp = _client(store).get("/devices/AAA")
    assert resp.status == 200
    assert "AAA" in resp.text


def test_unknown_serial_is_404(store) -> None:
    resp = _client(store).get("/devices/NOPE")
    assert resp.status == 404


# ── activity tab selection is total ──────────────────────────────────────────────────────────────


def test_every_activity_tab_including_unknown_and_absent_resolves(store) -> None:
    store._punches.append({"serial": "AAA", "pin": "1", "punch_time": WHEN, "status": 0,
                           "verify": 1, "work_code": 0, "received_utc": WHEN})
    store._uploads.append({"serial": "AAA", "table": "ATTLOG", "records": 1, "body_len": 9,
                           "received_utc": WHEN})
    store._unparsed.append({"serial": "AAA", "table": "?", "line": "junk", "received_utc": WHEN})
    client = _client(store)
    for tab in ("punches", "uploads", "unparsed", "", "bogus"):
        query = "" if tab == "" else f"tab={tab}"
        resp = client.get("/activity", query=query)
        assert resp.status == 200, tab
        assert "Activity" in resp.text, tab
