"""
The admin console's Roster_Sync view (multi-device-employee-sync): GET /roster-sync, and the
SyncGroup/Backfill fields on the device pages it shares data with.

Follows ``test_app_read_pages.py``'s exact pattern: this is a read-only page (no store method here
ever writes), so what matters at the handler seam is that it renders, that the store's own ordering
survives to the page, and that a device with no Sync_Group at all renders as inert rather than as an
error or a false "0 owed" -- the same "empty means opted out, not broken" convention the collector
side's own ``sync_group: str = ""`` field documents.
"""

from __future__ import annotations

import datetime as dt

from tests.conftest import WsgiClient

from adms.admin import auth
from adms.admin.store import DeletionEventRow, DeviceRow, RosterSyncRow
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


# ── the page renders ─────────────────────────────────────────────────────────────────────────────


def test_roster_sync_page_renders_with_no_data(store) -> None:
    """No device in a Sync_Group yet -- the feature's own default, inert state -- must render a
    calm empty page, never an error."""
    resp = _client(store).get("/roster-sync")
    assert resp.status == 200
    assert "Roster sync" in resp.text
    assert "Sync_Group" in resp.text or "sync group" in resp.text.lower() or "Sync group" in resp.text


def test_roster_sync_page_renders_a_behind_device(store) -> None:
    store.set_roster_sync_status([
        RosterSyncRow(
            serial="AAA", device_name="READER 1", sync_group="SITE_A",
            roster_sync_stamp=1, group_max_version=3, pins_owed=2,
        ),
    ])
    resp = _client(store).get("/roster-sync")
    assert resp.status == 200
    assert "AAA" in resp.text
    assert "SITE_A" in resp.text
    assert "2" in resp.text  # the owed count


def test_roster_sync_page_renders_a_current_device_without_a_warning(store) -> None:
    store.set_roster_sync_status([
        RosterSyncRow(
            serial="AAA", device_name="READER 1", sync_group="SITE_A",
            roster_sync_stamp=3, group_max_version=3, pins_owed=0,
        ),
    ])
    text = _client(store).get("/roster-sync").text
    assert "current" in text.lower()


def test_roster_sync_page_renders_the_delete_fanout_audit_trail(store) -> None:
    store.set_recent_deletions([
        DeletionEventRow(
            pin=999999, sync_group="SITE_A", roster_version=2, updated_utc=WHEN,
            commands_enqueued=3,
        ),
    ])
    resp = _client(store).get("/roster-sync")
    assert resp.status == 200
    assert "999999" in resp.text
    assert "SITE_A" in resp.text


def test_roster_sync_page_keeps_the_store_order(store) -> None:
    """The handler must not re-sort: the store's own ordering (most behind first) is the point."""
    store.set_roster_sync_status([
        RosterSyncRow(serial="ZZZ", device_name="z", sync_group="G", roster_sync_stamp=0,
                     group_max_version=5, pins_owed=5),
        RosterSyncRow(serial="AAA", device_name="a", sync_group="G", roster_sync_stamp=4,
                     group_max_version=5, pins_owed=1),
    ])
    text = _client(store).get("/roster-sync").text
    positions = [text.index(s) for s in ("ZZZ", "AAA")]
    assert positions == sorted(positions), "the roster sync page re-sorted the store's order"


# ── every role that can view the console can view this page (read-only, same as /activity) ───────


def test_every_role_can_view_roster_sync(store) -> None:
    for role in ("viewer", "operator", "admin"):
        resp = _client(store, role=role).get("/roster-sync")
        assert resp.status == 200, role


# ── device pages show SyncGroup/owed status consistently with the dedicated page ──────────────────


def test_device_list_shows_sync_group_and_owed_pill(store) -> None:
    store.add_device(_device("AAA", sync_group="SITE_A", roster_pins_owed=2))
    text = _client(store).get("/devices").text
    assert "SITE_A" in text
    assert "owed" in text.lower()


def test_device_list_shows_a_dash_for_a_device_with_no_sync_group(store) -> None:
    """A device never opted into Roster_Sync (the default, sync_group='') must render as
    unremarkable -- no warning, no owed count -- never as if the feature had failed to load."""
    store.add_device(_device("AAA"))
    text = _client(store).get("/devices").text
    assert "AAA" in text
    # Nothing from the roster-sync vocabulary should read as a warning for this row.
    assert "owed" not in text.lower()


def test_device_detail_shows_sync_group_fact(store) -> None:
    store.add_device(_device("AAA", sync_group="SITE_A", roster_pins_owed=0))
    text = _client(store).get("/devices/AAA").text
    assert "SITE_A" in text
    assert "current" in text.lower()


def test_device_detail_shows_not_in_a_sync_group_when_unset(store) -> None:
    store.add_device(_device("AAA"))
    text = _client(store).get("/devices/AAA").text
    assert "Not in a sync group" in text


# ── dashboard summary counters ──────────────────────────────────────────────────────────────────


def test_dashboard_shows_roster_sync_counters(store) -> None:
    store.set_summary({"roster_devices": 4, "roster_behind": 1, "deletions_24h": 2})
    text = _client(store).get("/").text
    assert "Roster sync devices" in text
    assert "Roster sync behind" in text
    assert "Deletions fanned out" in text


# ── per-request logging (the scale-to-zero idle-detection signal) ─────────────────────────────────


def test_an_authenticated_page_view_logs_one_info_line() -> None:
    """
    Every request that reaches a handler (i.e. cleared authentication) must produce one INFO log
    line -- this is the activity signal an idle-detection
    monitor can key on. Without it an operator actively using the console would look idle.
    """
    from tests.conftest import LogCapture

    from adms.admin.app import create_app

    store = _fresh_store()
    log = LogCapture()
    app = create_app(store, settings=Settings(), clock=lambda: WHEN, log=log.logger)
    u = store.add_user(username="u", role="viewer", password="pw")
    token = auth.new_session_token()
    store.create_session(
        token_hash=auth.token_hash(token), user_id=u.user_id,
        expires_utc=WHEN + auth.SESSION_IDLE_TIMEOUT, ip="1.2.3.4", user_agent="ua",
        csrf_secret=auth.new_csrf_secret(),
    )
    client = WsgiClient(app)
    client.cookies["adms_console"] = token

    resp = client.get("/")
    assert resp.status == 200
    info_lines = log.of_level("INFO")
    assert len(info_lines) == 1
    assert info_lines[0]["user"] == "u"
    assert info_lines[0]["path"] == "/"


def test_an_unauthenticated_request_logs_nothing() -> None:
    """A probe or an expired-cookie redirect never reaches a handler, so it must never count as
    activity -- otherwise a port scan or a stale bookmark would keep the service awake forever."""
    from tests.conftest import LogCapture

    from adms.admin.app import create_app

    store = _fresh_store()
    log = LogCapture()
    app = create_app(store, settings=Settings(), clock=lambda: WHEN, log=log.logger)
    client = WsgiClient(app)

    resp = client.get("/")
    assert resp.status == 303  # redirected to sign-in, never reaching a handler
    assert log.of_level("INFO") == []


def _fresh_store():
    from tests.conftest import FakeStore

    return FakeStore()
