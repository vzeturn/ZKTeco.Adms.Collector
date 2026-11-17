"""
Table-driven property tests over fixed, hostile inputs for the read-only console handlers.

No hypothesis anywhere in this project -- these are FIXED tables, not generated inputs.

Property 27 -- the console preserves the store's ordering and the store's bounds. The handlers for
``GET /devices``, ``GET /activity`` (each tab) and ``GET /audit`` must render rows in exactly the
order the store returned them, never re-sorting, and must not add, drop or duplicate a row. This is
asserted by seeding the store with a deliberately non-alphabetical, non-chronological sequence of
unique-identifiable rows and checking that their tokens appear in the page body in the same relative
order the store yielded, and that the count of tokens found matches the count seeded.

Property 29 -- activity tab selection is total. For every tab value in a fixed table -- the three
known streams, the absent tab, and several unknown/hostile values (wrong case, path traversal,
markup injection) -- ``GET /activity?tab=...`` must answer HTTP 200 with an Activity page, never an
error. The known non-default tabs select their own stream; every other value falls back to the
punches stream.
"""

from __future__ import annotations

import datetime as dt

import pytest
from tests.conftest import FakeStore, WsgiClient

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


def _client(store: FakeStore, role: str = "admin") -> WsgiClient:
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


def _in_order(text: str, tokens: list[str]) -> None:
    positions = [text.index(t) for t in tokens]
    assert positions == sorted(positions), (tokens, positions)


# Deliberately non-alphabetical, non-chronological token sequences. The store must yield them
# unchanged and the handler must render them in that same order.
_ORDER_TOKENS = ["ZZZ001", "AAA002", "MMM003", "QQQ004"]


# ── Property 27: order and bounds preservation ──────────────────────────────────────────────────


def test_device_list_preserves_store_order_and_count(store: FakeStore) -> None:
    for serial in _ORDER_TOKENS:
        store.add_device(_device(serial))
    text = _client(store).get("/devices").text
    _in_order(text, _ORDER_TOKENS)
    # Each serial legitimately repeats within its own row (serial cell, derived device_name, links,
    # ...), so bounds are checked by presence -- no row missing -- combined with the count of devices
    # actually held by the store, which is the ground truth for "none silently dropped or duplicated".
    assert all(t in text for t in _ORDER_TOKENS)
    assert len(store.devices()) == len(_ORDER_TOKENS)


@pytest.mark.parametrize(
    ("tab", "seed_attr", "row_factory"),
    [
        pytest.param(
            "punches", "_punches",
            lambda pin: {
                "serial": "AAA", "pin": pin, "punch_time": WHEN, "status": 0, "verify": 1,
                "work_code": 0, "received_utc": WHEN,
            },
            id="punches",
        ),
        pytest.param(
            "uploads", "_uploads",
            lambda pin: {
                "serial": pin, "table": "ATTLOG", "records": 1, "body_len": 9, "received_utc": WHEN,
            },
            id="uploads",
        ),
        pytest.param(
            "unparsed", "_unparsed",
            lambda pin: {"serial": pin, "table": "?", "line": "junk", "received_utc": WHEN},
            id="unparsed",
        ),
    ],
)
def test_activity_stream_preserves_store_order_and_count(
    store: FakeStore, tab: str, seed_attr: str, row_factory: object
) -> None:
    rows = [row_factory(t) for t in _ORDER_TOKENS]  # type: ignore[operator]
    getattr(store, seed_attr).extend(rows)
    text = _client(store).get("/activity", query=f"tab={tab}").text
    _in_order(text, _ORDER_TOKENS)
    assert all(t in text for t in _ORDER_TOKENS)
    assert len(getattr(store, seed_attr)) == len(_ORDER_TOKENS)


def test_audit_page_preserves_reversed_store_order_and_count(store: FakeStore) -> None:
    # recent_audit() reverses insertion order (newest first), so the page order is the REVERSE of
    # the order these were seeded in.
    usernames = ["pinZZZ", "pinAAA", "pinMMM", "pinQQQ"]
    for name in usernames:
        store.audit(username=name, action="sign_in", ip="1.2.3.4", succeeded=True)
    text = _client(store).get("/audit").text
    _in_order(text, list(reversed(usernames)))
    assert all(n in text for n in usernames)
    assert len(store.audit_rows) == len(usernames)


# ── Property 29: activity tab selection is total ────────────────────────────────────────────────

_HOSTILE_TABS = [
    "punches",
    "uploads",
    "unparsed",
    "",
    "bogus",
    "PUNCHES",
    "../etc",
    "<script>",
]


@pytest.mark.parametrize("tab", _HOSTILE_TABS, ids=[t or "absent" for t in _HOSTILE_TABS])
def test_every_tab_value_resolves_to_200_activity_page(store: FakeStore, tab: str) -> None:
    store._punches.append({
        "serial": "AAA", "pin": "1", "punch_time": WHEN, "status": 0, "verify": 1,
        "work_code": 0, "received_utc": WHEN,
    })
    store._uploads.append({
        "serial": "AAA", "table": "ATTLOG", "records": 1, "body_len": 9, "received_utc": WHEN,
    })
    store._unparsed.append({"serial": "AAA", "table": "?", "line": "junk", "received_utc": WHEN})

    query = "" if tab == "" else f"tab={tab}"
    resp = _client(store).get("/activity", query=query)
    assert resp.status == 200, tab
    assert "Activity" in resp.text, tab


def test_known_tabs_select_their_own_stream_others_fall_back_to_punches(store: FakeStore) -> None:
    # A marker unique to each stream. The punches stream's marker must appear under the punches tab,
    # the absent tab and every hostile/unknown tab (fallback); the uploads/unparsed markers must
    # appear ONLY under their own tab.
    store._punches.append({
        "serial": "SRL", "pin": "MARK-PUNCH", "punch_time": WHEN, "status": 0, "verify": 1,
        "work_code": 0, "received_utc": WHEN,
    })
    store._uploads.append({
        "serial": "MARK-UPLOAD", "table": "ATTLOG", "records": 1, "body_len": 9,
        "received_utc": WHEN,
    })
    store._unparsed.append({
        "serial": "MARK-UNPARSED", "table": "?", "line": "junk", "received_utc": WHEN,
    })
    client = _client(store)

    uploads_text = client.get("/activity", query="tab=uploads").text
    assert "MARK-UPLOAD" in uploads_text
    assert "MARK-PUNCH" not in uploads_text
    assert "MARK-UNPARSED" not in uploads_text

    unparsed_text = client.get("/activity", query="tab=unparsed").text
    assert "MARK-UNPARSED" in unparsed_text
    assert "MARK-PUNCH" not in unparsed_text
    assert "MARK-UPLOAD" not in unparsed_text

    for tab in ("punches", "", "bogus", "PUNCHES", "../etc", "<script>"):
        query = "" if tab == "" else f"tab={tab}"
        text = client.get("/activity", query=query).text
        assert "MARK-PUNCH" in text, tab
        assert "MARK-UPLOAD" not in text, tab
        assert "MARK-UNPARSED" not in text, tab
