"""
Device commands (task 7.3): a fixed allow-list, a destructive-command gate, and pending-only cancel.

Only a value in ``COMMAND_ALLOWLIST`` is ever queued -- no free text reaches the device. A destructive
member needs the destructive capability and still passes a confirm page that names the device and what
it erases. A disabled device refuses every command. Cancel touches a command only while it is pending.
"""

from __future__ import annotations

import datetime as dt

import pytest
from tests.conftest import WsgiClient

from adms.admin import auth
from adms.admin.app import COMMAND_ALLOWLIST
from adms.admin.store import DeviceRow
from adms.config import Settings

WHEN = dt.datetime(2026, 8, 12, 2, 0, 0, tzinfo=dt.UTC)
SERIAL = "CJXX204960333"

SAFE = [v for v, destructive in COMMAND_ALLOWLIST.items() if not destructive]
DESTRUCTIVE = [v for v, destructive in COMMAND_ALLOWLIST.items() if destructive]


def _device(**over: object) -> DeviceRow:
    base = {
        "serial": SERIAL, "device_name": "Lobby", "enabled": True, "machine_code": "MC01",
        "machine_id": 1, "machine_name": "Front Door", "machine_ip": "10.0.0.9",
        "firmware": "Ver 6.60", "platform": "ZMM220", "push_version": "2.4.1", "last_seen_utc": WHEN,
        "contact_count": 42, "last_ip": "10.0.0.9", "minutes_since_contact": 3, "state": "Online",
        "punches_last_24h": 17, "pending_commands": 0,
    }
    return DeviceRow(**{**base, **over})  # type: ignore[arg-type]


def _seed(store, role: str = "operator") -> tuple[WsgiClient, str]:
    from adms.admin.app import create_app

    app = create_app(store, settings=Settings(), clock=lambda: WHEN)
    u = store.add_user(username="u", role=role, password="pw")
    token = auth.new_session_token()
    secret = auth.new_csrf_secret()
    store.create_session(
        token_hash=auth.token_hash(token), user_id=u.user_id,
        expires_utc=WHEN + auth.SESSION_IDLE_TIMEOUT, ip="1.2.3.4", user_agent="ua",
        csrf_secret=secret,
    )
    c = WsgiClient(app)
    c.cookies["adms_console"] = token
    return c, auth.csrf_token(secret)


# ── the allow-list gates what can be queued ────────────────────────────────────────────────────────


@pytest.mark.parametrize("value", SAFE)
def test_a_safe_allowed_command_queues_audits_and_redirects(store, value: str) -> None:
    store.add_device(_device())
    client, csrf = _seed(store, "operator")
    resp = client.post(f"/devices/{SERIAL}/commands", form={"csrf_token": csrf, "command": value})
    assert resp.status == 303
    queued = [c for c in store.calls if c.method == "enqueue_command"]
    assert len(queued) == 1 and queued[0].kwargs["body"] == value
    assert store.audited("device.command")


def test_free_text_outside_the_allow_list_is_refused(store) -> None:
    store.add_device(_device())
    client, csrf = _seed(store, "admin")  # admin so a capability gate cannot mask the allow-list gate
    resp = client.post(
        f"/devices/{SERIAL}/commands", form={"csrf_token": csrf, "command": "rm -rf /"}
    )
    assert resp.status == 400
    assert not any(c.method == "enqueue_command" for c in store.calls)


# ── the destructive gate ───────────────────────────────────────────────────────────────────────────


def test_operator_cannot_queue_a_destructive_command(store) -> None:
    store.add_device(_device())
    client, csrf = _seed(store, "operator")
    resp = client.post(
        f"/devices/{SERIAL}/commands", form={"csrf_token": csrf, "command": DESTRUCTIVE[0]}
    )
    assert resp.status == 403
    assert not any(c.method == "enqueue_command" for c in store.calls)


def test_destructive_command_needs_a_confirm_before_it_queues(store) -> None:
    store.add_device(_device())
    client, csrf = _seed(store, "admin")
    # First POST, unconfirmed: a confirm page naming the device and the loss, no enqueue yet.
    resp = client.post(
        f"/devices/{SERIAL}/commands", form={"csrf_token": csrf, "command": DESTRUCTIVE[0]}
    )
    assert resp.status == 200
    assert SERIAL in resp.text
    assert not any(c.method == "enqueue_command" for c in store.calls)


def test_confirmed_destructive_command_queues(store) -> None:
    store.add_device(_device())
    client, csrf = _seed(store, "admin")
    resp = client.post(
        f"/devices/{SERIAL}/commands",
        form={"csrf_token": csrf, "command": DESTRUCTIVE[0], "confirm": "1"},
    )
    assert resp.status == 303
    assert any(c.method == "enqueue_command" for c in store.calls)
    assert store.audited("device.command")


# ── a disabled device refuses every command ────────────────────────────────────────────────────────


def test_a_disabled_device_refuses_commands(store) -> None:
    store.add_device(_device(enabled=False))
    client, csrf = _seed(store, "admin")
    resp = client.post(f"/devices/{SERIAL}/commands", form={"csrf_token": csrf, "command": SAFE[0]})
    assert resp.status == 400
    assert not any(c.method == "enqueue_command" for c in store.calls)


# ── cancel is pending-only ─────────────────────────────────────────────────────────────────────────


def test_cancel_removes_a_pending_command_and_redirects(store) -> None:
    store.add_device(_device())
    cid = store.enqueue_command(SERIAL, "REBOOT", "someone")
    client, csrf = _seed(store, "operator")
    resp = client.post(
        f"/devices/{SERIAL}/commands/{cid}/cancel", form={"csrf_token": csrf}
    )
    assert resp.status == 303
    assert any(c.method == "cancel_command" and c.kwargs["command_id"] == cid for c in store.calls)
    assert store.audited("device.command.cancel")


def test_cancel_of_a_non_pending_command_still_redirects_without_error(store) -> None:
    store.add_device(_device())
    client, csrf = _seed(store, "operator")
    # A command id that is not pending (never existed): cancel_command returns False, no crash.
    resp = client.post(f"/devices/{SERIAL}/commands/999/cancel", form={"csrf_token": csrf})
    assert resp.status == 303


def test_cancel_with_a_non_numeric_id_is_404_not_a_500(store) -> None:
    # The route regex admits letters, so a non-numeric id reaches the handler; it must not int()-crash.
    store.add_device(_device())
    client, csrf = _seed(store, "operator")
    resp = client.post(f"/devices/{SERIAL}/commands/abc/cancel", form={"csrf_token": csrf})
    assert resp.status == 404
    assert not any(c.method == "cancel_command" for c in store.calls)
