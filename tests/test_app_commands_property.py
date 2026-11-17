"""
Properties 24 and 25 (device commands, task 7.4): a command row exists iff the request was permitted,
and cancelling reaches only what has not been dispatched.

Property 24 drives a table over role, command value and confirm state and asserts the enqueue call
count is exactly 1 for the one permitted-and-final case per row, 0 otherwise. Property 25 exercises
``cancel_command`` sequentially against the FakeStore's real pending-only behaviour.
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


# ── Property 24: a command row exists iff the request was permitted ────────────────────────────────

_CASES = (
    [("operator", v, False, True, {200, 303}) for v in SAFE]
    + [("operator", v, False, False, {403}) for v in DESTRUCTIVE]
    + [("admin", v, False, False, {200}) for v in DESTRUCTIVE]
    + [("admin", v, True, True, {303}) for v in DESTRUCTIVE]
)
_IDS = (
    [f"safe-operator-{v}" for v in SAFE]
    + [f"destructive-operator-refused-{v}" for v in DESTRUCTIVE]
    + [f"destructive-admin-unconfirmed-{v}" for v in DESTRUCTIVE]
    + [f"destructive-admin-confirmed-{v}" for v in DESTRUCTIVE]
)


@pytest.mark.parametrize(("role", "value", "confirm", "expected_enqueue", "ok_statuses"), _CASES, ids=_IDS)
def test_a_command_row_exists_iff_the_request_is_permitted_and_final(
    store, role: str, value: str, confirm: bool, expected_enqueue: bool, ok_statuses: set[int]
) -> None:
    store.add_device(_device())
    client, csrf = _seed(store, role)
    form = {"csrf_token": csrf, "command": value}
    if confirm:
        form["confirm"] = "1"
    resp = client.post(f"/devices/{SERIAL}/commands", form=form)
    assert resp.status in ok_statuses
    assert len(store.calls_to("enqueue_command")) == (1 if expected_enqueue else 0)
    if expected_enqueue:
        assert store.calls_to("enqueue_command")[0].kwargs["body"] == value
        assert store.audited("device.command")


def test_free_text_outside_the_allow_list_is_refused(store) -> None:
    store.add_device(_device())
    client, csrf = _seed(store, "admin")
    resp = client.post(
        f"/devices/{SERIAL}/commands", form={"csrf_token": csrf, "command": "rm -rf /"}
    )
    assert resp.status == 400
    assert not store.calls_to("enqueue_command")


@pytest.mark.parametrize("value", SAFE + DESTRUCTIVE, ids=lambda v: f"disabled-{v}")
def test_any_command_against_a_disabled_device_is_refused(store, value: str) -> None:
    store.add_device(_device(enabled=False))
    client, csrf = _seed(store, "admin")
    resp = client.post(
        f"/devices/{SERIAL}/commands", form={"csrf_token": csrf, "command": value, "confirm": "1"}
    )
    assert resp.status == 400
    assert not store.calls_to("enqueue_command")


# ── Property 25: cancelling reaches only what has not been dispatched ──────────────────────────────


def test_cancel_sequence_pending_then_recancel(store) -> None:
    store.add_device(_device())
    cid = store.enqueue_command(SERIAL, "REBOOT", "someone")
    client, csrf = _seed(store, "operator")

    # First cancel: the command is still Pending -- cancel_command returns True, audited as success.
    resp = client.post(f"/devices/{SERIAL}/commands/{cid}/cancel", form={"csrf_token": csrf})
    assert resp.status == 303
    first_cancel = store.calls_to("cancel_command")
    assert len(first_cancel) == 1
    assert first_cancel[0].kwargs["command_id"] == cid
    cancel_audits = store.audited("device.command.cancel")
    assert len(cancel_audits) == 1
    assert cancel_audits[0].succeeded is True

    # Re-cancel the same id: FakeStore's own logic returns False, no crash, still audited (as a
    # failure this time) -- don't mock cancel_command, exercise its real pending-only behaviour.
    resp = client.post(f"/devices/{SERIAL}/commands/{cid}/cancel", form={"csrf_token": csrf})
    assert resp.status == 303
    second_cancel = store.calls_to("cancel_command")
    assert len(second_cancel) == 2
    cancel_audits = store.audited("device.command.cancel")
    assert len(cancel_audits) == 2
    assert cancel_audits[-1].succeeded is False


@pytest.mark.parametrize("command_id", ["999"], ids=["absent-id"])
def test_cancel_of_an_absent_id_returns_false_and_redirects_without_crash(store, command_id: str) -> None:
    store.add_device(_device())
    client, csrf = _seed(store, "operator")
    resp = client.post(f"/devices/{SERIAL}/commands/{command_id}/cancel", form={"csrf_token": csrf})
    assert resp.status == 303
    calls = store.calls_to("cancel_command")
    assert len(calls) == 1
    assert calls[0].kwargs["command_id"] == int(command_id)


@pytest.mark.parametrize("command_id", ["abc"], ids=["non-numeric-id"])
def test_cancel_with_a_non_numeric_id_is_404_and_calls_nothing(store, command_id: str) -> None:
    store.add_device(_device())
    client, csrf = _seed(store, "operator")
    resp = client.post(f"/devices/{SERIAL}/commands/{command_id}/cancel", form={"csrf_token": csrf})
    assert resp.status == 404
    assert not store.calls_to("cancel_command")
