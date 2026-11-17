"""
Device operations (task 7.1): enable, disable (with a confirm interstitial), and link/unlink.

Each mutation is an operator capability, needs a valid CSRF token, writes exactly one audit row, and
answers ``303`` -- never a rendered page in place, so a refresh cannot replay it. Linking validates the
machine code against ``machines()`` and refuses an unknown one; an empty code unlinks. A handler talks
only to the store: it must open no socket to the device, which the tests enforce by making any socket
construction during the call raise.
"""

from __future__ import annotations

import datetime as dt
import socket

import pytest
from tests.conftest import WsgiClient

from adms.admin import auth
from adms.admin.store import DeviceRow
from adms.config import Settings

WHEN = dt.datetime(2026, 8, 12, 2, 0, 0, tzinfo=dt.UTC)
SERIAL = "CJXX204960333"


def _device(serial: str = SERIAL, **over: object) -> DeviceRow:
    base = {
        "serial": serial, "device_name": f"dev-{serial}", "enabled": True, "machine_code": "MC01",
        "machine_id": 1, "machine_name": "Front Door", "machine_ip": "10.0.0.9",
        "firmware": "Ver 6.60", "platform": "ZMM220", "push_version": "2.4.1", "last_seen_utc": WHEN,
        "contact_count": 42, "last_ip": "10.0.0.9", "minutes_since_contact": 3, "state": "Online",
        "punches_last_24h": 17, "pending_commands": 1,
    }
    return DeviceRow(**{**base, **over})  # type: ignore[arg-type]


def _seed(store, role: str = "operator") -> tuple[WsgiClient, str]:
    """A signed-in client of ``role`` plus that session's CSRF token."""
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
    client = WsgiClient(app)
    client.cookies["adms_console"] = token
    return client, auth.csrf_token(secret)


@pytest.fixture
def no_socket(monkeypatch):
    """Make any socket construction during a handler explode, proving the handler stays off the wire."""
    def _boom(*_a, **_k):
        raise AssertionError("a device handler opened a socket")

    monkeypatch.setattr(socket, "socket", _boom)


# ── enable ────────────────────────────────────────────────────────────────────────────────────────


@pytest.mark.usefixtures("no_socket")
def test_enable_flips_the_flag_audits_and_redirects(store) -> None:
    store.add_device(_device(enabled=False))
    client, csrf = _seed(store)
    resp = client.post(f"/devices/{SERIAL}/enable", form={"csrf_token": csrf})
    assert resp.status == 303
    assert resp.location == f"/devices/{SERIAL}"
    assert ("set_device_enabled", True) in [
        (c.method, c.kwargs.get("enabled")) for c in store.calls if c.method == "set_device_enabled"
    ]
    assert store.audited("device.enable")


# ── disable: a confirm page first, then the mutation ───────────────────────────────────────────────


@pytest.mark.usefixtures("no_socket")
def test_disable_confirm_is_a_page_not_a_mutation(store) -> None:
    store.add_device(_device())
    client, _csrf = _seed(store)
    resp = client.get(f"/devices/{SERIAL}/confirm")
    assert resp.status == 200
    assert SERIAL in resp.text
    assert not any(c.method == "set_device_enabled" for c in store.calls)


@pytest.mark.usefixtures("no_socket")
def test_disable_flips_the_flag_audits_and_redirects(store) -> None:
    store.add_device(_device(enabled=True))
    client, csrf = _seed(store)
    resp = client.post(f"/devices/{SERIAL}/disable", form={"csrf_token": csrf})
    assert resp.status == 303
    assert ("set_device_enabled", False) in [
        (c.method, c.kwargs.get("enabled")) for c in store.calls if c.method == "set_device_enabled"
    ]
    assert store.audited("device.disable")


# ── link / unlink, validated against machines() ────────────────────────────────────────────────────


@pytest.mark.usefixtures("no_socket")
def test_link_to_a_known_machine_code_persists_and_redirects(store) -> None:
    store.add_device(_device(machine_code=""))
    store.set_machines([{"code": "MC07", "name": "Dock", "numeric_id": 1, "ip": "", "status": ""}])
    client, csrf = _seed(store)
    resp = client.post(f"/devices/{SERIAL}/link", form={"csrf_token": csrf, "machine_code": "MC07"})
    assert resp.status == 303
    assert ("link_device", "MC07") in [
        (c.method, c.kwargs.get("machine_code")) for c in store.calls if c.method == "link_device"
    ]
    assert store.audited("device.link")


@pytest.mark.usefixtures("no_socket")
def test_link_to_an_unknown_machine_code_is_refused_and_writes_nothing(store) -> None:
    store.add_device(_device(machine_code=""))
    store.set_machines([{"code": "MC07", "name": "Dock", "numeric_id": 1, "ip": "", "status": ""}])
    client, csrf = _seed(store)
    resp = client.post(f"/devices/{SERIAL}/link", form={"csrf_token": csrf, "machine_code": "GHOST"})
    assert resp.status in (400, 404)  # refused, not a redirect
    assert not any(c.method == "link_device" for c in store.calls)


@pytest.mark.usefixtures("no_socket")
def test_empty_machine_code_unlinks(store) -> None:
    store.add_device(_device(machine_code="MC07"))
    store.set_machines([{"code": "MC07", "name": "Dock", "numeric_id": 1, "ip": "", "status": ""}])
    client, csrf = _seed(store)
    resp = client.post(f"/devices/{SERIAL}/link", form={"csrf_token": csrf, "machine_code": ""})
    assert resp.status == 303
    assert ("link_device", "") in [
        (c.method, c.kwargs.get("machine_code")) for c in store.calls if c.method == "link_device"
    ]
    assert store.audited("device.link")


# ── a mutation on an unknown serial is a 404, and mutates nothing ──────────────────────────────────


@pytest.mark.usefixtures("no_socket")
def test_mutation_on_unknown_serial_is_404(store) -> None:
    client, csrf = _seed(store)
    resp = client.post("/devices/NOPE/enable", form={"csrf_token": csrf})
    assert resp.status == 404
    assert not any(c.method == "set_device_enabled" for c in store.calls)
