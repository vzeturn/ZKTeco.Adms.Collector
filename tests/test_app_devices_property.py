"""
Property 22 (device mutations, task 7.2): a mutation applies exactly the intended change or none.

Every device mutation -- enable, disable, link, unlink-via-empty-code -- either writes exactly one
store call with the intended kwargs and touches no other device's serial, or is refused and writes
zero write-shaped store calls. A refusal never leaves behind a succeeded "device.*" audit row.
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
OTHER_SERIAL = "OTHERSERIAL002"


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


def _writes(store) -> list:
    """Every store call that mutates device or command state, excluding reads and audit."""
    return [c for c in store.calls if c.method in ("set_device_enabled", "link_device")]


# ── enable / disable: exactly the intended bool, on exactly the target serial ──────────────────────


@pytest.mark.parametrize("flag", [True, False], ids=["enable", "disable"])
@pytest.mark.usefixtures("no_socket")
def test_enable_disable_writes_exactly_the_intended_flag(store, flag: bool) -> None:
    store.add_device(_device(enabled=not flag))
    store.add_device(_device(serial=OTHER_SERIAL, enabled=not flag))
    client, csrf = _seed(store)
    route = "enable" if flag else "disable"
    resp = client.post(f"/devices/{SERIAL}/{route}", form={"csrf_token": csrf})
    assert resp.status == 303
    writes = store.calls_to("set_device_enabled")
    assert len(writes) == 1
    assert writes[0].kwargs == {"serial": SERIAL, "enabled": flag}
    assert store.audited("device.enable" if flag else "device.disable")


# ── link: known code persists exactly that code, on exactly the target serial ──────────────────────


@pytest.mark.usefixtures("no_socket")
def test_link_with_a_known_machine_code_persists_exactly_that_code(store) -> None:
    store.add_device(_device(machine_code=""))
    store.add_device(_device(serial=OTHER_SERIAL, machine_code=""))
    store.set_machines([{"code": "MC07", "name": "Dock", "numeric_id": 1, "ip": "", "status": ""}])
    client, csrf = _seed(store)
    resp = client.post(f"/devices/{SERIAL}/link", form={"csrf_token": csrf, "machine_code": "MC07"})
    assert resp.status == 303
    writes = store.calls_to("link_device")
    assert len(writes) == 1
    assert writes[0].kwargs == {"serial": SERIAL, "machine_code": "MC07"}
    assert store.audited("device.link")


@pytest.mark.usefixtures("no_socket")
def test_link_with_an_empty_code_unlinks(store) -> None:
    store.add_device(_device(machine_code="MC07"))
    store.add_device(_device(serial=OTHER_SERIAL, machine_code="MC07"))
    store.set_machines([{"code": "MC07", "name": "Dock", "numeric_id": 1, "ip": "", "status": ""}])
    client, csrf = _seed(store)
    resp = client.post(f"/devices/{SERIAL}/link", form={"csrf_token": csrf, "machine_code": ""})
    assert resp.status == 303
    writes = store.calls_to("link_device")
    assert len(writes) == 1
    assert writes[0].kwargs == {"serial": SERIAL, "machine_code": ""}
    assert store.audited("device.link")


# ── refusals write zero write-shaped calls and no succeeded "device.*" audit row ───────────────────


@pytest.mark.usefixtures("no_socket")
def test_link_with_an_unknown_machine_code_is_refused_and_writes_nothing(store) -> None:
    store.add_device(_device(machine_code=""))
    store.set_machines([{"code": "MC07", "name": "Dock", "numeric_id": 1, "ip": "", "status": ""}])
    client, csrf = _seed(store)
    resp = client.post(f"/devices/{SERIAL}/link", form={"csrf_token": csrf, "machine_code": "GHOST"})
    assert resp.status in (400, 404)
    assert not store.calls_to("link_device")
    assert not any(r.action == "device.link" and r.succeeded for r in store.audit_rows)


@pytest.mark.parametrize(
    "route", ["enable", "disable", "link"], ids=["enable", "disable", "link"],
)
@pytest.mark.usefixtures("no_socket")
def test_mutation_on_an_unknown_serial_is_404_and_writes_nothing(store, route: str) -> None:
    client, csrf = _seed(store)
    form = {"csrf_token": csrf}
    if route == "link":
        form["machine_code"] = "MC07"
    resp = client.post(f"/devices/NOPE/{route}", form=form)
    assert resp.status == 404
    assert not _writes(store)
    assert not any(
        r.action in ("device.enable", "device.disable", "device.link") and r.succeeded
        for r in store.audit_rows
    )
