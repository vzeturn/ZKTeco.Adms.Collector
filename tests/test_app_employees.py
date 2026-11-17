"""
Employee device-admin routes (grant/revoke): GET /employees, POST /employees/lookup, and the
grant/revoke POSTs.

These are administer-capability, CSRF-guarded actions. The tests here cover what the generic authz
and CSRF suites cannot: PIN and password validation at the boundary, that grant/revoke reach the
store with the right arguments, that the acting audit row is written and never carries the password,
and that the result page reports how many devices were queued.
"""

from __future__ import annotations

import datetime as dt

from tests.conftest import DeviceRow, WsgiClient

from adms.admin import auth
from adms.config import Settings

WHEN = dt.datetime(2026, 8, 12, 2, 0, 0, tzinfo=dt.UTC)


def _seed(store, role: str = "admin") -> tuple[WsgiClient, str]:
    from adms.admin.app import create_app

    app = create_app(store, settings=Settings(), clock=lambda: WHEN)
    u = store.add_user(username="me", role=role, password="pw")
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


def _device(serial: str, *, enabled: bool = True) -> DeviceRow:
    return DeviceRow(
        serial=serial, device_name=serial, enabled=enabled, machine_code="", machine_id=None,
        machine_name="", machine_ip="", firmware="", platform="", push_version="",
        last_seen_utc=None, contact_count=0, last_ip="", minutes_since_contact=None,
        state="Online", punches_last_24h=0, pending_commands=0,
    )


# ── GET /employees renders the lookup form ───────────────────────────────────────────────────────


def test_get_employees_shows_lookup_form(store) -> None:
    client, _csrf = _seed(store)
    resp = client.get("/employees")
    assert resp.status == 200
    assert "/employees/lookup" in resp.text
    assert 'name="pin"' in resp.text


# ── lookup ───────────────────────────────────────────────────────────────────────────────────────


def test_lookup_shows_employee_and_grant_control(store) -> None:
    store.add_employee(pin=202120, name="Operator", card="C1", privilege=0)
    client, csrf = _seed(store)
    resp = client.post("/employees/lookup", form={"csrf_token": csrf, "pin": "202120"})
    assert resp.status == 200
    assert "Operator" in resp.text
    assert "/employees/202120/grant-admin" in resp.text  # a non-admin offers Grant


def test_lookup_of_admin_offers_revoke(store) -> None:
    store.add_employee(pin=202120, name="Admin One", privilege=3)
    client, csrf = _seed(store)
    resp = client.post("/employees/lookup", form={"csrf_token": csrf, "pin": "202120"})
    assert "/employees/202120/revoke-admin" in resp.text


def test_lookup_unknown_pin_is_404(store) -> None:
    client, csrf = _seed(store)
    resp = client.post("/employees/lookup", form={"csrf_token": csrf, "pin": "999999"})
    assert resp.status == 404


def test_lookup_non_numeric_pin_is_400(store) -> None:
    client, csrf = _seed(store)
    resp = client.post("/employees/lookup", form={"csrf_token": csrf, "pin": "abc"})
    assert resp.status == 400


# ── grant / revoke reach the store ───────────────────────────────────────────────────────────────


def test_grant_calls_store_and_reports_devices_queued(store) -> None:
    store.add_employee(pin=202120, name="Operator", card="C1", privilege=0)
    store.add_device(_device("A"))
    store.add_device(_device("B"))
    client, csrf = _seed(store)
    resp = client.post("/employees/202120/grant-admin", form={"csrf_token": csrf})

    assert resp.status == 200
    call = store.calls_to("set_employee_admin")[0]
    assert call.kwargs["pin"] == 202120
    assert call.kwargs["is_admin"] is True
    assert call.kwargs["has_password"] is False
    assert "queued for 2 devices" in resp.text
    # The employee now reads as an admin on the returned page.
    assert store.get_employee(202120).is_admin is True


def test_revoke_calls_store_with_is_admin_false(store) -> None:
    store.add_employee(pin=202120, name="Admin One", privilege=3)
    client, csrf = _seed(store)
    resp = client.post("/employees/202120/revoke-admin", form={"csrf_token": csrf})
    assert resp.status == 200
    assert store.calls_to("set_employee_admin")[0].kwargs["is_admin"] is False


def test_grant_with_password_passes_it_to_store(store) -> None:
    store.add_employee(pin=8888, name="Eight", privilege=0)
    client, csrf = _seed(store)
    resp = client.post("/employees/8888/grant-admin", form={"csrf_token": csrf, "password": "8888"})
    assert resp.status == 200
    assert store.calls_to("set_employee_admin")[0].kwargs["has_password"] is True
    assert store.device_passwords[8888] == 8888


# ── password validation ──────────────────────────────────────────────────────────────────────────


def test_non_numeric_password_is_400_and_store_untouched(store) -> None:
    store.add_employee(pin=8888, name="Eight", privilege=0)
    client, csrf = _seed(store)
    resp = client.post("/employees/8888/grant-admin", form={"csrf_token": csrf, "password": "letmein"})
    assert resp.status == 400
    assert not store.calls_to("set_employee_admin")


def test_too_long_password_is_400(store) -> None:
    store.add_employee(pin=8888, privilege=0)
    client, csrf = _seed(store)
    resp = client.post("/employees/8888/grant-admin", form={"csrf_token": csrf, "password": "123456789"})
    assert resp.status == 400


def test_blank_password_field_leaves_password_alone(store) -> None:
    store.add_employee(pin=202120, privilege=0)
    client, csrf = _seed(store)
    client.post("/employees/202120/grant-admin", form={"csrf_token": csrf, "password": ""})
    assert store.calls_to("set_employee_admin")[0].kwargs["has_password"] is False
    assert 202120 not in store.device_passwords


# ── audit never carries the password ─────────────────────────────────────────────────────────────


def test_grant_writes_audit_without_password(store) -> None:
    store.add_employee(pin=8888, name="Eight", privilege=0)
    client, csrf = _seed(store)
    client.post("/employees/8888/grant-admin", form={"csrf_token": csrf, "password": "8888"})

    rows = store.audited("employee.grant_admin")
    assert len(rows) == 1
    assert rows[0].target == "8888"
    # The device password must appear in no field of the audit row.
    assert "8888" not in rows[0].detail
    assert rows[0].detail == ""


def test_revoke_writes_revoke_audit(store) -> None:
    store.add_employee(pin=202120, privilege=3)
    client, csrf = _seed(store)
    client.post("/employees/202120/revoke-admin", form={"csrf_token": csrf})
    assert len(store.audited("employee.revoke_admin")) == 1


# ── grant of an unknown PIN never touches the store ──────────────────────────────────────────────


def test_grant_unknown_pin_is_404_and_no_write(store) -> None:
    client, csrf = _seed(store)
    resp = client.post("/employees/999999/grant-admin", form={"csrf_token": csrf})
    assert resp.status == 404
    assert not store.calls_to("set_employee_admin")
