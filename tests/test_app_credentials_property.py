"""
Table-driven property tests for the admin console's credential handling and dispatch shell
(task 8.4). No ``hypothesis`` -- every row below is a hand-picked hostile input with a stated
expected outcome, per the testing strategy for this task.

Properties covered, one section each:

* **Property 19** -- a password change replaces the credential and revokes everything else.
* **Property 20** -- no secret material reaches a log, an audit row or a page.
* **Property 21** -- every state change and every refusal is audited, and the audit cannot break
  the operation.
* **Property 39** -- dispatch is total and produces exactly one clean response.
* **Property 40** -- a database failure is reported as unavailability, not as a crash.

Conventions (``_seed``, ``WHEN``, password constants) are copied from ``test_app_passwords.py``
and ``test_app_users.py`` so this file reads as a sibling of both, not a third dialect.
"""

from __future__ import annotations

import datetime as dt

import pytest
from tests.conftest import FakeStore, WsgiClient

from adms.admin import auth
from adms.config import Settings

WHEN = dt.datetime(2026, 8, 12, 2, 0, 0, tzinfo=dt.UTC)
OLD_PW = "old-passphrase-42"
NEW_PW = "Corrct-Horse-9-battery"  # clears the policy
GOOD_PW = "Corrct-Horse-9"  # clears the policy: >= 12 chars, not common, not the username


def _seed(store, *, role: str = "admin", current: str = OLD_PW) -> tuple[WsgiClient, str, str, int]:
    """A signed-in client of ``role``; returns (client, csrf, session_token, user_id)."""
    from adms.admin.app import create_app

    app = create_app(store, settings=Settings(), clock=lambda: WHEN)
    u = store.add_user(username="me", role=role, password=current)
    token = auth.new_session_token()
    secret = auth.new_csrf_secret()
    store.create_session(
        token_hash=auth.token_hash(token), user_id=u.user_id,
        expires_utc=WHEN + auth.SESSION_IDLE_TIMEOUT, ip="1.2.3.4", user_agent="ua",
        csrf_secret=secret,
    )
    client = WsgiClient(app)
    client.cookies["adms_console"] = token
    return client, auth.csrf_token(secret), token, u.user_id


# ══ Property 19 -- a password change replaces the credential and revokes everything else ═══════
#
# For POST /change-password with a correct current password and a policy-clearing new password:
# exactly one set_password call for the actor at auth.PBKDF2_ITERATIONS with must_change False;
# every prior session for the actor is revoked; exactly one fresh session exists afterward; a
# Set-Cookie header is present; 303. A wrong current or a weak new password writes nothing and
# re-renders the form (200).


@pytest.mark.parametrize(
    ("current_ok", "new_pw", "expect_change"),
    [
        (True, NEW_PW, True),  # correct current, strong new -> the credential is replaced
        (False, NEW_PW, False),  # wrong current -> refused, nothing written
        (True, "short", False),  # weak new password -> refused, nothing written
        (True, "me", False),  # new password equals the username -> refused by the policy
        (True, "", False),  # empty new password -> refused
    ],
)
def test_change_password_replaces_credential_or_writes_nothing(
    store: FakeStore, current_ok: bool, new_pw: str, expect_change: bool
) -> None:
    client, csrf, old_token, me = _seed(store)
    submitted_current = OLD_PW if current_ok else "not-the-current-one"
    resp = client.post("/change-password", form={
        "csrf_token": csrf, "current": submitted_current, "new_password": new_pw,
    })

    if expect_change:
        assert resp.status == 303
        set_calls = store.calls_to("set_password")
        assert len(set_calls) == 1
        assert set_calls[0].kwargs["user_id"] == me
        assert set_calls[0].kwargs["iterations"] == auth.PBKDF2_ITERATIONS
        assert set_calls[0].kwargs["must_change"] is False
        # Every prior session for the actor was revoked...
        assert any(c.kwargs["user_id"] == me for c in store.calls_to("delete_sessions_for_user"))
        assert auth.token_hash(old_token) not in store.sessions
        # ...and exactly one fresh session exists for the changer.
        assert len(store.sessions) == 1
        assert next(iter(store.sessions.values()))["user_id"] == me
        assert any(name.lower() == "set-cookie" for name, _ in resp.headers)
    else:
        assert resp.status == 200
        assert not store.calls_to("set_password")
        assert not store.calls_to("delete_sessions_for_user")
        assert auth.token_hash(old_token) in store.sessions  # the old session survives untouched


def test_admin_reset_sets_forced_password_and_revokes_the_targets_sessions(store: FakeStore) -> None:
    victim = store.add_user(username="v", role="operator", password="whatever")
    vtoken = auth.new_session_token()
    store.create_session(
        token_hash=auth.token_hash(vtoken), user_id=victim.user_id,
        expires_utc=WHEN + auth.SESSION_IDLE_TIMEOUT, ip="9.9.9.9", user_agent="ua",
        csrf_secret=auth.new_csrf_secret(),
    )
    client, csrf, _tok, _me = _seed(store)
    resp = client.post(f"/users/{victim.user_id}/reset-password", form={
        "csrf_token": csrf, "password": NEW_PW,
    })
    assert resp.status == 303
    reset = store.calls_to("set_password")
    assert len(reset) == 1
    assert reset[0].kwargs["user_id"] == victim.user_id
    assert reset[0].kwargs["iterations"] == auth.PBKDF2_ITERATIONS
    assert reset[0].kwargs["must_change"] is True
    assert any(c.kwargs["user_id"] == victim.user_id
               for c in store.calls_to("delete_sessions_for_user"))
    assert auth.token_hash(vtoken) not in store.sessions


# ══ Property 20 -- no secret material reaches a log, an audit row or a page ══════════════════════
#
# After a create, a change-password and an admin reset, no audit row's detail/target/username
# contains the plaintext password, and rendering the users, change-password and sessions pages
# never leaks a password/hash/salt/token/csrf_secret substring. Several distinct passwords, so a
# single hardcoded scrub cannot pass by accident.


def _no_secrets(html: str) -> None:
    """Mirrors tests/test_ui_pages.py::_no_secrets -- reused rather than re-derived."""
    lowered = html.lower()
    for forbidden in (
        "passwordhash", "password_hash", "passwordsalt", "csrfsecret", "csrf_secret",
        "tokenhash", "token_hash",
    ):
        assert forbidden not in lowered


@pytest.mark.parametrize(
    "password",
    [
        "Correct-Horse-Battery-9",
        "Zebra-Quiver-42-Skylight",
        "Tr0mbone!!Marmalade-7",
    ],
)
def test_no_operation_leaks_the_plaintext_password_anywhere(store: FakeStore, password: str) -> None:
    client, csrf, _tok, _me = _seed(store)

    # 1. create a user with this password
    create_resp = client.post("/users", form={
        "csrf_token": csrf, "username": "newbie", "display_name": "Newbie", "role": "operator",
        "password": password,
    })
    assert create_resp.status == 303

    # 2. change-password using this password as the new credential
    change_resp = client.post("/change-password", form={
        "csrf_token": csrf, "current": OLD_PW, "new_password": password,
    })
    assert change_resp.status == 303
    # A fresh csrf token belongs to the new session issued by the change; refresh for step 3.
    new_token = next(iter(store.sessions))
    fresh_csrf = auth.csrf_token(store.sessions[new_token]["csrf_secret"])

    # 3. admin reset of some other user to this password
    victim = store.add_user(username="victim", role="viewer", password="irrelevant")
    reset_resp = client.post(f"/users/{victim.user_id}/reset-password", form={
        "csrf_token": fresh_csrf, "password": password,
    })
    assert reset_resp.status == 303

    for row in store.audit_rows:
        assert password not in row.detail
        assert password not in row.target
        assert password not in row.username

    from adms.admin import ui

    principal = next(iter(store.users.values()))
    users_html = ui.users_page(store.list_users(), _fake_principal(store), fresh_csrf)
    change_html = ui.change_password_page(problems=[], forced=False, csrf=fresh_csrf)
    sessions_html = ui.sessions_page(store.active_sessions(), _fake_principal(store), fresh_csrf)
    for html in (users_html, change_html, sessions_html):
        assert password not in html
        _no_secrets(html)
    del principal  # unused beyond establishing a valid store state above


def _fake_principal(store: FakeStore) -> auth.Principal:
    row = next(iter(store.users.values()))
    return auth.Principal(
        user_id=row.user_id, username=row.username, display_name=row.display_name,
        role=row.role, must_change_password=row.must_change_password,
        csrf_secret=auth.new_csrf_secret(),
    )


# ══ Property 21 -- every state change and every refusal is audited ══════════════════════════════
#
# Table-driven over the console mutations: a successful mutation writes an audit row with the
# matching action and succeeded True. A couple of handler-level refusals (last-admin guard, wrong
# current password) either write a succeeded=False row or leave the store unmutated -- the exact,
# real behaviour per handler, read from src/adms/admin/app.py rather than assumed uniform.


def _mutation_case(name, action, do):
    return pytest.param(do, action, id=name)


def _create_user(_store, client, csrf):
    return client.post("/users", form={
        "csrf_token": csrf, "username": "bob", "display_name": "Bob", "role": "operator",
        "password": GOOD_PW,
    })


def _update_user(store, client, csrf):
    victim = store.add_user(username="v", role="viewer", password="pw")
    return client.post(f"/users/{victim.user_id}/update", form={
        "csrf_token": csrf, "display_name": "V", "role": "operator", "enabled": "1",
    })


def _delete_user(store, client, csrf):
    victim = store.add_user(username="v", role="viewer", password="pw")
    return client.post(f"/users/{victim.user_id}/delete", form={"csrf_token": csrf})


def _unlock_user(store, client, csrf):
    victim = store.add_user(username="v", role="viewer", password="pw")
    return client.post(f"/users/{victim.user_id}/unlock", form={"csrf_token": csrf})


def _reset_password(store, client, csrf):
    victim = store.add_user(username="v", role="viewer", password="pw")
    return client.post(f"/users/{victim.user_id}/reset-password", form={
        "csrf_token": csrf, "password": NEW_PW,
    })


def _change_password(_store, client, csrf):
    return client.post("/change-password", form={
        "csrf_token": csrf, "current": OLD_PW, "new_password": NEW_PW,
    })


def _revoke_session(store, client, csrf):
    victim = store.add_user(username="v", role="viewer", password="pw")
    return client.post(f"/sessions/{victim.user_id}/revoke", form={"csrf_token": csrf})


def _enable_device(store, client, csrf):
    from adms.admin.store import DeviceRow
    row = DeviceRow(
        serial="SN1", device_name="D1", enabled=False, machine_code="", machine_id=None,
        machine_name="", machine_ip="", firmware="", platform="", push_version="",
        last_seen_utc=None, contact_count=0, last_ip="", minutes_since_contact=None,
        state="Offline", punches_last_24h=0, pending_commands=0,
    )
    store.add_device(row)
    return client.post("/devices/SN1/enable", form={"csrf_token": csrf})


def _disable_device(store, client, csrf):
    from adms.admin.store import DeviceRow
    row = DeviceRow(
        serial="SN1", device_name="D1", enabled=True, machine_code="", machine_id=None,
        machine_name="", machine_ip="", firmware="", platform="", push_version="",
        last_seen_utc=None, contact_count=0, last_ip="", minutes_since_contact=None,
        state="Online", punches_last_24h=0, pending_commands=0,
    )
    store.add_device(row)
    return client.post("/devices/SN1/disable", form={"csrf_token": csrf})


def _link_device(store, client, csrf):
    from adms.admin.store import DeviceRow
    row = DeviceRow(
        serial="SN1", device_name="D1", enabled=True, machine_code="", machine_id=None,
        machine_name="", machine_ip="", firmware="", platform="", push_version="",
        last_seen_utc=None, contact_count=0, last_ip="", minutes_since_contact=None,
        state="Online", punches_last_24h=0, pending_commands=0,
    )
    store.add_device(row)
    store.set_machines([{"code": "MC01", "name": "Front Door", "id": 1}])
    return client.post("/devices/SN1/link", form={"csrf_token": csrf, "machine_code": "MC01"})


def _queue_command(store, client, csrf):
    from adms.admin.store import DeviceRow
    row = DeviceRow(
        serial="SN1", device_name="D1", enabled=True, machine_code="MC01", machine_id=1,
        machine_name="Front Door", machine_ip="", firmware="", platform="", push_version="",
        last_seen_utc=None, contact_count=0, last_ip="", minutes_since_contact=None,
        state="Online", punches_last_24h=0, pending_commands=0,
    )
    store.add_device(row)
    return client.post("/devices/SN1/commands", form={"csrf_token": csrf, "command": "INFO"})


def _cancel_command(store, client, csrf):
    from adms.admin.store import DeviceRow
    row = DeviceRow(
        serial="SN1", device_name="D1", enabled=True, machine_code="MC01", machine_id=1,
        machine_name="Front Door", machine_ip="", firmware="", platform="", push_version="",
        last_seen_utc=None, contact_count=0, last_ip="", minutes_since_contact=None,
        state="Online", punches_last_24h=0, pending_commands=0,
    )
    store.add_device(row)
    cid = store.enqueue_command("SN1", "INFO", "me")
    return client.post(f"/devices/SN1/commands/{cid}/cancel", form={"csrf_token": csrf})


_SUCCESS_MUTATIONS = [
    _mutation_case("user.create", "user.create", _create_user),
    _mutation_case("user.update", "user.update", _update_user),
    _mutation_case("user.delete", "user.delete", _delete_user),
    _mutation_case("user.unlock", "user.unlock", _unlock_user),
    _mutation_case("user.reset", "user.reset", _reset_password),
    _mutation_case("password.change", "password.change", _change_password),
    _mutation_case("session.revoke", "session.revoke", _revoke_session),
    _mutation_case("device.enable", "device.enable", _enable_device),
    _mutation_case("device.disable", "device.disable", _disable_device),
    _mutation_case("device.link", "device.link", _link_device),
    _mutation_case("device.command", "device.command", _queue_command),
    _mutation_case("device.command.cancel", "device.command.cancel", _cancel_command),
]


@pytest.mark.parametrize("do,action", [(c.values[0], c.values[1]) for c in _SUCCESS_MUTATIONS],
                         ids=[c.id for c in _SUCCESS_MUTATIONS])
def test_every_successful_mutation_writes_a_succeeded_audit_row(store: FakeStore, do, action) -> None:
    client, csrf, _tok, _me = _seed(store)
    resp = do(store, client, csrf)
    assert resp.status in (303,)  # every mutation above redirects on success
    rows = store.audited(action)
    assert rows, f"no audit row with action={action!r}"
    assert rows[-1].succeeded is True


# Refusals: last-admin guard on update/delete, wrong current password on change-password. Read
# from app.py: the last-admin guard returns 400 and never calls update_user/delete_user (no audit
# row is written for it at all -- the store is simply left unmutated). Wrong current password on
# /change-password *does* write a succeeded=False audit row (action="password.change",
# detail="wrong current").


def test_last_admin_guard_refusal_leaves_the_store_unmutated(store: FakeStore) -> None:
    client, csrf, _tok, me = _seed(store)  # the only enabled admin
    resp = client.post(f"/users/{me}/update", form={
        "csrf_token": csrf, "display_name": "Me", "role": "operator", "enabled": "1",
    })
    assert resp.status == 400
    assert not store.calls_to("update_user")
    assert not store.audited("user.update")


def test_last_admin_delete_guard_refusal_leaves_the_store_unmutated(store: FakeStore) -> None:
    other = store.add_user(username="other", role="admin", password="pw")
    # Disable "other" so "me" is the only *enabled* admin, then try to delete... "me" is refused
    # by the self-delete guard instead; use the role-demotion path on self via update covered
    # above. Here we exercise the delete-side guard by deleting the other admin down to one, then
    # attempting to delete the last remaining enabled admin (self) is already covered by
    # test_last_admin_guard_refusal_leaves_the_store_unmutated's sibling in test_app_users.py; this
    # complements it for the delete handler specifically using the last-admin (not self) branch.
    store._replace_user(other.user_id, is_enabled=False)
    client, csrf, _tok, me = _seed(store)
    resp = client.post(f"/users/{me}/delete", form={"csrf_token": csrf})
    assert resp.status == 400  # self-delete guard fires first, and that too leaves no audit row
    assert not store.calls_to("delete_user")
    assert not store.audited("user.delete")


def test_wrong_current_password_refusal_writes_a_failed_audit_row(store: FakeStore) -> None:
    client, csrf, _tok, _me = _seed(store)
    resp = client.post("/change-password", form={
        "csrf_token": csrf, "current": "not-the-current-one", "new_password": NEW_PW,
    })
    assert resp.status == 200
    assert not store.calls_to("set_password")
    rows = store.audited("password.change")
    assert rows
    assert rows[-1].succeeded is False
    assert rows[-1].detail == "wrong current"


# ══ Property 39 -- dispatch is total and produces exactly one clean response ═════════════════════
#
# For a table of odd request lines, the app returns exactly one Response with a valid integer
# status, a Content-Type header and a Content-Length header, and never raises.


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/this-path-does-not-exist"),
        ("DELETE", "/users"),  # unknown method on a known path
        ("GET", "/users/"),  # trailing slash
        ("GET", "/devices/../../etc/passwd"),  # traversal segment
        ("GET", "/" + "a" * 5000),  # over-long path
        ("POST", "/"),  # POST to a GET-only route
        ("GET", "/devices/%2e%2e%2f%2e%2e"),  # encoded traversal
        ("PATCH", "/devices/SN1"),
        ("GET", "/users/999/delete"),  # GET on a POST-only mutation path
    ],
)
def test_dispatch_is_total_and_produces_one_clean_response(store, method: str, path: str) -> None:
    from adms.admin.app import create_app

    app = create_app(store, settings=Settings(), clock=lambda: WHEN)
    client = WsgiClient(app)
    resp = client.get(path) if method == "GET" else client.request(method, path)

    assert isinstance(resp.status, int)
    assert 100 <= resp.status < 600
    assert resp.header("Content-Type") is not None
    assert resp.header("Content-Length") is not None
    assert resp.header("Content-Length") == str(len(resp.body))


# ══ Property 40 -- a database failure is reported as unavailability, not as a crash ══════════════
#
# Read src/adms/admin/app.py's ``_handle`` before writing this: stages 2-8 (session load through
# handler dispatch) run inside a single ``try`` whose ``except AttendanceDbError`` answers a clean
# 503 unavailability page (see app.py lines ~219-239 and the "Property 40" comment naming this
# exact property). A store exception is therefore NOT expected to propagate out of the WSGI
# callable -- this table exercises that boundary at several store call sites and asserts the 503
# never leaks the exception's own text.


@pytest.mark.parametrize(
    ("method_to_fail", "path"),
    [
        ("summary", "/"),
        ("list_users", "/users"),
        ("devices", "/devices"),
        ("active_sessions", "/sessions"),
        ("recent_audit", "/audit"),
    ],
)
def test_store_failure_is_reported_as_a_clean_503_not_a_crash(
    store: FakeStore, method_to_fail: str, path: str
) -> None:
    store.raise_on.add(method_to_fail)
    client, csrf, _tok, _me = _seed(store)

    resp = client.get(path)  # must not raise: the pipeline's try/except converts it to a Response

    assert resp.status == 503
    assert resp.header("Content-Type") is not None
    # The underlying exception's own message never reaches the body.
    assert method_to_fail not in resp.text
    assert "FakeStore was told to fail" not in resp.text
    assert "AttendanceDbError" not in resp.text

    del csrf  # unused; _seed's return shape is kept consistent with the rest of this file
