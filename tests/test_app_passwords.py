"""
Password change and the admin reset (task 8.3): POST /change-password and the admin's reset action.

A self-service change requires the current password, applies the policy to the new one, then revokes
every session and issues one fresh session so the changer stays signed in while every other cookie
dies. A wrong current password or a policy failure re-renders the form in place (200) and writes no
password. An admin reset sets a temporary password the user must change, ends that user's sessions, and
audits the reset without ever recording the password itself.
"""

from __future__ import annotations

import datetime as dt

from tests.conftest import WsgiClient

from adms.admin import auth
from adms.config import Settings

WHEN = dt.datetime(2026, 8, 12, 2, 0, 0, tzinfo=dt.UTC)
OLD_PW = "old-passphrase-42"
NEW_PW = "Corrct-Horse-9-battery"  # clears the policy


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


# ── change-password: happy path ──────────────────────────────────────────────────────────────────


def test_change_password_replaces_the_credential_and_redirects(store) -> None:
    client, csrf, _tok, me = _seed(store)
    resp = client.post("/change-password", form={
        "csrf_token": csrf, "current": OLD_PW, "new_password": NEW_PW,
    })
    assert resp.status == 303
    set_calls = store.calls_to("set_password")
    assert len(set_calls) == 1
    assert set_calls[0].kwargs["user_id"] == me
    assert set_calls[0].kwargs["iterations"] == auth.PBKDF2_ITERATIONS
    assert set_calls[0].kwargs["must_change"] is False
    assert store.audited("password.change")


def test_change_password_revokes_every_session_then_issues_one_fresh(store) -> None:
    client, csrf, old_token, me = _seed(store)
    resp = client.post("/change-password", form={
        "csrf_token": csrf, "current": OLD_PW, "new_password": NEW_PW,
    })
    assert resp.status == 303
    # Every prior session was revoked...
    assert any(c.kwargs["user_id"] == me for c in store.calls_to("delete_sessions_for_user"))
    assert auth.token_hash(old_token) not in store.sessions
    # ...and exactly one fresh session exists for the changer, carried by a new Set-Cookie.
    assert len(store.sessions) == 1
    assert next(iter(store.sessions.values()))["user_id"] == me
    assert any(name.lower() == "set-cookie" for name, _ in resp.headers)


def test_change_password_new_cookie_is_a_working_session(store) -> None:
    client, csrf, _old, _me = _seed(store)
    client.post("/change-password", form={
        "csrf_token": csrf, "current": OLD_PW, "new_password": NEW_PW,
    })
    # The client kept the Set-Cookie; a follow-up request rides the fresh session, not a 302 to sign-in.
    resp = client.get("/")
    assert resp.status == 200


# ── change-password: refusals re-render in place, never write ────────────────────────────────────


def test_change_password_wrong_current_is_refused_and_writes_nothing(store) -> None:
    client, csrf, _tok, _me = _seed(store)
    resp = client.post("/change-password", form={
        "csrf_token": csrf, "current": "not-the-current-one", "new_password": NEW_PW,
    })
    assert resp.status == 200  # the form is shown again, not a redirect
    assert not store.calls_to("set_password")
    assert not store.calls_to("delete_sessions_for_user")


def test_change_password_weak_new_is_refused_and_never_echoed(store) -> None:
    client, csrf, _tok, _me = _seed(store)
    weak = "short"
    resp = client.post("/change-password", form={
        "csrf_token": csrf, "current": OLD_PW, "new_password": weak,
    })
    assert resp.status == 200
    assert not store.calls_to("set_password")
    assert weak not in resp.text  # a rejected password never returns to the page


def test_change_password_can_be_completed_while_forced(store) -> None:
    # A user whose password was reset carries must_change_password; they can still change it (the
    # forced-change stage lets /change-password through) and the redirect frees them.
    from adms.admin.app import create_app

    app = create_app(store, settings=Settings(), clock=lambda: WHEN)
    u = store.add_user(username="fresh", role="operator", password=OLD_PW,
                       must_change_password=True)
    token = auth.new_session_token()
    secret = auth.new_csrf_secret()
    store.create_session(
        token_hash=auth.token_hash(token), user_id=u.user_id,
        expires_utc=WHEN + auth.SESSION_IDLE_TIMEOUT, ip="1.2.3.4", user_agent="ua",
        csrf_secret=secret,
    )
    client = WsgiClient(app)
    client.cookies["adms_console"] = token
    resp = client.post("/change-password", form={
        "csrf_token": auth.csrf_token(secret), "current": OLD_PW, "new_password": NEW_PW,
    })
    assert resp.status == 303
    assert store.calls_to("set_password")[0].kwargs["must_change"] is False


# ── admin reset ──────────────────────────────────────────────────────────────────────────────────


def test_admin_reset_forces_a_change_and_ends_the_users_sessions(store) -> None:
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
    assert reset[0].kwargs["must_change"] is True
    assert any(c.kwargs["user_id"] == victim.user_id
               for c in store.calls_to("delete_sessions_for_user"))
    assert auth.token_hash(vtoken) not in store.sessions
    assert store.audited("user.reset")


def test_admin_reset_never_records_the_password_in_the_audit_row(store) -> None:
    victim = store.add_user(username="v", role="viewer", password="whatever")
    client, csrf, _tok, _me = _seed(store)
    client.post(f"/users/{victim.user_id}/reset-password", form={
        "csrf_token": csrf, "password": NEW_PW,
    })
    for row in store.audit_rows:
        assert NEW_PW not in row.detail
        assert NEW_PW not in row.target


def test_admin_reset_rejects_a_weak_password(store) -> None:
    victim = store.add_user(username="v", role="viewer", password="whatever")
    client, csrf, _tok, _me = _seed(store)
    resp = client.post(f"/users/{victim.user_id}/reset-password", form={
        "csrf_token": csrf, "password": "short",
    })
    assert resp.status == 400
    assert not store.calls_to("set_password")


def test_admin_reset_on_unknown_user_is_404(store) -> None:
    client, csrf, _tok, _me = _seed(store)
    resp = client.post("/users/999/reset-password", form={
        "csrf_token": csrf, "password": NEW_PW,
    })
    assert resp.status == 404
    assert not store.calls_to("set_password")


def test_admin_reset_with_a_non_numeric_id_is_404(store) -> None:
    client, csrf, _tok, _me = _seed(store)
    resp = client.post("/users/abc/reset-password", form={
        "csrf_token": csrf, "password": NEW_PW,
    })
    assert resp.status == 404
    assert not store.calls_to("set_password")
