"""
The sessions page and revocation (task 8.3): GET /sessions and POST /sessions/{user_id}/revoke.

An admin can read the live sessions and end all of a user's sessions with one action. Revoking your own
sessions signs you out: the response clears the cookie and redirects to sign-in, so an admin who revokes
themselves does not keep riding a now-dead cookie. Revocation is audited; the token itself never shows.
"""

from __future__ import annotations

import datetime as dt

from tests.conftest import WsgiClient

from adms.admin import auth
from adms.config import Settings

WHEN = dt.datetime(2026, 8, 12, 2, 0, 0, tzinfo=dt.UTC)


def _seed(store, *, role: str = "admin") -> tuple[WsgiClient, str, int]:
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
    return client, auth.csrf_token(secret), u.user_id


def _session_for(store, user_id: int) -> bytes:
    token = auth.new_session_token()
    th = auth.token_hash(token)
    store.create_session(
        token_hash=th, user_id=user_id, expires_utc=WHEN + auth.SESSION_IDLE_TIMEOUT,
        ip="9.9.9.9", user_agent="ua", csrf_secret=auth.new_csrf_secret(),
    )
    return th


# ── GET /sessions ────────────────────────────────────────────────────────────────────────────────


def test_sessions_page_lists_active_sessions(store) -> None:
    other = store.add_user(username="minh.le", role="operator", password="pw")
    _session_for(store, other.user_id)
    client, _csrf, _me = _seed(store)
    resp = client.get("/sessions")
    assert resp.status == 200
    assert "minh.le" in resp.text


# ── POST /sessions/{user_id}/revoke ──────────────────────────────────────────────────────────────


def test_revoke_ends_all_of_a_users_sessions_and_redirects(store) -> None:
    other = store.add_user(username="o", role="operator", password="pw")
    other_session = _session_for(store, other.user_id)
    client, csrf, _me = _seed(store)
    resp = client.post(f"/sessions/{other.user_id}/revoke", form={"csrf_token": csrf})
    assert resp.status == 303
    assert resp.location == "/sessions"
    assert any(c.kwargs["user_id"] == other.user_id
               for c in store.calls_to("delete_sessions_for_user"))
    assert other_session not in store.sessions
    assert store.audited("session.revoke")


def test_revoke_leaves_other_users_sessions_untouched(store) -> None:
    a = store.add_user(username="a", role="operator", password="pw")
    b = store.add_user(username="b", role="operator", password="pw")
    a_session = _session_for(store, a.user_id)
    b_session = _session_for(store, b.user_id)
    client, csrf, _me = _seed(store)
    client.post(f"/sessions/{a.user_id}/revoke", form={"csrf_token": csrf})
    assert a_session not in store.sessions
    assert b_session in store.sessions  # only a's sessions ended


def test_revoking_yourself_signs_you_out(store) -> None:
    # An admin who revokes their own user is signed out: cookie cleared, redirect to sign-in.
    client, csrf, me = _seed(store)
    resp = client.post(f"/sessions/{me}/revoke", form={"csrf_token": csrf})
    assert resp.status == 303
    assert resp.location == "/sign-in"
    cookie = next((v for name, v in resp.headers if name.lower() == "set-cookie"), "")
    assert "Max-Age=0" in cookie  # the session cookie is cleared
    assert not any(s["user_id"] == me for s in store.sessions.values())


def test_revoke_with_a_non_numeric_id_is_404(store) -> None:
    client, csrf, _me = _seed(store)
    resp = client.post("/sessions/abc/revoke", form={"csrf_token": csrf})
    assert resp.status == 404
    assert not store.calls_to("delete_sessions_for_user")


def test_a_rendered_revoke_form_clears_the_real_csrf_gate(store) -> None:
    # End-to-end guard against a field-name drift: the hidden token a page renders must be the field
    # the CSRF gate reads. Extract the token and action from the *rendered* page and post them back;
    # if the name or value disagreed with the gate, the request would be the "This form expired" 400.
    import re

    other = store.add_user(username="o", role="operator", password="pw")
    _session_for(store, other.user_id)
    client, _csrf, _me = _seed(store)
    page = client.get("/sessions").text
    form = re.search(r"<form\b[^>]*action=\"(/sessions/[0-9a-fA-F-]+/revoke)\".*?</form>", page, re.DOTALL)
    assert form is not None
    action = form.group(1)
    field = re.search(r'name="([^"]+)"[^>]*value="([^"]+)"', form.group(0))
    assert field is not None
    resp = client.post(action, form={field.group(1): field.group(2)})
    assert "This form expired" not in resp.text
    assert resp.status == 303
