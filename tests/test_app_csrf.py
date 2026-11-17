"""
The CSRF stage: every POST with a session needs a valid per-session token (task 4.5).

Example tests driven from the route table: for every ``POST`` route that carries ``csrf=True`` a
signed-in request with a missing, malformed or wrong-secret token is refused with a 400 and audited,
while the same request with the session's own token passes the gate. ``POST /sign-in`` is the one
exception: it has no session, so the central 400 gate never applies -- it runs its own double-submit
CSRF check instead. The exhaustive coverage is Property 6 in the ``* 4.6`` sibling.
"""

from __future__ import annotations

import datetime as dt

import pytest
from tests.conftest import WsgiClient

from adms.admin import auth
from adms.admin.app import _ROUTES, AdminWsgiApp, create_app
from adms.config import Settings

WHEN = dt.datetime(2026, 8, 12, 2, 0, 0, tzinfo=dt.UTC)

CSRF_POSTS = [r for r in _ROUTES if r.method == "POST" and r.csrf and "{" not in r.pattern]


def _app(store) -> AdminWsgiApp:
    return create_app(store, settings=Settings(), clock=lambda: WHEN)


def _sign_in(store, role: str = "admin") -> tuple[str, bytes]:
    u = store.add_user(username="u", role=role, password="pw")
    token = auth.new_session_token()
    secret = auth.new_csrf_secret()
    store.create_session(
        token_hash=auth.token_hash(token), user_id=u.user_id,
        expires_utc=WHEN + auth.SESSION_IDLE_TIMEOUT, ip="1.2.3.4", user_agent="ua",
        csrf_secret=secret,
    )
    return token, secret


def _client(store, token: str) -> WsgiClient:
    c = WsgiClient(_app(store))
    c.cookies["adms_console"] = token
    return c


@pytest.mark.parametrize("route", CSRF_POSTS, ids=lambda r: r.pattern)
@pytest.mark.parametrize("bad", ["", "not-a-token", "nonce.deadbeef"], ids=["absent", "garbage", "forged"])
def test_post_without_a_valid_csrf_token_is_refused(store, route, bad: str) -> None:
    token, _secret = _sign_in(store)
    form = {} if bad == "" else {"csrf_token": bad}
    resp = _client(store, token).post(route.pattern, form=form)
    assert resp.status == 400
    assert store.audited("csrf_reject")  # the rejection is on the record
    # nothing mutated: no write-shaped store call slipped past the gate
    assert not any(c.method.startswith(("set_", "enqueue", "delete_session", "unlock", "create_user"))
                   for c in store.calls)


@pytest.mark.parametrize("route", CSRF_POSTS, ids=lambda r: r.pattern)
def test_post_with_the_session_token_passes_the_csrf_gate(store, route) -> None:
    token, secret = _sign_in(store)
    resp = _client(store, token).post(route.pattern, form={"csrf_token": auth.csrf_token(secret)})
    # A valid token clears the CSRF gate. A handler may still 400 on its own input validation (an
    # empty create form), so the assertion is narrower: the refusal is never the CSRF one, whose
    # page is the only 400 that reads "This form expired".
    assert "This form expired" not in resp.text


def test_sign_in_post_is_not_subject_to_the_central_csrf_gate(store) -> None:
    # /sign-in has no session secret, so the central "This form expired" 400 gate never fires for it.
    # Its own double-submit check re-renders the form (200) instead; either way it is never a 400.
    store.add_user(username="thu", role="admin", password="pw")
    resp = WsgiClient(_app(store)).post(
        "/sign-in", form={"username": "thu", "password": "pw"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert resp.status != 400
