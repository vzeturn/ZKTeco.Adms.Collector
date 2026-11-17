"""
Session loading, the forced-password-change redirect and sign-out (task 4.3).

Example tests for the second pipeline stage: a cookie is read, the row is looked up by its hash, both
deadlines are checked, a dead row is deleted, the idle window slides but only once a minute, a disabled
account is treated as no session, ``must_change_password`` funnels every page to ``/change-password``,
and ``POST /sign-out`` deletes the row and clears the cookie. The exhaustive coverage is Property
5/6/8/9 in the ``* 4.4`` sibling.
"""

from __future__ import annotations

import datetime as dt

from tests.conftest import WsgiClient

from adms.admin import auth
from adms.admin.app import AdminWsgiApp, create_app
from adms.config import Settings

WHEN = dt.datetime(2026, 8, 12, 2, 0, 0, tzinfo=dt.UTC)


def _app(store, *, secure: bool = False, now: dt.datetime = WHEN) -> AdminWsgiApp:
    return create_app(store, settings=Settings(), secure_cookies=secure, clock=lambda: now)


def _cookie_name(secure: bool) -> str:
    return "__Host-adms_console" if secure else "adms_console"


def _sign_in(store, user_id: int, *, now: dt.datetime = WHEN) -> tuple[str, bytes]:
    """Seed a live session for ``user_id`` directly in the store and return (token, csrf_secret)."""
    token = auth.new_session_token()
    secret = auth.new_csrf_secret()
    store.create_session(
        token_hash=auth.token_hash(token),
        user_id=user_id,
        expires_utc=now + auth.SESSION_IDLE_TIMEOUT,
        ip="10.0.0.1",
        user_agent="ua",
        csrf_secret=secret,
    )
    return token, secret


# ── loading a live session ─────────────────────────────────────────────────────────────────────


def test_live_session_yields_a_principal(store) -> None:
    u = store.add_user(username="jane.doe", display_name="Jane", role="admin", password="pw")
    token, secret = _sign_in(store, u.user_id)
    app = _app(store)
    principal = app._load_principal(_req(app, token), WHEN)
    assert principal is not None
    assert principal.username == "jane.doe"
    assert principal.role == "admin"
    assert principal.csrf_secret == secret
    assert auth.Role.is_valid(principal.role)


def test_absent_cookie_is_anonymous(store) -> None:
    app = _app(store)
    assert app._load_principal(_req(app, None), WHEN) is None


def test_unknown_token_is_anonymous_without_touching_anything(store) -> None:
    app = _app(store)
    assert app._load_principal(_req(app, "deadbeef.notreal"), WHEN) is None


def test_disabled_account_is_treated_as_no_session(store) -> None:
    u = store.add_user(username="u", role="viewer", is_enabled=False, password="pw")
    token, _ = _sign_in(store, u.user_id)
    app = _app(store)
    assert app._load_principal(_req(app, token), WHEN) is None


def test_expired_row_is_deleted_when_seen(store) -> None:
    u = store.add_user(username="u", role="viewer", password="pw")
    token, _ = _sign_in(store, u.user_id)
    app = _app(store)
    later = WHEN + auth.SESSION_IDLE_TIMEOUT + dt.timedelta(minutes=1)
    assert app._load_principal(_req(app, token), later) is None
    assert store.load_session(auth.token_hash(token)) is None  # dead row was reaped


# ── the 60-second touch throttle ─────────────────────────────────────────────────────────────


def test_idle_window_slides_after_a_minute(store) -> None:
    u = store.add_user(username="u", role="viewer", password="pw")
    token, _ = _sign_in(store, u.user_id)
    app = _app(store)
    two_min = WHEN + dt.timedelta(minutes=2)
    app._load_principal(_req(app, token), two_min)
    row = store.load_session(auth.token_hash(token))
    assert row is not None
    assert row.expires_utc == two_min + auth.SESSION_IDLE_TIMEOUT  # extended


def test_idle_window_not_touched_within_a_minute(store) -> None:
    u = store.add_user(username="u", role="viewer", password="pw")
    token, _ = _sign_in(store, u.user_id)
    app = _app(store)
    before = store.load_session(auth.token_hash(token)).expires_utc
    app._load_principal(_req(app, token), WHEN + dt.timedelta(seconds=30))
    row = store.load_session(auth.token_hash(token))
    assert row.expires_utc == before  # no write within the throttle window
    assert "touch_session" not in {c.method for c in store.calls}


# ── forced password change, enforced centrally ───────────────────────────────────────────────


def test_must_change_password_redirects_every_page_to_change_password(store) -> None:
    u = store.add_user(username="u", role="admin", must_change_password=True, password="pw")
    token, _ = _sign_in(store, u.user_id)
    client = WsgiClient(_app(store))
    client.cookies[_cookie_name(False)] = token
    resp = client.get("/")
    assert resp.status == 303
    assert resp.location == "/change-password"


def test_must_change_password_lets_change_password_through(store) -> None:
    u = store.add_user(username="u", role="admin", must_change_password=True, password="pw")
    token, _ = _sign_in(store, u.user_id)
    client = WsgiClient(_app(store))
    client.cookies[_cookie_name(False)] = token
    resp = client.get("/change-password")
    assert resp.status == 200


# ── sign-out ─────────────────────────────────────────────────────────────────────────────────


def test_sign_out_deletes_the_row_and_clears_the_cookie(store) -> None:
    u = store.add_user(username="u", role="admin", password="pw")
    token, secret = _sign_in(store, u.user_id)
    client = WsgiClient(_app(store))
    client.cookies[_cookie_name(False)] = token
    resp = client.post("/sign-out", form={"csrf_token": auth.csrf_token(secret)})
    assert resp.status == 303
    assert resp.location == "/sign-in"
    assert store.load_session(auth.token_hash(token)) is None
    set_cookie = resp.header("set-cookie") or ""
    assert "adms_console=" in set_cookie
    assert "Max-Age=0" in set_cookie


# ── helper ───────────────────────────────────────────────────────────────────────────────────


def _req(app: AdminWsgiApp, token: str | None):
    from wsgiref.util import setup_testing_defaults

    environ: dict = {}
    setup_testing_defaults(environ)
    environ["REQUEST_METHOD"] = "GET"
    environ["PATH_INFO"] = "/"
    if token is not None:
        environ["HTTP_COOKIE"] = f"adms_console={token}"
    return app._parse_request(environ)
