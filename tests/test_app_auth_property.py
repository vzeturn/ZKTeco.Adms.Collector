"""
Exhaustive, table-driven authentication properties (task 4.4): Properties 10, 11, 15, 16, 17, 18.

Companion to ``test_app_signin.py`` (example tests for ``_authenticate``) and ``test_app_session.py``
(example tests for ``_load_principal``) -- this module drives the same surfaces over fixed tables so
every branch of the uniform-failure contract, the session deadlines, the touch throttle, the cookie
attributes and the forced-password-change gate is covered by name, not by example.
"""

from __future__ import annotations

import datetime as dt
import re

from tests.conftest import WsgiClient

from adms.admin import auth
from adms.admin.app import GENERIC_FAILURE, AdminWsgiApp, create_app
from adms.config import Settings

WHEN = dt.datetime(2026, 8, 12, 2, 0, 0, tzinfo=dt.UTC)
ORIGIN = "http://127.0.0.1"  # matches wsgiref's SERVER_NAME/PORT default


def _app(store, *, secure: bool = False, now: dt.datetime = WHEN) -> AdminWsgiApp:
    return create_app(store, settings=Settings(), secure_cookies=secure, clock=lambda: now)


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


def _req(app: AdminWsgiApp, token: str | None):
    from wsgiref.util import setup_testing_defaults

    environ: dict = {}
    setup_testing_defaults(environ)
    environ["REQUEST_METHOD"] = "GET"
    environ["PATH_INFO"] = "/"
    if token is not None:
        environ["HTTP_COOKIE"] = f"adms_console={token}"
    return app._parse_request(environ)


# ── Property 10: every sign-in failure is indistinguishable ─────────────────────────────────────


def _seed_unknown(_store):
    return "ghost", "whatever"


def _seed_wrong_password(store):
    store.add_user(username="wrongpw", role="viewer", password="right")
    return "wrongpw", "wrong"


def _seed_disabled(store):
    store.add_user(username="disabled", role="viewer", is_enabled=False, password="right")
    return "disabled", "right"


def _seed_locked(store):
    u = store.add_user(username="locked", role="viewer", password="right")
    store._replace_user(u.user_id, locked_until_utc=WHEN + dt.timedelta(minutes=5))
    return "locked", "right"


def _seed_empty_username(store):
    store.add_user(username="someone", role="viewer", password="right")
    return "", "right"


def _seed_empty_password(store):
    store.add_user(username="pwless", role="viewer", password="right")
    return "pwless", ""


_FAILURE_TABLE = (
    ("unknown user", _seed_unknown),
    ("wrong password", _seed_wrong_password),
    ("disabled user", _seed_disabled),
    ("locked user", _seed_locked),
    ("empty username", _seed_empty_username),
    ("empty password", _seed_empty_password),
)


def test_every_sign_in_failure_is_indistinguishable(store) -> None:
    messages: set[str] = set()
    for _label, seed in _FAILURE_TABLE:
        username, password = seed(store)
        token, message = _app(store)._authenticate(username, password, "1.2.3.4", "ua", WHEN)
        assert token is None
        assert message == GENERIC_FAILURE
        assert "create_session" not in {c.method for c in store.calls}
        messages.add(message)
    assert len(messages) == 1


def test_every_sign_in_failure_is_audited(store) -> None:
    for _label, seed in _FAILURE_TABLE:
        username, password = seed(store)
        _app(store)._authenticate(username, password, "1.2.3.4", "ua", WHEN)
        assert store.audited("sign_in")


# ── Property 11: a success leaves exactly one new live session and clean counters ───────────────


_SUCCESS_TABLE = (
    ("viewer", "viewer"),
    ("operator", "operator"),
    ("admin", "admin"),
)


def test_success_leaves_one_live_session_and_clean_counters(store) -> None:
    for idx, (label, role) in enumerate(_SUCCESS_TABLE):
        username = f"user_{label}_{idx}"
        store.add_user(username=username, role=role, password="right")
        before = len(store.calls)
        app = _app(store)
        token, message = app._authenticate(username, "right", "1.2.3.4", "ua", WHEN)
        since = store.calls[before:]

        assert token is not None, label
        assert message == "", label
        created = [c for c in since if c.method == "create_session"]
        assert len(created) == 1, label
        assert "record_login_success" in {c.method for c in since}, label
        signins = [c for c in since if c.method == "audit" and c.kwargs["action"] == "sign_in"]
        assert any(c.kwargs.get("succeeded") for c in signins), label

        row = store.load_session(auth.token_hash(token))
        assert row is not None, label
        assert row.expires_utc == WHEN + auth.SESSION_IDLE_TIMEOUT, label


# ── Property 15: a session is live only while both deadlines hold ───────────────────────────────


def test_idle_deadline_one_minute_past_creation_is_live(store) -> None:
    u = store.add_user(username="p15a", role="viewer", password="pw")
    token, _ = _sign_in(store, u.user_id)
    app = _app(store)
    principal = app._load_principal(_req(app, token), WHEN + dt.timedelta(minutes=1))
    assert principal is not None


def test_idle_deadline_just_under_eight_hours_is_live(store) -> None:
    u = store.add_user(username="p15b", role="viewer", password="pw")
    token, _ = _sign_in(store, u.user_id)
    app = _app(store)
    now = WHEN + dt.timedelta(hours=7, minutes=59)
    principal = app._load_principal(_req(app, token), now)
    assert principal is not None


def test_idle_deadline_just_past_eight_hours_reaps_the_row(store) -> None:
    u = store.add_user(username="p15c", role="viewer", password="pw")
    token, _ = _sign_in(store, u.user_id)
    app = _app(store)
    now = WHEN + dt.timedelta(hours=8, minutes=1)
    principal = app._load_principal(_req(app, token), now)
    assert principal is None
    assert store.load_session(auth.token_hash(token)) is None


def test_absolute_deadline_past_seven_days_reaps_the_row_even_if_idle_fresh(store) -> None:
    u = store.add_user(username="p15d", role="viewer", password="pw")
    token, _ = _sign_in(store, u.user_id, now=WHEN)
    digest = auth.token_hash(token)
    # Force the session's created_utc far enough into the past that the absolute ceiling has
    # passed, while its expires_utc (the idle deadline) is set to still be in the future -- the
    # only way to isolate the absolute check from the idle check with this store's API.
    old_created = WHEN - dt.timedelta(days=8)
    store.sessions[digest]["created_utc"] = old_created
    store.sessions[digest]["expires_utc"] = WHEN + dt.timedelta(minutes=5)
    app = _app(store)
    principal = app._load_principal(_req(app, token), WHEN)
    assert principal is None
    assert store.load_session(digest) is None


# ── Property 16: the sliding window is extended, but not on every request ───────────────────────


_NO_TOUCH_OFFSETS = (dt.timedelta(seconds=30), dt.timedelta(seconds=59))
_TOUCH_OFFSETS = (dt.timedelta(seconds=61), dt.timedelta(minutes=2), dt.timedelta(minutes=5))


def test_touch_throttle_holds_under_a_minute(store) -> None:
    for offset in _NO_TOUCH_OFFSETS:
        u = store.add_user(username=f"p16no_{offset.total_seconds()}", role="viewer", password="pw")
        token, _ = _sign_in(store, u.user_id)
        digest = auth.token_hash(token)
        before = store.load_session(digest).expires_utc
        app = _app(store)
        app._load_principal(_req(app, token), WHEN + offset)
        assert "touch_session" not in {c.method for c in store.calls}, offset
        assert store.load_session(digest).expires_utc == before, offset


def test_touch_throttle_extends_after_a_minute(store) -> None:
    for offset in _TOUCH_OFFSETS:
        u = store.add_user(username=f"p16yes_{offset.total_seconds()}", role="viewer", password="pw")
        token, _ = _sign_in(store, u.user_id)
        digest = auth.token_hash(token)
        now = WHEN + offset
        app = _app(store)
        app._load_principal(_req(app, token), now)
        assert "touch_session" in {c.method for c in store.calls}, offset
        row = store.load_session(digest)
        assert row.expires_utc == now + auth.SESSION_IDLE_TIMEOUT, offset


# ── Property 17: cookie attributes match the transport ───────────────────────────────────────────


def _sign_in_over_http(store, *, secure: bool, origin: str) -> tuple[WsgiClient, object]:
    """GET /sign-in to mint the CSRF cookie + token, then POST the credentials back with the token."""
    client = WsgiClient(_app(store, secure=secure), https=secure)
    page = client.get("/sign-in")
    token = re.search(rb'name="csrf_token"[^>]*value="([^"]+)"', page.body).group(1).decode("ascii")
    resp = client.post(
        "/sign-in",
        form={"username": "thu", "password": "right", "csrf_token": token},
        headers={"Origin": origin},
    )
    return client, resp


def test_cookie_attributes_match_the_transport_plain_http(store) -> None:
    store.add_user(username="thu", role="admin", password="right")
    _client, resp = _sign_in_over_http(store, secure=False, origin="http://127.0.0.1")
    session = next(c for c in resp.headers_named("set-cookie") if "adms_console=" in c)
    assert "HttpOnly" in session
    assert "SameSite=Lax" in session
    assert "Path=/" in session
    assert "Secure" not in session
    assert "Max-Age" not in session


def test_cookie_attributes_match_the_transport_tls(store) -> None:
    store.add_user(username="thu", role="admin", password="right")
    _client, resp = _sign_in_over_http(store, secure=True, origin="https://127.0.0.1")
    session = next(c for c in resp.headers_named("set-cookie") if "adms_console=" in c)
    assert "__Host-adms_console=" in session
    assert "Secure" in session
    assert "HttpOnly" in session
    assert "SameSite=Lax" in session
    assert "Path=/" in session
    assert "Max-Age" not in session


# ── Property 18: a must-change-password session reaches nothing else ────────────────────────────


_GUARDED_PATHS = ("/", "/devices", "/activity", "/audit", "/users")


def test_must_change_password_redirects_every_guarded_page(store) -> None:
    u = store.add_user(username="mustchange", role="admin", must_change_password=True, password="pw")
    token, _secret = _sign_in(store, u.user_id)
    for path in _GUARDED_PATHS:
        client = WsgiClient(_app(store))
        client.cookies["adms_console"] = token
        resp = client.get(path)
        assert resp.status == 303, path
        assert resp.location == "/change-password", path


def test_must_change_password_lets_change_password_through(store) -> None:
    u = store.add_user(username="mustchange2", role="admin", must_change_password=True, password="pw")
    token, _secret = _sign_in(store, u.user_id)

    client = WsgiClient(_app(store))
    client.cookies["adms_console"] = token
    resp = client.get("/change-password")
    assert resp.status == 200


def test_must_change_password_lets_sign_out_through(store) -> None:
    # The forced-change funnel exempts /sign-out (and /change-password): a user who must change their
    # password can still leave. Its CSRF and authorization gates are satisfied, so it dispatches.
    u = store.add_user(username="mustchange3", role="admin", must_change_password=True, password="pw")
    token, secret = _sign_in(store, u.user_id)

    client = WsgiClient(_app(store))
    client.cookies["adms_console"] = token
    resp = client.post("/sign-out", form={"csrf_token": auth.csrf_token(secret)})
    assert resp.status == 303
    assert resp.location == "/sign-in"
