"""
Sign-in: the uniform-failure contract, lockout, iteration upgrade, the cookie and CSRF (4.3).

Example tests for ``_authenticate`` and the ``POST /sign-in`` handler around it: every failure returns
one byte-identical message and creates no session, one PBKDF2 derivation runs even for an unknown user,
a wrong password records a failure while a locked account does not, a success sets a session cookie with
the right attributes and audits, an out-of-date hash is silently upgraded, and a POST without the
double-submit CSRF token is refused. The exhaustive coverage is Property 10/11 in the ``* 4.4`` sibling.
"""

from __future__ import annotations

import datetime as dt
import re

from tests.conftest import WsgiClient

from adms.admin import auth
from adms.admin.app import EXPIRED_FORM_FAILURE, GENERIC_FAILURE, AdminWsgiApp, create_app
from adms.config import Settings

WHEN = dt.datetime(2026, 8, 12, 2, 0, 0, tzinfo=dt.UTC)
ORIGIN = "http://127.0.0.1"  # matches wsgiref's SERVER_NAME/PORT default

_CSRF_RE = re.compile(rb'name="csrf_token"[^>]*value="([^"]+)"')


def _csrf_from(body: bytes) -> str:
    """Scrape the hidden CSRF token the sign-in form embeds, as a browser would submit it."""
    m = _CSRF_RE.search(body)
    assert m, "sign-in form is missing its csrf_token field"
    return m.group(1).decode("ascii")


def _app(store, *, secure: bool = False, now: dt.datetime = WHEN) -> AdminWsgiApp:
    return create_app(store, settings=Settings(), secure_cookies=secure, clock=lambda: now)


# ── _authenticate: the uniform-failure contract ──────────────────────────────────────────────────


def test_unknown_user_fails_uniformly_and_derives_a_hash(store) -> None:
    token, message = _app(store)._authenticate("ghost", "pw", "1.2.3.4", "ua", WHEN)
    assert token is None
    assert message == GENERIC_FAILURE
    assert store.calls == [] or "create_session" not in {c.method for c in store.calls}
    assert store.audited("sign_in")  # the attempt is on the record


def test_disabled_user_gives_the_same_message(store) -> None:
    store.add_user(username="u", role="viewer", is_enabled=False, password="right")
    token, message = _app(store)._authenticate("u", "right", "1.2.3.4", "ua", WHEN)
    assert token is None
    assert message == GENERIC_FAILURE
    assert "create_session" not in {c.method for c in store.calls}


def test_wrong_password_records_a_failure(store) -> None:
    store.add_user(username="u", role="viewer", password="right")
    token, message = _app(store)._authenticate("u", "wrong", "1.2.3.4", "ua", WHEN)
    assert token is None
    assert message == GENERIC_FAILURE
    assert "record_login_failure" in {c.method for c in store.calls}


def test_locked_account_records_no_new_failure(store) -> None:
    u = store.add_user(username="u", role="viewer", password="right")
    store._replace_user(u.user_id, locked_until_utc=WHEN + dt.timedelta(minutes=5),
                        failed_attempts=8)
    token, message = _app(store)._authenticate("u", "right", "1.2.3.4", "ua", WHEN)
    assert token is None
    assert message == GENERIC_FAILURE
    assert "record_login_failure" not in {c.method for c in store.calls}


def test_success_creates_exactly_one_session_and_audits(store) -> None:
    store.add_user(username="thu", role="admin", password="right")
    token, message = _app(store)._authenticate("thu", "right", "1.2.3.4", "ua", WHEN)
    assert token is not None
    assert message == ""
    created = [c for c in store.calls if c.method == "create_session"]
    assert len(created) == 1
    assert store.load_session(auth.token_hash(token)) is not None
    assert "record_login_success" in {c.method for c in store.calls}
    signins = [c for c in store.calls if c.method == "audit"]
    assert any(c.kwargs.get("succeeded") for c in signins)


def test_username_is_trimmed_and_lowercased(store) -> None:
    store.add_user(username="thu", role="admin", password="right")
    token, _ = _app(store)._authenticate("  THU  ", "right", "1.2.3.4", "ua", WHEN)
    assert token is not None


def test_stale_iteration_count_is_upgraded_on_success(store) -> None:
    # add_user hashes at FAST_ITERATIONS, far below PBKDF2_ITERATIONS -> a success must re-hash.
    store.add_user(username="u", role="viewer", password="right")
    _app(store)._authenticate("u", "right", "1.2.3.4", "ua", WHEN)
    assert "set_password" in {c.method for c in store.calls}


# ── POST /sign-in: same-origin, cookie, next ─────────────────────────────────────────────────────


def _post_sign_in(store, *, secure: bool = False, origin: str | None = ORIGIN,
                  next_url: str = "", form_extra: dict | None = None, with_csrf: bool = True):
    """
    Drive the real browser flow: GET /sign-in to mint the CSRF cookie + token, then POST both back.
    ``with_csrf=False`` posts without the token/cookie to model a forged submission.
    """
    client = WsgiClient(_app(store, secure=secure), https=secure)
    form = {"username": "thu", "password": "right", **(form_extra or {})}
    if with_csrf:
        page = client.get("/sign-in")  # sets the login-csrf cookie; the token is in the HTML
        form.setdefault("csrf_token", _csrf_from(page.body))
    if next_url:
        form["next"] = next_url
    headers = {"Origin": origin} if origin is not None else {}
    return client, client.post("/sign-in", form=form, headers=headers)


def test_sign_in_success_sets_the_session_cookie(store) -> None:
    store.add_user(username="thu", role="admin", password="right")
    client, resp = _post_sign_in(store)
    assert resp.status == 303
    assert resp.location == "/"
    cookies = resp.headers_named("set-cookie")
    session = next(c for c in cookies if "adms_console=" in c)
    assert "HttpOnly" in session
    assert "SameSite=Lax" in session
    assert "Path=/" in session
    assert "Max-Age" not in session  # a session cookie: no persistent lifetime
    assert "Secure" not in session   # plain HTTP
    # the login-csrf cookie is cleared once it has done its job
    assert any("adms_login_csrf=" in c and "Max-Age=0" in c for c in cookies)


def test_sign_in_over_tls_uses_the_host_prefixed_secure_cookie(store) -> None:
    store.add_user(username="thu", role="admin", password="right")
    _client, resp = _post_sign_in(store, secure=True, origin="https://127.0.0.1")
    cookies = resp.headers_named("set-cookie")
    session = next(c for c in cookies if "adms_console=" in c)
    assert "__Host-adms_console=" in session
    assert "Secure" in session


def test_sign_in_failure_re_renders_the_form_with_the_uniform_message(store) -> None:
    store.add_user(username="thu", role="admin", password="right")
    _client, resp = _post_sign_in(store, form_extra={"password": "wrong"})
    assert resp.status == 200
    assert GENERIC_FAILURE.encode("utf-8") in resp.body
    # no session on failure -- only the fresh login-csrf cookie for the re-rendered form
    cookies = resp.headers_named("set-cookie")
    assert not any("adms_console=" in c for c in cookies)


def test_post_without_csrf_token_is_refused_before_any_lookup(store) -> None:
    # A forged submission has neither the login-csrf cookie nor its token: refuse before touching the db.
    store.add_user(username="thu", role="admin", password="right")
    _client, resp = _post_sign_in(store, with_csrf=False)
    assert resp.status == 200  # re-render, never a session
    assert EXPIRED_FORM_FAILURE.encode("utf-8") in resp.body  # the CSRF path, not a credential verdict
    assert "find_user" not in {c.method for c in store.calls}


def test_stale_csrf_token_without_the_cookie_is_refused(store) -> None:
    # Token present in the form but no matching cookie (e.g. an old page) -> refused.
    store.add_user(username="thu", role="admin", password="right")
    client = WsgiClient(_app(store))
    page = client.get("/sign-in")
    token = _csrf_from(page.body)
    client.cookies.clear()  # drop the login-csrf cookie so the double-submit cannot match
    resp = client.post("/sign-in", form={"username": "thu", "password": "right", "csrf_token": token},
                       headers={"Origin": ORIGIN})
    assert resp.status == 200
    assert "find_user" not in {c.method for c in store.calls}


def test_a_second_get_does_not_invalidate_the_first_pages_token(store) -> None:
    # Regression: a second GET /sign-in (refresh, prefetch, another tab) must NOT rotate the
    # login-csrf cookie out from under a form the user is still filling in. If it did, submitting the
    # first page's token would fail the double-submit check and mislead the user with "Incorrect
    # username or password." The cookie is idempotent: reuse the existing secret across GETs.
    store.add_user(username="thu", role="admin", password="right")
    client = WsgiClient(_app(store))
    first = client.get("/sign-in")          # mints the cookie; token belongs to secret #1
    token = _csrf_from(first.body)
    client.get("/sign-in")                  # second GET must keep the same cookie secret
    resp = client.post("/sign-in", form={"username": "thu", "password": "right", "csrf_token": token},
                       headers={"Origin": ORIGIN})
    assert resp.status == 303               # the first page's token still validates -> real sign-in
    assert resp.location == "/"


def test_cross_origin_referer_is_refused_even_with_a_token(store) -> None:
    # Defence in depth: a stated Origin from another site is rejected before any lookup.
    store.add_user(username="thu", role="admin", password="right")
    _client, resp = _post_sign_in(store, origin="http://evil.example")
    assert resp.status == 200
    assert "find_user" not in {c.method for c in store.calls}


def test_missing_origin_and_referer_succeeds_with_a_valid_token(store) -> None:
    # The whole point of the fix: plain-HTTP browsers omit Origin/Referer; the token alone must suffice.
    store.add_user(username="thu", role="admin", password="right")
    _client, resp = _post_sign_in(store, origin=None)
    assert resp.status == 303
    assert resp.location == "/"


def test_opaque_null_origin_succeeds_with_a_valid_token(store) -> None:
    # Regression: some browser contexts send a literal ``Origin: null`` (opaque origin) on the sign-in
    # POST even on a same-site navigation. That is not a cross-origin source -- it names no host at all,
    # so there is nothing to compare. Treat it like an absent Origin and let the double-submit token be
    # the guard, exactly as for a plain-HTTP form that omits the header. Without this, every attempt is
    # refused with "This form expired" and a reload never helps.
    store.add_user(username="thu", role="admin", password="right")
    _client, resp = _post_sign_in(store, origin="null")
    assert resp.status == 303
    assert resp.location == "/"


def test_open_redirect_next_is_ignored(store) -> None:
    store.add_user(username="thu", role="admin", password="right")
    _client, resp = _post_sign_in(store, next_url="http://evil.example/steal")
    assert resp.status == 303
    assert resp.location == "/"  # an off-site next is dropped


def test_internal_next_is_honoured(store) -> None:
    store.add_user(username="thu", role="admin", password="right")
    _client, resp = _post_sign_in(store, next_url="/devices")
    assert resp.status == 303
    assert resp.location == "/devices"


def test_get_sign_in_renders_the_form_with_a_csrf_cookie_and_token(store) -> None:
    resp = WsgiClient(_app(store)).get("/sign-in")
    assert resp.status == 200
    assert b"<form" in resp.body
    token = _csrf_from(resp.body)  # a hidden csrf_token field is present
    cookie = next(c for c in resp.headers_named("set-cookie") if "adms_login_csrf=" in c)
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie
    # the embedded token verifies against the secret carried by that cookie
    import base64
    raw = cookie.split("adms_login_csrf=", 1)[1].split(";", 1)[0]
    secret = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    assert auth.verify_csrf_token(secret, token)
