"""
Exhaustive gate properties (task 4.6): Properties 6, 9, and 23.

Where ``test_app_csrf.py`` and ``test_app_authz.py`` prove the gates by example over a few token and
role choices, this module drives the *whole* route table against the *whole* role set so no route and
no role pair escapes coverage -- the exhaustive siblings those files point at.

- **Property 6** — every mutating POST (``csrf=True``) with a session but without that session's own
  token is refused with a 400 and audited, for *every* such route and *every* way a token can be wrong.
- **Property 9** — the authorization matrix has no gaps: for *every* guarded route and *every* role,
  a role below the route's requirement is denied (403 + audit) and a role at or above it passes the gate.
- **Property 23** — every successful mutation answers with a redirect. Only the two mutations whose
  handlers exist in this wave (``POST /sign-in`` success, ``POST /sign-out``) are assertable now; the
  device/user/session mutation handlers land in waves 7-9, so their Property-23 coverage is deferred to
  ``test_app_devices.py`` / ``test_app_commands.py`` / ``test_app_users.py``. This is recorded, not skipped.
"""

from __future__ import annotations

import datetime as dt
import re

import pytest
from tests.conftest import WsgiClient

from adms.admin import auth
from adms.admin.app import _ROUTES, AdminWsgiApp, create_app
from adms.config import Settings

WHEN = dt.datetime(2026, 8, 12, 2, 0, 0, tzinfo=dt.UTC)
ORIGIN = "http://127.0.0.1"  # wsgiref's SERVER_NAME/PORT default

# Concrete routes only: patterns with a ``{param}`` cannot be hit without a real id, and the gate runs
# before the handler resolves the id, so the concrete siblings exercise the same gate code.
CONCRETE = [r for r in _ROUTES if "{" not in r.pattern]
CSRF_POSTS = [r for r in CONCRETE if r.method == "POST" and r.csrf]
GUARDED = [r for r in CONCRETE if r.requires]

_RANK = {"view": 0, "operate": 1, "administer": 2}
_ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2}
_ROLES = ("viewer", "operator", "admin")

# Every distinct way a CSRF token can be wrong: absent, malformed, well-shaped but forged, and a
# structurally valid token minted from a *different* secret than the session's.
_WRONG_TOKENS = ("absent", "garbage", "forged", "other-secret")

_WRITE_PREFIXES = ("set_", "enqueue", "delete_session", "unlock", "create_user", "update_", "revoke")


def _app(store, *, secure: bool = False) -> AdminWsgiApp:
    return create_app(store, settings=Settings(), secure_cookies=secure, clock=lambda: WHEN)


def _sign_in(store, role: str) -> tuple[str, bytes]:
    """Seed a live session for a fresh user of ``role``; return (token, csrf_secret)."""
    u = store.add_user(username=f"u_{role}", role=role, password="pw")
    token = auth.new_session_token()
    secret = auth.new_csrf_secret()
    store.create_session(
        token_hash=auth.token_hash(token),
        user_id=u.user_id,
        expires_utc=WHEN + auth.SESSION_IDLE_TIMEOUT,
        ip="1.2.3.4",
        user_agent="ua",
        csrf_secret=secret,
    )
    return token, secret


def _client(store, token: str, *, secure: bool = False) -> WsgiClient:
    c = WsgiClient(_app(store, secure=secure), https=secure)
    c.cookies["__Host-adms_console" if secure else "adms_console"] = token
    return c


def _form_for(kind: str) -> dict[str, str]:
    if kind == "absent":
        return {}
    if kind == "garbage":
        return {"csrf_token": "not-a-token"}
    if kind == "forged":
        return {"csrf_token": "nonce.deadbeef"}
    if kind == "other-secret":  # a valid token, but minted from a foreign secret
        return {"csrf_token": auth.csrf_token(auth.new_csrf_secret())}
    raise AssertionError(kind)


# ── Property 6: no POST changes state without a valid CSRF token ─────────────────────────────────


@pytest.mark.parametrize("route", CSRF_POSTS, ids=lambda r: r.pattern)
@pytest.mark.parametrize("kind", _WRONG_TOKENS)
def test_no_mutating_post_passes_without_the_session_token(store, route, kind: str) -> None:
    token, _secret = _sign_in(store, "admin")  # admin so authz never masks a CSRF pass-through
    resp = _client(store, token).post(route.pattern, form=_form_for(kind))
    assert resp.status == 400, (route.pattern, kind)
    assert store.audited("csrf_reject"), (route.pattern, kind)
    assert not any(c.method.startswith(_WRITE_PREFIXES) for c in store.calls), (route.pattern, kind)


@pytest.mark.parametrize("route", CSRF_POSTS, ids=lambda r: r.pattern)
def test_the_session_token_clears_the_csrf_gate_for_every_mutation(store, route) -> None:
    token, secret = _sign_in(store, "admin")
    resp = _client(store, token).post(route.pattern, form={"csrf_token": auth.csrf_token(secret)})
    # A valid token must clear the CSRF gate. A handler may still 400 on its own input validation
    # (an empty create form, say), so what this asserts is narrower: the refusal, if any, is never
    # the CSRF one. The CSRF rejection is the only 400 that renders "This form expired".
    assert "This form expired" not in resp.text, route.pattern


# ── Property 9: the authorization matrix has no gaps ─────────────────────────────────────────────


@pytest.mark.parametrize("route", GUARDED, ids=lambda r: f"{r.method}:{r.pattern}")
@pytest.mark.parametrize("role", _ROLES)
def test_every_guarded_route_denies_below_and_admits_at_or_above(store, route, role: str) -> None:
    token, secret = _sign_in(store, role)
    form = {"csrf_token": auth.csrf_token(secret)} if route.csrf else {}
    resp = _client(store, token).request(route.method, route.pattern, form=form)

    permitted = _ROLE_RANK[role] >= _RANK[route.requires]
    if permitted:
        assert resp.status != 403, (route.pattern, role)  # authorization let it through
    else:
        assert resp.status == 403, (route.pattern, role)  # refused before any handler ran
        assert store.audited("denied"), (route.pattern, role)


def test_every_guarded_route_has_a_known_requirement() -> None:
    # A gap in the matrix would be a route whose ``requires`` names a capability the mapping does not
    # know; such a route would silently fall through ``_permits`` to False for everyone. Assert the
    # vocabulary is closed so the matrix above is exhaustive over real capabilities, not typos.
    assert {r.requires for r in GUARDED} <= set(_RANK)


# ── Property 23: every successful mutation answers with a redirect ───────────────────────────────
# Only the mutations whose handlers exist this wave are assertable; the rest are deferred (see module
# docstring). Both assertable mutations must answer 30x, never 200 -- a mutation that renders a page
# in place would let a refresh replay the write.


def test_successful_sign_in_answers_with_a_redirect(store) -> None:
    store.add_user(username="thu", role="admin", password="right")
    client = WsgiClient(_app(store))
    page = client.get("/sign-in")  # mint the double-submit CSRF cookie + token, as a browser would
    token = re.search(rb'name="csrf_token"[^>]*value="([^"]+)"', page.body).group(1).decode("ascii")
    resp = client.post(
        "/sign-in",
        form={"username": "thu", "password": "right", "csrf_token": token},
        headers={"Origin": ORIGIN},
    )
    assert resp.status == 303
    assert resp.location == "/"


def test_successful_sign_out_answers_with_a_redirect(store) -> None:
    token, secret = _sign_in(store, "viewer")
    resp = _client(store, token).post("/sign-out", form={"csrf_token": auth.csrf_token(secret)})
    assert resp.status == 303
    assert resp.location == "/sign-in"
