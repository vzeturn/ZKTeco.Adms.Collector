"""
The authorization stage: anonymous redirect/401 and the capability matrix (task 4.5).

Example tests driven from the route table so a route added later is covered without touching this file:
an anonymous ``GET`` of a guarded route redirects to sign-in with ``next``, an anonymous ``POST``
gets a 401 page, a signed-in principal below the route's ``requires`` gets a 403 with an audit row, and
a principal at or above it passes the gate. The exhaustive matrix is Property 9 in the ``* 4.6`` sibling.
"""

from __future__ import annotations

import datetime as dt

import pytest
from tests.conftest import WsgiClient

from adms.admin import auth
from adms.admin.app import _ROUTES, AdminWsgiApp, create_app
from adms.config import Settings

WHEN = dt.datetime(2026, 8, 12, 2, 0, 0, tzinfo=dt.UTC)

GUARDED = [r for r in _ROUTES if r.requires]
CONCRETE = [r for r in GUARDED if "{" not in r.pattern]  # patterns we can hit without a real id


def _app(store) -> AdminWsgiApp:
    return create_app(store, settings=Settings(), clock=lambda: WHEN)


def _sign_in(store, role: str) -> str:
    u = store.add_user(username="u", role=role, password="pw")
    token = auth.new_session_token()
    store.create_session(
        token_hash=auth.token_hash(token), user_id=u.user_id,
        expires_utc=WHEN + auth.SESSION_IDLE_TIMEOUT, ip="1.2.3.4", user_agent="ua",
        csrf_secret=auth.new_csrf_secret(),
    )
    return token


def _client(store, token: str | None = None) -> WsgiClient:
    c = WsgiClient(_app(store))
    if token:
        c.cookies["adms_console"] = token
    return c


# ── anonymous ──────────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("route", [r for r in CONCRETE if r.method == "GET"],
                         ids=lambda r: r.pattern)
def test_anonymous_get_of_a_guarded_route_redirects_to_sign_in(store, route) -> None:
    resp = _client(store).get(route.pattern)
    assert resp.status == 303
    assert resp.location.startswith("/sign-in?next=")


@pytest.mark.parametrize("route", [r for r in CONCRETE if r.method == "POST"],
                         ids=lambda r: r.pattern)
def test_anonymous_post_of_a_guarded_route_is_401(store, route) -> None:
    resp = _client(store).post(route.pattern, form={})
    assert resp.status == 401


# ── the capability matrix ───────────────────────────────────────────────────────────────────────

_RANK = {"view": 0, "operate": 1, "administer": 2}
_ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2}


@pytest.mark.parametrize("route", CONCRETE, ids=lambda r: f"{r.method}:{r.pattern}")
@pytest.mark.parametrize("role", ["viewer", "operator", "admin"])
def test_capability_matrix_denies_below_and_admits_at_or_above(store, route, role) -> None:
    token = _sign_in(store, role)
    client = _client(store, token)
    csrf = auth.csrf_token(store.load_session(auth.token_hash(token)).csrf_secret)
    form = {"csrf_token": csrf} if route.csrf else {}
    resp = client.request(route.method, route.pattern, form=form)

    permitted = _ROLE_RANK[role] >= _RANK[route.requires]
    if not permitted:
        assert resp.status == 403  # denied before any handler runs
        assert store.audited("denied")  # every refusal is on the record
    else:
        # allowed past the gate; the handler itself is built in a later wave, so it 404s -- what
        # matters here is that authorization did NOT block it.
        assert resp.status != 403
