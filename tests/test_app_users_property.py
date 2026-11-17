"""
Table-driven property tests for user management (task 8.2), over fixed hostile inputs.

No ``hypothesis`` here -- the table below enumerates the interesting cases by hand instead of letting
a generator find them, and each row states the outcome it must produce.

Property 30 -- creation and update accept exactly what the rules allow. A create is accepted (303,
exactly one ``create_user`` call) iff the username matches ``[A-Za-z0-9_.-]{1,64}``, the role is one of
viewer/operator/admin, the password clears :func:`auth.password_problems`, and the username is not
already taken; any single violation is 400 with zero ``create_user`` calls. Update accepts iff the role
is valid, redirecting with one ``update_user`` call carrying the submitted fields.

Property 31 -- the console cannot lock itself out. Disabling, demoting or deleting the last enabled
admin is refused (400, zero mutating calls); the same action on an admin succeeds once a second enabled
admin exists. Self-delete is refused regardless of how many admins remain.

Property 32 -- revocation is complete and leaves no orphans. Disabling a user ends that user's
sessions; deleting a user removes the user (and, via the store's own ``delete_user``, their sessions
too -- checked by reading ``store.sessions`` back). A refused mutation ends no sessions and deletes
nobody.
"""

from __future__ import annotations

import datetime as dt

import pytest
from tests.conftest import WsgiClient

from adms.admin import auth
from adms.config import Settings

WHEN = dt.datetime(2026, 8, 12, 2, 0, 0, tzinfo=dt.UTC)
GOOD_PW = "Corrct-Horse-9"  # clears the policy: >= 12 chars, not common, not the username


def _seed(store, role: str = "admin") -> tuple[WsgiClient, str, int]:
    """A signed-in client of ``role`` plus that session's CSRF token and the acting user's id."""
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


# ══ Property 30 -- creation/update accept exactly what the rules allow ═════════════════════════════

# (id, username, role, password, expect_ok)
_CREATE_CASES: list[tuple[str, str, str, str, bool]] = [
    ("valid-minimal-username", "b", "viewer", GOOD_PW, True),
    ("valid-full-shape", "Bob.Smith-9_ops", "operator", GOOD_PW, True),
    ("valid-admin-role", "newadmin", "admin", GOOD_PW, True),
    ("empty-username", "", "viewer", GOOD_PW, False),
    ("username-with-space", "has space", "viewer", GOOD_PW, False),
    ("username-with-slash", "a/b", "viewer", GOOD_PW, False),
    ("username-65-chars", "a" * 65, "viewer", GOOD_PW, False),
    ("username-path-traversal", "../x", "viewer", GOOD_PW, False),
    ("username-64-chars-ok", "a" * 64, "viewer", GOOD_PW, True),
    ("empty-role", "bob", "", GOOD_PW, False),
    ("unknown-role-superuser", "bob", "superuser", GOOD_PW, False),
    ("role-wrong-case", "bob", "Admin", GOOD_PW, False),
    ("password-too-short", "bob", "viewer", "short", False),
    ("password-common", "bob", "viewer", "password123", False),
    ("password-contains-username", "bobsmith", "viewer", "bobsmith-is-the-password", False),
    ("password-empty", "bob", "viewer", "", False),
]


@pytest.mark.parametrize(
    "username,role,password,expect_ok", [c[1:] for c in _CREATE_CASES], ids=[c[0] for c in _CREATE_CASES]
)
def test_create_accepts_exactly_the_allowed_inputs(store, username, role, password, expect_ok) -> None:
    client, csrf, _me = _seed(store)
    resp = client.post("/users", form={
        "csrf_token": csrf, "username": username, "display_name": "X", "role": role,
        "password": password,
    })
    created = store.calls_to("create_user")
    if expect_ok:
        assert resp.status == 303
        assert len(created) == 1
        assert created[0].kwargs["username"] == username
        assert created[0].kwargs["role"] == role
    else:
        assert resp.status == 400
        assert not created


def test_create_rejects_a_username_already_taken(store) -> None:
    store.add_user(username="taken", role="viewer", password="pw")
    client, csrf, _me = _seed(store)
    resp = client.post("/users", form={
        "csrf_token": csrf, "username": "taken", "display_name": "X", "role": "viewer",
        "password": GOOD_PW,
    })
    assert resp.status == 400
    assert not store.calls_to("create_user")


# (id, role, expect_ok)
_UPDATE_CASES: list[tuple[str, str, bool]] = [
    ("valid-viewer", "viewer", True),
    ("valid-operator", "operator", True),
    ("valid-admin", "admin", True),
    ("empty-role", "", False),
    ("unknown-role", "superuser", False),
    ("role-wrong-case", "Admin", False),
]


@pytest.mark.parametrize(
    "role,expect_ok", [c[1:] for c in _UPDATE_CASES], ids=[c[0] for c in _UPDATE_CASES]
)
def test_update_accepts_exactly_a_valid_role(store, role, expect_ok) -> None:
    victim = store.add_user(username="v", role="viewer", password="pw")
    client, csrf, _me = _seed(store)  # "me" stays the sole admin; victim is not an admin so no guard
    resp = client.post(f"/users/{victim.user_id}/update", form={
        "csrf_token": csrf, "display_name": "V", "role": role, "enabled": "1",
    })
    updated = store.calls_to("update_user")
    if expect_ok:
        assert resp.status == 303
        assert len(updated) == 1
        assert updated[0].kwargs["role"] == role
        assert updated[0].kwargs["display_name"] == "V"
        assert updated[0].kwargs["is_enabled"] is True
    else:
        assert resp.status == 400
        assert not updated


# ══ Property 31 -- the console cannot lock itself out ══════════════════════════════════════════════

# (id, action) applied to the last enabled admin -- each must be refused.
_LOCKOUT_ACTIONS: list[tuple[str, str]] = [
    ("disable-last-admin", "disable"),
    ("demote-last-admin", "demote"),
    ("delete-last-admin", "delete"),
]


def _apply_action(client: WsgiClient, csrf: str, user_id: int, action: str):
    if action == "disable":
        return client.post(f"/users/{user_id}/update", form={
            "csrf_token": csrf, "display_name": "X", "role": "admin", "enabled": "",
        })
    if action == "demote":
        return client.post(f"/users/{user_id}/update", form={
            "csrf_token": csrf, "display_name": "X", "role": "operator", "enabled": "1",
        })
    assert action == "delete"
    return client.post(f"/users/{user_id}/delete", form={"csrf_token": csrf})


@pytest.mark.parametrize("action", [c[1] for c in _LOCKOUT_ACTIONS], ids=[c[0] for c in _LOCKOUT_ACTIONS])
def test_last_enabled_admin_cannot_be_disabled_demoted_or_deleted(store, action) -> None:
    client, csrf, me = _seed(store)  # "me" is the only enabled admin
    resp = _apply_action(client, csrf, me, action)
    assert resp.status == 400
    assert not store.calls_to("update_user")
    assert not store.calls_to("delete_user")


@pytest.mark.parametrize("action", [c[1] for c in _LOCKOUT_ACTIONS], ids=[c[0] for c in _LOCKOUT_ACTIONS])
def test_a_second_enabled_admin_permits_the_same_action(store, action) -> None:
    other = store.add_user(username="second", role="admin", password="pw")
    client, csrf, _me = _seed(store)  # me + second: two enabled admins
    resp = _apply_action(client, csrf, other.user_id, action)
    assert resp.status == 303
    if action == "delete":
        assert any(c.kwargs["user_id"] == other.user_id for c in store.calls_to("delete_user"))
    else:
        assert store.calls_to("update_user")


@pytest.mark.parametrize("admin_count", [1, 2, 5], ids=["one-admin", "two-admins", "five-admins"])
def test_an_admin_can_never_delete_their_own_account(store, admin_count) -> None:
    for i in range(admin_count - 1):
        store.add_user(username=f"admin{i}", role="admin", password="pw")
    client, csrf, me = _seed(store)  # brings the total to admin_count
    resp = client.post(f"/users/{me}/delete", form={"csrf_token": csrf})
    assert resp.status == 400
    assert not store.calls_to("delete_user")


# ══ Property 32 -- revocation is complete and leaves no orphans ════════════════════════════════════


def _seed_session_for(store, user_id: int) -> bytes:
    token = auth.new_session_token()
    th = auth.token_hash(token)
    store.create_session(
        token_hash=th, user_id=user_id, expires_utc=WHEN + auth.SESSION_IDLE_TIMEOUT,
        ip="9.9.9.9", user_agent="ua", csrf_secret=auth.new_csrf_secret(),
    )
    return th


def test_disabling_a_user_ends_exactly_that_users_sessions(store) -> None:
    victim = store.add_user(username="v", role="operator", password="pw")
    victim_session = _seed_session_for(store, victim.user_id)
    client, csrf, me = _seed(store)
    resp = client.post(f"/users/{victim.user_id}/update", form={
        "csrf_token": csrf, "display_name": "V", "role": "operator", "enabled": "",
    })
    assert resp.status == 303
    assert any(
        c.kwargs["user_id"] == victim.user_id for c in store.calls_to("delete_sessions_for_user")
    )
    assert victim_session not in store.sessions
    # The acting admin's own session, seeded by _seed, is left alone -- only the victim's is gone.
    assert any(s["user_id"] == me for s in store.sessions.values())


def test_deleting_a_user_leaves_no_session_for_that_user(store) -> None:
    victim = store.add_user(username="v", role="viewer", password="pw")
    victim_session = _seed_session_for(store, victim.user_id)
    client, csrf, _me = _seed(store)
    resp = client.post(f"/users/{victim.user_id}/delete", form={"csrf_token": csrf})
    assert resp.status == 303
    assert any(c.kwargs["user_id"] == victim.user_id for c in store.calls_to("delete_user"))
    assert victim_session not in store.sessions
    assert not any(s["user_id"] == victim.user_id for s in store.sessions.values())


def test_a_refused_mutation_ends_no_sessions_and_deletes_nobody(store) -> None:
    # "me" is the last enabled admin; disabling would lock the console out and must touch nothing.
    client, csrf, me = _seed(store)
    resp = client.post(f"/users/{me}/update", form={
        "csrf_token": csrf, "display_name": "Me", "role": "admin", "enabled": "",
    })
    assert resp.status == 400
    assert not store.calls_to("delete_sessions_for_user")
    assert not store.calls_to("delete_user")
    assert not store.calls_to("update_user")
