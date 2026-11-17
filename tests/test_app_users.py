"""
User management and the last-admin guard (task 8.1): GET /users, create, update, unlock, delete.

Every mutation here is an administer capability, needs a valid CSRF token, writes exactly one audit
row, and answers 303 -- never a page in place. Creation validates the username shape, refuses a
duplicate, requires a valid role and a password that clears the policy, and always forces a change on
first sign-in so the admin never holds another person's lasting password. The last-admin guard runs at
the point of change: the final enabled admin cannot be demoted, disabled or deleted, or the console
locks itself out. An admin cannot delete their own account. Disabling or deleting a user ends that
user's sessions, so a revoked account cannot keep riding a live cookie.
"""

from __future__ import annotations

import datetime as dt

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


# ── GET /users renders the roster ──────────────────────────────────────────────────────────────────


def test_users_page_lists_users(store) -> None:
    store.add_user(username="alice", role="operator", password="pw")
    client, _csrf, _me = _seed(store)
    resp = client.get("/users")
    assert resp.status == 200
    assert "alice" in resp.text


# ── create ──────────────────────────────────────────────────────────────────────────────────────────


def test_create_makes_a_user_forced_to_change_password_and_redirects(store) -> None:
    client, csrf, _me = _seed(store)
    resp = client.post("/users", form={
        "csrf_token": csrf, "username": "bob", "display_name": "Bob", "role": "operator",
        "password": GOOD_PW,
    })
    assert resp.status == 303
    created = store.calls_to("create_user")
    assert len(created) == 1
    assert created[0].kwargs["username"] == "bob"
    assert created[0].kwargs["role"] == "operator"
    # The admin sets a temporary password; the user must replace it on first sign-in.
    assert created[0].kwargs["must_change_password"] is True
    assert store.audited("user.create")


def test_create_rejects_a_duplicate_username(store) -> None:
    store.add_user(username="bob", role="operator", password="pw")
    client, csrf, _me = _seed(store)
    resp = client.post("/users", form={
        "csrf_token": csrf, "username": "bob", "display_name": "Bob", "role": "operator",
        "password": GOOD_PW,
    })
    assert resp.status == 400
    assert not store.calls_to("create_user")


def test_create_rejects_an_unknown_role(store) -> None:
    client, csrf, _me = _seed(store)
    resp = client.post("/users", form={
        "csrf_token": csrf, "username": "bob", "display_name": "Bob", "role": "superuser",
        "password": GOOD_PW,
    })
    assert resp.status == 400
    assert not store.calls_to("create_user")


def test_create_rejects_a_bad_username_shape(store) -> None:
    client, csrf, _me = _seed(store)
    resp = client.post("/users", form={
        "csrf_token": csrf, "username": "has space", "display_name": "X", "role": "viewer",
        "password": GOOD_PW,
    })
    assert resp.status == 400
    assert not store.calls_to("create_user")


def test_create_rejects_a_weak_password_and_never_echoes_it(store) -> None:
    client, csrf, _me = _seed(store)
    weak = "short"
    resp = client.post("/users", form={
        "csrf_token": csrf, "username": "bob", "display_name": "X", "role": "viewer",
        "password": weak,
    })
    assert resp.status == 400
    assert not store.calls_to("create_user")
    assert weak not in resp.text  # a rejected password is never reflected back into the page


# ── update: role/display/enabled, guarded by the last-admin rule ────────────────────────────────────


def test_update_changes_role_and_redirects(store) -> None:
    victim = store.add_user(username="v", role="viewer", password="pw")
    client, csrf, _me = _seed(store)
    resp = client.post(f"/users/{victim.user_id}/update", form={
        "csrf_token": csrf, "display_name": "V", "role": "operator", "enabled": "1",
    })
    assert resp.status == 303
    updated = store.calls_to("update_user")
    assert len(updated) == 1
    assert updated[0].kwargs["role"] == "operator"
    assert updated[0].kwargs["is_enabled"] is True
    assert store.audited("user.update")


def test_update_disabling_a_user_ends_that_users_sessions(store) -> None:
    victim = store.add_user(username="v", role="operator", password="pw")
    vtoken = auth.new_session_token()
    store.create_session(
        token_hash=auth.token_hash(vtoken), user_id=victim.user_id,
        expires_utc=WHEN + auth.SESSION_IDLE_TIMEOUT, ip="9.9.9.9", user_agent="ua",
        csrf_secret=auth.new_csrf_secret(),
    )
    client, csrf, _me = _seed(store)
    resp = client.post(f"/users/{victim.user_id}/update", form={
        "csrf_token": csrf, "display_name": "V", "role": "operator", "enabled": "",
    })
    assert resp.status == 303
    assert store.calls_to("update_user")[0].kwargs["is_enabled"] is False
    assert any(
        c.kwargs["user_id"] == victim.user_id for c in store.calls_to("delete_sessions_for_user")
    )


def test_update_cannot_disable_the_last_enabled_admin(store) -> None:
    # The acting admin is the only enabled admin; disabling them would lock the console out.
    client, csrf, me = _seed(store)
    resp = client.post(f"/users/{me}/update", form={
        "csrf_token": csrf, "display_name": "Me", "role": "admin", "enabled": "",
    })
    assert resp.status == 400
    assert not store.calls_to("update_user")


def test_update_cannot_demote_the_last_enabled_admin(store) -> None:
    client, csrf, me = _seed(store)
    resp = client.post(f"/users/{me}/update", form={
        "csrf_token": csrf, "display_name": "Me", "role": "operator", "enabled": "1",
    })
    assert resp.status == 400
    assert not store.calls_to("update_user")


def test_update_can_demote_an_admin_when_another_enabled_admin_remains(store) -> None:
    other = store.add_user(username="other", role="admin", password="pw")
    client, csrf, _me = _seed(store)  # now two enabled admins
    resp = client.post(f"/users/{other.user_id}/update", form={
        "csrf_token": csrf, "display_name": "O", "role": "operator", "enabled": "1",
    })
    assert resp.status == 303
    assert store.calls_to("update_user")[0].kwargs["role"] == "operator"


def test_update_on_unknown_user_is_404(store) -> None:
    client, csrf, _me = _seed(store)
    resp = client.post("/users/999/update", form={
        "csrf_token": csrf, "display_name": "X", "role": "viewer", "enabled": "1",
    })
    assert resp.status == 404
    assert not store.calls_to("update_user")


def test_update_with_a_non_numeric_id_is_404(store) -> None:
    client, csrf, _me = _seed(store)
    resp = client.post("/users/abc/update", form={
        "csrf_token": csrf, "display_name": "X", "role": "viewer", "enabled": "1",
    })
    assert resp.status == 404
    assert not store.calls_to("update_user")


# ── unlock ──────────────────────────────────────────────────────────────────────────────────────────


def test_unlock_clears_the_lock_and_redirects(store) -> None:
    victim = store.add_user(username="v", role="viewer", password="pw")
    client, csrf, _me = _seed(store)
    resp = client.post(f"/users/{victim.user_id}/unlock", form={"csrf_token": csrf})
    assert resp.status == 303
    assert any(c.kwargs["user_id"] == victim.user_id for c in store.calls_to("unlock_user"))
    assert store.audited("user.unlock")


def test_unlock_on_unknown_user_is_404(store) -> None:
    client, csrf, _me = _seed(store)
    resp = client.post("/users/999/unlock", form={"csrf_token": csrf})
    assert resp.status == 404
    assert not store.calls_to("unlock_user")


# ── delete: self-delete and last-admin guards ──────────────────────────────────────────────────────


def test_delete_removes_a_user_and_redirects(store) -> None:
    victim = store.add_user(username="v", role="viewer", password="pw")
    client, csrf, _me = _seed(store)
    resp = client.post(f"/users/{victim.user_id}/delete", form={"csrf_token": csrf})
    assert resp.status == 303
    assert any(c.kwargs["user_id"] == victim.user_id for c in store.calls_to("delete_user"))
    assert store.audited("user.delete")


def test_delete_refuses_self_deletion(store) -> None:
    client, csrf, me = _seed(store)
    resp = client.post(f"/users/{me}/delete", form={"csrf_token": csrf})
    assert resp.status == 400
    assert not store.calls_to("delete_user")


def test_delete_can_remove_another_admin_when_an_enabled_admin_remains(store) -> None:
    # Deleting another admin is allowed as long as the actor stays an enabled admin; the last-admin
    # guard bites through self-delete (covered above), which is why removing a peer admin is fine.
    other_admin = store.add_user(username="second", role="admin", password="pw")
    client, csrf, _me = _seed(store)  # me + second are the two enabled admins
    resp = client.post(f"/users/{other_admin.user_id}/delete", form={"csrf_token": csrf})
    assert resp.status == 303
    assert any(c.kwargs["user_id"] == other_admin.user_id for c in store.calls_to("delete_user"))


def test_delete_on_unknown_user_is_404(store) -> None:
    client, csrf, _me = _seed(store)
    resp = client.post("/users/999/delete", form={"csrf_token": csrf})
    assert resp.status == 404
    assert not store.calls_to("delete_user")
