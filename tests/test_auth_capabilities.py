"""
Table-driven property tests over hostile fixed inputs for the role/capability matrix in
:mod:`adms.admin.auth`. No hypothesis, no new dependency -- plain pytest parametrize.

The module under test is settled and NOT modified here.
"""

from __future__ import annotations

import pytest

from adms.admin.auth import Principal, Role

# ── Property 8: capabilities follow from the role, exactly ────────────────────────────────

VALID_ROLES = ("viewer", "operator", "admin")
INVALID_ROLES = ("", "Admin", "root", "3", "operatorx", "\U0001F600")  # last is the grinning-face emoji

ALL_ROLES = [
    *[pytest.param(role, id=f"valid-{role}") for role in VALID_ROLES],
    *[pytest.param(role, id=f"invalid-{role!r}") for role in INVALID_ROLES],
]

#: Expected capability set per role, expressed explicitly so the assertion states the policy
#: rather than re-deriving it from the implementation under test.
EXPECTED_CAPABILITIES = {
    "viewer": {"can_view"},
    "operator": {"can_view", "can_operate"},
    "admin": {"can_view", "can_operate", "can_administer", "can_send_destructive_command"},
}

DUMMY_SECRET = b"\x00" * 32


def _principal_for(role: str) -> Principal:
    return Principal(
        user_id=1,
        username="probe",
        display_name="Probe",
        role=role,
        must_change_password=False,
        csrf_secret=DUMMY_SECRET,
    )


@pytest.mark.parametrize("role", ALL_ROLES)
def test_capability_matrix_matches_expected_table(role):
    expected = EXPECTED_CAPABILITIES.get(role, set())  # invalid roles: no capability granted
    principal = _principal_for(role)

    assert principal.can_view == ("can_view" in expected)
    assert principal.can_operate == ("can_operate" in expected)
    assert principal.can_administer == ("can_administer" in expected)
    assert principal.can_send_destructive_command == ("can_send_destructive_command" in expected)


# ── Role.is_valid and Role.at_least over the same role set ─────────────────────────────────


@pytest.mark.parametrize("role", ALL_ROLES)
def test_role_is_valid_matches_membership_in_valid_roles(role):
    assert Role.is_valid(role) == (role in VALID_ROLES)


@pytest.mark.parametrize("role", ALL_ROLES)
def test_role_at_least_operator_matches_operate_capability(role):
    expected = EXPECTED_CAPABILITIES.get(role, set())
    assert Role.at_least(role, Role.OPERATOR) == ("can_operate" in expected)


@pytest.mark.parametrize("role", ALL_ROLES)
def test_role_at_least_admin_matches_administer_capability(role):
    expected = EXPECTED_CAPABILITIES.get(role, set())
    assert Role.at_least(role, Role.ADMIN) == ("can_administer" in expected)


@pytest.mark.parametrize("role", ALL_ROLES)
def test_role_at_least_viewer_matches_view_capability(role):
    expected = EXPECTED_CAPABILITIES.get(role, set())
    assert Role.at_least(role, Role.VIEWER) == ("can_view" in expected)


def test_role_at_least_rejects_an_invalid_minimum():
    # An unrecognised "minimum" ranks above every real role (default 99), so nothing clears it.
    assert Role.at_least(Role.ADMIN, "superadmin") is False
