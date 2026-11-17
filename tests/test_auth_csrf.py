"""
Table-driven property tests over hostile fixed inputs for CSRF tokens in
:mod:`adms.admin.auth`. No hypothesis, no new dependency -- plain pytest parametrize.

The module under test is settled and NOT modified here.
"""

from __future__ import annotations

import pytest

from adms.admin.auth import csrf_token, new_csrf_secret, verify_csrf_token

# ── Property 5: a CSRF token verifies against its own session and no other ────────────────

# Fixed, distinct secrets rather than two calls to new_csrf_secret(): deterministic, and the
# equal-by-chance case new_csrf_secret() is meant to rule out is astronomically unlikely anyway.
SECRET_A = b"\x01" * 32
SECRET_B = b"\x02" * 32


def test_token_from_secret_a_verifies_against_a_only():
    token = csrf_token(SECRET_A)
    assert verify_csrf_token(SECRET_A, token) is True
    assert verify_csrf_token(SECRET_B, token) is False


def test_token_from_secret_b_verifies_against_b_only():
    token = csrf_token(SECRET_B)
    assert verify_csrf_token(SECRET_B, token) is True
    assert verify_csrf_token(SECRET_A, token) is False


def test_new_csrf_secret_produces_usable_distinct_secrets():
    secret_1 = new_csrf_secret()
    secret_2 = new_csrf_secret()
    assert len(secret_1) == 32
    assert len(secret_2) == 32
    token = csrf_token(secret_1)
    assert verify_csrf_token(secret_1, token) is True
    if secret_1 != secret_2:
        assert verify_csrf_token(secret_2, token) is False


# ── Malformed tokens must never verify ─────────────────────────────────────────────────────


def _tampered_real_token(secret: bytes) -> str:
    """A genuine token from ``secret`` with the last hex character of its mac flipped."""
    token = csrf_token(secret)
    nonce, _, mac = token.partition(".")
    flipped_last = "0" if mac[-1] != "0" else "1"
    return f"{nonce}.{mac[:-1]}{flipped_last}"


MALFORMED_TOKENS = [
    pytest.param("", id="empty-string"),
    pytest.param("noseparator", id="no-dot-separator"),
    pytest.param(".onlymac", id="empty-nonce"),
    pytest.param("nonce.", id="empty-mac"),
    pytest.param("abc.def", id="garbage-nonce-and-mac"),
    pytest.param("..", id="two-dots-both-empty"),
    pytest.param(".", id="single-dot-both-empty"),
]


@pytest.mark.parametrize("token", MALFORMED_TOKENS)
def test_malformed_token_never_verifies(token):
    assert verify_csrf_token(SECRET_A, token) is False


def test_tampered_mac_on_a_real_token_does_not_verify():
    tampered = _tampered_real_token(SECRET_A)
    assert verify_csrf_token(SECRET_A, tampered) is False


def test_real_token_verified_against_wrong_secret_does_not_verify():
    token = csrf_token(SECRET_A)
    assert verify_csrf_token(SECRET_B, token) is False


# ── Nonces are unique per mint, yet each still verifies ────────────────────────────────────


def test_many_tokens_from_the_same_secret_have_unique_nonces_and_all_verify():
    tokens = [csrf_token(SECRET_A) for _ in range(25)]
    assert len(set(tokens)) == len(tokens)
    for token in tokens:
        assert verify_csrf_token(SECRET_A, token) is True
