"""
Table-driven property tests over hostile fixed inputs for password hashing/policy in
:mod:`adms.admin.auth`. No hypothesis, no new dependency -- plain pytest parametrize.

The module under test is settled and NOT modified here.
"""

from __future__ import annotations

import unicodedata

import pytest

from adms.admin.auth import hash_password, password_problems, verify_password

# ── Property 12: hashing round-trips and respects its stored cost ─────────────────────────

PASSWORDS_AND_SALTS = [
    pytest.param("correct horse battery staple", b"\x00" * 32, id="ascii-lowercase-zero-salt"),
    pytest.param("Tr0ub4dor&3-extra-long-phrase", b"\xff" * 32, id="mixed-symbols-ff-salt"),
    pytest.param("Xin chào cà phê sữa đá", bytes(range(32)), id="vietnamese-diacritics"),
    pytest.param("   leading and trailing spaces   ", b"\x01\x02\x03" * 10 + b"\x04\x05", id="space-padded"),
    pytest.param("", b"\xaa" * 32, id="empty-password"),
    pytest.param("a" * 200, b"\x7f" * 32, id="max-length-repeat"),
]

ITERATION_COUNTS = [1000, 2000, 5000]


@pytest.mark.parametrize("iterations", ITERATION_COUNTS, ids=[f"iter={n}" for n in ITERATION_COUNTS])
@pytest.mark.parametrize("password,salt", PASSWORDS_AND_SALTS)
def test_hash_round_trips_at_its_own_iteration_count(password, salt, iterations):
    digest = hash_password(password, salt, iterations)
    assert verify_password(password, salt, digest, iterations) is True


@pytest.mark.parametrize("iterations", ITERATION_COUNTS, ids=[f"iter={n}" for n in ITERATION_COUNTS])
@pytest.mark.parametrize("password,salt", PASSWORDS_AND_SALTS)
def test_verify_rejects_a_different_password(password, salt, iterations):
    digest = hash_password(password, salt, iterations)
    wrong = password + "!" if password else "not-empty"
    assert verify_password(wrong, salt, digest, iterations) is False


@pytest.mark.parametrize("iterations", ITERATION_COUNTS, ids=[f"iter={n}" for n in ITERATION_COUNTS])
@pytest.mark.parametrize("password,salt", PASSWORDS_AND_SALTS)
def test_verify_rejects_a_different_iteration_count(password, salt, iterations):
    digest = hash_password(password, salt, iterations)
    other_iterations = iterations + 1000
    assert verify_password(password, salt, digest, other_iterations) is False


NFC_NFD_PAIRS = [
    pytest.param("Xin chào cà phê", id="xin-chao-ca-phe"),
    pytest.param("Mật khẩu Tiếng Việt", id="mat-khau-tieng-viet"),
    pytest.param("Đà Lạt sương mù buổi sáng", id="da-lat-suong-mu"),
]


@pytest.mark.parametrize("iterations", ITERATION_COUNTS, ids=[f"iter={n}" for n in ITERATION_COUNTS])
@pytest.mark.parametrize("password", NFC_NFD_PAIRS)
def test_nfc_and_nfd_spellings_hash_identically(password, iterations):
    salt = b"\x10" * 32
    nfc = unicodedata.normalize("NFC", password)
    nfd = unicodedata.normalize("NFD", password)
    assert nfc != nfd  # sanity: the fixture actually exercises two different byte spellings

    digest_nfc = hash_password(nfc, salt, iterations)
    digest_nfd = hash_password(nfd, salt, iterations)
    assert digest_nfc == digest_nfd
    assert verify_password(nfd, salt, digest_nfc, iterations) is True
    assert verify_password(nfc, salt, digest_nfd, iterations) is True


def test_iteration_upgrade_rehash_invariant():
    """
    Pure-function level of the rehash-on-signin invariant: a password hashed at a low cost
    still verifies at that cost; hashing again at a higher cost yields different bytes but
    still verifies at the higher cost. app.py's rehash orchestration is out of scope here.
    """
    password = "correct horse battery staple long"
    salt = b"\x22" * 32
    low_iterations = 1000
    high_iterations = 5000

    low_hash = hash_password(password, salt, low_iterations)
    assert verify_password(password, salt, low_hash, low_iterations) is True

    high_hash = hash_password(password, salt, high_iterations)
    assert high_hash != low_hash
    assert verify_password(password, salt, high_hash, high_iterations) is True
    # The old hash must not satisfy verification at the new cost -- that's the whole point of
    # storing the iteration count per row instead of assuming a global constant.
    assert verify_password(password, salt, low_hash, high_iterations) is False


# ── Property 13: the password policy states every reason it refuses ───────────────────────

TOO_SHORT = "short"
TOO_LONG = "a" * 201
LEADING_SPACE = " leadingspace12345"
TRAILING_SPACE = "trailingspace12345 "
CONTAINS_USERNAME = "alice-supersecret1"

COMMON_PASSWORDS = [
    "password", "123456", "12345678", "qwerty", "111111", "123123",
    "admin", "administrator", "letmein", "welcome", "matkhau", "password123",
]

VIOLATION_CASES = [
    pytest.param(TOO_SHORT, "", "Must be at least 12 characters.", id="too-short"),
    pytest.param(TOO_LONG, "", "Must be at most 200 characters.", id="too-long-201-chars"),
    pytest.param(LEADING_SPACE, "", "Must not begin or end with a space.", id="leading-space"),
    pytest.param(TRAILING_SPACE, "", "Must not begin or end with a space.", id="trailing-space"),
    pytest.param(CONTAINS_USERNAME, "alice", "Must not contain the username.", id="contains-username"),
    pytest.param(
        "ALICE-supersecret1", "alice", "Must not contain the username.",
        id="contains-username-case-insensitive",
    ),
] + [
    pytest.param(common, "", "This password is too common.", id=f"common-{common}")
    for common in COMMON_PASSWORDS
]


@pytest.mark.parametrize("password,username,expected_message", VIOLATION_CASES)
def test_policy_reports_the_specific_violation(password, username, expected_message):
    problems = password_problems(password, username)
    assert problems  # non-empty
    assert expected_message in problems


ACCEPTABLE_PASSWORDS = [
    pytest.param("correct horse battery staple", "", id="long-passphrase"),
    pytest.param("Tr0ub4dor&3-extra-long-phrase", "bob", id="mixed-symbols-with-unrelated-username"),
    pytest.param("Xin chào cà phê sữa đá 2026", "", id="vietnamese-diacritics-long-enough"),
    pytest.param("a" * 200, "", id="max-length-boundary-accepted"),
    pytest.param("a" * 12, "", id="min-length-boundary-accepted"),
]


@pytest.mark.parametrize("password,username", ACCEPTABLE_PASSWORDS)
def test_policy_accepts_clean_passwords(password, username):
    assert password_problems(password, username) == []
