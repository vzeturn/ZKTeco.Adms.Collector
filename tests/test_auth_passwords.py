"""
Regression locks on :mod:`adms.admin.auth` password handling.

``auth.py`` is a settled module -- these tests do not drive new behaviour, they pin the behaviour that
already exists so it cannot drift. The property suite in this file's ``* 1.2`` sibling adds the hostile
inputs; this one starts with the single fact everything else rests on.
"""

from __future__ import annotations

from adms.admin.auth import PBKDF2_ITERATIONS


def test_iteration_count_is_600k() -> None:
    """
    The stored cost must stay at the desktop tool's 600,000.

    Named as a test rather than a comment because the number is a security parameter shared with
    another system: a well-meaning edit lowering it to speed something up would weaken every hash, and
    a failing test is the only thing that argues back. Raising it deliberately is fine -- update this
    line and the rehash-on-sign-in path carries existing users forward -- but it may not drift silently.
    """
    assert PBKDF2_ITERATIONS == 600_000
