"""
Tests for the command builders `multi-device-employee-sync` added/corrected in
``adms.protocol.commands``: ``update_fingertmp``, ``update_facetmp``, ``delete_userinfo``, and the
now-deprecated ``delete_user`` alias.

No adapter, no service, no database -- these are pure rendering functions, exactly like
``update_user``/``query_user_info`` in ``test_commands_codec.py``, whose style this file follows.

Two of these renderings carry a hardware fact confirmed on a device, not just a vendor-guide
spelling:

* ``update_fingertmp``'s exact field order and casing (``PIN``/``FID``/``Size``/``Valid``/``TMP``)
  is what a device (firmware Ver 6.60) accepted with ``ReturnCode=0`` and then echoed back
  byte-identical on query. Changing this rendering without re-verifying against hardware would be
  silently reintroducing an unverified command.
* ``delete_userinfo``'s wording is what the same firmware accepted after ``DATA DELETE USER`` (the
  wording ``delete_user`` used to render) was rejected with ``ReturnCode=-1004``. The alias test
  below exists specifically to guard against ``delete_user`` ever reverting to that rejected
  wording.

``update_facetmp`` has no hardware confirmation --
its test only pins the *rendering contract*, matching the read-side field names in
``operlog.py``'s ``_parse_face``, not a firmware acceptance fact.
"""

from __future__ import annotations

from adms.protocol.commands import (
    delete_user,
    delete_userinfo,
    update_facetmp,
    update_fingertmp,
)

# ── update_fingertmp: Requirement 24.1 ──────────────────────────────────────────────────────


def test_update_fingertmp_renders_verified_field_order_and_casing() -> None:
    # Feature: multi-device-employee-sync, Requirement 24.1
    """
    The exact wording and field order verified against real firmware: ``DATA UPDATE FINGERTMP``
    followed by tab-separated ``PIN``, ``FID``, ``Size``, ``Valid``, ``TMP`` fields, in that order
    and that casing. This is the rendering that was pushed to a device and round-tripped
    successfully -- any change to field order, casing or separator here is a change to a command
    that has only ever been confirmed working in this exact form.
    """
    body = update_fingertmp("999999", 6, "TT9TUzIxAAAEfH4E", size=16, valid=1)
    assert body == "DATA UPDATE FINGERTMP PIN=999999\tFID=6\tSize=16\tValid=1\tTMP=TT9TUzIxAAAEfH4E"


def test_update_fingertmp_size_defaults_to_template_length() -> None:
    # Feature: multi-device-employee-sync, Requirement 24.1
    """
    When ``size`` is not given, it defaults to ``len(template)`` -- matching what a device's own
    ``FP`` upload reports when it does not know a better value (``operlog.py``'s ``_parse_finger``
    does the same on the read side), so a caller that has a template but no separately-tracked
    size still renders a self-consistent command.
    """
    template = "A" * 1532
    body = update_fingertmp("1", 6, template)
    assert f"Size={len(template)}" in body
    assert body.endswith(f"TMP={template}")


def test_update_fingertmp_valid_defaults_to_one() -> None:
    # Feature: multi-device-employee-sync, Requirement 24.1
    body = update_fingertmp("1", 0, "abc")
    assert "Valid=1" in body


def test_update_fingertmp_never_raises_on_empty_template() -> None:
    # Feature: multi-device-employee-sync, Requirement 24.1
    """An empty template still renders (size 0, empty TMP) -- rendering is pure and total, exactly
    as every other builder in this module is; whether an empty template should ever be *enqueued*
    is Roster_Sync's decision, not this function's."""
    body = update_fingertmp("1", 0, "")
    assert body == "DATA UPDATE FINGERTMP PIN=1\tFID=0\tSize=0\tValid=1\tTMP="


# ── update_facetmp: Requirement 24.2 (NOT VERIFIED against firmware) ────────────────────────


def test_update_facetmp_renders_the_biodata_wording_and_field_names() -> None:
    # Feature: multi-device-employee-sync, Requirement 24.2
    """
    Renders ``DATA UPDATE BIODATA`` with the same field names ``operlog.py``'s ``_parse_face``
    reads on the way in (``PIN``/``FID``/``SIZE``/``VALID``/``TMP``, upper-cased ``SIZE``/``VALID``
    matching the face parser's own field spelling, distinct from ``update_fingertmp``'s
    ``Size``/``Valid``). This pins the rendering contract only -- see the module docstring: there
    is no hardware confirmation behind this one yet.
    """
    body = update_facetmp("42", 0, "ZmFjZXRtcA==", size=12, valid=1)
    assert body == "DATA UPDATE BIODATA PIN=42\tFID=0\tSIZE=12\tVALID=1\tTMP=ZmFjZXRtcA=="


def test_update_facetmp_size_defaults_to_template_length() -> None:
    # Feature: multi-device-employee-sync, Requirement 24.2
    template = "B" * 200
    body = update_facetmp("1", 0, template)
    assert f"SIZE={len(template)}" in body


# ── delete_userinfo: Requirement 24.2b, 24.9-24.10 ──────────────────────────────────────────


def test_delete_userinfo_renders_the_accepted_wording() -> None:
    # Feature: multi-device-employee-sync, Requirement 24.2b
    """
    The wording confirmed accepted (``ReturnCode=0``) by real firmware, and confirmed by a
    follow-up query to have actually removed the user -- not merely acknowledged the request.
    """
    assert delete_userinfo("999999") == "DATA DELETE USERINFO PIN=999999"


def test_delete_user_alias_renders_the_same_accepted_wording_not_the_rejected_one() -> None:
    # Feature: multi-device-employee-sync, Requirement 24.2b
    """
    The single most important guard in this file: ``delete_user`` -- kept only so an import of the
    old name does not break -- must render EXACTLY what ``delete_userinfo`` renders, never the
    literal ``DATA DELETE USER`` wording it used to render before this feature. That old wording is
    confirmed rejected (``ReturnCode=-1004``) by real firmware; nothing may ever enqueue it again,
    including through this deprecated alias.
    """
    for pin in ("1", "999999", "202120"):
        assert delete_user(pin) == delete_userinfo(pin)
        assert "DATA DELETE USER PIN=" not in delete_user(pin), (
            f"pin={pin}: delete_user must never render the rejected 'DATA DELETE USER' wording "
            f"(no trailing INFO) -- got {delete_user(pin)!r}"
        )
        assert delete_user(pin) == f"DATA DELETE USERINFO PIN={pin}"
