"""
The page shell and the non-data pages: sign-in, change-password, confirm and error (task 2.3).

These are example tests for the accessible-structure contract every page rests on -- doctype, one
``<h1>``, a working skip link, landmarks, real labels, an announced error region, and a CSRF field in
every console form. The exhaustive over-all-inputs coverage is Property 33/34/7 in the ``* 2.4`` sibling.

The token here is a real one minted for a throwaway session secret so the "every form carries a usable
token" check is meaningful rather than a string-presence check.
"""

from __future__ import annotations

import re

import pytest

from adms.admin import auth, ui

SECRET = auth.new_csrf_secret()
TOKEN = auth.csrf_token(SECRET)


def _principal(role: str = auth.Role.ADMIN) -> auth.Principal:
    return auth.Principal(
        user_id=1,
        username="jane.doe",
        display_name="Jane Doe",
        role=role,
        must_change_password=False,
        csrf_secret=SECRET,
    )


# ── page shell ───────────────────────────────────────────────────────────────────────────────


def _shell() -> str:
    return ui.page(
        title="Devices",
        body="<p>content</p>",
        principal=_principal(),
        active="devices",
        csrf=TOKEN,
    )


def test_page_starts_with_doctype_and_declares_language() -> None:
    html = _shell()
    assert html.lstrip().lower().startswith("<!doctype html>")
    assert re.search(r'<html[^>]*\blang="en"', html) is not None


def test_page_has_exactly_one_h1() -> None:
    assert len(re.findall(r"<h1\b", _shell())) == 1


def test_page_skip_link_is_first_focusable_and_targets_main() -> None:
    html = _shell()
    # The skip link's own <a ...> must open before any other focusable element.
    skip_tag = html.find('<a class="skip-link"')
    assert skip_tag != -1
    others = [
        html.find("<a ", skip_tag + 1),
        html.find("<input"),
        html.find("<button"),
    ]
    for pos in others:
        assert pos == -1 or pos > skip_tag  # nothing focusable precedes the skip link
    href = re.search(r'class="skip-link"[^>]*href="#([\w-]+)"', html) or re.search(
        r'href="#([\w-]+)"[^>]*class="skip-link"', html
    )
    assert href is not None
    assert f'id="{href.group(1)}"' in html  # the target exists


def test_page_has_main_and_nav_landmarks() -> None:
    html = _shell()
    assert "<main" in html
    assert "<nav" in html


def test_page_marks_the_active_nav_item_as_current() -> None:
    assert 'aria-current="page"' in _shell()


def test_page_escapes_the_body_owner_but_trusts_body_html() -> None:
    # body is trusted, already-escaped HTML; the principal's display name is a value and is escaped.
    html = ui.page(
        title="T", body="<p>ok</p>", principal=ui_principal_named('<x>"'), csrf=TOKEN
    )
    assert "<p>ok</p>" in html  # body passed through verbatim
    assert "<x>" not in html.split("<main")[0].replace('class="skip-link"', "")


def ui_principal_named(name: str) -> auth.Principal:
    return auth.Principal(
        user_id=1,
        username="u",
        display_name=name,
        role=auth.Role.VIEWER,
        must_change_password=False,
        csrf_secret=SECRET,
    )


# ── sign-in ──────────────────────────────────────────────────────────────────────────────────


def test_sign_in_page_has_labelled_username_and_password_controls() -> None:
    html = ui.sign_in_page()
    for field in ("username", "password"):
        assert re.search(rf'<label[^>]*\bfor="{field}"', html) is not None
        assert re.search(rf'<input[^>]*\bid="{field}"', html) is not None


def test_sign_in_password_field_is_type_password() -> None:
    html = ui.sign_in_page()
    assert re.search(r'<input[^>]*id="password"[^>]*type="password"', html) or re.search(
        r'<input[^>]*type="password"[^>]*id="password"', html
    )


def test_sign_in_error_is_announced_and_username_is_preserved() -> None:
    html = ui.sign_in_page(error="Incorrect username or password.", username="jane.doe")
    assert 'role="alert"' in html
    assert 'aria-live="polite"' in html
    assert "Incorrect username or password." in html
    assert 'value="jane.doe"' in html  # so the user need not retype it


def test_sign_in_carries_next_url_as_a_hidden_field() -> None:
    html = ui.sign_in_page(next_url="/devices")
    assert re.search(r'<input[^>]*type="hidden"[^>]*name="next"[^>]*value="/devices"', html) or (
        'name="next"' in html and 'value="/devices"' in html
    )


def test_sign_in_never_shows_a_password_value() -> None:
    html = ui.sign_in_page(error="x", username="u")
    assert re.search(r'id="password"[^>]*value=', html) is None


# ── change password ──────────────────────────────────────────────────────────────────────────


def test_change_password_lists_problems_in_an_alert_region() -> None:
    html = ui.change_password_page(
        problems=["Must be at least 12 characters.", "This password is too common."],
        forced=True,
        csrf=TOKEN,
    )
    assert 'role="alert"' in html
    assert "Must be at least 12 characters." in html
    assert "This password is too common." in html


def test_change_password_marks_the_field_invalid_and_describes_it() -> None:
    html = ui.change_password_page(problems=["Too short."], forced=False, csrf=TOKEN)
    invalid = re.search(r'aria-invalid="true"', html)
    describedby = re.search(r'aria-describedby="([\w-]+)"', html)
    assert invalid is not None
    assert describedby is not None
    assert f'id="{describedby.group(1)}"' in html  # the description element exists


def test_change_password_forced_explains_why() -> None:
    forced = ui.change_password_page(problems=[], forced=True, csrf=TOKEN)
    voluntary = ui.change_password_page(problems=[], forced=False, csrf=TOKEN)
    assert forced != voluntary  # the forced variant says something the voluntary one does not


# ── confirm ──────────────────────────────────────────────────────────────────────────────────


def test_confirm_page_posts_to_the_action_with_hidden_fields_and_token() -> None:
    html = ui.confirm_page(
        title="Delete user",
        prompt="Delete jane.doe? This cannot be undone.",
        action="/users/5/delete",
        hidden={"user_id": "5"},
        csrf=TOKEN,
        danger=True,
    )
    assert 'action="/users/5/delete"' in html
    assert 'method="post"' in html.lower()
    assert re.search(r'name="user_id"[^>]*value="5"', html) or re.search(
        r'value="5"[^>]*name="user_id"', html
    )
    assert TOKEN in html
    assert "Delete jane.doe? This cannot be undone." in html


def test_confirm_page_escapes_a_hostile_prompt() -> None:
    html = ui.confirm_page(
        title="T",
        prompt='<script>alert(1)</script>',
        action="/x",
        hidden={},
        csrf=TOKEN,
    )
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_confirm_page_danger_flag_changes_the_button_styling() -> None:
    danger = ui.confirm_page(title="T", prompt="p", action="/x", hidden={}, csrf=TOKEN, danger=True)
    plain = ui.confirm_page(title="T", prompt="p", action="/x", hidden={}, csrf=TOKEN, danger=False)
    assert "danger" in danger
    assert danger != plain


# ── error ────────────────────────────────────────────────────────────────────────────────────


def test_error_page_shows_status_and_is_a_full_document() -> None:
    html = ui.error_page(status=404, heading="Not found", detail="No such page.")
    assert html.lstrip().lower().startswith("<!doctype html>")
    assert "404" in html
    assert "Not found" in html
    assert "No such page." in html
    assert len(re.findall(r"<h1\b", html)) == 1


def test_error_page_escapes_the_detail() -> None:
    html = ui.error_page(status=400, heading="Bad request", detail="<b>x</b>")
    assert "<b>x</b>" not in html
    assert "&lt;b&gt;x&lt;/b&gt;" in html


# ── the token appears in every console form ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "html",
    [
        ui.change_password_page(problems=[], forced=False, csrf=TOKEN),
        ui.confirm_page(title="T", prompt="p", action="/x", hidden={}, csrf=TOKEN),
    ],
)
def test_console_forms_carry_a_verifiable_token(html: str) -> None:
    found = re.findall(r'name="csrf_token"[^>]*value="([^"]+)"', html) + re.findall(
        r'value="([^"]+)"[^>]*name="csrf_token"', html
    )
    assert found, "no csrf field found"
    assert any(auth.verify_csrf_token(SECRET, value) for value in found)
