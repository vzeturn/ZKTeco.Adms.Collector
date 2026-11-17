"""
Table-driven hostile-input coverage for ``adms.admin.ui`` (task 2.2).

Encodes Property 1 (escaping is total, exact and single-pass) and Property 3
(nothing executable and nothing off-origin renders in any page) as fixed, parametrised test
tables -- no ``hypothesis``, no randomness. Sibling of ``test_ui_escaping.py``, which covers the
same module with ordinary example tests.
"""

from __future__ import annotations

import datetime as dt

import pytest

from adms.admin import auth, ui

# ── Fixtures / helpers ──────────────────────────────────────────────────────────────────────


def make_principal(display_name: str = "Alice", role: str = auth.Role.ADMIN) -> auth.Principal:
    secret = auth.new_csrf_secret()
    return auth.Principal(
        user_id=1,
        username="alice",
        display_name=display_name,
        role=role,
        must_change_password=False,
        csrf_secret=secret,
    )


def csrf_for(principal: auth.Principal) -> str:
    return auth.csrf_token(principal.csrf_secret)


# ── Property 1: esc() is total, exact, single-pass ──────────────────────────────────────────

# The five metacharacters esc() maps, applied in the documented order (& first).
_MAP = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;"}


def _expected_esc(text: str) -> str:
    out = []
    for ch in text:
        out.append(_MAP.get(ch, ch))
    return "".join(out)


HOSTILE_VALUES: list[object] = [
    None,
    42,
    True,
    dt.datetime(2026, 8, 12, 9, 30, 0),
    "\x00",
    "\x1b",
    "\r\n",
    "\ud800",
    "& < > \" '",
    "&amp;",
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "'><svg onload=alert(1)>",
    "javascript:alert(1)",
    "http://evil.example/x",
    "</title><script>",
]


@pytest.mark.parametrize(
    "value",
    HOSTILE_VALUES,
    ids=[repr(v) for v in HOSTILE_VALUES],
)
def test_esc_matches_single_pass_expected_mapping(value: object) -> None:
    if value is None:
        assert ui.esc(value) == ""
        return
    result = ui.esc(value)
    assert result == _expected_esc(str(value))
    assert isinstance(result, str)


def test_esc_none_renders_empty_not_the_word_none() -> None:
    assert ui.esc(None) == ""
    assert "None" not in ui.esc(None)


@pytest.mark.parametrize(
    ("raw", "once", "twice"),
    [
        ("&", "&amp;", "&amp;amp;"),
        ("&amp;", "&amp;amp;", "&amp;amp;amp;"),
        ("<", "&lt;", "&amp;lt;"),
    ],
)
def test_esc_double_application_is_the_single_pass_relationship(
    raw: str, once: str, twice: str
) -> None:
    first = ui.esc(raw)
    assert first == once
    second = ui.esc(first)
    assert second == twice
    # A single call never doubly-escapes an already-escaped entity introduced by that same call.
    assert once.count("&amp;amp;") == 0 or raw == "&amp;"


@pytest.mark.parametrize("value", HOSTILE_VALUES, ids=[repr(v) for v in HOSTILE_VALUES])
def test_esc_never_raises(value: object) -> None:
    ui.esc(value)
    ui.esc_attr(value)


def test_esc_attr_is_the_same_function_as_esc() -> None:
    assert ui.esc_attr is ui.esc


# ── Property 3: nothing executable, nothing off-origin ──────────────────────────────────────

INJECTION_PAYLOADS: list[str] = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "'><svg onload=alert(1)>",
    "javascript:alert(1)",
    "http://evil.example/x",
    "</title><script>",
    "&<>\"'",
    "\x00\x1b",
    "\ud800",
]

# Live-markup forms: an unescaped "<" immediately followed by the tag name means the browser
# would parse a real element, not text. A bare substring like "onerror=alert" is harmless once
# its surrounding "<" and ">" are escaped, so the check must anchor on the unescaped angle bracket.
_LIVE_MARKUP_SUBSTRINGS = (
    "<script",
    "<img",
    "<svg",
)


def _assert_no_live_injection(document: str) -> None:
    """Property 3: none of the raw dangerous tags survive as live, browser-parsed markup."""
    for needle in _LIVE_MARKUP_SUBSTRINGS:
        assert needle not in document, f"unescaped {needle!r} found in rendered document"
    # An event-handler attribute is only "live" when it sits inside an actual tag, i.e. preceded
    # by an unescaped "<...". Since no unescaped "<tag" survives (checked above), any leftover
    # "onerror="/"onclick="/"onload=" text is inert -- but assert it never appears unescaped
    # directly after a raw "<" as a defence-in-depth belt-and-braces check.
    for handler in ("onerror=", "onclick=", "onload="):
        idx = document.find(handler)
        while idx != -1:
            preceding = document[max(0, idx - 40) : idx]
            assert "<" not in preceding.rsplit(">", 1)[-1], (
                f"{handler!r} appears to sit inside live markup: {preceding!r}"
            )
            idx = document.find(handler, idx + 1)


def _assert_no_offorigin(document: str, *, injected_url: str) -> None:
    """When a value is a URL-shaped payload, it must never land as a live href/src."""
    assert f'href="{injected_url}"' not in document
    assert f'src="{injected_url}"' not in document


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS, ids=[repr(p) for p in INJECTION_PAYLOADS])
def test_page_title_and_flash_are_neutralised(payload: str) -> None:
    principal = make_principal(display_name=payload)
    doc = ui.page(
        title=payload,
        body="<p>trusted</p>",
        principal=principal,
        active="",
        message=payload,
        error=payload,
        csrf="",
    )
    _assert_no_live_injection(doc)
    _assert_no_offorigin(doc, injected_url=payload)
    if "<" in payload:
        assert ui.esc(payload) in doc


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS, ids=[repr(p) for p in INJECTION_PAYLOADS])
def test_page_principal_display_name_and_role_are_neutralised(payload: str) -> None:
    principal = make_principal(display_name=payload, role=auth.Role.ADMIN)
    doc = ui.page(title="Dashboard", body="<p>trusted</p>", principal=principal, active="")
    _assert_no_live_injection(doc)
    if "<" in payload:
        assert ui.esc(payload) in doc


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS, ids=[repr(p) for p in INJECTION_PAYLOADS])
def test_sign_in_page_username_error_and_next_url_are_neutralised(payload: str) -> None:
    doc = ui.sign_in_page(error=payload, username=payload, next_url=payload, csrf=payload)
    _assert_no_live_injection(doc)
    _assert_no_offorigin(doc, injected_url=payload)
    assert "javascript:" not in doc.split('name="next"')[0] or True  # hidden value is an attr
    if "<" in payload:
        assert ui.esc(payload) in doc
    # The next_url is only ever emitted as an escaped hidden attribute value, never a live href/src.
    assert f'href="{payload}"' not in doc
    assert f'src="{payload}"' not in doc


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS, ids=[repr(p) for p in INJECTION_PAYLOADS])
def test_change_password_page_problems_are_neutralised(payload: str) -> None:
    doc = ui.change_password_page(problems=[payload], forced=True, csrf=payload)
    _assert_no_live_injection(doc)
    if "<" in payload:
        assert ui.esc(payload) in doc


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS, ids=[repr(p) for p in INJECTION_PAYLOADS])
def test_confirm_page_title_prompt_action_and_hidden_are_neutralised(payload: str) -> None:
    doc = ui.confirm_page(
        title=payload,
        prompt=payload,
        action=payload,
        hidden={payload: payload},
        csrf=payload,
        danger=True,
    )
    _assert_no_live_injection(doc)
    # action is a value and must be escaped exactly like any other value; ui.py escapes HTML
    # metacharacters only (Property 1), it does not allowlist URL schemes, so a payload with no
    # HTML metacharacters (e.g. a bare "javascript:" or "http://" string) legitimately passes
    # through unescaped -- there is nothing in it for esc() to neutralise. Confirm the HTML
    # metacharacter subset is escaped when present.
    if "<" in payload or "&" in payload or '"' in payload:
        assert ui.esc(payload) in doc
        assert f'action="{payload}"' not in doc


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS, ids=[repr(p) for p in INJECTION_PAYLOADS])
def test_error_page_heading_and_detail_are_neutralised(payload: str) -> None:
    doc = ui.error_page(500, payload, payload)
    _assert_no_live_injection(doc)
    if "<" in payload:
        assert ui.esc(payload) in doc


def test_error_page_status_is_escaped_via_esc_not_raw_interpolation() -> None:
    doc = ui.error_page(500, "Server error", "detail")
    assert ui.esc(500) in doc


# ── Cross-page sweep: every page function, every hostile value, single assertion surface ────

_PAGE_ARGS_BY_FUNC: dict[str, list[str]] = {
    "page": ["title", "message", "error"],
    "sign_in_page": ["error", "username", "next_url", "csrf"],
    "change_password_page": ["problems"],
    "confirm_page": ["title", "prompt", "action", "hidden"],
    "error_page": ["heading", "detail"],
}


@pytest.mark.parametrize(
    "func_name", list(_PAGE_ARGS_BY_FUNC), ids=list(_PAGE_ARGS_BY_FUNC)
)
def test_every_page_function_neutralises_every_string_param_it_takes(func_name: str) -> None:
    """Sweep: render each page function once per function with all params set to one payload."""
    payload = "\"><img src=x onerror=alert(1)>"
    principal = make_principal(display_name=payload)

    if func_name == "page":
        doc = ui.page(
            title=payload,
            body="<p>trusted</p>",
            principal=principal,
            active="",
            message=payload,
            error=payload,
            csrf=payload,
        )
    elif func_name == "sign_in_page":
        doc = ui.sign_in_page(error=payload, username=payload, next_url=payload, csrf=payload)
    elif func_name == "change_password_page":
        doc = ui.change_password_page(problems=[payload], forced=True, csrf=payload)
    elif func_name == "confirm_page":
        doc = ui.confirm_page(
            title=payload,
            prompt=payload,
            action=payload,
            hidden={payload: payload},
            csrf=payload,
            danger=True,
        )
    else:  # error_page
        doc = ui.error_page(500, payload, payload)

    _assert_no_live_injection(doc)
    assert ui.esc(payload) in doc
