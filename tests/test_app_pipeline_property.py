"""
Table-driven property tests for the request pipeline (task 4.2).

Fixed-input parametrisations of Property 4/35/36/37/38, exercised only through the routes reachable
without a session -- the stylesheet, ``/healthz`` and unknown paths -- plus the pure parsing and
routing methods directly. No hypothesis, no randomness: every table below is spelled out in full so a
failure points at one exact input.
"""

from __future__ import annotations

import io
from urllib.parse import urlencode

import pytest

from adms.admin import ui
from adms.admin.app import AdminWsgiApp, _client_ip, _match_pattern, create_app
from adms.config import Settings


def _app(store) -> AdminWsgiApp:
    return create_app(store, settings=Settings())


def _environ(method: str, path: str, *, query: str = "", body: bytes = b"",
             headers: dict[str, str] | None = None) -> dict:
    from wsgiref.util import setup_testing_defaults

    environ: dict = {}
    setup_testing_defaults(environ)
    environ["REQUEST_METHOD"] = method
    environ["PATH_INFO"] = path
    environ["QUERY_STRING"] = query
    environ["wsgi.input"] = io.BytesIO(body)
    environ["CONTENT_LENGTH"] = str(len(body))
    for name, value in (headers or {}).items():
        environ["HTTP_" + name.upper().replace("-", "_")] = value
    return environ


def _call(app: AdminWsgiApp, environ: dict) -> tuple[int, list[tuple[str, str]], bytes]:
    captured: dict = {}

    def start_response(status, headers, _exc=None):
        captured["status"] = status
        captured["headers"] = headers
        return lambda _d: None

    chunks = app(environ, start_response)
    body = b"".join(chunks)
    return int(captured["status"].split(" ", 1)[0]), captured["headers"], body


def _dict(headers: list[tuple[str, str]]) -> dict[str, str]:
    return {k.lower(): v for k, v in headers}


def _assert_security_headers(hd: dict[str, str]) -> None:
    csp = hd["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "script-src" not in csp
    assert "style-src 'self'" in csp
    assert "form-action 'self'" in csp
    assert "base-uri 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert hd["x-content-type-options"] == "nosniff"
    assert hd["x-frame-options"] == "DENY"
    assert hd["referrer-policy"] == "no-referrer"


# ══ Property 4 — security headers are uniform on every reachable response ═══════════════════════


@pytest.mark.parametrize("path", ["/assets/console.css", "/healthz", "/no-such-page"])
def test_property4_security_headers_on_every_response(store, path: str) -> None:
    _, headers, _ = _call(_app(store), _environ("GET", path))
    _assert_security_headers(_dict(headers))


def test_property4_security_headers_on_304(store) -> None:
    app = _app(store)
    etag = _dict(_call(app, _environ("GET", "/assets/console.css"))[1])["etag"]
    status, headers, _ = _call(
        app, _environ("GET", "/assets/console.css", headers={"If-None-Match": etag})
    )
    assert status == 304
    _assert_security_headers(_dict(headers))


@pytest.mark.parametrize("path", ["/healthz", "/no-such-page"])
def test_property4_no_store_on_dynamic_routes(store, path: str) -> None:
    _, headers, _ = _call(_app(store), _environ("GET", path))
    assert _dict(headers)["cache-control"] == "no-store"


def test_property4_stylesheet_is_not_no_store(store) -> None:
    _, headers, _ = _call(_app(store), _environ("GET", "/assets/console.css"))
    assert "no-store" not in _dict(headers)["cache-control"]


# ══ Property 37 — oversized input is refused before a handler runs ══════════════════════════════

_OVERSIZED_CASES = [
    pytest.param(b"a=" + b"a" * (128 * 1024), id="single-128kb-value"),
    pytest.param("&".join(f"f{i}=1" for i in range(500)).encode("utf-8"), id="500-fields"),
    pytest.param(("k" * (100 * 1024) + "=1").encode("utf-8"), id="100kb-key"),
]


@pytest.mark.parametrize("body", _OVERSIZED_CASES)
def test_property37_body_capped_before_handler_sees_it(store, body: bytes) -> None:
    from adms.admin.app import MAX_FORM_BYTES, MAX_FORM_FIELDS

    app = _app(store)
    req = app._parse_request(_environ("POST", "/sign-in", body=body))
    total = sum(len(k) + len(v) for k, v in req.form.items())
    assert total <= MAX_FORM_BYTES
    assert len(req.form) <= MAX_FORM_FIELDS


# ══ Property 38 — a path parameter that fails its pattern never reaches the database ════════════

_HOSTILE_SERIALS = [
    "",
    "a/b",
    "has space",
    "a" * 65,
    "semi;colon",
    "../etc",
    "a%2Fb",
    "tab\tchar",
    "new\nline",
]


@pytest.mark.parametrize("bad", _HOSTILE_SERIALS, ids=[repr(v) for v in _HOSTILE_SERIALS])
def test_property38_hostile_serial_never_captured_cleanly(bad: str) -> None:
    params = _match_pattern("/devices/{serial}", f"/devices/{bad}")
    assert params is None or params.get("serial") != bad


def test_property38_valid_serial_matches_cleanly() -> None:
    params = _match_pattern("/devices/{serial}", "/devices/CJXX204960333")
    assert params == {"serial": "CJXX204960333"}


def test_property38_valid_integer_id_matches_cleanly() -> None:
    params = _match_pattern("/users/{user_id}/unlock", "/users/12345/unlock")
    assert params == {"user_id": "12345"}


@pytest.mark.parametrize("bad", ["a/b", "has space"], ids=["slash", "space"])
def test_property38_full_request_404s_and_never_touches_store(store, bad: str) -> None:
    status, _, _ = _call(_app(store), _environ("GET", f"/devices/{bad}"))
    assert status == 404
    assert store.calls == []


# ══ Property 35 — the stylesheet is conditionally cacheable ═════════════════════════════════════


def test_property35_first_get_is_200_with_etag_and_full_body(store) -> None:
    status, headers, body = _call(_app(store), _environ("GET", "/assets/console.css"))
    assert status == 200
    assert body == ui.STYLESHEET.encode("utf-8")
    assert ui.STYLESHEET_ETAG in _dict(headers)["etag"]
    assert store.calls == []


def test_property35_matching_if_none_match_is_304_empty_body(store) -> None:
    app = _app(store)
    etag = _dict(_call(app, _environ("GET", "/assets/console.css"))[1])["etag"]
    status, _, body = _call(
        app, _environ("GET", "/assets/console.css", headers={"If-None-Match": etag})
    )
    assert status == 304
    assert body == b""
    assert store.calls == []


def test_property35_stale_if_none_match_is_200_full_body(store) -> None:
    app = _app(store)
    status, _, body = _call(
        app, _environ("GET", "/assets/console.css", headers={"If-None-Match": '"stale-value"'})
    )
    assert status == 200
    assert body == ui.STYLESHEET.encode("utf-8")
    assert store.calls == []


# ══ Property 36 — encoding and parsing round-trip ════════════════════════════════════════════════

_FORM_CASES = [
    pytest.param({"q": "a b"}, id="space"),
    pytest.param({"q": "a+b"}, id="plus-sign"),
    pytest.param({"q": "50%"}, id="percent-sign"),
    pytest.param({"q": "a&b=c"}, id="ampersand-and-equals-in-value"),
    pytest.param({"q": "Xin chào"}, id="unicode"),
    pytest.param({"q": ""}, id="empty-value"),
]


@pytest.mark.parametrize("form", _FORM_CASES)
def test_property36_form_body_round_trips(store, form: dict[str, str]) -> None:
    app = _app(store)
    body = urlencode(form).encode("utf-8")
    req = app._parse_request(_environ("POST", "/sign-in", body=body))
    assert req.form == form


@pytest.mark.parametrize("form", _FORM_CASES)
def test_property36_query_string_round_trips(store, form: dict[str, str]) -> None:
    app = _app(store)
    req = app._parse_request(_environ("GET", "/activity", query=urlencode(form)))
    assert req.query == form


_XFF_CASES = [
    pytest.param("203.0.113.5:52713, 10.0.0.1", None, "203.0.113.5", id="ipv4-port-stripped"),
    pytest.param("203.0.113.5, 10.0.0.1", None, "203.0.113.5", id="ipv4-no-port-leftmost"),
    pytest.param("2001:db8::1", None, "2001:db8::1", id="ipv6-left-intact"),
    pytest.param("", "198.51.100.7", "198.51.100.7", id="no-xff-falls-back-to-remote-addr"),
]


@pytest.mark.parametrize(("xff", "remote_addr", "expected"), _XFF_CASES)
def test_property36_client_ip_table(xff: str, remote_addr: str | None, expected: str) -> None:
    environ: dict = {"REMOTE_ADDR": remote_addr or ""}
    headers = {"x-forwarded-for": xff} if xff else {}
    assert _client_ip(environ, headers) == expected
