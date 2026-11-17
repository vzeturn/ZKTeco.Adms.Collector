"""
The request pipeline's parsing, routing, headers and static routes (task 4.1).

Example tests for the shell of :mod:`adms.admin.app` before any session, CSRF or handler logic is
wired: the body is bounded and parsed, a ``{name}`` path parameter is matched and validated, the
route table is scanned first-match, the stylesheet is served with an ETag and honours
``If-None-Match`` with a 304, ``/healthz`` answers without a database, an unknown path renders the
console's own 404, and every response carries the security headers. The exhaustive over-all-routes
coverage is Property 4/35/36/37/38 in the ``* 4.2`` sibling.
"""

from __future__ import annotations

import dataclasses
import io

import pytest

from adms.admin import ui
from adms.admin.app import AdminWsgiApp, Request, Response, create_app
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


# ── the value types ────────────────────────────────────────────────────────────────────────────


def test_response_with_header_is_immutable_and_appends() -> None:
    base = Response(status=200, body=b"x")
    out = base.with_header("X-Test", "1")
    assert out is not base
    assert base.headers == ()
    assert ("X-Test", "1") in out.headers


def test_request_is_frozen() -> None:
    req = Request(method="GET", path="/", query={}, form={}, cookies={}, headers={},
                  ip="1.2.3.4", user_agent="ua")
    with pytest.raises(dataclasses.FrozenInstanceError):
        req.method = "POST"  # type: ignore[misc]


# ── static: the stylesheet ───────────────────────────────────────────────────────────────────


def test_stylesheet_is_served_with_etag_and_long_cache(store) -> None:
    status, headers, body = _call(_app(store), _environ("GET", "/assets/console.css"))
    hd = {k.lower(): v for k, v in headers}
    assert status == 200
    assert hd["content-type"].startswith("text/css")
    assert body.decode("utf-8") == ui.STYLESHEET
    assert ui.STYLESHEET_ETAG in hd["etag"]
    assert "max-age=3600" in hd["cache-control"]
    assert "public" in hd["cache-control"]


def test_stylesheet_honours_if_none_match_with_304(store) -> None:
    etag = _dict(_call(_app(store), _environ("GET", "/assets/console.css"))[1])["etag"]
    status, _, body = _call(
        _app(store), _environ("GET", "/assets/console.css", headers={"If-None-Match": etag})
    )
    assert status == 304
    assert body == b""


def test_stylesheet_wrong_etag_returns_the_body(store) -> None:
    status, _, body = _call(
        _app(store),
        _environ("GET", "/assets/console.css", headers={"If-None-Match": '"stale"'}),
    )
    assert status == 200
    assert body.decode("utf-8") == ui.STYLESHEET


def test_stylesheet_never_touches_the_store(store) -> None:
    _call(_app(store), _environ("GET", "/assets/console.css"))
    assert store.calls == []  # short-circuits before any session or query work


# ── static: healthz ──────────────────────────────────────────────────────────────────────────


def test_healthz_answers_ok_in_plain_text_without_the_store(store) -> None:
    status, headers, body = _call(_app(store), _environ("GET", "/healthz"))
    hd = {k.lower(): v for k, v in headers}
    assert status == 200
    assert hd["content-type"].startswith("text/plain")
    assert body == b"ok"
    assert store.calls == []  # a probe cannot generate database load


# ── routing and 404 ──────────────────────────────────────────────────────────────────────────


def test_unknown_path_renders_the_console_404(store) -> None:
    status, headers, body = _call(_app(store), _environ("GET", "/no-such-page"))
    hd = {k.lower(): v for k, v in headers}
    assert status == 404
    assert hd["content-type"].startswith("text/html")
    assert body.lstrip().lower().startswith(b"<!doctype html>")
    assert b"404" in body


def test_route_table_uses_the_name_path_parameter_pattern(store) -> None:
    app = _app(store)
    route, params = app._match_route("GET", "/devices/CJXX204960333")
    assert route is not None
    assert params == {"serial": "CJXX204960333"}


@pytest.mark.parametrize(
    "bad",
    ["", "a/b", "with space", "a" * 65, "semi;colon", "slash/", "..%2f"],
)
def test_path_parameter_rejects_values_outside_its_pattern(store, bad: str) -> None:
    app = _app(store)
    route, params = app._match_route("GET", f"/devices/{bad}")
    # either no route matched, or the offending value never became a clean parameter
    assert route is None or params.get("serial") not in {bad}


def test_first_match_wins_in_the_route_table(store) -> None:
    app = _app(store)
    # /devices is a distinct route from /devices/{serial}; the bare path must not be captured.
    route, params = app._match_route("GET", "/devices")
    assert route is not None
    assert params == {}


# ── body parsing bounds ──────────────────────────────────────────────────────────────────────


def test_body_is_bounded_at_64k(store) -> None:
    app = _app(store)
    huge = b"x=" + b"a" * (128 * 1024)
    req = app._parse_request(_environ("POST", "/sign-in", body=huge))
    # the raw form value cannot exceed the cap; the bound is enforced before parsing
    assert sum(len(k) + len(v) for k, v in req.form.items()) <= 64 * 1024


def test_field_count_is_capped_at_200(store) -> None:
    app = _app(store)
    many = "&".join(f"f{i}=1" for i in range(500)).encode("utf-8")
    req = app._parse_request(_environ("POST", "/sign-in", body=many))
    assert len(req.form) <= 200


def test_form_body_round_trips_urlencoding(store) -> None:
    app = _app(store)
    body = b"username=jane.doe&password=p%40ss+word"
    req = app._parse_request(_environ("POST", "/sign-in", body=body))
    assert req.form["username"] == "jane.doe"
    assert req.form["password"] == "p@ss word"


def test_query_is_parsed_into_a_dict(store) -> None:
    app = _app(store)
    req = app._parse_request(_environ("GET", "/activity", query="tab=uploads"))
    assert req.query["tab"] == "uploads"


def test_client_ip_prefers_forwarded_for_with_the_port_stripped(store) -> None:
    app = _app(store)
    req = app._parse_request(
        _environ("GET", "/", headers={"X-Forwarded-For": "203.0.113.5:52713, 10.0.0.1"})
    )
    assert req.ip == "203.0.113.5"


# ── security headers on every response ────────────────────────────────────────────────────────


@pytest.mark.parametrize("path", ["/assets/console.css", "/healthz", "/no-such-page"])
def test_security_headers_present_on_every_response(store, path: str) -> None:
    _, headers, _ = _call(_app(store), _environ("GET", path))
    hd = {k.lower(): v for k, v in headers}
    csp = hd["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "script-src" not in csp  # no JavaScript is ever allowed
    assert "style-src 'self'" in csp
    assert "form-action 'self'" in csp
    assert "base-uri 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert hd["x-content-type-options"] == "nosniff"
    assert hd["x-frame-options"] == "DENY"
    assert hd["referrer-policy"] == "no-referrer"


def test_no_store_on_everything_but_the_stylesheet(store) -> None:
    _, css_headers, _ = _call(_app(store), _environ("GET", "/assets/console.css"))
    _, page_headers, _ = _call(_app(store), _environ("GET", "/healthz"))
    assert "no-store" not in _dict(css_headers)["cache-control"]
    assert _dict(page_headers)["cache-control"] == "no-store"


def _dict(headers: list[tuple[str, str]]) -> dict[str, str]:
    return {k.lower(): v for k, v in headers}
