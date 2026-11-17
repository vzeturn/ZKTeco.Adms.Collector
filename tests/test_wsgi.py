"""
Property tests for ``adms.wsgi`` -- the only module that knows the hosting model.

Five properties live here, each implemented by exactly one test function, table-driven over
deliberately hostile fixed inputs per the design's Testing Strategy. No ``hypothesis``.

Property 5 (translation is total) and Property 6 (the body read is bounded) are deliberately kept
separate even though both exercise ``build_request``/``_read_body``: Property 5 is about the
*outer* boundary -- ``AdmsWsgiApp.__call__`` never lets an unreadable request escape as anything
other than a 400, and always calls ``start_response`` exactly once with an iterable of bytes.
Property 6 is about the *inner* contract of ``_read_body`` itself -- the exact byte count it
returns for a given declared length and stream. A stream that raises belongs to Property 5 (it is
what turns into the 400); a bad declared ``CONTENT_LENGTH`` belongs to Property 6 (it is handled
inside ``_read_body`` and never raises at all).

None of this re-litigates V3 (task 4.3): the body is read before ``AdmsService`` sees the request,
bounded and deliberate, and that ordering is not touched by anything here. These tests assert the
bound holds and that the read is total, which is what V3's docstring already documents as true.
"""

from __future__ import annotations

import dataclasses
import importlib
import io
from typing import Any, cast

import pytest
from conftest import SERIAL_DISABLED, SERIAL_LINKED, SERIAL_UNLINKED, SERIAL_UNREGISTERED

from adms import wsgi
from adms.errors import ConfigError
from adms.models import AdmsRequest, AdmsResponse
from adms.service import AdmsService

# ── Shared test doubles ──────────────────────────────────────────────────────────────────────


class _StubService:
    """
    A minimal stand-in for ``AdmsService``: one fixed response, and every request it was handed.

    Not the fake graph from ``conftest`` -- these properties are about ``wsgi.py``'s own
    translation and envelope logic, not about routing or authorisation, so a service that always
    answers the same way and remembers what it saw is the right amount of double.
    """

    __slots__ = ("received", "response")

    def __init__(self, response: AdmsResponse | None = None) -> None:
        self.response = response or AdmsResponse(body="OK", status=200)
        self.received: list[AdmsRequest] = []

    def handle(self, request: AdmsRequest) -> AdmsResponse:
        self.received.append(request)
        return self.response


class _StartResponseRecorder:
    """Records every call to a WSGI ``start_response``, so a test can assert on call count too."""

    __slots__ = ("calls",)

    def __init__(self) -> None:
        self.calls: list[tuple[str, list[tuple[str, str]]]] = []

    def __call__(self, status: str, headers: list[tuple[str, str]]) -> None:
        self.calls.append((status, headers))


class _RaisingStream:
    """A ``wsgi.input`` stand-in that fails mid-read, as a dropped device connection would."""

    def read(self, _size: int = -1) -> bytes:
        raise OSError("simulated: the client disconnected mid-body")


def _invoke(app: wsgi.AdmsWsgiApp, environ: dict[str, Any]) -> tuple[str, list[tuple[str, str]], bytes]:
    """
    Call a WSGI app once, asserting the two structural guarantees every property below relies on:
    ``start_response`` is invoked exactly once, and the returned iterable yields only ``bytes``.
    """
    recorder = _StartResponseRecorder()
    result = app(environ, recorder)
    chunks = list(result)
    assert all(isinstance(chunk, bytes) for chunk in chunks), f"non-bytes chunk in {chunks!r}"
    assert len(recorder.calls) == 1, f"start_response called {len(recorder.calls)} times, want exactly 1"
    status_line, headers = recorder.calls[0]
    return status_line, headers, b"".join(chunks)


# ── Property 5: Request translation is total ────────────────────────────────────────────────

_TRANSLATION_CASES: list[dict[str, Any]] = [
    {
        "id": "empty environ -- every key missing",
        "environ": {},
        "expect_400": False,
        "check": lambda req: req.method == "GET" and req.path == "/" and req.body == b"" and req.query == {},
    },
    {
        "id": "missing wsgi.input, CONTENT_LENGTH present",
        "environ": {"CONTENT_LENGTH": "10"},
        "expect_400": False,
        "check": lambda req: req.body == b"",
    },
    {
        "id": "hostile headers -- control characters and unicode",
        "environ": {
            "HTTP_X_FORWARDED_FOR": "\x00\x01evil, 10.0.0.9",
            "HTTP_SN": "does-not-matter-here",
            "HTTP_ACCEPT_LANGUAGE": "vi-VN,\u200bvi;q=0.9",
        },
        "expect_400": False,
        "check": lambda req: "x-forwarded-for" in req.headers and "sn" in req.headers,
    },
    {
        "id": "a stream that raises on read",
        "environ": {"CONTENT_LENGTH": "5", "wsgi.input": _RaisingStream()},
        "expect_400": True,
        "check": None,
    },
    {
        "id": "a body of arbitrary, non-UTF-8 content",
        "environ": {
            "CONTENT_LENGTH": str(len(bytes(range(256)))),
            "wsgi.input": io.BytesIO(bytes(range(256))),
        },
        "expect_400": False,
        "check": lambda req: req.body == bytes(range(256)),
    },
    {
        "id": "SCRIPT_NAME virtual directory prefixed onto PATH_INFO",
        "environ": {"SCRIPT_NAME": "/secret-prefix", "PATH_INFO": "/iclock/cdata"},
        "expect_400": False,
        "check": lambda req: req.path == "/secret-prefix/iclock/cdata",
    },
    {
        "id": "query string keys resolved case-insensitively",
        "environ": {"QUERY_STRING": "SN=ABC123&Table=ATTLOG"},
        "expect_400": False,
        "check": lambda req: req.q("sn") == "ABC123" and req.q("TABLE") == "ATTLOG",
    },
    {
        "id": "a lower-cased method is upper-cased",
        "environ": {"REQUEST_METHOD": "post"},
        "expect_400": False,
        "check": lambda req: req.method == "POST",
    },
    {
        "id": "PATH_INFO absent falls back to a bare slash",
        "environ": {"SCRIPT_NAME": "/app"},
        "expect_400": False,
        "check": lambda req: req.path == "/app/",
    },
]


@pytest.mark.parametrize("case", _TRANSLATION_CASES, ids=[c["id"] for c in _TRANSLATION_CASES])
def test_property_5_request_translation_is_total(case: dict[str, Any]) -> None:
    # Feature: adms-attendance-system, Property 5: Request translation is total. For all WSGI
    # environments -- missing keys, hostile headers, a stream that raises, a body of any content --
    # build_request either produces an AdmsRequest whose path is SCRIPT_NAME + PATH_INFO and whose
    # query lookup is case-insensitive across spellings, or the application answers 400 Bad Request;
    # in every case start_response is called exactly once and the return value is an iterable of
    # bytes.
    stub = _StubService()
    app = wsgi.AdmsWsgiApp(cast(AdmsService, stub))

    status_line, headers, body = _invoke(app, dict(case["environ"]))
    header_map = dict(headers)

    if case["expect_400"]:
        assert status_line.startswith("400"), case["id"]
        assert body == b"Bad Request", case["id"]
        assert not stub.received, f"{case['id']}: the service must not be reached for an unreadable request"
    else:
        assert stub.received, f"{case['id']}: build_request succeeded, so the service must have been called"
        request = stub.received[-1]
        if case["check"] is not None:
            assert case["check"](request), f"{case['id']}: request={request!r}"
        assert status_line.startswith(str(stub.response.status)), case["id"]

    assert header_map["Content-Type"] == "text/plain", case["id"]


# ── Property 6: The body read is bounded, and a bad declared length yields an empty body ────

_BODY_CASES: list[dict[str, Any]] = [
    {
        "id": "32 MiB declared, 3 bytes actually sent",
        "content_length": str(32 * 1024 * 1024),
        "stream_bytes": b"abc",
        "max_body_bytes": None,  # the real bound
        "expected": b"abc",
    },
    {
        "id": "declared far exceeds the bound -- the bound wins",
        "content_length": "10000",
        "stream_bytes": b"a" * 100,
        "max_body_bytes": 16,
        "expected": b"a" * 16,
    },
    {
        "id": "declared is smaller than the bound -- the declared length wins",
        "content_length": "5",
        "stream_bytes": b"z" * 50,
        "max_body_bytes": 1000,
        "expected": b"z" * 5,
    },
    {
        "id": "absent CONTENT_LENGTH",
        "content_length": None,
        "stream_bytes": b"there is definitely a body here",
        "max_body_bytes": None,
        "expected": b"",
    },
    {
        "id": "empty CONTENT_LENGTH",
        "content_length": "",
        "stream_bytes": b"there is definitely a body here",
        "max_body_bytes": None,
        "expected": b"",
    },
    {
        "id": "whitespace-only CONTENT_LENGTH",
        "content_length": "   ",
        "stream_bytes": b"there is definitely a body here",
        "max_body_bytes": None,
        "expected": b"",
    },
    {
        "id": "non-numeric CONTENT_LENGTH",
        "content_length": "not-a-number",
        "stream_bytes": b"there is definitely a body here",
        "max_body_bytes": None,
        "expected": b"",
    },
    {
        "id": "negative CONTENT_LENGTH",
        "content_length": "-5",
        "stream_bytes": b"there is definitely a body here",
        "max_body_bytes": None,
        "expected": b"",
    },
    {
        "id": "zero CONTENT_LENGTH",
        "content_length": "0",
        "stream_bytes": b"there is definitely a body here",
        "max_body_bytes": None,
        "expected": b"",
    },
]


@pytest.mark.parametrize("case", _BODY_CASES, ids=[c["id"] for c in _BODY_CASES])
def test_property_6_body_read_is_bounded_and_bad_length_yields_empty_body(
    case: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Feature: adms-attendance-system, Property 6: The body read is bounded, and a bad declared
    # length yields an empty body. For all pairs of declared CONTENT_LENGTH and actual stream
    # contents, the body read is at most min(declared, 33554432) bytes and never more than the
    # stream holds; and for all absent, empty, non-numeric, negative or zero declared lengths the
    # body is empty and nothing raises.
    if case["max_body_bytes"] is not None:
        monkeypatch.setattr(wsgi, "MAX_BODY_BYTES", case["max_body_bytes"])

    stream = io.BytesIO(case["stream_bytes"])
    environ: dict[str, Any] = {"wsgi.input": stream}
    if case["content_length"] is not None:
        environ["CONTENT_LENGTH"] = case["content_length"]

    body = wsgi._read_body(environ)

    assert body == case["expected"], case["id"]
    assert len(body) <= len(case["stream_bytes"]), f"{case['id']}: read more than the stream held"


# ── Property 7: The client address is derived correctly and authorises nothing ──────────────

_CLIENT_IP_CASES: list[dict[str, Any]] = [
    {
        "id": "XFF present, no port, single entry",
        "headers": {"x-forwarded-for": "10.0.0.5"},
        "remote_addr": "127.0.0.1",
        "expected": "10.0.0.5",
    },
    {
        "id": "XFF present with a single trailing :port, stripped",
        "headers": {"x-forwarded-for": "10.0.0.5:52341"},
        "remote_addr": "127.0.0.1",
        "expected": "10.0.0.5",
    },
    {
        "id": "XFF with several entries -- the leftmost wins, port stripped",
        "headers": {"x-forwarded-for": "10.0.0.5:1111, 10.0.0.6:2222"},
        "remote_addr": "127.0.0.1",
        "expected": "10.0.0.5",
    },
    {
        "id": "XFF absent -- falls back to REMOTE_ADDR",
        "headers": {},
        "remote_addr": "192.168.1.1",
        "expected": "192.168.1.1",
    },
    {
        "id": "XFF present but empty -- falls back to REMOTE_ADDR",
        "headers": {"x-forwarded-for": ""},
        "remote_addr": "192.168.1.1",
        "expected": "192.168.1.1",
    },
    {
        "id": "XFF is IPv6 -- left intact, colons untouched",
        "headers": {"x-forwarded-for": "2001:db8::1"},
        "remote_addr": "127.0.0.1",
        "expected": "2001:db8::1",
    },
    {
        "id": "XFF leftmost entry padded with whitespace",
        "headers": {"x-forwarded-for": "  10.0.0.9  , 10.0.0.10"},
        "remote_addr": "127.0.0.1",
        "expected": "10.0.0.9",
    },
    {
        "id": "XFF leftmost entry blank after a leading comma -- falls back to REMOTE_ADDR",
        "headers": {"x-forwarded-for": " ,10.0.0.2"},
        "remote_addr": "192.168.1.1",
        "expected": "192.168.1.1",
    },
    {
        "id": "neither XFF nor REMOTE_ADDR -- empty string, never None",
        "headers": {},
        "remote_addr": None,
        "expected": "",
    },
]


def test_property_7_client_address_is_derived_correctly_and_authorises_nothing(
    fake: Any, wire: Any
) -> None:
    # Feature: adms-attendance-system, Property 7: The client address is derived correctly and
    # authorises nothing. For all header combinations, the client address is the leftmost
    # X-Forwarded-For entry when present and REMOTE_ADDR otherwise, with a single trailing :port
    # removed and IPv6 left intact; and for all requests, varying the client address across the
    # entire route and registration matrix changes neither the status nor the body.

    # -- Part A: pure derivation, table-driven over header/REMOTE_ADDR combinations --
    for case in _CLIENT_IP_CASES:
        environ: dict[str, Any] = {} if case["remote_addr"] is None else {"REMOTE_ADDR": case["remote_addr"]}
        derived = wsgi._client_ip(environ, case["headers"])
        assert derived == case["expected"], case["id"]

    # -- Part B: the client address authorises nothing, across the whole route/registration matrix.
    # dataclasses.replace keeps every other field of the request fixed, isolating source_ip as the
    # only variable, so a difference in outcome could only come from the address itself.
    service, _stores = fake()
    ips = ["10.0.0.9", "203.0.113.7", "::1", "", "10.0.0.9:12345"]
    punch = [wire.punch(101, "2026-08-07 08:00:00")]
    templates: dict[str, AdmsRequest] = {
        "handshake-linked": wire.handshake(SERIAL_LINKED),
        "handshake-unlinked": wire.handshake(SERIAL_UNLINKED),
        "handshake-disabled": wire.handshake(SERIAL_DISABLED),
        "handshake-unregistered": wire.handshake(SERIAL_UNREGISTERED),
        "attlog-linked": wire.attlog(SERIAL_LINKED, punch),
        "attlog-unlinked": wire.attlog(SERIAL_UNLINKED, punch),
        "attlog-disabled": wire.attlog(SERIAL_DISABLED, punch),
        "unknown-route": wire.request("GET", "/nonsense"),
    }

    for label, template in templates.items():
        outcomes = {
            (service.handle(dataclasses.replace(template, source_ip=ip)).status,
             service.handle(dataclasses.replace(template, source_ip=ip)).body)
            for ip in ips
        }
        assert len(outcomes) == 1, f"{label}: varying source_ip changed the outcome -- {outcomes}"


# ── Property 8: The response envelope is uniform ─────────────────────────────────────────────

_ENVELOPE_CASES: list[dict[str, Any]] = [
    {"status": 200, "body": "OK", "reason": "OK"},
    {"status": 200, "body": "OK: 3", "reason": "OK"},
    {"status": 400, "body": "Bad Request", "reason": "Bad Request"},
    {"status": 401, "body": "Unauthorized", "reason": "Unauthorized"},
    {"status": 404, "body": "Not Found", "reason": "Not Found"},
    {"status": 500, "body": "Server Error", "reason": "Internal Server Error"},
    {"status": 503, "body": "Storage Unavailable", "reason": "Service Unavailable"},
    {"status": 200, "body": "GET OPTION FROM: CJXX204960333\r\nStamp=0\r\n", "reason": "OK"},
    # Multi-byte UTF-8 content: Content-Length must be the byte length, not len(str).
    {"status": 200, "body": "Nguy\u1ec5n V\u0103n \u00c1nh: OK", "reason": "OK"},
    {"status": 200, "body": "", "reason": "OK"},
    # A status this module names no explicit reason for still gets a sensible phrase.
    {"status": 299, "body": "edge of the 2xx range", "reason": "OK"},
]


@pytest.mark.parametrize(
    "case", _ENVELOPE_CASES, ids=[f"{c['status']}-{i}" for i, c in enumerate(_ENVELOPE_CASES)]
)
def test_property_8_response_envelope_is_uniform(case: dict[str, Any]) -> None:
    # Feature: adms-attendance-system, Property 8: The response envelope is uniform. For all
    # routes and all statuses, the response carries Content-Type: text/plain with no charset
    # parameter, a Content-Length equal to the byte length of the encoded body, Cache-Control:
    # no-store and X-Content-Type-Options: nosniff; and each status is paired with its standard
    # reason phrase.
    recorder = _StartResponseRecorder()
    response = AdmsResponse(body=case["body"], status=case["status"])

    result = wsgi.AdmsWsgiApp._emit(recorder, response)
    payload = b"".join(result)

    assert len(recorder.calls) == 1
    status_line, headers = recorder.calls[0]
    header_map = dict(headers)

    assert status_line == f"{case['status']} {case['reason']}", case["body"]
    assert header_map["Content-Type"] == "text/plain"
    assert "charset" not in header_map["Content-Type"].lower()
    assert payload == case["body"].encode("utf-8")
    assert header_map["Content-Length"] == str(len(payload))
    assert header_map["Cache-Control"] == "no-store"
    assert header_map["X-Content-Type-Options"] == "nosniff"


# ── Property 9: The object graph is composed on first use, not at import ────────────────────


def test_property_9_object_graph_is_composed_on_first_use_not_at_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Feature: adms-attendance-system, Property 9: The object graph is composed on first use, not
    # at import. For any configuration, importing adms.wsgi raises nothing, and a configuration
    # fault surfaces only when create_app is called -- as a logged failure from a running site
    # rather than as an import error with no explanation.
    from adms import composition

    def _broken_get_service() -> Any:
        raise ConfigError("simulated: no database configuration")

    monkeypatch.setattr(composition, "get_service", _broken_get_service)

    # Re-importing the module executes its top-level code again. It must not raise, even though
    # the composition root it would eventually call is now broken -- proving the two are not
    # wired together at import time.
    reloaded = importlib.reload(wsgi)
    assert reloaded is wsgi

    # An explicitly supplied service bypasses composition entirely, so the broken root must never
    # be touched here either.
    stub = _StubService()
    app_with_explicit_service = reloaded.create_app(service=cast(AdmsService, stub))
    assert isinstance(app_with_explicit_service, reloaded.AdmsWsgiApp)

    # Only when composition is actually needed -- no service supplied -- does the fault surface,
    # and it surfaces as this module's own ConfigError, not an import-time failure.
    with pytest.raises(ConfigError):
        reloaded.create_app()
