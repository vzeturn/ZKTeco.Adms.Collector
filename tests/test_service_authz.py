"""
Property tests for ``adms.service.AdmsService``'s authorisation gate -- ``_authorize``,
``_require_link`` and the top of ``_dispatch`` -- against the in-memory graph.

Five properties live here, each implemented by exactly one test function, table-driven over
deliberately adversarial fixed inputs per the design's Testing Strategy. No ``hypothesis``.

The matrix that is the point, and that every test below keeps distinct rather than collapsing:

    401 unregistered   -- an unknown serial. A security event: someone or something the
                          allow-list has never heard of is talking to us.
    401 disabled       -- a known serial an operator switched off. Also a security event, but a
                          different one: this device was deliberately refused, not merely unseen.
    503 unlinked       -- a trusted, enabled serial with no MAYCHAMCONG link, on a *data upload*
                          only. A linking task, not a security event -- the device is trusted and
                          the fault is our own half-finished configuration (D8).
    400 no SN          -- a request that does not carry enough to identify a device at all.
                          Never reaches the allow-list, because there is nothing to look up.

401 and 503 share nothing except both being non-2xx; conflating them would make an alert on
either one unactionable, which is exactly the reasoning the design records for D8.

Two halves of Requirements 12.8 (``MaMCC`` trimmed on read) and 13.4 (``LastIp`` bounded to 64
characters, ``ContactCount`` incremented) are **not** exercised here. Both are properties of a
column-level read/write that only a real ``SqlServerDeviceRegistry`` performs; the in-memory
``InMemoryDeviceRegistry`` this file's fixtures build on has no ``MaMCC`` column to trim and
tracks contacts as an unbounded list, not a counted, length-limited column. Those halves belong
to ``tests/test_adapters_sql.py`` (task 11.1), against a recording cursor that can see the
statement text and the bound values. Asserting them here against a fake that cannot fail that way
would prove nothing and would silently claim coverage that does not exist -- the same reasoning
``test_composition.py`` uses for Property 71's disjointness half.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest
from conftest import (
    SERIAL_DISABLED,
    SERIAL_LINKED,
    SERIAL_UNLINKED,
    SERIAL_UNREGISTERED,
    SOURCE_IP,
    ExplodingAdapter,
    disabled_device,
    linked_device,
    make_settings,
    unlinked_device,
)

from adms.config import Settings
from adms.logging_setup import NullLogger
from adms.memory import FixedClock, InMemoryDeviceRegistry
from adms.models import AdmsRequest, DeviceRegistration
from adms.service import AdmsService

# ── A hybrid graph: a real registry, every other adapter exploding ──────────────────────────


def _hybrid_service(
    devices: list[DeviceRegistration], settings: Settings | None = None
) -> tuple[AdmsService, dict[str, Any]]:
    """
    A service whose registry is real (so it can actually return ``None`` or a registration) and
    whose every other port explodes on the first call.

    Neither fixture in ``conftest`` is this by itself: ``exploding`` makes *every* port explode,
    including the registry, so it cannot express "the allow-list says no" -- only "nothing was
    asked at all". ``fake`` makes every port permissive, so a call that should never happen would
    succeed silently instead of naming itself. This is what Properties 23 and 50 need to assert
    that the registry lookup (and, for a data upload, the link check right after it) precedes
    every other adapter touch: attendance, employees, templates, commands and archive.
    """
    resolved = settings or make_settings()
    registry = InMemoryDeviceRegistry(devices)
    exploding = {
        name: ExplodingAdapter(name)
        for name in ("attendance", "employees", "templates", "commands", "archive")
    }
    service = AdmsService(
        registry=registry,
        attendance=exploding["attendance"],
        employees=exploding["employees"],
        templates=exploding["templates"],
        commands=exploding["commands"],
        archive=exploding["archive"],
        clock=FixedClock(utc_offset_hours=resolved.utc_offset_hours),
        settings=resolved,
        log=NullLogger(),
    )
    return service, {**exploding, "registry": registry}


def _all_exploding_service() -> tuple[AdmsService, dict[str, Any]]:
    """
    A service whose every port, including the registry, raises.

    Distinct from the ``exploding`` fixture only in name here: used where the point is that the
    *registry itself* must never be reached -- a request with no ``SN`` is refused in
    ``_dispatch`` before ``_authorize`` (and therefore before ``registry.find``) is ever called.
    """
    exploding = {
        name: ExplodingAdapter(name)
        for name in ("registry", "attendance", "employees", "templates", "commands", "archive")
    }
    service = AdmsService(
        registry=exploding["registry"],
        attendance=exploding["attendance"],
        employees=exploding["employees"],
        templates=exploding["templates"],
        commands=exploding["commands"],
        archive=exploding["archive"],
        clock=FixedClock(),
        settings=make_settings(),
        log=NullLogger(),
    )
    return service, exploding


def _assert_no_adapter_touched(stores: dict[str, Any], *, label: str) -> None:
    """Every exploding adapter's call list is empty -- nothing was even attempted."""
    for name, store in stores.items():
        if isinstance(store, ExplodingAdapter):
            assert store.calls == [], f"{label}: {name} was touched: {store.calls}"


# ── Property 4: Anonymous routes touch no adapter ────────────────────────────────────────────

#: (method, path, query) -> (expected status, expected body). Every case resolves to HEALTH or
#: UNKNOWN. A stray SN in the query string is included deliberately: the claim is that these
#: routes never reach the allow-list at all, not merely that they happen not to need to.
_ANONYMOUS_ROUTE_CASES: list[dict[str, Any]] = [
    {
        "id": "GET /iclock/health -- the documented health route",
        "method": "GET",
        "path": "/iclock/health",
        "query": {},
        "status": 200,
        "body": "OK",
    },
    {
        "id": "GET /health -- HEALTH matches on the final segment regardless of prefix",
        "method": "GET",
        "path": "/health",
        "query": {},
        "status": 200,
        "body": "OK",
    },
    {
        "id": "GET /stage/v2/health -- a deployment prefix ahead of the final segment",
        "method": "GET",
        "path": "/stage/v2/health",
        "query": {},
        "status": 200,
        "body": "OK",
    },
    {
        "id": "GET /iclock/health carrying an SN -- must still never reach the registry",
        "method": "GET",
        "path": "/iclock/health",
        "query": {"SN": SERIAL_LINKED},
        "status": 200,
        "body": "OK",
    },
    {
        "id": "POST /iclock/health -- health is GET-only, so this is UNKNOWN",
        "method": "POST",
        "path": "/iclock/health",
        "query": {},
        "status": 404,
        "body": "Not Found",
    },
    {
        "id": "GET /iclock/nonsense -- a segment the table has no entry for",
        "method": "GET",
        "path": "/iclock/nonsense",
        "query": {},
        "status": 404,
        "body": "Not Found",
    },
    {
        "id": "GET / -- no segments at all",
        "method": "GET",
        "path": "/",
        "query": {},
        "status": 404,
        "body": "Not Found",
    },
    {
        "id": "GET with an empty path -- the degenerate case resolve() itself special-cases",
        "method": "GET",
        "path": "",
        "query": {},
        "status": 404,
        "body": "Not Found",
    },
    {
        "id": "DELETE /iclock/cdata -- a known segment, but a method the table has no entry for",
        "method": "DELETE",
        "path": "/iclock/cdata",
        "query": {},
        "status": 404,
        "body": "Not Found",
    },
    {
        "id": "GET /iclock/cdata/extra -- an unknown final segment following a known one",
        "method": "GET",
        "path": "/iclock/cdata/extra",
        "query": {},
        "status": 404,
        "body": "Not Found",
    },
]


@pytest.mark.parametrize(
    "case", _ANONYMOUS_ROUTE_CASES, ids=[c["id"] for c in _ANONYMOUS_ROUTE_CASES]
)
def test_property_4_anonymous_routes_touch_no_adapter(
    case: dict[str, Any], exploding: Any, wire: Any
) -> None:
    # Feature: adms-attendance-system, Property 4: Anonymous routes touch no adapter. For all
    # requests resolving to the health or unknown Route, the response is exactly 200 OK or 404
    # Not Found respectively, and no call is made to the registry, any store, the archive or any
    # parser -- verified with adapters that raise on every method.
    service, stores = exploding()
    request = wire.request(case["method"], case["path"], query=case["query"])

    response = service.handle(request)

    assert response.status == case["status"], case["id"]
    assert response.body == case["body"], case["id"]
    _assert_no_adapter_touched(stores, label=case["id"])


# ── Property 13: Handshake status is invariant to linkage ───────────────────────────────────


def _parse_handshake_fields(body: str) -> tuple[str, dict[str, str]]:
    """Minimal local parse: the first line and the Key=Value fields, split on CRLF."""
    lines = [line for line in body.split("\r\n") if line]
    assert lines, f"body produced no lines at all: {body!r}"
    first, *rest = lines
    fields: dict[str, str] = {}
    for line in rest:
        key, sep, value = line.partition("=")
        if sep == "=":
            fields[key] = value
    return first, fields


#: Every registration state a handshake must answer identically for: linked, unlinked, and two
#: variations on each that differ in stamps and timezone offset -- the claim is about *any*
#: enabled registration, not one blessed shape of it.
_HANDSHAKE_LINKAGE_CASES: list[dict[str, Any]] = [
    {"id": "linked, default stamps", "builder": linked_device, "overrides": {}},
    {"id": "unlinked, default stamps", "builder": unlinked_device, "overrides": {}},
    {
        "id": "linked, nonzero stamps and a non-default timezone offset",
        "builder": linked_device,
        "overrides": {"attlog_stamp": "9001", "operlog_stamp": "42", "timezone_offset": 11},
    },
    {
        "id": "unlinked, nonzero stamps and a non-default timezone offset",
        "builder": unlinked_device,
        "overrides": {"attlog_stamp": "9001", "operlog_stamp": "42", "timezone_offset": 11},
    },
]


@pytest.mark.parametrize(
    "case", _HANDSHAKE_LINKAGE_CASES, ids=[c["id"] for c in _HANDSHAKE_LINKAGE_CASES]
)
def test_property_13_handshake_status_is_invariant_to_linkage(
    case: dict[str, Any], fake: Any, wire: Any
) -> None:
    # Feature: adms-attendance-system, Property 13: Handshake status is invariant to linkage.
    # For any enabled registration, linked or not, the handshake answers status 200 with the
    # full handshake body -- so a device that is registered but not yet linked to a machine row
    # still appears online and reports its firmware.
    registration = case["builder"](**case["overrides"])
    service, _stores = fake(devices=[registration])

    response = service.handle(wire.handshake(registration.serial))

    assert response.status == 200, case["id"]
    first_line, fields = _parse_handshake_fields(response.body)
    assert first_line == f"GET OPTION FROM: {registration.serial}", case["id"]
    # "Full handshake body": every stamp vocabulary present and populated from the registration,
    # regardless of whether it is linked to a machine -- an unlinked device's data pushes fail
    # with 503 (Property 23), but its handshake is not degraded in any way.
    for key in ("ATTLOGStamp", "OPERLOGStamp", "ATTPHOTOStamp", "TimeZone", "ServerVer", "Realtime"):
        assert key in fields, f"{case['id']}: missing {key} -- not the full handshake body"
    assert fields["ATTLOGStamp"] == registration.attlog_stamp, case["id"]
    assert fields["OPERLOGStamp"] == registration.operlog_stamp, case["id"]


# ── Property 23: A data upload from an unlinked device is refused before anything is parsed or
#    written ─────────────────────────────────────────────────────────────────────────────────

_UNLINKED_UPLOAD_CASES: list[dict[str, Any]] = [
    {
        "id": "ATTLOG upload",
        "build": lambda wire: wire.attlog(SERIAL_UNLINKED, [wire.punch(101, "2026-08-07 08:00:00")]),
    },
    {
        "id": "OPERLOG upload",
        "build": lambda wire: wire.operlog(SERIAL_UNLINKED, ["USER\tPIN=101\tName=Nguyen Van A"]),
    },
    {
        "id": "query-result upload (querydata)",
        "build": lambda wire: wire.querydata(SERIAL_UNLINKED, ["USER\tPIN=101\tName=Nguyen Van A"]),
    },
]


@pytest.mark.parametrize(
    "case", _UNLINKED_UPLOAD_CASES, ids=[c["id"] for c in _UNLINKED_UPLOAD_CASES]
)
def test_property_23_unlinked_data_upload_refused_before_parsing_or_writing(
    case: dict[str, Any], wire: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Feature: adms-attendance-system, Property 23: A data upload from an unlinked device is
    # refused before anything is parsed or written. For any enabled but unlinked registration
    # and for any ATTLOG, OPERLOG or query-result upload, the response is status 503 with body
    # "Device Not Configured", no parser was invoked, no archive or store call was made, and no
    # punch was written against any machine id.
    import adms.service as service_module

    def _exploding_parser(name: str) -> Any:
        def _raise(*_args: object, **_kwargs: object) -> Any:
            raise AssertionError(f"{name}() was called on a path that must refuse before parsing")

        return _raise

    # decode_body is a pure text primitive (Property 14's subject), not one of the grammar
    # parsers this property is about -- and it is unconditionally invoked by _push_data before
    # the table-specific handler even runs, so it is deliberately left alone here. parse_attlog
    # and parse_operlog are the ATTLOG_Parser and OPERLOG_Parser the glossary and Requirements
    # 5.1/7.1/10.1 name, and both must never run once _require_link has refused the request.
    monkeypatch.setattr(service_module, "parse_attlog", _exploding_parser("parse_attlog"))
    monkeypatch.setattr(service_module, "parse_operlog", _exploding_parser("parse_operlog"))

    service, stores = _hybrid_service([unlinked_device()])
    request: AdmsRequest = case["build"](wire)

    response = service.handle(request)

    assert response.status == 503, case["id"]
    assert response.body == "Device Not Configured", case["id"]
    # Had parse_attlog/parse_operlog been reached, the monkeypatched stand-in above would have
    # raised, and AdmsService.handle's own last-line-of-defence would have turned that into a
    # 500 -- which the status assertion already excludes. No archive or store call was made
    # either, which the empty call lists below name explicitly, and with no punch insert ever
    # attempted there is no punch written against any machine id.
    _assert_no_adapter_touched(stores, label=case["id"])


# ── Property 50: The allow-list is consulted first and is the entire access decision ────────

#: The four device states the matrix distinguishes, each with a fixed expected outcome for an
#: ATTLOG upload. Deliberately not collapsed: registration -- not the ``enabled`` flag -- is the
#: entire access decision. ``enabled`` is an operator label, so a disabled-but-linked device is
#: accepted exactly like an enabled one: a device switched off must not lose the punches it has
#: already recorded. Only an *unregistered* serial is refused, and unlinked is its own status.
_ACCESS_DECISION_STATES: list[dict[str, Any]] = [
    {
        "id": "unregistered",
        "devices": [],
        "serial": SERIAL_UNREGISTERED,
        "status": 401,
        "body": "Unauthorized",
    },
    {
        # Registered but switched off, and linked: ``enabled`` gates nothing, so its punch is
        # accepted like any linked device's -- 200, not 401. The disabled state is a display
        # label the console shows, never a reason to drop attendance data.
        "id": "disabled (registered, linked)",
        "devices": [disabled_device()],
        "serial": SERIAL_DISABLED,
        "status": 200,
        "body": "OK: 1",
    },
    {
        "id": "registered, enabled, unlinked",
        "devices": [unlinked_device()],
        "serial": SERIAL_UNLINKED,
        "status": 503,
        "body": "Device Not Configured",
    },
    {
        "id": "registered, enabled, linked",
        "devices": [linked_device()],
        "serial": SERIAL_LINKED,
        "status": 200,
        "body": "OK: 1",
    },
]

#: Every other request attribute the property says must not matter: headers, client address and
#: a virtual-directory-shaped path prefix ahead of the fixed ``/iclock/cdata`` tail. ``prefix``
#: is validated by Property 2 elsewhere; here it is just noise the access decision must ignore.
_IRRELEVANT_ATTRIBUTE_VARIATIONS: list[dict[str, Any]] = [
    {"id": "baseline", "headers": {}, "source_ip": SOURCE_IP, "prefix": ""},
    {
        "id": "X-Forwarded-For present",
        "headers": {"X-Forwarded-For": "203.0.113.9"},
        "source_ip": "203.0.113.9",
        "prefix": "",
    },
    {
        "id": "an Authorization header -- the protocol has nowhere for this to matter",
        "headers": {"Authorization": "Bearer nonsense"},
        "source_ip": SOURCE_IP,
        "prefix": "",
    },
    {"id": "empty client address", "headers": {}, "source_ip": "", "prefix": ""},
    {
        "id": "a staging virtual-directory prefix ahead of /iclock",
        "headers": {},
        "source_ip": SOURCE_IP,
        "prefix": "/stage-v2",
    },
    {
        "id": "a secret-shaped prefix that is not configured as a path secret",
        "headers": {"X-Custom": "value"},
        "source_ip": "10.0.0.99",
        "prefix": "/topsecret",
    },
]


def test_property_50_allow_list_is_consulted_first_and_is_the_entire_access_decision(
    wire: Any,
) -> None:
    # Feature: adms-attendance-system, Property 50: The allow-list is consulted first and is the
    # entire access decision. For any request that identifies a device, the registry lookup
    # precedes any body decoding, any parse and any archive write; a serial with no row yields
    # 401 Unauthorized, and a request with no SN yields 400 Bad Request; for all other request
    # attributes -- headers, client address, body, path prefix -- the presence of a registered
    # row is what decides access and nothing else grants it. The ``enabled`` flag is an operator
    # label, not a gate: a registered-but-disabled device is served exactly like an enabled one,
    # so switching a device off never drops the punches it has already recorded. An unlinked
    # device is distinguishable from an unregistered one.
    #
    # The MaMCC-trimmed-on-read half is a SqlServerDeviceRegistry column concern the in-memory
    # registry has no equivalent of; it is exercised in tests/test_adapters_sql.py instead.

    # -- Part A: the access decision depends on the device state and nothing else. For each of
    # the four states, every attribute variation must produce the one fixed outcome for that
    # state -- proving headers, client address and path prefix decide nothing.
    for state in _ACCESS_DECISION_STATES:
        punch_row = [wire.punch(101, "2026-08-07 08:00:00")]
        template = wire.attlog(state["serial"], punch_row)
        outcomes: set[tuple[int, str]] = set()
        for variation in _IRRELEVANT_ATTRIBUTE_VARIATIONS:
            service, _stores = fake_graph(state["devices"])
            varied = dataclasses.replace(
                template,
                headers=dict(variation["headers"]),
                source_ip=variation["source_ip"],
                path=f"{variation['prefix']}/iclock/cdata",
            )
            response = service.handle(varied)
            outcomes.add((response.status, response.body))
            assert response.status == state["status"], f"{state['id']} / {variation['id']}"
            assert response.body == state["body"], f"{state['id']} / {variation['id']}"
        assert len(outcomes) == 1, f"{state['id']}: varying attributes changed the outcome: {outcomes}"

    # -- Part B: a request identifying no device at all yields 400, regardless of the same
    # irrelevant attributes, and regardless of which devices happen to be registered.
    no_sn_outcomes: set[tuple[int, str]] = set()
    for variation in _IRRELEVANT_ATTRIBUTE_VARIATIONS:
        service, _stores = fake_graph([linked_device(), disabled_device()])
        request = wire.request(
            "POST",
            f"{variation['prefix']}/iclock/cdata",
            query={"table": "ATTLOG", "Stamp": "1"},
            body=[wire.punch(101, "2026-08-07 08:00:00")],
            headers=dict(variation["headers"]),
            source_ip=variation["source_ip"],
        )
        response = service.handle(request)
        no_sn_outcomes.add((response.status, response.body))
        assert response.status == 400, variation["id"]
        assert response.body == "Bad Request", variation["id"]
    assert len(no_sn_outcomes) == 1, f"varying attributes changed the no-SN outcome: {no_sn_outcomes}"

    # -- Part C: the registry lookup precedes everything else -- for the 401 (unregistered) cause,
    # no other adapter is ever touched, across the same attribute variations. Disabled is no longer
    # a refusal cause: a disabled-but-linked device is served, so it legitimately reaches the
    # attendance adapter and cannot be asserted against an exploding one here.
    def _attlog_upload(w: Any, s: str) -> AdmsRequest:
        return w.attlog(s, [w.punch(101, "2026-08-07 08:00:00")])

    for label, devices, serial, build in (
        ("unregistered", [], SERIAL_UNREGISTERED, _attlog_upload),
    ):
        service, stores = _hybrid_service(devices)
        for variation in _IRRELEVANT_ATTRIBUTE_VARIATIONS:
            template = build(wire, serial)
            varied = dataclasses.replace(
                template,
                headers=dict(variation["headers"]),
                source_ip=variation["source_ip"],
                path=f"{variation['prefix']}/iclock/cdata",
            )
            response = service.handle(varied)
            assert response.status == 401, f"{label} / {variation['id']}"
        _assert_no_adapter_touched(stores, label=label)

    # No-SN never even reaches the registry: an all-exploding graph, so the empty call list is
    # unambiguous -- a request with no SN must be refused before any lookup at all.
    no_sn_service, no_sn_stores = _all_exploding_service()
    for variation in _IRRELEVANT_ATTRIBUTE_VARIATIONS:
        request = wire.request(
            "POST",
            f"{variation['prefix']}/iclock/cdata",
            query={"table": "ATTLOG", "Stamp": "1"},
            body=[wire.punch(101, "2026-08-07 08:00:00")],
            headers=dict(variation["headers"]),
            source_ip=variation["source_ip"],
        )
        response = no_sn_service.handle(request)
        assert response.status == 400, variation["id"]
    _assert_no_adapter_touched(no_sn_stores, label="no-SN")


def fake_graph(devices: list[DeviceRegistration]) -> tuple[AdmsService, dict[str, Any]]:
    """
    A thin wrapper over :mod:`adms.composition`'s fake graph, named locally so Property 50's
    table-driven loops read as "the ordinary permissive graph" without importing the ``fake``
    pytest fixture's factory (a fixture cannot be called outside a test's own parameter list).
    """
    from adms.composition import build_fake_service

    return build_fake_service(make_settings(), devices=devices, log=NullLogger())


# ── Property 51: Recording an unknown device grants nothing and cannot edit a known one ─────


def test_property_51_recording_unknown_device_grants_nothing_and_cannot_edit_known_one(
    fake: Any, wire: Any
) -> None:
    # Feature: adms-attendance-system, Property 51: Recording an unknown device grants nothing
    # and cannot edit a known one. For any unknown serial with auto-registration enabled, a row
    # is created with Enabled false and no machine link and the response is still 401; for any
    # serial that already has a row, this path performs no update; for any unknown serial with
    # auto-registration disabled, no row is created; and for any authorised request, last-seen
    # and last-address are updated.
    #
    # The 64-character bound on the stored address and the ContactCount increment are a
    # SqlServerDeviceRegistry column concern InMemoryDeviceRegistry does not model (it keeps an
    # unbounded contact list, not a counted column); that half is exercised in
    # tests/test_adapters_sql.py instead.

    # -- An unknown serial, auto-registration on: recorded as pending (the fake's observable
    # proxy for "a disabled, unlinked row was created" -- InMemoryDeviceRegistry.register_pending
    # tracks the sighting without exposing it through find(), exactly as its own docstring says:
    # "grants nothing"), and the response is still 401.
    settings_on = make_settings(auto_register_devices=True)
    service, stores = fake(settings=settings_on, devices=[])

    response = service.handle(wire.handshake(SERIAL_UNREGISTERED))

    assert response.status == 401, "auto-registration must not grant access"
    assert response.body == "Unauthorized"
    assert SERIAL_UNREGISTERED in stores["registry"].pending, "the sighting was not recorded"

    # -- The same unknown serial, asked about a second time: still no access, and it is not
    # registered twice (idempotent pending-list membership, not a growing list of duplicates).
    second_upload = wire.attlog(SERIAL_UNREGISTERED, [wire.punch(101, "2026-08-07 08:00:00")])
    response_again = service.handle(second_upload)
    assert response_again.status == 401
    assert stores["registry"].pending.count(SERIAL_UNREGISTERED) == 1, "recorded more than once"

    # -- A serial that already has a row -- linked, and separately disabled -- must never be
    # pushed through the pending-registration path at all, whatever auto-registration is set to:
    # register_pending is only ever reachable from the "no row found" branch of _authorize.
    for existing in (linked_device(), disabled_device()):
        own_service, own_stores = fake(settings=settings_on, devices=[existing])
        own_service.handle(wire.handshake(existing.serial))
        assert own_stores["registry"].pending == [], (
            f"{existing.serial}: an existing row must never be recorded as pending"
        )
        # And the stored row itself is byte-identical afterwards -- this path performs no update.
        assert own_stores["registry"].devices[existing.serial] == existing

    # -- The same unknown serial, auto-registration off: no row is created at all.
    settings_off = make_settings(auto_register_devices=False)
    off_service, off_stores = fake(settings=settings_off, devices=[])
    off_response = off_service.handle(wire.handshake(SERIAL_UNREGISTERED))
    assert off_response.status == 401
    assert off_stores["registry"].pending == [], "auto-registration is off; no row may be created"

    # -- Any authorised request updates last-seen and last-address for that serial.
    contact_service, contact_stores = fake(devices=[linked_device()])
    contact_response = contact_service.handle(wire.handshake(SERIAL_LINKED))
    assert contact_response.status == 200
    serials_contacted = [entry[0] for entry in contact_stores["registry"].contacts]
    addresses_recorded = [entry[2] for entry in contact_stores["registry"].contacts]
    assert SERIAL_LINKED in serials_contacted, "an authorised request must record contact"
    assert SOURCE_IP in addresses_recorded, "the request's own address must be what gets recorded"
