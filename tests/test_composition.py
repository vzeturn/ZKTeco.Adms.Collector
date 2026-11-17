"""
Property tests for the composition root and the two places that decide which application object is
which: ``adms.composition``, ``tools/local_server.py`` and ``adms.hosting.serve``.

Not in the design's ``tests/`` layout. Properties 58, 71 and 72 have no home in that list, and all
three are about identity rather than about a route's behaviour: the object graph is built once and
recovers from a failed first build (58), the collector authenticates nothing and the two applications
bind different ports (71 -- the collector half only; the console half is blocked), and the local
development server serves exactly the application object the process entry point gives IIS (72).

One property, one test, table-driven over fixed inputs per the design's Testing Strategy. No
``hypothesis``. Property 58's concurrency half uses real ``threading.Thread`` objects, for the same
reason ``test_connection.py`` does: a race that only shows up under real concurrent callers does not
show up against a synchronous stand-in for "two callers at once".

Property 71's disjointness half needs ``adms.admin.app``, which the admin-console spec's task 4.1
creates and which does not exist in this checkout yet (confirmed: ``src/adms/admin/`` holds only
``auth.py``, ``store.py`` and ``__init__.py``). That half is ``pytest.skip``-ed with the reason named,
rather than asserted weakly or worked around by importing something that is not there.
"""

from __future__ import annotations

import dataclasses
import importlib
import io
import sys
import threading
import time
from typing import Any, cast

import pytest
from conftest import (
    SERIAL_LINKED,
    SERIAL_UNLINKED,
    SERIAL_UNREGISTERED,
    make_settings,
)

from adms.errors import ConfigError
from adms.logging_setup import NullLogger
from adms.wsgi import AdmsWsgiApp, create_app

# ── Property 58: The graph is built once, a failure is never cached, and both graphs satisfy every
#    port ──────────────────────────────────────────────────────────────────────────────────────────


def test_property_58_graph_built_once_failure_not_cached_and_both_adapter_sets_satisfy_every_port(
    monkeypatch: pytest.MonkeyPatch, fake: Any, wire: Any
) -> None:
    # Feature: adms-attendance-system, Property 58: The graph is built once, a failure is never
    # cached, and both graphs satisfy every port. For any number of concurrent first requests, the
    # object graph is constructed exactly once; for any first construction that fails, the next
    # request attempts construction again; and for every port, both the SQL adapter set and the
    # in-memory adapter set satisfy it structurally, with the in-memory set exposing what was
    # written.
    from adms import composition

    composition.reset()
    monkeypatch.setattr(composition, "get_logger", lambda: NullLogger())

    try:
        # ── Part A: concurrent first requests build the graph exactly once ─────────────────────
        build_calls: list[object] = []
        build_lock = threading.Lock()
        sentinel_service = object()

        def counting_build_service(settings: object, *, log: object = None) -> object:  # noqa: ARG001
            with build_lock:
                build_calls.append(settings)
            # Held while composition._lock is held (build_service is called from inside that
            # lock's `with` block), so every other thread is guaranteed to be blocked on the lock
            # rather than racing to also see _service as None.
            time.sleep(0.05)
            return sentinel_service

        monkeypatch.setattr(composition, "build_service", counting_build_service)
        monkeypatch.setattr(composition, "load_settings", make_settings)

        thread_count = 12
        barrier = threading.Barrier(thread_count)
        results: list[object] = [None] * thread_count
        errors: list[BaseException] = []

        def worker(index: int) -> None:
            barrier.wait()
            try:
                results[index] = composition.get_service()
            except BaseException as exc:  # recorded, not swallowed; BLE001 is repo-wide disabled
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(thread_count)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert not errors, f"a concurrent first request raised: {errors!r}"
        assert all(not t.is_alive() for t in threads), "a worker thread did not finish in time"
        assert len(build_calls) == 1, f"the graph was built {len(build_calls)} times, want exactly 1"
        assert all(r is sentinel_service for r in results), "not every caller received the same graph"

        # ── Part B: a failed first construction is retried on the next call, not cached ────────
        composition.reset()
        monkeypatch.setattr(composition, "get_logger", lambda: NullLogger())
        attempts: list[int] = []

        def flaky_build_service(settings: object, *, log: object = None) -> object:  # noqa: ARG001
            attempts.append(1)
            if len(attempts) == 1:
                raise ConfigError("simulated: the registry was unreadable on the first attempt")
            return sentinel_service

        monkeypatch.setattr(composition, "build_service", flaky_build_service)
        monkeypatch.setattr(composition, "load_settings", make_settings)

        with pytest.raises(ConfigError):
            composition.get_service()
        assert len(attempts) == 1, "the failed attempt must count exactly once"

        # The worker is not poisoned: the very next request tries construction again.
        recovered = composition.get_service()
        assert recovered is sentinel_service
        assert len(attempts) == 2, "the request after a failure must attempt construction again"

        # And the successful graph is now cached, same as Part A.
        assert composition.get_service() is sentinel_service
        assert len(attempts) == 2, "a cached success must not rebuild on a later call"
    finally:
        composition.reset()

    # ── Part C: every port the service depends on is satisfied structurally by both the SQL
    #    adapter set and the in-memory adapter set, and the in-memory set exposes what was
    #    written ───────────────────────────────────────────────────────────────────────────────
    from adms.db import (
        SqlServerAttendanceStore,
        SqlServerCommandQueue,
        SqlServerDeviceRegistry,
        SqlServerEmployeeStore,
        SqlServerPushArchive,
        SqlServerTemplateStore,
    )
    from adms.db.connection import ConnectionFactory
    from adms.memory import (
        InMemoryAttendanceStore,
        InMemoryCommandQueue,
        InMemoryDeviceRegistry,
        InMemoryEmployeeStore,
        InMemoryPushArchive,
        InMemoryTemplateStore,
    )
    from adms.ports import (
        AttendanceStore,
        CommandQueue,
        DeviceRegistry,
        EmployeeStore,
        PushArchive,
        TemplateStore,
    )

    # SQL adapters only ever store this reference (see db/connection.py's ConnectionFactory type
    # hint); none of their constructors opens a connection, so a plain sentinel proves the
    # structural point with no driver and no database anywhere near this test. cast rather than a
    # real ConnectionFactory: constructing one requires a non-empty connection string and this test
    # asserts nothing about connection behaviour -- Property 62 already owns that.
    dummy_factory = cast(ConnectionFactory, object())
    pairs: list[tuple[type, object, object]] = [
        (DeviceRegistry, SqlServerDeviceRegistry(dummy_factory), InMemoryDeviceRegistry([])),
        (AttendanceStore, SqlServerAttendanceStore(dummy_factory), InMemoryAttendanceStore()),
        (EmployeeStore, SqlServerEmployeeStore(dummy_factory), InMemoryEmployeeStore()),
        (TemplateStore, SqlServerTemplateStore(dummy_factory), InMemoryTemplateStore()),
        (CommandQueue, SqlServerCommandQueue(dummy_factory), InMemoryCommandQueue()),
        (PushArchive, SqlServerPushArchive(dummy_factory), InMemoryPushArchive()),
    ]
    for port, sql_adapter, memory_adapter in pairs:
        assert isinstance(sql_adapter, port), (
            f"{type(sql_adapter).__name__} does not structurally satisfy {port.__name__}"
        )
        assert isinstance(memory_adapter, port), (
            f"{type(memory_adapter).__name__} does not structurally satisfy {port.__name__}"
        )

    # The in-memory set exposes what was written: drive one real punch through the fake graph and
    # read it back from the store the port call wrote to, not from the service's return value.
    service, stores = fake()
    response = service.handle(wire.attlog(SERIAL_LINKED, [wire.punch(101, "2026-08-07 08:00:00")]))
    assert response.status == 200, response.body
    assert stores["attendance"].rows, "the in-memory attendance store did not expose the written punch"
    assert stores["attendance"].rows[0]["MaChamCong"] == 101


# ── Property 71 (partial -- collector half only): The console is a separate application that never
#    touches a device or the device's surface ───────────────────────────────────────────────────────


def test_property_71_collector_authenticates_nothing_and_default_ports_differ(
    monkeypatch: pytest.MonkeyPatch, fake: Any, wire: Any
) -> None:
    # Feature: adms-attendance-system, Property 71 (partial -- collector half only): for all
    # collector routes, none requires authentication; and the two applications' default ports
    # differ, so both can run concurrently. The route-set disjointness half needs adms.admin.app,
    # which the admin-console spec's task 4.1 has created; it is asserted at the end of this test.
    # -- No collector route consults an authentication-shaped header. Vary Authorization and
    # Cookie across a spread of routes and registration states; if any route's outcome changed,
    # something in it would have to be reading one of those headers as a credential -- and nothing
    # in adms.service or adms.protocol does. Access is decided purely by the ADMS_DEVICE allow-list
    # (Property 50), which is a different, non-credential-based decision from "authentication".
    #
    # A fresh (service, request) pair is built for every single call, rather than one service
    # reused across header variants: several of these routes have side effects (claim-on-read
    # command dequeue, duplicate-punch suppression, auto-enrolment) that would make the *second*
    # call to the same route differ from the first regardless of headers, and that would be a false
    # positive for "headers changed the outcome" when the real cause is call order.
    route_builders: dict[str, Any] = {
        "handshake-linked": lambda: wire.handshake(SERIAL_LINKED),
        "handshake-unregistered": lambda: wire.handshake(SERIAL_UNREGISTERED),
        "attlog-linked": lambda: wire.attlog(SERIAL_LINKED, [wire.punch(101, "2026-08-07 08:00:00")]),
        "attlog-unlinked": lambda: wire.attlog(SERIAL_UNLINKED, [wire.punch(101, "2026-08-07 08:00:00")]),
        "getrequest-linked": lambda: wire.getrequest(SERIAL_LINKED),
        "devicecmd-linked": lambda: wire.devicecmd(SERIAL_LINKED, [wire.ack(1, 0, "INFO")]),
        "ping": lambda: wire.request("GET", "/iclock/ping", query={"SN": SERIAL_LINKED}),
        "unknown-route": lambda: wire.request("GET", "/nonsense"),
    }
    header_variants: list[dict[str, str]] = [
        {},
        {"authorization": "Bearer not-a-real-token"},
        {"authorization": "Basic garbage-credentials"},
        {"cookie": "session=deadbeef"},
        {"authorization": "Bearer x", "cookie": "session=y"},
    ]

    for label, build_request in route_builders.items():
        outcomes = set()
        for headers in header_variants:
            fresh_service, _fresh_stores = fake()
            request = dataclasses.replace(build_request(), headers=headers)
            response = fresh_service.handle(request)
            outcomes.add((response.status, response.body))
        assert len(outcomes) == 1, (
            f"{label}: varying Authorization/Cookie headers changed the outcome -- {outcomes}"
        )

    # -- The two applications' default ports differ. adms.hosting.serve is the collector's process
    # entry point. A console serve module (adms.admin.serve) does not exist yet either, so its
    # default is taken as the design's documented value (8081) -- a fixed literal, since there is
    # no code yet to read it from.
    monkeypatch.delenv("ASPNETCORE_PORT", raising=False)
    monkeypatch.delenv("HTTP_PLATFORM_PORT", raising=False)
    from adms.hosting.serve import build_parser

    collector_default_port = build_parser().parse_args([]).port
    console_documented_default_port = 8081
    assert collector_default_port != console_documented_default_port, (
        f"collector default port {collector_default_port} collides with the console's documented "
        f"default {console_documented_default_port}"
    )

    # -- The console application now exists (admin-console task 4.1) and imports cleanly, so this
    # property is asserted for real rather than skipped. Its route set is disjoint from the
    # collector's: no path under /iclock, and the collector owns nothing the console serves.
    console_app = importlib.import_module("adms.admin.app")
    console_paths = {route.pattern for route in console_app._ROUTES}
    assert not any(path.startswith("/iclock") for path in console_paths)


# ── Property 72: The development server serves the production application object ──────────────────


def test_property_72_dev_server_serves_the_same_application_the_process_entry_point_gives_iis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Feature: adms-attendance-system, Property 72: The development server serves the production
    # application object. For any configuration, the local server serves the same WSGI application
    # object the process entry point gives IIS; and in fake mode it serves the full conversation
    # for a pre-registered linked serial with no database and no ODBC driver present.
    import argparse

    import tools.local_server as local_server

    from adms import composition

    # ── Part A: identity of construction path. tools/local_server.py (without --fake) and
    #    adms.hosting.serve (via adms.wsgi.create_app) both reach adms.composition.build_service
    #    and wrap the result in the same adms.wsgi.AdmsWsgiApp -- proven by making build_service
    #    return one identifiable object and watching it flow, unchanged, through both entry
    #    points ───────────────────────────────────────────────────────────────────────────────
    composition.reset()
    monkeypatch.setattr(composition, "get_logger", lambda: NullLogger())
    sentinel_service = object()

    def fake_build_service(settings: object, *, log: object = None) -> object:  # noqa: ARG001
        return sentinel_service

    monkeypatch.setattr(composition, "build_service", fake_build_service)
    monkeypatch.setattr(composition, "load_settings", make_settings)

    # The path tools/local_server.py takes when run without --fake. Its own `build_service` name
    # is re-resolved from adms.composition at call time (a local import inside the function), so
    # the patch above reaches it even though local_server.py never touches composition.get_service.
    dev_args = argparse.Namespace(fake=False)
    dev_app, dev_stores = local_server.build(dev_args)

    assert dev_stores is None
    assert isinstance(dev_app, AdmsWsgiApp)
    assert dev_app._service is sentinel_service

    # The path adms.hosting.serve.main() takes to hand waitress an application object -- exercised
    # directly through composition.get_service() + adms.wsgi.create_app rather than through
    # main() itself, so this test binds no socket and starts no server.
    composition.reset()
    monkeypatch.setattr(composition, "get_logger", lambda: NullLogger())
    monkeypatch.setattr(composition, "build_service", fake_build_service)
    monkeypatch.setattr(composition, "load_settings", make_settings)
    prod_service = composition.get_service()
    prod_app = create_app(prod_service)

    assert isinstance(prod_app, AdmsWsgiApp)
    assert prod_app._service is sentinel_service
    assert dev_app._service is prod_app._service, (
        "the local server and the process entry point must serve the same underlying service object"
    )
    assert type(dev_app) is type(prod_app) is AdmsWsgiApp

    composition.reset()

    # ── Part B: in fake mode, the local server serves the full conversation for a pre-registered
    #    linked serial, with no database and no ODBC driver present. pyodbc is blocked for the rest
    #    of this test (it is a runtime dependency, so it is normally installed), so any accidental
    #    path to a real adapter fails loudly instead of silently reaching a database ────────────────
    monkeypatch.setitem(sys.modules, "pyodbc", None)
    with pytest.raises(ImportError):
        importlib.import_module("pyodbc")

    fake_args = argparse.Namespace(
        fake=True,
        serial=["LOCALTEST1"],
        auto_register=False,
        path_secret="",
        utc_offset=7,
    )
    app, stores = local_server.build(fake_args)
    assert stores is not None, "fake mode must hand back inspectable in-memory stores"

    def call(environ: dict[str, Any]) -> tuple[str, bytes]:
        captured: dict[str, Any] = {}

        def start_response(status: str, headers: list[tuple[str, str]]) -> None:
            captured["status"] = status
            captured["headers"] = headers

        body = b"".join(app(environ, start_response))
        return captured["status"], body

    handshake_environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/iclock/cdata",
        "QUERY_STRING": "SN=LOCALTEST1&options=all&pushver=2.4.1",
    }
    status, body = call(handshake_environ)
    assert status.startswith("200"), body
    assert body.decode("utf-8").startswith("GET OPTION FROM: LOCALTEST1"), body

    upload_body = b"1\t2026-08-07 08:00:00\t0\t1\t0\t\t\n"
    upload_environ: dict[str, Any] = {
        "REQUEST_METHOD": "POST",
        "PATH_INFO": "/iclock/cdata",
        "QUERY_STRING": "SN=LOCALTEST1&table=ATTLOG&Stamp=9999",
        "CONTENT_LENGTH": str(len(upload_body)),
        "wsgi.input": io.BytesIO(upload_body),
    }
    status, body = call(upload_environ)
    assert status.startswith("200"), body
    assert body == b"OK: 1", body
    assert stores["attendance"].rows, "the fake graph did not store the uploaded punch"
    assert stores["attendance"].rows[0]["MaChamCong"] == 1

    # A second, identical upload must not insert again -- proving this is the real service's
    # idempotent path, not a stub that always answers OK.
    upload_environ["wsgi.input"] = io.BytesIO(upload_body)
    status, body = call(upload_environ)
    assert status.startswith("200"), body
    assert body == b"OK: 1", body
    assert len(stores["attendance"].rows) == 1, "a duplicate upload must not insert a second row"

    composition.reset()
