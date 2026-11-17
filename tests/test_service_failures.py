"""
``AdmsService``'s failure handling -- what happens when a data-carrying write itself fails,
whatever :meth:`~adms.service.AdmsService.handle` maps every failure to, and how severely each
one is logged -- against the in-memory graph.

Three properties live here, each implemented by exactly one test function, table-driven over
deliberately adversarial fixed inputs per the design's Testing Strategy. No ``hypothesis``.

**Property 48** is this file's namesake claim: fail each data-carrying write *in turn* -- the
raw-punch archive, the existing-key read, the punch insert, the employee upsert, the template
writes, the command claim and the acknowledgement update -- and confirm each produces a non-2xx
status and no acknowledgement, with no partial trace left in the store that write would have
populated. This is the mirror image of ``tests/test_service_besteffort.py``'s Property 49: that
file proves the *closed* best-effort set never changes an acknowledged result when it fails; this
file proves the writes explicitly excluded from that set -- because they carry the data itself --
are never swallowed. Each case here uses :func:`_explode` to replace one store method outright
(not merely to fail a predicate-matched call, as ``test_service_besteffort.py``'s ``_raise_on``
does), because every method exercised here is called at most once per request in the bodies this
file constructs, and a full replacement makes unambiguous that the write itself never ran to
completion.

**Property 64** is the total-mapping claim over ``handle`` itself: for any request and any
adapter fault, ``handle`` returns rather than raises, the status is always one of the six the
design names, and the body is always one of exactly six fixed phrases -- never the exception's
own message. Every fault case here plants a fragment that reads exactly like a real ODBC driver
error, including a full DSN with a password, in the fault's own message, so the leak check has
something real to catch if ``_public_message`` (or the generic-exception branch) ever regressed
to using ``str(exc)``.

**Property 66** is about the two logging branches in ``AdmsService.handle`` themselves --
``if exc.status >= 500: error else: warn`` -- rather than about any adapter. Every case here is
chosen so the fault fires before any other log line could be produced on that request (no
rejected ATTLOG lines, no unsupported OPERLOG record kinds, no best-effort failures), so filtering
the capture by level in isolation is enough to make "exactly one" an unambiguous count.

Scope note: none of these three properties is about the wsgi/hosting layer's own bounded
totality (Property 5) or about ``build_request`` failing to parse an environment into a request
at all (that 400 path lives in ``adms.wsgi``, not in ``AdmsService.handle``, and is
``tests/test_wsgi.py``'s subject, task 9.1). "400 for a request that does not parse as ADMS" is
exercised here at the layer ``AdmsService.handle`` actually owns: a request with no ``SN`` at
all, which is exactly what ``ProtocolError`` exists to refuse.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from conftest import (
    SERIAL_DISABLED,
    SERIAL_LINKED,
    SERIAL_UNLINKED,
    SERIAL_UNREGISTERED,
    LogCapture,
    disabled_device,
    linked_device,
    make_settings,
    unlinked_device,
)

from adms.errors import AttendanceDbError, ConfigError

__all__: list[str] = []


def _explode(exc: BaseException) -> Callable[..., Any]:
    """
    Replace a store method outright with one that raises ``exc`` on the first call.

    Deliberately a full replacement, not a wrapper that still calls through on a predicate miss
    (contrast ``test_service_besteffort.py``'s ``_raise_on``): every method exercised in this file
    is called at most once per request body, so there is nothing for a predicate to distinguish,
    and a full replacement makes it unambiguous that the write itself never completed.
    """

    def _raise(*_args: Any, **_kwargs: Any) -> Any:
        raise exc

    return _raise


# ── Property 48: No 2xx precedes a commit, and no data write failure is swallowed ───────────

#: One case per data-carrying write the design enumerates by name. Each fails exactly the one
#: method named, over a request body chosen so that method is reached and so the failure has
#: nothing else queued behind it that could mask a partial write. ``check`` reads back the store
#: the failing method belongs to and confirms it holds nothing that write would have added --
#: the write left no partial trace, matching "the transaction is rolled back so nothing partial
#: is left behind."
_DATA_WRITE_FAILURE_CASES: list[dict[str, Any]] = [
    {
        "id": "raw-punch archive (attendance.archive_attlog)",
        "devices": [linked_device()],
        "build": lambda w: w.attlog(SERIAL_LINKED, [w.punch(801, "2026-08-07 08:00:00")]),
        "fault": ("attendance", "archive_attlog"),
        "settings": {"enroll_query_enabled": False},
        "check": lambda stores: stores["attendance"].rows == [],
    },
    {
        "id": "existing-key read (attendance.existing_punch_keys)",
        "devices": [linked_device()],
        "build": lambda w: w.attlog(SERIAL_LINKED, [w.punch(802, "2026-08-07 08:00:00")]),
        "fault": ("attendance", "existing_punch_keys"),
        "settings": {"enroll_query_enabled": False},
        "check": lambda stores: stores["attendance"].rows == [],
    },
    {
        "id": "punch insert (attendance.add_attendance)",
        "devices": [linked_device()],
        "build": lambda w: w.attlog(SERIAL_LINKED, [w.punch(803, "2026-08-07 08:00:00")]),
        "fault": ("attendance", "add_attendance"),
        "settings": {"enroll_query_enabled": False},
        "check": lambda stores: stores["attendance"].rows == [],
    },
    {
        "id": "employee upsert (employees.upsert_employees)",
        "devices": [linked_device()],
        "build": lambda w: w.operlog(
            SERIAL_LINKED, ["USER\tPIN=804\tName=Nguyen Van F\tPri=0\tCard=1\tEnable=1"]
        ),
        "fault": ("employees", "upsert_employees"),
        "settings": {},
        "check": lambda stores: stores["employees"].employees == {},
    },
    {
        "id": "template writes -- fingerprints (templates.save_fingerprints)",
        "devices": [linked_device()],
        "build": lambda w: w.operlog(SERIAL_LINKED, ["FP\tPIN=805\tFID=0\tSize=4\tValid=1\tTMP=Zmlu"]),
        "fault": ("templates", "save_fingerprints"),
        "settings": {},
        "check": lambda stores: stores["templates"].fingers == {},
    },
    {
        "id": "template writes -- faces (templates.save_faces)",
        "devices": [linked_device()],
        "build": lambda w: w.operlog(
            SERIAL_LINKED, ["FACE\tPIN=806\tFID=0\tSIZE=8\tVALID=1\tTMP=ZmFjZQ=="]
        ),
        "fault": ("templates", "save_faces"),
        "settings": {},
        "check": lambda stores: stores["templates"].faces == {},
    },
    {
        "id": "command claim (commands.dequeue)",
        "devices": [linked_device()],
        "build": lambda w: w.getrequest(SERIAL_LINKED),
        "fault": ("commands", "dequeue"),
        "settings": {},
        "check": lambda stores: stores["commands"].sent == [],
    },
    {
        "id": "acknowledgement update (commands.ack)",
        "devices": [linked_device()],
        "build": lambda w: w.devicecmd(SERIAL_LINKED, [w.ack(41, 0, "CHECK")]),
        "fault": ("commands", "ack"),
        "settings": {},
        "check": lambda stores: stores["commands"].acks == [],
    },
]


@pytest.mark.parametrize(
    "case", _DATA_WRITE_FAILURE_CASES, ids=[c["id"] for c in _DATA_WRITE_FAILURE_CASES]
)
def test_property_48_no_2xx_precedes_a_commit_and_no_data_write_failure_is_swallowed(
    case: dict[str, Any], fake: Any, wire: Any
) -> None:
    # Feature: adms-attendance-system, Property 48: No 2xx precedes a commit, and no data write
    # failure is swallowed. For all writes that carry the request's data -- the raw-punch
    # archive, the existing-key read, the punch insert, the employee upsert, the template writes,
    # the command claim and the acknowledgement update -- failing each in turn produces a non-2xx
    # status and no acknowledgement; and for any failure inside a logical write, the transaction
    # is rolled back so nothing partial is left behind.
    """
    Failing each data-carrying write in turn produces a non-2xx status and no acknowledgement,
    and leaves no partial trace in the store that write would have populated.

    **Validates: Requirements 11.1, 11.8, 27.9**
    """
    settings = make_settings(**case["settings"])
    service, stores = fake(settings=settings, devices=case["devices"])
    store_name, method_name = case["fault"]
    setattr(
        stores[store_name],
        method_name,
        _explode(AttendanceDbError(f"synthetic failure injected on {store_name}.{method_name}")),
    )

    response = service.handle(case["build"](wire))

    assert not (200 <= response.status < 300), (
        f"{case['id']}: got a 2xx ({response.status}) after a failed write"
    )
    assert response.body != "OK" and not response.body.startswith("OK:"), (
        f"{case['id']}: the body looks like an acknowledgement: {response.body!r}"
    )
    assert case["check"](stores), f"{case['id']}: the failed write left a partial trace: {stores}"


# ── Property 64: Request handling is total, and every failure maps to its status and phrase ─

#: The complete status vocabulary handle() may ever answer with -- its own postcondition.
_VALID_STATUSES = {200, 400, 401, 404, 500, 503}

#: The complete device-facing failure vocabulary. Any status >= 300 must carry exactly one of
#: these phrases, verbatim -- never str(exc), never a SQL fragment, never a stack trace.
_FIXED_PHRASES = {
    "Bad Request",
    "Unauthorized",
    "Device Not Configured",
    "Storage Unavailable",
    "Server Error",
    "Not Found",
}

#: Route- and authorisation-driven outcomes: no adapter fault is injected here at all, so these
#: confirm the status/phrase mapping that comes purely from routing and the allow-list, which is
#: the other half of "every failure maps to its status and fixed phrase" -- not every failure
#: comes from an adapter.
_NO_FAULT_CASES: list[dict[str, Any]] = [
    {
        "id": "no SN parameter -- 400 Bad Request",
        "build": lambda w: w.request("POST", "/iclock/cdata", query={"table": "ATTLOG"}),
        "devices": [],
        "status": 400,
        "body": "Bad Request",
    },
    {
        "id": "unregistered serial -- 401 Unauthorized",
        "build": lambda w: w.handshake(SERIAL_UNREGISTERED),
        "devices": [],
        "status": 401,
        "body": "Unauthorized",
    },
    {
        # ``enabled`` is an operator label, not an access gate: a registered-but-disabled device
        # completes its handshake exactly like an enabled one (200, full body), so switching a
        # device off never refuses it. There is therefore no disabled-refusal case here anymore;
        # a disabled-but-linked *upload* is covered as a 200 in test_service_authz Property 50.
        "id": "disabled serial handshake -- 200, no longer a refusal",
        "build": lambda w: w.handshake(SERIAL_DISABLED),
        "devices": [disabled_device()],
        "status": 200,
        "body": None,  # full handshake body; only the status matters for this case
    },
    {
        "id": "enabled but unlinked, data upload -- 503 Device Not Configured",
        "build": lambda w: w.attlog(SERIAL_UNLINKED, [w.punch(1, "2026-08-07 08:00:00")]),
        "devices": [unlinked_device()],
        "status": 503,
        "body": "Device Not Configured",
    },
    {
        "id": "unknown route -- 404 Not Found",
        "build": lambda w: w.request("GET", "/iclock/nonsense"),
        "devices": [],
        "status": 404,
        "body": "Not Found",
    },
    {
        "id": "a valid upload from a linked device -- 200, not a failure at all",
        "build": lambda w: w.attlog(SERIAL_LINKED, [w.punch(2, "2026-08-07 08:00:00")]),
        "devices": [linked_device()],
        "status": 200,
        "body": None,  # varies with the count sent; only the status matters for this case
    },
]

#: A fragment shaped exactly like a real driver error: a full DSN, including a password. This is
#: the specific case the postcondition calls out -- "even when the underlying fault's own message
#: contains a connection string" -- so every fault case below carries it in its own message,
#: giving the leak check something real to catch.
_CONNECTION_STRING_FRAGMENT = (
    "Driver={ODBC Driver 18 for SQL Server};Server=sql01.internal,1433;"
    "Database=ATTENDANCEDB;UID=adms_collector;PWD=Correct-Horse-Battery-Staple;"
)

#: Adapter faults, one per failure category the postcondition names by name: database
#: unreachable (AttendanceDbError -> 503), a configuration fault (ConfigError -> 500) and an
#: unclassified failure (a plain exception no AdmsError subclass covers -> 500). A fourth case
#: repeats the database-unreachable category against a different call site (the acknowledgement
#: update) so the leak check is not exercised only once.
_ADAPTER_FAULT_CASES: list[dict[str, Any]] = [
    {
        "id": "database unreachable -- AttendanceDbError -- 503 Storage Unavailable",
        "build": lambda w: w.attlog(SERIAL_LINKED, [w.punch(3, "2026-08-07 08:00:00")]),
        "fault": ("attendance", "add_attendance", AttendanceDbError),
        "status": 503,
        "body": "Storage Unavailable",
    },
    {
        "id": "configuration fault -- ConfigError -- 500 Server Error",
        "build": lambda w: w.operlog(
            SERIAL_LINKED, ["USER\tPIN=811\tName=Nguyen Van G\tPri=0\tEnable=1"]
        ),
        "fault": ("employees", "upsert_employees", ConfigError),
        "status": 500,
        "body": "Server Error",
    },
    {
        "id": "unclassified failure -- plain exception -- 500 Server Error",
        "build": lambda w: w.operlog(SERIAL_LINKED, ["FP\tPIN=812\tFID=0\tSize=4\tValid=1\tTMP=Zmlu"]),
        "fault": ("templates", "save_fingerprints", RuntimeError),
        "status": 500,
        "body": "Server Error",
    },
    {
        "id": "acknowledgement update fails -- AttendanceDbError -- 503 Storage Unavailable",
        "build": lambda w: w.devicecmd(SERIAL_LINKED, [w.ack(41, 0, "CHECK")]),
        "fault": ("commands", "ack", AttendanceDbError),
        "status": 503,
        "body": "Storage Unavailable",
    },
]


def test_property_64_request_handling_is_total_and_every_failure_maps_to_its_status_and_phrase(
    fake: Any, wire: Any
) -> None:
    # Feature: adms-attendance-system, Property 64: Request handling is total, and every failure
    # maps to its status and fixed phrase. For all requests and for all adapter faults, handle
    # returns a response rather than raising; the status is one of 200, 400, 401, 404, 500, 503,
    # with 400 for a request that does not parse as ADMS, 503 when the database is unreachable,
    # and 500 for a configuration fault or any unclassified failure; and for all failures, the
    # body is one of exactly six fixed phrases and contains no exception message, SQL fragment,
    # server name or stack trace -- even when the underlying fault's own message contains a
    # connection string.
    """
    **Validates: Requirements 27.1, 27.2, 27.5, 27.6, 27.7, 27.12**
    """
    # -- Part A: routing and authorisation alone decide the status; no adapter fault involved.
    for case in _NO_FAULT_CASES:
        service, _stores = fake(devices=case["devices"])

        response = service.handle(case["build"](wire))  # must return, never raise

        assert response.status == case["status"], case["id"]
        assert response.status in _VALID_STATUSES, case["id"]
        if case["body"] is not None:
            assert response.body == case["body"], case["id"]
        if response.status >= 300:
            assert response.body in _FIXED_PHRASES, case["id"]

    # -- Part B: adapter faults, each carrying a real connection-string fragment (DSN, password
    # included) in its own message. handle() must still return -- not raise -- with the fixed
    # phrase for the exception's own status, and none of the fragment leaking into the body.
    for case in _ADAPTER_FAULT_CASES:
        service, stores = fake(devices=[linked_device()])
        store_name, method_name, exc_type = case["fault"]
        setattr(
            stores[store_name],
            method_name,
            _explode(exc_type(f"driver error: {_CONNECTION_STRING_FRAGMENT}")),
        )

        response = service.handle(case["build"](wire))  # must return, never raise

        assert response.status == case["status"], case["id"]
        assert response.status in _VALID_STATUSES, case["id"]
        assert response.body == case["body"], case["id"]
        assert response.body in _FIXED_PHRASES, case["id"]
        for leaked in (
            "PWD=Correct-Horse-Battery-Staple",
            "Correct-Horse-Battery-Staple",
            "UID=adms_collector",
            "sql01.internal",
            "Database=ATTENDANCEDB",
            "driver error",
            "ODBC Driver",
        ):
            assert leaked not in response.body, (
                f"{case['id']}: {leaked!r} leaked into the response body {response.body!r}"
            )


# ── Property 66: Log severity follows the status class ──────────────────────────────────────

#: One case per failure category, chosen so the fault fires before any other log line could be
#: produced on that same request -- no rejected ATTLOG lines, no unsupported OPERLOG kinds, no
#: best-effort failures alongside it -- so filtering the capture by level alone makes "exactly
#: one" an unambiguous count. The first three have no injected fault at all: they are the
#: AdmsError subclasses AdmsService itself raises (ProtocolError, DeviceNotRegisteredError,
#: DeviceNotLinkedError), which is what makes the < 500 / >= 500 split a property of
#: AdmsService.handle rather than of any particular adapter. (``enabled`` is no longer a gate, so
#: a disabled device is not a refusal case here.) The last three inject an adapter fault to reach
#: the >= 500 branch by a route that started as a legitimate request rather than a refusal.
_SEVERITY_CASES: list[dict[str, Any]] = [
    {
        "id": "protocol error, no SN -- 400, warning, no traceback",
        "build": lambda w: w.request("POST", "/iclock/cdata", query={"table": "ATTLOG"}),
        "devices": [],
        "fault": None,
        "expect_level": "WARN",
    },
    {
        "id": "unregistered device -- 401, warning, no traceback",
        "build": lambda w: w.handshake(SERIAL_UNREGISTERED),
        "devices": [],
        "fault": None,
        "expect_level": "WARN",
    },
    {
        "id": "enabled but unlinked, data upload -- 503, error, bounded traceback",
        "build": lambda w: w.attlog(SERIAL_UNLINKED, [w.punch(4, "2026-08-07 08:00:00")]),
        "devices": [unlinked_device()],
        "fault": None,
        "expect_level": "ERROR",
    },
    {
        "id": "database unreachable -- AttendanceDbError, 503, error, bounded traceback",
        "build": lambda w: w.attlog(SERIAL_LINKED, [w.punch(5, "2026-08-07 08:00:00")]),
        "devices": [linked_device()],
        "fault": ("attendance", "add_attendance", AttendanceDbError),
        "expect_level": "ERROR",
    },
    {
        "id": "configuration fault -- ConfigError, 500, error, bounded traceback",
        "build": lambda w: w.operlog(
            SERIAL_LINKED, ["USER\tPIN=821\tName=Nguyen Van H\tPri=0\tEnable=1"]
        ),
        "devices": [linked_device()],
        "fault": ("employees", "upsert_employees", ConfigError),
        "expect_level": "ERROR",
    },
    {
        "id": "unclassified failure -- plain exception, 500, error, bounded traceback",
        "build": lambda w: w.operlog(SERIAL_LINKED, ["FP\tPIN=822\tFID=0\tSize=4\tValid=1\tTMP=Zmlu"]),
        "devices": [linked_device()],
        "fault": ("templates", "save_fingerprints", RuntimeError),
        "expect_level": "ERROR",
    },
]


@pytest.mark.parametrize("case", _SEVERITY_CASES, ids=[c["id"] for c in _SEVERITY_CASES])
def test_property_66_log_severity_follows_the_status_class(
    case: dict[str, Any], fake: Any, wire: Any
) -> None:
    # Feature: adms-attendance-system, Property 66: Log severity follows the status class. For
    # all failures with a status of 500 or above, exactly one error-level line is written
    # carrying a bounded traceback; for all failures below 500, exactly one warning-level line is
    # written carrying the reason and no traceback.
    """
    **Validates: Requirements 12.6, 27.10, 27.11**
    """
    settings = make_settings(enroll_query_enabled=False)
    log_capture = LogCapture()
    service, stores = fake(settings=settings, devices=case["devices"], log=log_capture.logger)

    if case["fault"] is not None:
        store_name, method_name, exc_type = case["fault"]
        setattr(stores[store_name], method_name, _explode(exc_type("synthetic failure for Property 66")))

    response = service.handle(case["build"](wire))

    assert response.status >= 400, case["id"]

    errors = log_capture.of_level("ERROR")
    warnings = log_capture.of_level("WARN")

    if case["expect_level"] == "ERROR":
        assert len(errors) == 1, f"{case['id']}: expected exactly one error line, got {errors}"
        assert len(warnings) == 0, f"{case['id']}: expected no warning line, got {warnings}"
        assert "trace" in errors[0], f"{case['id']}: an error-level failure must carry a traceback"
        frame_lines = [
            line for line in errors[0]["trace"].splitlines() if line.strip().startswith("File ")
        ]
        assert 1 <= len(frame_lines) <= 6, f"{case['id']}: traceback not bounded: {errors[0]['trace']}"
    else:
        assert len(warnings) == 1, f"{case['id']}: expected exactly one warning line, got {warnings}"
        assert len(errors) == 0, f"{case['id']}: expected no error line, got {errors}"
        assert "reason" in warnings[0], f"{case['id']}: a warning-level failure must carry a reason"
        assert "trace" not in warnings[0], f"{case['id']}: a failure below 500 must carry no traceback"
