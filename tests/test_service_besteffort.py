"""
``AdmsService``'s best-effort discipline (D16) -- every side operation that is not the data
itself, against the in-memory graph.

One property lives here, parametrised over every call site the design enumerates as best-effort:
contact recording (the per-request heartbeat), options storage, the resumption-stamp advance,
every archive write (the verbatim request body, unparsed lines, device operations and user
photos), and every step of auto-enrolment (the missing-PIN lookup, the cooldown check and the
command enqueue). Each case fails exactly one adapter method call, on exactly the call site named,
and asserts three things against an identical fault-free baseline built from the same settings,
devices and :class:`~adms.memory.FixedClock`: the response is unchanged, every data-carrying write
still happened, and exactly one warning was newly logged because of the failure.

Why a baseline comparison rather than fixed expected values
-------------------------------------------------------------
Several of these requests legitimately produce warnings that have nothing to do with the fault
under test -- an ATTLOG batch with a rejected line always logs "Some ATTLOG lines were unusable"
whether or not the archive write that follows it succeeds. Asserting "exactly one warning in
total" would conflate that pre-existing warning with the one the fault under test is supposed to
add. Comparing against a fault-free baseline of the identical request isolates the warning the
failure itself produces, which is the claim the property actually makes.

Why the resumption stamp is not part of the data-carrying comparison
----------------------------------------------------------------------
Failing the stamp advance means the stamp genuinely does not move -- that is the whole point of
D17/D16's ordering rule, and the device is expected to re-send while dedup absorbs it. The
data-carrying snapshot compared between baseline and faulty runs is therefore deliberately
limited to the writes Requirement 11.9's closed set names as never best-effort: the punch insert,
its raw-punch archive, the employee upsert and the template writes. The stamp, the heartbeat, the
options mapping and the archived request bodies are the very things being failed in various cases
and are not expected to match the baseline when they are the fault under test.

Scope note: the boundary this property protects
-------------------------------------------------
The enumerated best-effort set is closed by design -- the writes that carry the data itself are
never in it. This file's own property only exercises the best-effort side; a single boundary
check at the end of the file confirms the other side of that line still holds (failing a
data-carrying write is not swallowed). Exhaustive coverage of every data-carrying write's failure
is ``tests/test_service_failures.py``'s job (task 10.7); duplicating it here would be redundant
with that file rather than complementary to it.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from conftest import (
    SERIAL_LINKED,
    LogCapture,
    linked_device,
    make_settings,
)

__all__: list[str] = []

# ── A targeted fault: raise from one adapter method, only when a predicate matches the call ────


def _always(_args: tuple[Any, ...], _kwargs: dict[str, Any]) -> bool:
    """The default predicate: every call to the patched method raises."""
    return True


def _raise_on(
    store: Any,
    method_name: str,
    predicate: Callable[[tuple[Any, ...], dict[str, Any]], bool] = _always,
    message: str = "synthetic failure injected by test_service_besteffort",
) -> None:
    """
    Replace one method on ``store`` with a version that raises exactly when ``predicate`` matches
    the call's own arguments, and otherwise behaves exactly as before.

    A predicate is needed rather than an unconditional raise because some best-effort call sites
    share a method with another call site on the very same request -- ``record_contact`` is
    called once as the per-request heartbeat in ``_dispatch`` and, on an ``options`` upload, a
    second time from ``_device_options`` carrying ``info=``. Raising unconditionally would fail
    both calls on that request and log two warnings instead of the one the failing call site is
    supposed to produce; the predicate isolates the one call this test is about.
    """
    original = getattr(store, method_name)

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if predicate(args, kwargs):
            raise RuntimeError(message)
        return original(*args, **kwargs)

    setattr(store, method_name, wrapper)


# ── The data-carrying snapshot: exactly Requirement 11.9's closed set, never best-effort ───────


def _data_snapshot(stores: dict[str, Any]) -> dict[str, Any]:
    """
    Everything the design says must never be best-effort: the punch insert, the raw-punch archive
    of the parsed data, the employee upsert and the template writes.

    Deliberately excludes the resumption stamp, the heartbeat/options record, the queued command
    history and the verbatim/unparsed archive rows -- those are exactly the best-effort
    operations under test in one case or another, and are expected to differ from the baseline
    precisely when they are the one failing.
    """
    return {
        "attendance_rows": list(stores["attendance"].rows),
        "attendance_archived": list(stores["attendance"].archived),
        "employees": dict(stores["employees"].employees),
        "fingers": {pin: list(templates) for pin, templates in stores["templates"].fingers.items()},
        "faces": {pin: list(templates) for pin, templates in stores["templates"].faces.items()},
    }


# ── The cases: one per best-effort call site the design enumerates ─────────────────────────────

#: (method, admin, time, obj, p1, p2, p3) -- OPLOG's positional layout, matching operlog.py's own
#: docstring. Used only to give _persist_operlog something to hand to archive_operations.
_OPLOG_LINE = "OPLOG\t0\t1\t2026-08-07 08:10:00\tobj\tp1\tp2\tp3"

_BEST_EFFORT_CASES: list[dict[str, Any]] = [
    {
        "id": "contact recording -- the per-request heartbeat (Requirement 13.5)",
        "request": lambda w: w.attlog(SERIAL_LINKED, [w.punch(101, "2026-08-07 08:00:00")]),
        "settings": {"enroll_query_enabled": False},
        "fault": ("registry", "record_contact", lambda _a, k: k.get("info") is None),
        "status": 200,
        "body": "OK: 1",
        "warning": "Could not record device contact.",
    },
    {
        "id": "options storage (Requirement 6.8)",
        "request": lambda w: w.options(SERIAL_LINKED, {"~DeviceName": "iFace990", "FirmVer": "6.60"}),
        "settings": {},
        "fault": ("registry", "record_contact", lambda _a, k: k.get("info") is not None),
        "status": 200,
        "body": "OK",
        "warning": "Could not store device options.",
    },
    {
        "id": "stamp advance (Requirement 11.5)",
        "request": lambda w: w.attlog(SERIAL_LINKED, [w.punch(102, "2026-08-07 08:01:00")], stamp="9999"),
        "settings": {"enroll_query_enabled": False},
        "fault": ("registry", "advance_stamp", _always),
        "status": 200,
        "body": "OK: 1",
        "warning": "Could not advance the resumption stamp",
    },
    {
        "id": "archive write -- the verbatim request body (Requirement 18.12)",
        "request": lambda w: w.attlog(SERIAL_LINKED, [w.punch(103, "2026-08-07 08:02:00")]),
        "settings": {"enroll_query_enabled": False},
        "fault": ("archive", "archive_request", _always),
        "status": 200,
        "body": "OK: 1",
        "warning": "Could not archive the raw request body.",
    },
    {
        "id": "archive write -- unparsed lines (Requirement 18.12)",
        # A KV-layout line with no pin key at all is rejected by parse_attlog before any punch
        # exists, so _attlog returns after _safe_archive_unparsed with no other archive or store
        # call reached -- this isolates archive_unparsed from every other archive write.
        "request": lambda w: w.attlog(SERIAL_LINKED, ["Foo=1\tBar=2"]),
        "settings": {"enroll_query_enabled": False},
        "fault": ("archive", "archive_unparsed", _always),
        "status": 200,
        "body": "OK: 1",
        "warning": "Could not archive unparsed lines.",
    },
    {
        "id": "archive write -- device operations (Requirement 18.12)",
        "request": lambda w: w.operlog(
            SERIAL_LINKED, ["USER\tPIN=910\tName=Nguyen Van C\tPri=0", _OPLOG_LINE]
        ),
        "settings": {},
        "fault": ("archive", "archive_operations", _always),
        "status": 200,
        "body": "OK: 2",
        "warning": "Could not archive device operations.",
    },
    {
        "id": "archive write -- user photos (Requirement 18.12)",
        "request": lambda w: w.operlog(
            SERIAL_LINKED,
            [
                "USER\tPIN=911\tName=Tran Thi D\tPri=0",
                "USERPIC\tPIN=911\tFileName=pic.jpg\tSize=4\tContent=Zmlu",
            ],
        ),
        "settings": {},
        "fault": ("archive", "archive_photos", _always),
        "status": 200,
        "body": "OK: 2",
        "warning": "Could not archive user photos.",
    },
    {
        "id": "enrolment step -- the missing-PIN lookup (Requirement 20.4)",
        "request": lambda w: w.attlog(SERIAL_LINKED, [w.punch(950, "2026-08-07 08:03:00")]),
        "settings": {"enroll_query_enabled": True},
        "fault": ("employees", "missing_employee_pins", _always),
        "status": 200,
        "body": "OK: 1",
        "warning": "Could not queue enrolment requests; the punches are already stored.",
    },
    {
        "id": "enrolment step -- the cooldown check (Requirement 20.4)",
        "request": lambda w: w.attlog(SERIAL_LINKED, [w.punch(951, "2026-08-07 08:04:00")]),
        "settings": {"enroll_query_enabled": True},
        "fault": ("commands", "pins_with_recent_request", _always),
        "status": 200,
        "body": "OK: 1",
        "warning": "Could not queue enrolment requests; the punches are already stored.",
    },
    {
        "id": "enrolment step -- queueing the command (Requirement 20.4)",
        "request": lambda w: w.attlog(SERIAL_LINKED, [w.punch(952, "2026-08-07 08:05:00")]),
        "settings": {"enroll_query_enabled": True},
        "fault": ("commands", "enqueue", _always),
        "status": 200,
        "body": "OK: 1",
        "warning": "Could not queue enrolment requests; the punches are already stored.",
    },
]


@pytest.mark.parametrize("case", _BEST_EFFORT_CASES, ids=[c["id"] for c in _BEST_EFFORT_CASES])
def test_property_49_every_side_operation_is_individually_best_effort(
    case: dict[str, Any], fake: Any, wire: Any
) -> None:
    # Feature: adms-attendance-system, Property 49: Every side operation is individually
    # best-effort and cannot change an acknowledged result. For each of contact recording,
    # options storage, stamp advance, every archive write and every enrolment step, failing that
    # operation alone leaves the status, the body and every data write unchanged, and produces
    # exactly one warning.
    """
    For each of contact recording, options storage, stamp advance, every archive write and every
    enrolment step, failing that operation alone leaves the status, the body and every data write
    unchanged, and produces exactly one warning attributable to that failure.

    **Validates: Requirements 6.8, 11.5, 13.5, 18.12, 20.4**
    """
    devices = [linked_device()]
    settings = make_settings(**case["settings"])

    # -- Baseline: an identical graph, identical request, nothing faulted.
    baseline_logs = LogCapture()
    baseline_service, baseline_stores = fake(settings=settings, devices=devices, log=baseline_logs.logger)
    baseline_response = baseline_service.handle(case["request"](wire))

    # -- Faulty: the same graph shape, with exactly the named call site raising.
    faulty_logs = LogCapture()
    faulty_service, faulty_stores = fake(settings=settings, devices=devices, log=faulty_logs.logger)
    store_name, method_name, predicate = case["fault"]
    _raise_on(faulty_stores[store_name], method_name, predicate)
    faulty_response = faulty_service.handle(case["request"](wire))

    # -- The response is unchanged.
    assert faulty_response.status == baseline_response.status == case["status"], case["id"]
    assert faulty_response.body == baseline_response.body == case["body"], case["id"]

    # -- Every data-carrying write still happened, exactly as it did in the fault-free baseline.
    assert _data_snapshot(faulty_stores) == _data_snapshot(baseline_stores), (
        f"{case['id']}: a data-carrying write differed from the fault-free baseline"
    )

    # -- Exactly one warning was newly logged because of this failure -- not "exactly one
    # warning in total", because some of these requests (the rejected-line case, in particular)
    # legitimately log a warning of their own regardless of whether the fault fires.
    baseline_warning_count = len(baseline_logs.of_level("WARN"))
    faulty_warnings = faulty_logs.of_level("WARN")
    assert len(faulty_warnings) == baseline_warning_count + 1, (
        f"{case['id']}: expected exactly one new warning, baseline had {baseline_warning_count}, "
        f"faulty had {len(faulty_warnings)}: {faulty_warnings}"
    )
    assert any(case["warning"] in w.get("msg", "") for w in faulty_warnings), (
        f"{case['id']}: no warning mentioned {case['warning']!r}: {faulty_warnings}"
    )


# ── Boundary confirmation: the closed set is actually closed ────────────────────────────────────


def test_boundary_data_carrying_writes_are_never_best_effort(fake: Any, wire: Any) -> None:
    """
    Not Property 49 itself, and not a new property: a brief confirmation of the boundary the
    design's D16 says keeps the best-effort set closed. The writes that carry the data itself --
    the punch insert and the employee upsert among them -- are never wrapped as best-effort, so
    failing one must still surface as a non-2xx rather than being logged and swallowed the way
    every case above is. Exhaustive coverage of every data-carrying write's failure belongs to
    ``tests/test_service_failures.py`` (task 10.7); this checks two representative cases only, so
    the boundary this file's own property depends on is not merely asserted by omission.
    """
    settings = make_settings(enroll_query_enabled=False)

    # -- The punch insert itself (AttendanceStore.add_attendance).
    service, stores = fake(settings=settings, devices=[linked_device()])
    _raise_on(stores["attendance"], "add_attendance", _always)
    response = service.handle(wire.attlog(SERIAL_LINKED, [wire.punch(601, "2026-08-07 08:06:00")]))
    assert response.status >= 500, "a failed punch insert must not be acknowledged"

    # -- The employee upsert (EmployeeStore.upsert_employees).
    service2, stores2 = fake(settings=settings, devices=[linked_device()])
    _raise_on(stores2["employees"], "upsert_employees", _always)
    response2 = service2.handle(wire.operlog(SERIAL_LINKED, ["USER\tPIN=602\tName=Pham Van E\tPri=0"]))
    assert response2.status >= 500, "a failed employee upsert must not be acknowledged"
