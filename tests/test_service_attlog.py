"""
``AdmsService._attlog`` -- the punch upload, against the in-memory graph.

Six properties live here, all about *ordering* and *counting* rather than about what a line
parses to (that is ``test_attlog.py``, which has no service and no adapters). The design states one
call order for the whole route: rejected-line archive (if any) -> verbatim archive -> parsed
archive -> existing-keys read -> insert -> stamp advance -> enrolment. Every ordering assertion below
walks a recorded call list rather than only the end state, because a later step overwriting an
earlier one's effect would still look correct if only the end state were checked.

Properties 22, 24, 25 and 26 are driven entirely through ``AdmsService.handle`` against the fake
graph (:func:`conftest.build_fake_service`), tracking calls on the in-memory stores it returns.
Property 47 splits: the ordering half ("the stamp moves last") is checked the same way, but the
table-name-safety and length-bound halves ("only ATTLOG/OPERLOG/ATTPHOTO select a column", "bounded
to 32 characters") are checked directly against ``SqlServerDeviceRegistry.advance_stamp`` with a
:class:`~conftest.RecordingDatabase`, because neither guarantee exists in the in-memory fake's
``advance_stamp`` (it maps the same three table names but neither truncates the stamp nor could ever
demonstrate "nothing is interpolated" -- there is no SQL text in it to inspect). That is still no
database, no ODBC driver and no network listener: the recording cursor is exactly what the harness
provides for driving a real adapter with neither.

**Scope note on Property 26's archive half.** Property 26's text also claims the raw-punch archive
(``ADMS_ATTLOG_RAW`` in production) "gains each row at most once and raises no constraint violation
on the retry." That half is a guarantee of ``SqlServerAttendanceStore.archive_attlog``'s
``INSERT ... WHERE NOT EXISTS`` (see ``src/adms/db/attendance.py``); the in-memory
``InMemoryAttendanceStore.archive_attlog`` used by the fake graph has no equivalent guard -- it
extends its list unconditionally on every call, by design of that fake (it exists to expose what was
written, not to reproduce every adapter-level constraint). Task 10.2 runs "against in-memory
adapters" and this file does not touch ``src/``, so that half is left to whatever exercises the real
adapter and is not asserted here; what *is* asserted, and is fully observable through the fake, is the
half that matters device-side -- ``CheckInOut`` idempotence and an unchanged acknowledgement -- plus
the retry never raising.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, cast

import pytest
from conftest import (
    MACHINE_ID,
    SERIAL_LINKED,
    RecordingDatabase,
    linked_device,
    make_settings,
)

from adms.db import ConnectionFactory, SqlServerDeviceRegistry
from adms.protocol import responses

# ── A small call-order recorder for the in-memory stores ───────────────────────────────────────
#
# The fake stores in adms.memory carry no shared order log of their own -- each keeps only its own
# list of what it received. Ordering across stores (archive before insert, insert before stamp) is
# exactly what several properties below are about, so this wraps chosen methods on the stores a test
# cares about and records every call, in invocation order, as "<store>.<method>". The wrapped method
# still does exactly what it always did; this only observes.


class _CallOrder:
    """Records calls to selected methods on selected stores, in the order they happen."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def track(self, stores: dict[str, Any], spec: dict[str, list[str]]) -> None:
        for store_name, methods in spec.items():
            store = stores[store_name]
            for method_name in methods:
                original = getattr(store, method_name)
                label = f"{store_name}.{method_name}"

                def wrapper(*args: Any, _original: Any = original, _label: str = label, **kwargs: Any) -> Any:
                    self.calls.append((_label, args, kwargs))
                    return _original(*args, **kwargs)

                setattr(store, method_name, wrapper)

    @property
    def names(self) -> list[str]:
        return [call[0] for call in self.calls]

    def args_of(self, label: str, occurrence: int = 0) -> tuple[Any, ...]:
        matches = [call[1] for call in self.calls if call[0] == label]
        return matches[occurrence]


#: Every store method any test below needs to observe. Tracked once per fake graph so each test's
#: expectations read as a flat list of labels rather than a maze of per-store assertions.
_TRACKED = {
    "archive": ["archive_request", "archive_unparsed"],
    "attendance": ["archive_attlog", "existing_punch_keys", "add_attendance"],
    "registry": ["advance_stamp"],
    "employees": ["missing_employee_pins"],
    "commands": ["pins_with_recent_request", "enqueue"],
}


def _rows_key(row: dict[str, Any]) -> tuple[int, dt.datetime]:
    return (row["MaChamCong"], row["GioCham"])


# ── Property 22 ──────────────────────────────────────────────────────────────────────────────


def test_property_22_acknowledged_count_is_the_count_sent_clamped_at_zero(fake: Any, wire: Any) -> None:
    # Feature: adms-attendance-system, Property 22: The acknowledged count is the count the
    # device sent, clamped at zero
    """
    For any ATTLOG upload -- a mix of usable and rejected lines, all usable, all rejected, or usable
    lines that duplicate what is already stored -- the response is ``OK: <n>`` where ``n`` is the
    number of lines the Device sent, never the number stored. For all integers, a negative count is
    emitted as ``OK: 0``.

    **Validates: Requirements 5.5, 5.8, 5.9, 11.2, 11.3**
    """
    settings = make_settings(enroll_query_enabled=False)

    # -- Table-driven: sent count is line count, regardless of how many of those lines land in
    #    CheckInOut. --
    cases = [
        (
            "all usable",
            [wire.punch(901, "2026-08-07 08:00:00"), wire.punch(902, "2026-08-07 08:01:00")],
            2,
            2,
        ),
        (
            "usable mixed with one unparseable line",
            [
                wire.punch(903, "2026-08-07 08:02:00"),
                "BADPIN\tnot-a-timestamp",
                wire.punch(904, "2026-08-07 08:03:00"),
            ],
            3,
            2,
        ),
        (
            "every line unusable",
            ["NOFIELDATALL", "PIN=\tTime=2026-08-07 08:04:00"],
            2,
            0,
        ),
    ]
    for case_id, rows, expected_sent, expected_rows in cases:
        service, stores = fake(settings=settings, devices=[linked_device()])
        response = service.handle(wire.attlog(SERIAL_LINKED, rows))
        assert response.status == 200, case_id
        assert response.body == f"OK: {expected_sent}", case_id
        assert len(stores["attendance"].rows) == expected_rows, case_id

    # -- Duplicate suppression must shrink what is stored without shrinking what is acknowledged. --
    service, stores = fake(settings=settings, devices=[linked_device()])
    first = service.handle(wire.attlog(SERIAL_LINKED, [wire.punch(905, "2026-08-07 08:05:00")]))
    assert first.body == "OK: 1"
    second = service.handle(
        wire.attlog(
            SERIAL_LINKED,
            [wire.punch(905, "2026-08-07 08:05:00"), wire.punch(906, "2026-08-07 08:06:00")],
        )
    )
    assert second.body == "OK: 2", "the full count sent must be acknowledged, not the count inserted"
    assert len(stores["attendance"].rows) == 2, "only the genuinely new punch was inserted"

    # -- The Responder's own clamp, independent of any route. --
    assert responses.ok_count(-1).body == "OK: 0"
    assert responses.ok_count(-1000).body == "OK: 0"
    assert responses.ok_count(0).body == "OK: 0"
    assert responses.ok_count(5).body == "OK: 5"


# ── Property 24 ──────────────────────────────────────────────────────────────────────────────


def test_property_24_verbatim_body_is_archived_before_any_interpreted_row_is_written(
    fake: Any, wire: Any
) -> None:
    # Feature: adms-attendance-system, Property 24: The verbatim body is archived before any
    # interpreted row is written
    """
    For any ATTLOG upload, the verbatim-body archive call precedes every parsed-row write, and both
    the verbatim copy and the parsed copy exist afterwards. Checked here as the whole recorded call
    order the design specifies for the route: rejected-line archive (if any) -> verbatim archive ->
    parsed archive -> existing-keys read -> insert -> stamp advance -> enrolment -- because a later
    step is never allowed to precede, let alone undo, an earlier one.

    **Validates: Requirements 5.7, 11.9, 18.13**
    """
    # -- No rejected lines, and the roster already knows the PIN: the chain runs once through
    #    enrolment's own lookup, which finds nothing missing and stops there. --
    settings = make_settings()  # enrolment on -- its default -- so the chain's tail is exercised too
    service, stores = fake(settings=settings, devices=[linked_device()])
    stores["employees"].preexisting.add(910)
    order = _CallOrder()
    order.track(stores, _TRACKED)

    response = service.handle(wire.attlog(SERIAL_LINKED, [wire.punch(910, "2026-08-07 08:10:00")]))

    assert response.status == 200
    assert order.names == [
        "archive.archive_request",
        "attendance.archive_attlog",
        "attendance.existing_punch_keys",
        "attendance.add_attendance",
        "registry.advance_stamp",
        "employees.missing_employee_pins",
    ], "no rejected line, a known PIN: verbatim precedes every parsed write, in the design's order"
    assert len(stores["archive"].requests) == 1, "the verbatim copy exists"
    assert len(stores["attendance"].archived) == 1, "the parsed copy exists"

    # -- A rejected line alongside a usable one from an unknown PIN: the rejected-line archive
    #    (still verbatim, of the unparseable line) leads, and enrolment runs all the way through to
    #    queuing both requests for the one unknown PIN. --
    service2, stores2 = fake(settings=settings, devices=[linked_device()])
    order2 = _CallOrder()
    order2.track(stores2, _TRACKED)

    response2 = service2.handle(
        wire.attlog(
            SERIAL_LINKED,
            ["UNPARSEABLE\tnot-a-timestamp", wire.punch(911, "2026-08-07 08:11:00")],
        )
    )

    assert response2.status == 200
    assert order2.names == [
        "archive.archive_unparsed",
        "archive.archive_request",
        "attendance.archive_attlog",
        "attendance.existing_punch_keys",
        "attendance.add_attendance",
        "registry.advance_stamp",
        "employees.missing_employee_pins",
        "commands.pins_with_recent_request",
        "commands.enqueue",
        "commands.enqueue",
    ], "a rejected line and an unknown PIN: the whole chain, in the design's order, end to end"
    assert len(stores2["archive"].requests) == 1
    assert len(stores2["attendance"].archived) == 1


# ── Property 25 ──────────────────────────────────────────────────────────────────────────────


def test_property_25_lines_that_cannot_be_understood_are_counted_and_kept_never_dropped(
    fake: Any, wire: Any, logs: Any
) -> None:
    # Feature: adms-attendance-system, Property 25: Lines that cannot be understood are counted and
    # kept, never dropped
    """
    For any ATTLOG upload containing lines the parser rejects, every such line is written to the
    unparsed archive verbatim, is included in the acknowledged count, and produces a warning naming
    the count and a sample.

    **Validates: Requirements 5.6, 18.8**
    """
    settings = make_settings(enroll_query_enabled=False)
    cases = [
        (
            "one rejected line among two usable",
            [
                wire.punch(920, "2026-08-07 08:20:00"),
                "BADLINE\tnot-a-timestamp",
                wire.punch(921, "2026-08-07 08:21:00"),
            ],
            ["BADLINE\tnot-a-timestamp"],
            3,
        ),
        (
            "every line unusable",
            ["NOFIELDSATALL", "PIN=\tTime=2026-08-07 08:22:00"],
            ["NOFIELDSATALL", "PIN=\tTime=2026-08-07 08:22:00"],
            2,
        ),
    ]

    for case_id, rows, expected_rejected, expected_sent in cases:
        service, stores = fake(settings=settings, devices=[linked_device()], log=logs.logger)
        response = service.handle(wire.attlog(SERIAL_LINKED, rows))

        assert response.body == f"OK: {expected_sent}", case_id

        archived_lines = [entry[2] for entry in stores["archive"].unparsed if entry[0] == SERIAL_LINKED]
        assert archived_lines == expected_rejected, f"{case_id}: every rejected line kept, verbatim"
        assert all(entry[1] == "ATTLOG" for entry in stores["archive"].unparsed), case_id

        warnings = logs.of_level("WARN")
        matching = [w for w in warnings if w.get("rejected") == len(expected_rejected)]
        assert matching, f"{case_id}: expected a warning naming {len(expected_rejected)} rejected line(s)"
        assert matching[-1]["sample"] == expected_rejected[0][:200], case_id


# ── Property 26 ──────────────────────────────────────────────────────────────────────────────


def test_property_26_attendance_upload_is_idempotent(fake: Any, wire: Any) -> None:
    # Feature: adms-attendance-system, Property 26: Attendance upload is idempotent
    """
    For any ATTLOG body, submitting it twice leaves ``CheckInOut`` with exactly the rows one
    submission leaves and returns the same acknowledgement both times; for any body mixing
    already-stored punches with new ones, exactly the new punches are inserted and the full count
    sent is still acknowledged. See this file's module docstring for why the raw-archive
    natural-key-dedup half of this property is not re-asserted against the in-memory fake.

    **Validates: Requirements 5.11, 5.12, 18.4**
    """
    settings = make_settings(enroll_query_enabled=False)

    # -- The exact same body, twice: same rows, same acknowledgement both times. --
    service, stores = fake(settings=settings, devices=[linked_device()])
    body_rows = [wire.punch(930, "2026-08-07 08:30:00"), wire.punch(931, "2026-08-07 08:31:00")]

    first = service.handle(wire.attlog(SERIAL_LINKED, body_rows))
    rows_after_first = {_rows_key(row) for row in stores["attendance"].rows}

    second = service.handle(wire.attlog(SERIAL_LINKED, body_rows))
    rows_after_second = {_rows_key(row) for row in stores["attendance"].rows}

    assert first.body == second.body == "OK: 2"
    assert rows_after_first == rows_after_second
    assert len(stores["attendance"].rows) == 2, "the retry inserted nothing new"

    # -- A body mixing an already-stored punch with a genuinely new one: only the new one is
    #    inserted, and the full sent count is still acknowledged. --
    service2, stores2 = fake(settings=settings, devices=[linked_device()])
    established = service2.handle(wire.attlog(SERIAL_LINKED, [wire.punch(932, "2026-08-07 08:32:00")]))
    assert established.body == "OK: 1"

    mixed = service2.handle(
        wire.attlog(
            SERIAL_LINKED,
            [wire.punch(932, "2026-08-07 08:32:00"), wire.punch(933, "2026-08-07 08:33:00")],
        )
    )
    assert mixed.body == "OK: 2", "the full sent count, not the count actually inserted"
    assert len(stores2["attendance"].rows) == 2, "the already-stored punch was not duplicated"
    assert {_rows_key(row) for row in stores2["attendance"].rows} == {
        (932, dt.datetime(2026, 8, 7, 8, 32, 0)),
        (933, dt.datetime(2026, 8, 7, 8, 33, 0)),
    }


# ── Property 27 ──────────────────────────────────────────────────────────────────────────────


PROPERTY_27_CASES = [
    pytest.param(
        [(940, "2026-08-07 08:00:00")],
        dt.datetime(2026, 8, 7, 8, 0, 0),
        dt.datetime(2026, 8, 7, 8, 0, 1),
        id="a_single_punch_window_is_one_second_wide",
    ),
    pytest.param(
        [(941, "2026-08-07 08:00:00"), (942, "2026-08-07 08:05:30"), (943, "2026-08-07 08:02:00")],
        dt.datetime(2026, 8, 7, 8, 0, 0),
        dt.datetime(2026, 8, 7, 8, 5, 31),
        id="the_window_spans_only_earliest_to_one_second_past_latest_not_the_whole_day",
    ),
    pytest.param(
        [(944, "2026-08-07 23:59:30"), (945, "2026-08-08 00:00:10")],
        dt.datetime(2026, 8, 7, 23, 59, 30),
        dt.datetime(2026, 8, 8, 0, 0, 11),
        id="a_batch_straddling_midnight_is_still_bounded_by_its_own_span",
    ),
]


@pytest.mark.parametrize(("punches", "expected_from", "expected_to"), PROPERTY_27_CASES)
def test_property_27_duplicate_detection_window_is_derived_from_the_batch(
    fake: Any, wire: Any, punches: list[tuple[int, str]], expected_from: dt.datetime, expected_to: dt.datetime
) -> None:
    # Feature: adms-attendance-system, Property 27: The duplicate-detection window is derived from
    # the batch
    """
    For any non-empty batch of usable punches, the existing-key lookup is asked for exactly the
    interval from the earliest punch to one second after the latest.

    **Validates: Requirement 5.10**
    """
    settings = make_settings(enroll_query_enabled=False)
    service, stores = fake(settings=settings, devices=[linked_device()])
    order = _CallOrder()
    order.track(stores, {"attendance": ["existing_punch_keys"]})

    rows = [wire.punch(pin, ts) for pin, ts in punches]
    response = service.handle(wire.attlog(SERIAL_LINKED, rows))

    assert response.status == 200
    machine_id, from_inclusive, to_exclusive = order.args_of("attendance.existing_punch_keys")
    assert machine_id == MACHINE_ID
    assert from_inclusive == expected_from
    assert to_exclusive == expected_to


# ── Property 47 ──────────────────────────────────────────────────────────────────────────────


def test_property_47_resumption_cursor_moves_last_only_for_known_tables_and_bounded(
    fake: Any, wire: Any
) -> None:
    # Feature: adms-attendance-system, Property 47: The resumption cursor moves last, only for
    # known tables, and bounded
    """
    For any upload, the stamp write occurs after every write it covers has committed. For all
    device-supplied table names, only ``ATTLOG``, ``OPERLOG`` and ``ATTPHOTO`` select a column --
    every other value, including SQL fragments, is ignored rather than interpolated. For all stamp
    values, the stored value is bounded to 32 characters.

    The ordering half runs through the fake graph, tracking the same store methods Property 24 does.
    The table-name-safety and length-bound halves run directly against
    :class:`~adms.db.SqlServerDeviceRegistry.advance_stamp`, the only place either guarantee is
    actually implemented -- the in-memory fake's ``advance_stamp`` selects among the same three table
    names but does not truncate the stamp, and has no SQL text for "never interpolated" to be a claim
    about.

    **Validates: Requirements 11.4, 11.6, 11.7**
    """
    # -- Ordering: the stamp write is not recorded until the insert it covers has happened. --
    settings = make_settings(enroll_query_enabled=False)
    service, stores = fake(settings=settings, devices=[linked_device()])
    order = _CallOrder()
    order.track(stores, {"attendance": ["add_attendance"], "registry": ["advance_stamp"]})

    response = service.handle(wire.attlog(SERIAL_LINKED, [wire.punch(950, "2026-08-07 08:50:00")]))

    assert response.status == 200
    assert order.names == ["attendance.add_attendance", "registry.advance_stamp"], (
        "the stamp must not be recorded until the write it covers has committed"
    )

    # -- Table-name safety: only the three known tables ever select a column, case-insensitively;
    #    every other value, including SQL fragments, produces no statement at all. --
    known_tables = [
        ("ATTLOG", "AttLogStamp"),
        ("OPERLOG", "OperLogStamp"),
        ("ATTPHOTO", "AttPhotoStamp"),
        ("attlog", "AttLogStamp"),
        ("OperLog", "OperLogStamp"),
    ]
    for table, column in known_tables:
        db = RecordingDatabase()
        registry = SqlServerDeviceRegistry(cast(ConnectionFactory, db))
        registry.advance_stamp("SERIALX", table, "999")
        assert len(db.calls) == 1, f"table={table!r} must select exactly one column"
        assert column in db.calls[0].sql, f"table={table!r} must select {column}"
        assert db.calls[0].params == ("999", "SERIALX"), "the stamp and serial are bound, not formatted"
        assert db.commits == 1

    hostile_tables = [
        "UNKNOWN",
        "",
        "ATTLOG; DROP TABLE dbo.ADMS_DEVICE;--",
        "ATTLOG' OR '1'='1",
        "OPERLOG\"; DELETE FROM dbo.ADMS_DEVICE --",
        "attlogX",
        " ATTLOG",
    ]
    for table in hostile_tables:
        db = RecordingDatabase()
        registry = SqlServerDeviceRegistry(cast(ConnectionFactory, db))
        registry.advance_stamp("SERIALX", table, "999")
        assert db.calls == [], f"table={table!r} must select nothing and interpolate nothing"
        assert db.commits == 0

    # -- Bound: a stamp over 32 characters is truncated before it is bound. --
    db = RecordingDatabase()
    registry = SqlServerDeviceRegistry(cast(ConnectionFactory, db))
    long_stamp = "X" * 50
    registry.advance_stamp("SERIALX", "ATTLOG", long_stamp)
    assert db.calls[0].params[0] == long_stamp[:32]
    assert len(db.calls[0].params[0]) == 32
