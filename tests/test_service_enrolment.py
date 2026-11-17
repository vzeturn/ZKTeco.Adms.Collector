"""
``AdmsService._request_missing_employees`` -- the auto-enrolment loop -- and the two rendering
helpers it calls through, against the in-memory graph.

Four properties live here. Three (53, 54, 56) are about ``_request_missing_employees`` itself,
driven end to end through ``AdmsService.handle`` against :func:`conftest.build_fake`, exactly the
way ``test_service_attlog.py`` drives the rest of the ``ATTLOG`` route. The fourth (55) is about
the pure rendering helpers in :mod:`adms.protocol.commands` -- ``query_user_info`` and
``query_fingerprints`` -- which take no adapter at all, so that half is called directly; a second
half confirms the override set on ``Settings`` (task 3.1's wiring) actually reaches the queued
command body through the service.

**Scope note, matching this file's siblings.** Design Property 53's text also claims the
missing-PIN lookup makes "at most ``ceil(n / 1000)``" round trips for a large batch. That is a
guarantee of the SQL employee store's chunked query (``SqlServerEmployeeStore.missing_employee_pins``);
``InMemoryEmployeeStore`` -- what every fixture here is built on -- does no chunking of any kind, so
there is nothing in this file for that half to be a claim about. It belongs to
``tests/test_adapters_sql.py`` (task 11.1) instead. The half of Property 53 that *is* fully
observable through the fake -- no round trip at all for an empty PIN set -- is asserted below,
against an employee store that explodes on any call.

Property 54's digit-boundary claim is implemented once, in ``InMemoryCommandQueue.pins_with_recent_
request`` (mirrored by the SQL adapter's own regex, out of scope here). It is tested both directly
against that method -- the cheapest way to cover the adversarial PIN pairs a batch could ever
contain -- and end to end through the service, so the claim is verified both as a unit of logic and
as an effect a device would actually observe.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from conftest import (
    SERIAL_LINKED,
    ExplodingAdapter,
    linked_device,
    make_settings,
)

from adms.memory import (
    FixedClock,
    InMemoryAttendanceStore,
    InMemoryCommandQueue,
    InMemoryDeviceRegistry,
    InMemoryPushArchive,
    InMemoryTemplateStore,
)
from adms.protocol.commands import (
    DEFAULT_QUERY_FINGERTMP,
    DEFAULT_QUERY_USERINFO,
    query_fingerprints,
    query_user_info,
)
from adms.service import AdmsService

# ── A hybrid graph: everything real except an exploding employee store ──────────────────────────


def _service_with_exploding_employees(
    devices: list[Any], *, settings: Any = None, log: Any = None
) -> tuple[AdmsService, dict[str, Any]]:
    """
    A service whose employee store raises on any call, and whose every other port is the
    ordinary in-memory fake.

    Needed by Property 53's empty-set half: asserting "no round trip happened" against a
    permissive fake would prove nothing, because a permissive ``missing_employee_pins()`` call
    would succeed silently either way.
    """
    resolved = settings or make_settings()
    registry = InMemoryDeviceRegistry(devices)
    employees = ExplodingAdapter("employees")
    service = AdmsService(
        registry=registry,
        attendance=InMemoryAttendanceStore(),
        employees=employees,
        templates=InMemoryTemplateStore(),
        commands=InMemoryCommandQueue(),
        archive=InMemoryPushArchive(),
        clock=FixedClock(utc_offset_hours=resolved.utc_offset_hours),
        settings=resolved,
        log=log,
    )
    return service, {"registry": registry, "employees": employees}


# ── Property 53 ──────────────────────────────────────────────────────────────────────────────


def test_property_53_auto_enrolment_asks_about_exactly_the_unknown_pins_once_per_cooldown_within_a_cap(
    fake: Any, wire: Any, logs: Any
) -> None:
    # Feature: adms-attendance-system, Property 53: Auto-enrolment asks about exactly the unknown
    # PINs, once per cooldown, within a cap
    """
    For any ATTLOG batch and any roster state, with enrolment enabled: every PIN with no employee
    row and no request inside the cooldown is asked about -- one user-record command, plus one
    fingerprint command when that option is on -- no PIN with an employee row is asked about, at
    most the configured number of PINs is asked about per batch with the deferred count logged, a
    PIN inside the cooldown produces no further command however many times it punches, and every
    punch is stored and acknowledged regardless. The missing-PIN lookup makes no round trip for an
    empty set. With enrolment disabled, no command is queued and every punch is still stored and
    acknowledged.

    **Validates: Requirements 20.1, 20.2, 20.3, 20.5, 20.6, 20.8, 20.9, 20.10, 20.12**
    """

    # -- No PIN with an employee row is asked about; every unknown PIN gets exactly one
    #    user-record command plus one fingerprint command, since both options are on by default.
    settings = make_settings()
    service, stores = fake(settings=settings, devices=[linked_device()])
    stores["employees"].preexisting.add(401)  # already known -- must never be asked about

    response = service.handle(
        wire.attlog(
            SERIAL_LINKED,
            [
                wire.punch(401, "2026-08-07 09:00:00"),
                wire.punch(402, "2026-08-07 09:01:00"),
                wire.punch(403, "2026-08-07 09:02:00"),
            ],
        )
    )

    assert response.status == 200
    assert response.body == "OK: 3", "every punch is acknowledged, known or not"
    assert len(stores["attendance"].rows) == 3, "every punch is stored, known or not"

    pending = stores["commands"].pending.get(SERIAL_LINKED, [])
    bodies = [c.body for c in pending]
    assert "DATA QUERY USERINFO PIN=401" not in bodies, "a known PIN must never be asked about"
    assert "DATA QUERY FINGERTMP PIN=401" not in bodies, "a known PIN must never be asked about"
    assert bodies.count("DATA QUERY USERINFO PIN=402") == 1
    assert bodies.count("DATA QUERY FINGERTMP PIN=402") == 1
    assert bodies.count("DATA QUERY USERINFO PIN=403") == 1
    assert bodies.count("DATA QUERY FINGERTMP PIN=403") == 1
    assert len(pending) == 4, "exactly two commands per unknown PIN, none for the known one"

    # -- Fingerprints off: one command per unknown PIN, never two.
    settings_no_fp = make_settings(enroll_query_include_fingerprints=False)
    service_no_fp, stores_no_fp = fake(settings=settings_no_fp, devices=[linked_device()])
    service_no_fp.handle(wire.attlog(SERIAL_LINKED, [wire.punch(404, "2026-08-07 09:04:00")]))
    pending_no_fp = stores_no_fp["commands"].pending.get(SERIAL_LINKED, [])
    assert [c.body for c in pending_no_fp] == ["DATA QUERY USERINFO PIN=404"]

    # -- The cap: at most the configured number of PINs is asked about per batch, the lowest
    #    PINs first, and the deferred count is logged.
    settings_capped = make_settings(
        enroll_query_max_per_batch=2, enroll_query_include_fingerprints=False
    )
    service_capped, stores_capped = fake(
        settings=settings_capped, devices=[linked_device()], log=logs.logger
    )
    unknown_pins = [501, 502, 503, 504, 505]
    rows = [wire.punch(p, f"2026-08-07 09:{p - 500:02d}:00") for p in unknown_pins]
    capped_response = service_capped.handle(wire.attlog(SERIAL_LINKED, rows))

    assert capped_response.status == 200
    assert capped_response.body == "OK: 5", "the count sent, not the count asked about"
    pending_capped = stores_capped["commands"].pending.get(SERIAL_LINKED, [])
    asked_pins = sorted(int(c.body.rsplit("=", 1)[1]) for c in pending_capped)
    assert asked_pins == [501, 502], "at most the configured cap, the lowest PINs first"
    queued_logs = [
        r for r in logs.of_level("INFO") if "Queued enrolment requests" in r.get("msg", "")
    ]
    assert queued_logs, "expected a log line naming the queued PINs and the deferred count"
    assert queued_logs[-1]["deferred"] == 3, "the three PINs left over must be logged as deferred"

    # -- A PIN inside the cooldown produces no further command however many times it punches;
    #    the punch is still stored and acknowledged every time.
    settings_cooldown = make_settings(enroll_query_include_fingerprints=False)
    service_cd, stores_cd = fake(settings=settings_cooldown, devices=[linked_device()])
    for minute in range(4):
        cooldown_response = service_cd.handle(
            wire.attlog(SERIAL_LINKED, [wire.punch(601, f"2026-08-07 10:0{minute}:00")])
        )
        assert cooldown_response.status == 200
        assert cooldown_response.body == "OK: 1"
    assert len(stores_cd["attendance"].rows) == 4, "every punch from the unknown PIN is stored"
    pending_cd = stores_cd["commands"].pending.get(SERIAL_LINKED, [])
    assert [c.body for c in pending_cd] == ["DATA QUERY USERINFO PIN=601"], (
        "only the first punch triggered a request; the cooldown suppressed the other three"
    )

    # -- Enrolment disabled: no command is queued at all, and every punch is still stored and
    #    acknowledged.
    settings_off = make_settings(enroll_query_enabled=False)
    service_off, stores_off = fake(settings=settings_off, devices=[linked_device()])
    off_response = service_off.handle(
        wire.attlog(
            SERIAL_LINKED,
            [wire.punch(701, "2026-08-07 11:00:00"), wire.punch(702, "2026-08-07 11:01:00")],
        )
    )
    assert off_response.status == 200
    assert off_response.body == "OK: 2"
    assert len(stores_off["attendance"].rows) == 2
    assert stores_off["commands"].pending == {}, "enrolment disabled must queue nothing"

    # -- The missing-PIN lookup makes no round trip for an empty set: a batch with no numeric
    #    PIN at all must never call employees.missing_employee_pins.
    service_no_pin, stores_no_pin = _service_with_exploding_employees([linked_device()])
    no_pin_response = service_no_pin.handle(
        wire.attlog(SERIAL_LINKED, ["ALPHA123\t2026-08-07 12:00:00"])
    )
    assert no_pin_response.status == 200
    assert no_pin_response.body == "OK: 1"
    assert stores_no_pin["employees"].calls == [], (
        "no numeric PIN in the batch; missing_employee_pins must not be called"
    )


# ── Property 54 ──────────────────────────────────────────────────────────────────────────────

#: (existing command body, PINs being asked about, expected hit set). Each case pairs PINs where
#: one is a textual prefix of the other, so a substring match would wrongly suppress the longer
#: (or the shorter) one.
_DIGIT_BOUNDARY_CASES: list[tuple[str, set[int], set[int]]] = [
    ("DATA QUERY USERINFO PIN=12", {12, 123}, {12}),
    ("DATA QUERY USERINFO PIN=123", {12, 123}, {123}),
    ("DATA QUERY USERINFO PIN=1", {1, 11, 100, 21}, {1}),
    ("DATA QUERY USERINFO PIN=100", {1, 10, 100, 1000}, {100}),
    ("DATA QUERY FINGERTMP PIN=5", {5, 50, 500, 55}, {5}),
    ("DATA QUERY USERINFO PIN=12 DATA QUERY USERINFO PIN=123", {12, 123}, {12, 123}),
]


def test_property_54_the_cooldown_matches_a_pin_only_at_a_digit_boundary(
    fake: Any, wire: Any
) -> None:
    # Feature: adms-attendance-system, Property 54: The cooldown matches a PIN only at a digit
    # boundary
    """
    For all pairs of distinct PINs where one is a prefix of the other, a recent request for one
    does not suppress a request for the other -- ``PIN=12`` never matches ``PIN=123``, in either
    direction.

    **Validates: Requirement 20.7**
    """
    now = dt.datetime(2026, 1, 1, 0, 0, 0)
    since = now - dt.timedelta(hours=1)

    for body, pins, expected in _DIGIT_BOUNDARY_CASES:
        queue = InMemoryCommandQueue(now=now)
        queue.history.append((SERIAL_LINKED, 1, body, now))
        hit = queue.pins_with_recent_request(SERIAL_LINKED, pins, since)
        assert hit == expected, f"body={body!r} pins={pins}"

    # -- End to end: whichever of a prefix pair is asked about first, the other is never
    #    suppressed by it.
    for first_pin, second_pin in [(123, 12), (12, 123)]:
        settings = make_settings(enroll_query_include_fingerprints=False)
        service, stores = fake(settings=settings, devices=[linked_device()])

        service.handle(wire.attlog(SERIAL_LINKED, [wire.punch(first_pin, "2026-08-07 15:00:00")]))
        after_first = [c.body for c in stores["commands"].pending.get(SERIAL_LINKED, [])]
        assert after_first == [f"DATA QUERY USERINFO PIN={first_pin}"], (first_pin, second_pin)

        service.handle(wire.attlog(SERIAL_LINKED, [wire.punch(second_pin, "2026-08-07 15:01:00")]))
        after_second = [c.body for c in stores["commands"].pending.get(SERIAL_LINKED, [])]
        assert after_second == [
            f"DATA QUERY USERINFO PIN={first_pin}",
            f"DATA QUERY USERINFO PIN={second_pin}",
        ], f"first={first_pin} second={second_pin}: the digit-adjacent PIN must not be suppressed"


# ── Property 55 ──────────────────────────────────────────────────────────────────────────────

#: Both rendering functions share the same contract; each is paired with its own default so the
#: "blank falls back to the documented default" case can compute its own expectation.
_QUERY_FUNCS: list[tuple[Any, str]] = [
    (query_user_info, DEFAULT_QUERY_USERINFO),
    (query_fingerprints, DEFAULT_QUERY_FINGERTMP),
]

#: (case id, override template, expected rendered body for pin "789").
_RENDER_CASES: list[tuple[str, str, str]] = [
    (
        "a placeholder anywhere in the template is substituted",
        "GET USER {pin} DETAILS",
        "GET USER 789 DETAILS",
    ),
    ("every occurrence of the placeholder is substituted", "A={pin} B={pin}", "A=789 B=789"),
    ("no placeholder at all: PIN=<pin> is appended", "DATA QUERY USER", "DATA QUERY USER PIN=789"),
    (
        "a stray unmatched brace with no placeholder does not raise, and still appends",
        "DATA QUERY {typo",
        "DATA QUERY {typo PIN=789",
    ),
    (
        "a stray unmatched brace alongside a real placeholder does not raise",
        "LOOKUP {pin} extra {typo",
        "LOOKUP 789 extra {typo",
    ),
    (
        "leading and trailing whitespace around the template is trimmed",
        "  DATA QUERY USER {pin}  ",
        "DATA QUERY USER 789",
    ),
]


def test_property_55_the_enrolment_command_wording_is_configurable(fake: Any, wire: Any) -> None:
    # Feature: adms-attendance-system, Property 55: The enrolment command wording is configurable
    """
    For any override string, the queued command body is that string with ``{pin}`` replaced by
    the PIN, or that string with `` PIN=<pin>`` appended when it carries no placeholder; for all
    blank overrides, the documented default wording is used; and for all override strings,
    including ones containing stray braces, rendering raises nothing. Checked against both
    ``query_user_info`` and ``query_fingerprints``, since both share the rendering rule, and
    against the whole service path with ``Settings.query_userinfo_command`` /
    ``query_fingertmp_command`` (task 3.1's wiring), to confirm an override actually reaches the
    queued body.

    **Validates: Requirement 20.15**
    """
    pin = "789"

    for fn, default_template in _QUERY_FUNCS:
        for case_id, override, expected in _RENDER_CASES:
            rendered = fn(pin, override)  # must never raise
            assert rendered == expected, f"{fn.__name__}: {case_id}"

        # -- Blank falls back to the documented default for this function.
        blank_rendered = fn(pin, "")
        assert blank_rendered == default_template.replace("{pin}", pin), (
            f"{fn.__name__}: a blank override must fall back to the documented default"
        )

    # -- The override reaches the queued body end to end, through Settings and the service.
    settings = make_settings(
        query_userinfo_command="CUSTOM USERINFO {pin}",
        query_fingertmp_command="CUSTOM FINGERTMP",  # no placeholder -- PIN=<pin> is appended
    )
    service, stores = fake(settings=settings, devices=[linked_device()])
    service.handle(wire.attlog(SERIAL_LINKED, [wire.punch(801, "2026-08-07 13:00:00")]))
    bodies = [c.body for c in stores["commands"].pending.get(SERIAL_LINKED, [])]
    assert "CUSTOM USERINFO 801" in bodies
    assert "CUSTOM FINGERTMP PIN=801" in bodies

    # -- A blank override -- Settings' own default -- falls back to the documented default,
    #    reached the same way.
    default_service, default_stores = fake(settings=make_settings(), devices=[linked_device()])
    default_service.handle(wire.attlog(SERIAL_LINKED, [wire.punch(802, "2026-08-07 13:01:00")]))
    default_bodies = [c.body for c in default_stores["commands"].pending.get(SERIAL_LINKED, [])]
    assert "DATA QUERY USERINFO PIN=802" in default_bodies
    assert "DATA QUERY FINGERTMP PIN=802" in default_bodies


# ── Property 56 ──────────────────────────────────────────────────────────────────────────────


def test_property_56_enrolment_closes_the_loop(fake: Any, wire: Any) -> None:
    # Feature: adms-attendance-system, Property 56: Enrolment closes the loop
    """
    For any device answer on the query-result route carrying a user record and templates for a
    previously unknown PIN, that PIN afterwards has an employee row and its templates stored, and
    a subsequent punch from that PIN queues no further request.

    **Validates: Requirement 20.11**
    """
    settings = make_settings(enroll_query_include_fingerprints=True)
    service, stores = fake(settings=settings, devices=[linked_device()])

    # -- An unknown PIN punches: no employee row yet, and a request is queued.
    first = service.handle(wire.attlog(SERIAL_LINKED, [wire.punch(901, "2026-08-07 14:00:00")]))
    assert first.status == 200
    assert first.body == "OK: 1"
    assert 901 not in stores["employees"].employees, "the PIN has no employee row yet"
    pending_after_first_punch = [c.body for c in stores["commands"].pending.get(SERIAL_LINKED, [])]
    assert pending_after_first_punch == [
        "DATA QUERY USERINFO PIN=901",
        "DATA QUERY FINGERTMP PIN=901",
    ]

    # -- The device answers the query on the query-result route, carrying both a user record and
    #    a fingerprint template for the previously unknown PIN.
    answer = service.handle(
        wire.querydata(
            SERIAL_LINKED,
            [
                "USER\tPIN=901\tName=Pham Van C\tPri=0\tCard=901\tEnable=1",
                "FP\tPIN=901\tFID=0\tSize=4\tValid=1\tTMP=b25l",
            ],
            query_type="userinfo_and_fp",
        )
    )
    assert answer.status == 200

    # -- The PIN now has an employee row and stored templates.
    assert 901 in stores["employees"].employees
    assert stores["employees"].employees[901].name == "Pham Van C"
    assert stores["templates"].fingers.get(901), "the fingerprint template must be stored"
    assert stores["templates"].fingers[901][0].template == "b25l"
    assert stores["employees"].missing_employee_pins({901}) == set(), "no longer missing"

    # -- A subsequent punch from that PIN queues no further request: the roster now knows it.
    second = service.handle(wire.attlog(SERIAL_LINKED, [wire.punch(901, "2026-08-07 14:05:00")]))
    assert second.status == 200
    assert second.body == "OK: 1"
    pending_after_second_punch = [
        c.body for c in stores["commands"].pending.get(SERIAL_LINKED, [])
    ]
    assert pending_after_second_punch == pending_after_first_punch, (
        "no new command was queued -- the enrolment loop is closed"
    )
