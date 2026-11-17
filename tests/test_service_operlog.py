"""
``AdmsService``'s roster and biometric upload path -- ``_operlog``, ``_query_data``, the photo
and file routes, and the unsupported-table fallback -- against the in-memory graph.

Five properties live here, all about what happens to a payload this service either cannot fully
use (an unparseable line, an unsupported table, a binary file) or has *two* ways of receiving (a
spontaneous ``OPERLOG`` upload versus a solicited ``querydata`` answer). Every test drives
``AdmsService.handle`` end to end; where a claim is specifically about "no adapter was touched",
the service is built with the legacy-schema adapters (``attendance``, ``employees``, ``templates``)
replaced by :class:`~conftest.ExplodingAdapter`, exactly as ``test_service_authz.py`` does for the
authorisation matrix -- a permissive fake would let a call that should never happen succeed
silently instead of naming itself.

**Property 46 is where task 4.1's fix gets its permanent regression test.** Before that task,
``_query_data`` called ``_persist_operlog`` *before* ``_archive_request`` -- the reverse of
``_operlog``'s own order, and the reverse of what Requirement 11.9 demands unconditionally. This
file asserts the recorded call order on the ``querydata`` route directly, tracking
``archive.archive_request`` and ``employees.upsert_employees`` the same way
``test_service_attlog.py`` tracks the ``ATTLOG`` route's order. The assertion is written to name
exactly what the pre-fix code would have produced, so a regression here fails loudly rather than
as a bare inequality.

Two scope notes, matching this file's siblings:

* **Property 36's "no delete is issued" half** cannot be exercised through the service at all.
  ``parse_operlog`` already filters every ``FP``/``FACE``/``BIODATA`` line with an empty template
  to ``unparsed`` before a :class:`~adms.models.FingerTemplate` or
  :class:`~adms.models.FaceTemplate` object is ever constructed (see ``test_operlog.py``'s
  Requirement-7.4 coverage), so no batch of only-empty templates can reach
  ``TemplateStore.save_fingerprints``/``save_faces`` by any route this service exposes. The
  guard the design describes ("dropped *before* the delete runs, as a second line of defence") is
  therefore exercised directly against :class:`~adms.memory.InMemoryTemplateStore`, bypassing the
  parser on purpose -- which is exactly what a *second* line of defence means.
* **Property 39's one-transaction half** is a guarantee of the real SQL adapter's transaction
  (``SqlServerTemplateStore.save_fingerprints``); the in-memory fake this task runs against has no
  partial-failure state for a transaction to roll back from. That half belongs to
  ``tests/test_adapters_sql.py`` (task 11.1) instead.
"""

from __future__ import annotations

from typing import Any

from conftest import (
    SERIAL_LINKED,
    ExplodingAdapter,
    linked_device,
    make_settings,
)

from adms.memory import (
    FixedClock,
    InMemoryCommandQueue,
    InMemoryDeviceRegistry,
    InMemoryPushArchive,
    InMemoryTemplateStore,
)
from adms.models import FaceTemplate, FingerTemplate
from adms.service import AdmsService

# ── A hybrid graph: registry/archive/commands real, every legacy-schema adapter exploding ──────


def _hybrid_no_legacy_writes(
    devices: list[Any], *, log: Any = None
) -> tuple[AdmsService, dict[str, Any]]:
    """
    A service whose registry, archive and command queue are the ordinary in-memory fakes, but
    whose every legacy-schema adapter -- attendance, employees, templates -- explodes on the
    first call.

    Needed by Properties 36 and 41, both of which claim a call was never made against
    ``NHANVIEN``/``CheckInOut``/``dbo.TEMPLATE``/``dbo.Face``. A permissive fake would let such a
    call succeed silently; this one names it, the same way ``test_service_authz.py``'s
    ``_hybrid_service`` does for the authorisation matrix.
    """
    settings = make_settings()
    exploding = {
        name: ExplodingAdapter(name) for name in ("attendance", "employees", "templates")
    }
    registry = InMemoryDeviceRegistry(devices)
    archive = InMemoryPushArchive()
    commands = InMemoryCommandQueue()
    service = AdmsService(
        registry=registry,
        attendance=exploding["attendance"],
        employees=exploding["employees"],
        templates=exploding["templates"],
        commands=commands,
        archive=archive,
        clock=FixedClock(utc_offset_hours=settings.utc_offset_hours),
        settings=settings,
        log=log,
    )
    stores: dict[str, Any] = {**exploding, "registry": registry, "archive": archive, "commands": commands}
    return service, stores


def _assert_no_legacy_adapter_touched(stores: dict[str, Any], *, label: str) -> None:
    for name in ("attendance", "employees", "templates"):
        store = stores[name]
        assert store.calls == [], f"{label}: {name} was touched: {store.calls}"


# ── A small call-order recorder, matching test_service_attlog.py's own ──────────────────────────


class _CallOrder:
    """Records calls to selected methods on selected stores, in the order they happen."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def track(self, stores: dict[str, Any], spec: dict[str, list[str]]) -> None:
        for store_name, methods in spec.items():
            store = stores[store_name]
            for method_name in methods:
                original = getattr(store, method_name)
                label = f"{store_name}.{method_name}"

                def wrapper(*args: Any, _original: Any = original, _label: str = label, **kwargs: Any) -> Any:
                    self.calls.append(_label)
                    return _original(*args, **kwargs)

                setattr(store, method_name, wrapper)

    @property
    def names(self) -> list[str]:
        return self.calls


# ── Property 36 ──────────────────────────────────────────────────────────────────────────────

#: Every line the design says must overwrite nothing: a USER line with no PIN, and FP/FACE/BIODATA
#: lines each missing a PIN or carrying no template. The parser already returns each of these as
#: unparsed (see test_operlog.py's Requirement-7.4 coverage); the claim tested here is that the
#: filtering is honoured all the way to the store boundary -- neither employees nor templates is
#: ever called for a batch made entirely of these.
_NO_STORE_OPERLOG_LINES: list[tuple[str, str]] = [
    ("USER\tName=No Pin At All\tPri=0", "user line with no PIN"),
    ("FP\tPIN=701\tFID=0\tSize=512\tValid=1", "fp line with a PIN but no template"),
    ("FP\tPIN=\tFID=0\tTMP=Zmlu", "fp line with an empty PIN"),
    ("FACE\tPIN=702\tFID=0\tSIZE=1024\tVALID=1", "face line with a PIN but no template"),
    ("FACE\tPIN=\tFID=0\tTMP=ZmFjZQ==", "face line with an empty PIN"),
    (
        "BIODATA\tPin=703\tNo=1\tIndex=0\tValid=1\tDuress=0\tType=1",
        "biodata line with a PIN but no template",
    ),
    ("BIODATA\tPin=\tNo=1\tType=1\tTmp=Ymlv", "biodata line with an empty PIN"),
]


def test_property_36_no_record_ever_overwrites_stored_data_with_nothing(wire: Any) -> None:
    # Feature: adms-attendance-system, Property 36: No record ever overwrites stored data with
    # nothing
    """
    For all USER lines with no PIN and for all FP, FACE and BIODATA lines with no PIN or an empty
    template, the line is returned as unparsed and no store call is made; and for any template
    batch whose payloads are all empty, no delete is issued at all, so a user's stored biometrics
    survive.

    **Validates: Requirements 7.4, 16.5**
    """
    for line, case_id in _NO_STORE_OPERLOG_LINES:
        service, stores = _hybrid_no_legacy_writes([linked_device()])

        response = service.handle(wire.operlog(SERIAL_LINKED, [line]))

        assert response.status == 200, case_id
        assert response.body == "OK: 1", f"{case_id}: the unparsed line is still counted"
        _assert_no_legacy_adapter_touched(stores, label=case_id)
        assert stores["archive"].unparsed == [(SERIAL_LINKED, "OPERLOG", line)], case_id

    # -- The store's own defence, exercised directly because the parser never lets a batch of
    # only-empty templates reach it: an empty-payload batch issues no delete at all, and every PIN
    # already stored survives untouched.
    store = InMemoryTemplateStore()
    existing_finger = [FingerTemplate(pin="810", finger_id=0, template="Zmlu==", size=6, valid=1)]
    store.fingers[810] = existing_finger
    written = store.save_fingerprints(
        [FingerTemplate(pin="810", finger_id=1, template="", size=0, valid=1)]
    )
    assert written == 0, "an empty-payload batch inserts nothing"
    assert store.fingers[810] == existing_finger, "a user's stored fingerprints must survive"

    existing_face = [FaceTemplate(pin="811", face_id=0, template="ZmFjZQ==", size=8, valid=1)]
    store.faces[811] = existing_face
    written_faces = store.save_faces([FaceTemplate(pin="811", face_id=1, template="", size=0, valid=1)])
    assert written_faces == 0, "an empty-payload batch inserts nothing"
    assert store.faces[811] == existing_face, "a user's stored face template must survive"


# ── Property 38 ──────────────────────────────────────────────────────────────────────────────


def test_property_38_unified_biometric_envelope_produces_the_same_rows_as_the_separate_ones(
    fake: Any, wire: Any, logs: Any
) -> None:
    # Feature: adms-attendance-system, Property 38: The unified biometric envelope produces the
    # same rows as the separate ones
    """
    For any set of templates, a body expressing them as BIODATA with type 1 and type 2 produces
    exactly the stored fingerprint and face rows that the equivalent FP and FACE body produces;
    and for all other BIODATA types, the record is counted, archived and logged, and no template
    is stored.

    **Validates: Requirements 7.8, 7.9**
    """
    settings = make_settings()

    # -- The unified envelope: BIODATA type 1 (fingerprint) and type 2 (face) for one PIN. --
    biodata_service, biodata_stores = fake(settings=settings, devices=[linked_device()])
    biodata_response = biodata_service.handle(
        wire.operlog(
            SERIAL_LINKED,
            [
                "BIODATA\tPin=901\tNo=0\tIndex=0\tValid=1\tDuress=0\tType=1\tTmp=Zmlu",
                "BIODATA\tPin=901\tNo=0\tIndex=0\tValid=1\tDuress=0\tType=2\tTmp=ZmFjZQ==",
            ],
        )
    )

    # -- The equivalent separate envelope: one FP line, one FACE line, same PIN, same payloads,
    # same reported sizes as BIODATA.as_finger()/as_face() derive (len(template)). --
    separate_service, separate_stores = fake(settings=settings, devices=[linked_device()])
    separate_response = separate_service.handle(
        wire.operlog(
            SERIAL_LINKED,
            [
                "FP\tPIN=901\tFID=0\tSize=4\tValid=1\tTMP=Zmlu",
                "FACE\tPIN=901\tFID=0\tSIZE=8\tVALID=1\tTMP=ZmFjZQ==",
            ],
        )
    )

    assert biodata_response.status == separate_response.status == 200
    assert biodata_stores["templates"].fingers == separate_stores["templates"].fingers
    assert biodata_stores["templates"].faces == separate_stores["templates"].faces
    assert biodata_stores["templates"].fingers[901][0].template == "Zmlu"
    assert biodata_stores["templates"].faces[901][0].template == "ZmFjZQ=="

    # -- Any other BIODATA type: counted (still in the Ok_Count), archived as part of the
    # verbatim body, logged, and stores no template. Type 7 (palm) has no ATTENDANCEDB column.
    unsupported_service, unsupported_stores = fake(
        settings=settings, devices=[linked_device()], log=logs.logger
    )
    unsupported_response = unsupported_service.handle(
        wire.operlog(
            SERIAL_LINKED,
            ["BIODATA\tPin=902\tNo=0\tIndex=0\tValid=1\tDuress=0\tType=7\tTmp=cGFsbQ=="],
        )
    )

    assert unsupported_response.status == 200
    assert unsupported_response.body == "OK: 1", "the record is still counted"
    assert 902 not in unsupported_stores["templates"].fingers
    assert 902 not in unsupported_stores["templates"].faces
    archived_bodies = [
        r["body"] for r in unsupported_stores["archive"].requests if r["serial"] == SERIAL_LINKED
    ]
    assert any("Type=7" in body for body in archived_bodies), "the verbatim body is archived"
    info_logs = logs.of_level("INFO")
    assert any(
        "no ATTENDANCEDB column" in rec.get("msg", "") and rec.get("count") == 1 for rec in info_logs
    ), "an unsupported BIODATA type must be logged"


# ── Property 39 ──────────────────────────────────────────────────────────────────────────────


def test_property_39_template_replacement_is_exactly_scoped_and_payloads_are_stored_verbatim(
    fake: Any, wire: Any
) -> None:
    # Feature: adms-attendance-system, Property 39: Template replacement is exactly scoped, and
    # payloads are stored verbatim
    """
    For any template batch, every PIN mentioned ends with exactly the uploaded rows for that PIN,
    every PIN not mentioned is byte-identical afterwards, no unscoped delete is ever issued, and
    every stored template equals the base64 text the device sent including its padding.

    The one-transaction half is a guarantee of the real SQL adapter's transaction; see this file's
    module docstring for why it is not re-asserted against the in-memory fake.

    **Validates: Requirements 16.1, 16.2, 16.3, 16.4**
    """
    settings = make_settings()
    service, stores = fake(settings=settings, devices=[linked_device()])

    # -- Establish three PINs with existing rows: two fingerprints and one face, none of them the
    # PIN the second batch will touch except PIN 811.
    seed_response = service.handle(
        wire.operlog(
            SERIAL_LINKED,
            [
                "FP\tPIN=811\tFID=0\tSize=4\tValid=1\tTMP=b25l",
                "FP\tPIN=812\tFID=0\tSize=4\tValid=1\tTMP=dHdv",
                "FP\tPIN=813\tFID=0\tSize=5\tValid=1\tTMP=dGhyZWU=",
                "FACE\tPIN=812\tFID=0\tSIZE=8\tVALID=1\tTMP=ZmFjZQ==",
            ],
        )
    )
    assert seed_response.status == 200
    untouched_812_fingers = list(stores["templates"].fingers[812])
    untouched_812_faces = list(stores["templates"].faces[812])
    untouched_813_fingers = list(stores["templates"].fingers[813])

    # -- A second batch replaces PIN 811's fingers with two (a device re-enrolling both fingers at
    # once) and mentions nobody else.
    replacement_response = service.handle(
        wire.operlog(
            SERIAL_LINKED,
            [
                "FP\tPIN=811\tFID=0\tSize=8\tValid=1\tTMP=cmVwbGFjZTE=",
                "FP\tPIN=811\tFID=1\tSize=8\tValid=1\tTMP=cmVwbGFjZTI=",
            ],
        )
    )
    assert replacement_response.status == 200

    stored_811 = stores["templates"].fingers[811]
    assert len(stored_811) == 2, "PIN 811 ends with exactly the uploaded rows, not merged with the old one"
    assert {t.finger_id for t in stored_811} == {0, 1}
    assert {t.template for t in stored_811} == {"cmVwbGFjZTE=", "cmVwbGFjZTI="}, "verbatim, padding included"

    # -- Every PIN not mentioned in the second batch is byte-identical afterwards: no unscoped
    # delete touched them.
    assert stores["templates"].fingers[812] == untouched_812_fingers, "PIN 812's fingers were not mentioned"
    assert stores["templates"].faces[812] == untouched_812_faces, "PIN 812's face was not mentioned"
    assert stores["templates"].fingers[813] == untouched_813_fingers, "PIN 813 was not mentioned at all"


# ── Property 41 ──────────────────────────────────────────────────────────────────────────────

#: Table names this version does not support -- deliberately excluding any case-variant of a
#: table the service *does* recognise (table matching upper-cases the value first, so "attlog"
#: would resolve to ATTLOG and is not a valid case here).
_UNSUPPORTED_TABLE_CASES: list[tuple[str, str]] = [
    ("", "empty table name"),
    ("   ", "whitespace-only table name"),
    ("SMS", "a tag this version has never supported"),
    ("WORKCODE", "a real ZKTeco table this version does not implement"),
    ("OPERLOGX", "close to a known name but not an exact match"),
    ("ATTLOG; DROP TABLE dbo.ADMS_DEVICE;--", "a SQL-fragment-shaped table name"),
    ("'; DROP TABLE ADMS_DEVICE --", "a quote-based SQL fragment"),
]

_FILE_ROUTE_PATHS = ["/iclock/fdata", "/iclock/rtdata", "/iclock/edata", "/iclock/filedata"]


def test_property_41_unsupported_payload_is_always_acknowledged_and_never_reaches_the_legacy_schema(
    wire: Any, logs: Any
) -> None:
    # Feature: adms-attendance-system, Property 41: A payload this version cannot use is always
    # acknowledged, and never reaches the legacy schema
    """
    For all table names the service does not support, and for all file-upload routes, the
    request is acknowledged with 2xx, the payload (or a size placeholder for a binary upload) is
    archived, a warning names the table, and no legacy-schema adapter is called.

    **Validates: Requirements 8.2, 8.3, 8.4, 8.5**
    """
    rows = ["some\tdevice\tline", "another\tline"]
    for table_name, case_id in _UNSUPPORTED_TABLE_CASES:
        service, stores = _hybrid_no_legacy_writes([linked_device()], log=logs.logger)

        request = wire.request(
            "POST", "/iclock/cdata", body=rows, query={"SN": SERIAL_LINKED, "table": table_name}
        )
        response = service.handle(request)

        assert 200 <= response.status < 300, case_id
        assert response.body == "OK: 2", case_id
        expected_table = table_name.strip().upper() or "UNKNOWN"
        archived = [r for r in stores["archive"].requests if r["serial"] == SERIAL_LINKED]
        assert archived, case_id
        assert archived[-1]["table"] == expected_table, case_id
        assert archived[-1]["body"] == "\n".join(rows) + "\n", case_id
        warnings = [w for w in logs.of_level("WARN") if w.get("table") == table_name.strip().upper()]
        assert warnings, f"{case_id}: expected a warning naming the table"
        _assert_no_legacy_adapter_touched(stores, label=case_id)

    # -- Every file-upload route: acknowledged with a bare OK, a size placeholder archived, and no
    # legacy-schema adapter touched.
    for path in _FILE_ROUTE_PATHS:
        service, stores = _hybrid_no_legacy_writes([linked_device()])
        body = b"\x00\x01binary-blob-not-text"

        response = service.handle(wire.request("POST", path, body=body, query={"SN": SERIAL_LINKED}))

        assert response.status == 200, path
        assert response.body == "OK", path
        archived = [r for r in stores["archive"].requests if r["serial"] == SERIAL_LINKED]
        assert archived, path
        assert archived[-1]["table"] == "FILE", path
        assert archived[-1]["body"] == f"<{len(body)} bytes>", path
        _assert_no_legacy_adapter_touched(stores, label=path)


# ── Property 46 ──────────────────────────────────────────────────────────────────────────────


def test_property_46_a_solicited_result_is_persisted_exactly_as_a_spontaneous_one(
    fake: Any, wire: Any
) -> None:
    # Feature: adms-attendance-system, Property 46: A solicited result is persisted exactly as a
    # spontaneous one
    """
    For any body, arriving on the query-result route with a non-options type produces exactly the
    stored rows that the same body produces as a spontaneous OPERLOG upload; arriving with type
    options is handled as a device self-description; and for all type values, including empty and
    hostile, the type is recorded in the archive's table field.

    This is also where task 4.1's V1 fix gets its permanent regression test: on the querydata
    route, the verbatim archive call must precede every write ``_persist_operlog`` makes, matching
    ``_operlog``'s own order (Requirement 11.9, unconditional). Before task 4.1, ``_query_data``
    called ``_persist_operlog`` *before* ``_archive_request`` -- the recorded order below would
    have started with ``employees.upsert_employees``, not ``archive.archive_request``, against
    that code, and the assertion would have failed. It does not fail here, because the fix is in
    place.

    **Validates: Requirements 10.2, 10.3, 10.4**
    """
    settings = make_settings()

    # -- Same body, same rows, whichever route it arrives by. --
    body = ["USER\tPIN=1201\tName=Nguyen Van A\tPri=0\tCard=1\tEnable=1"]
    querydata_service, querydata_stores = fake(settings=settings, devices=[linked_device()])
    querydata_response = querydata_service.handle(
        wire.querydata(SERIAL_LINKED, body, query_type="userinfo")
    )
    operlog_service, operlog_stores = fake(settings=settings, devices=[linked_device()])
    operlog_response = operlog_service.handle(wire.operlog(SERIAL_LINKED, body))

    assert querydata_response.status == operlog_response.status == 200
    assert querydata_response.body == operlog_response.body == "OK: 1"
    assert querydata_stores["employees"].employees == operlog_stores["employees"].employees

    # -- type=options is a device self-description, not an OPERLOG persist: bare OK, and the
    # options land on the registration through record_contact.
    options_service, options_stores = fake(settings=settings, devices=[linked_device()])
    options_response = options_service.handle(wire.querydata(SERIAL_LINKED, [], query_type="options"))
    assert options_response.status == 200
    assert options_response.body == "OK"
    assert SERIAL_LINKED in options_stores["registry"].options

    # -- The type value, including empty and hostile ones, is recorded in the archive's table
    # field verbatim -- never interpreted, never dropped.
    hostile_types = ["", "userinfo", "fptmp", "'; DROP TABLE ADMS_DEVICE --", "a" * 100]
    for type_value in hostile_types:
        service, stores = fake(settings=settings, devices=[linked_device()])
        response = service.handle(wire.querydata(SERIAL_LINKED, body, query_type=type_value))
        assert response.status == 200, type_value
        archived = [r for r in stores["archive"].requests if r["serial"] == SERIAL_LINKED]
        assert archived, type_value
        assert archived[-1]["table"] == f"QUERY:{type_value}", type_value

    # -- The V1 regression test: on the querydata route, the verbatim archive call precedes every
    # write _persist_operlog makes, exactly matching _operlog's own recorded order.
    order_service, order_stores = fake(settings=settings, devices=[linked_device()])
    order = _CallOrder()
    order.track(order_stores, {"archive": ["archive_request"], "employees": ["upsert_employees"]})

    order_response = order_service.handle(
        wire.querydata(SERIAL_LINKED, ["USER\tPIN=1202\tName=Tran Thi B\tPri=0\tCard=2\tEnable=1"])
    )

    assert order_response.status == 200
    assert order.names == ["archive.archive_request", "employees.upsert_employees"], (
        "the verbatim archive must precede the persisted write on the querydata route -- this is "
        "task 4.1's fix; against the pre-fix code this recorded order would have started with "
        "employees.upsert_employees instead, and this assertion would have failed"
    )
