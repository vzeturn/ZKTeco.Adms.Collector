"""
Property tests for the SQL adapters -- ``SqlServerAttendanceStore``, ``SqlServerEmployeeStore`` and
``SqlServerTemplateStore`` -- against :class:`~conftest.RecordingDatabase`.

Nine properties live here, all about what a single SQL adapter does with the values it is handed, in
isolation from the service that calls it: the shape of a row handed to ``dbo.CheckInOut_add``, the
column bounds and the HR-code asymmetry in the ``NHANVIEN`` merge, the delete-then-insert scoping and
the derived columns for templates, and the fixed message that leaves the database layer when the
driver fails. ``test_service_attlog.py`` and ``test_service_operlog.py`` already cover the
*orchestration* of these adapters (call order, best-effort, idempotence end to end); this file is
adapter-internal: what statement text, what parameter order, what filtering happens before a value
ever reaches ``cursor.execute``/``executemany``.

Every adapter here is constructed directly against a :class:`~conftest.RecordingDatabase`, cast to
``ConnectionFactory`` -- the same idiom ``test_service_attlog.py``'s Property 47 test and
``test_composition.py`` use for driving a real SQL adapter with no ODBC driver and no database. The
recording cursor answers every read from a scripted queue and records every statement and every bound
parameter, in order, across every call the adapter makes -- which is what lets a property assert
"no value ever reaches statement text" as a fact about the recorded calls rather than an inspection of
the source.

One property, one test, table-driven over adversarial fixed inputs per the design's Testing Strategy.
No ``hypothesis``.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, cast

import pytest
from conftest import (
    MACHINE_ID,
    MACHINE_NAME,
    ROWCOUNT_ONLY,
    RecordingDatabase,
)

from adms.db import SqlServerAttendanceStore, SqlServerEmployeeStore, SqlServerTemplateStore
from adms.db.connection import BATCH_SIZE, ConnectionFactory
from adms.db.schema import FINGER_VERSION, format_enabled, parse_enabled
from adms.errors import AttendanceDbError
from adms.models import AttendanceLog, DeviceUser, FaceTemplate, FingerTemplate

# ── Property 28 ──────────────────────────────────────────────────────────────────────────────


def test_property_28_duplicate_suppression_does_not_depend_on_the_stored_procedure() -> None:
    # Feature: adms-attendance-system, Property 28: Duplicate suppression does not depend on the
    # stored procedure. For any batch, and for any procedure behaviour -- one that deduplicates and
    # one that does not -- the stored punches are free of (MaChamCong, GioCham) duplicates: in-batch
    # repeats are collapsed and keys already present in the window are removed before the procedure
    # is called.
    """
    ``dbo.CheckInOut_add`` sits behind ``{CALL ...}`` through ``executemany``, whose per-statement
    result ``add_attendance`` never reads -- so whatever the deployed procedure does with a
    duplicate cannot be what this filtering depends on. Driven against two differently-scripted
    recording databases (one producing nothing for the call, one producing a rowcount-only result,
    standing in for "a procedure that silently no-ops on a repeat" versus "one that reports
    something"), the row set this store hands to the procedure must be identical and
    duplicate-free in both -- because the filtering happens entirely before the call, from the
    batch's own in-batch tracking and the caller-supplied ``existing_keys``, never from anything
    the procedure signals back.

    **Validates: Requirements 14.6, 14.7, 14.8, 17.6**
    """
    logs = [
        AttendanceLog(pin="601", timestamp=dt.datetime(2026, 8, 7, 8, 0, 0)),
        AttendanceLog(pin="601", timestamp=dt.datetime(2026, 8, 7, 8, 0, 0)),  # in-batch repeat
        AttendanceLog(pin="602", timestamp=dt.datetime(2026, 8, 7, 8, 1, 0)),
        AttendanceLog(pin="603", timestamp=dt.datetime(2026, 8, 7, 8, 2, 0)),  # already stored
    ]
    existing_keys = {(603, dt.datetime(2026, 8, 7, 8, 2, 0))}

    for db in (RecordingDatabase(), RecordingDatabase().script(ROWCOUNT_ONLY)):
        store = SqlServerAttendanceStore(cast(ConnectionFactory, db))
        inserted = store.add_attendance(
            logs, machine_id=MACHINE_ID, machine_name=MACHINE_NAME, existing_keys=existing_keys
        )

        calls = db.matching("CheckInOut_add")
        assert len(calls) == 1
        rows = calls[0].rows
        assert inserted == len(rows) == 2, "one in-batch repeat and one already-stored key removed"
        keys = [(row[0], row[2]) for row in rows]
        assert len(keys) == len(set(keys)), "no two dispatched rows share a PunchKey"
        assert all(key not in existing_keys for key in keys), "no dispatched row was already stored"
        assert keys == [
            (601, dt.datetime(2026, 8, 7, 8, 0, 0)),
            (602, dt.datetime(2026, 8, 7, 8, 1, 0)),
        ]


# ── Property 29 ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("batch_size", [1, 3, 99, 100, 101, 250], ids=lambda n: f"{n}_logs")
def test_property_29_a_projected_punch_carries_the_legacy_shape(batch_size: int) -> None:
    # Feature: adms-attendance-system, Property 29: A projected punch carries the legacy shape. For
    # any batch, every row handed to dbo.CheckInOut_add is a seven-value tuple in the verified
    # parameter order with KieuCham = '1', NguonCham = '', NgayCham equal to the date part of the
    # same value written to GioCham, MaSoMay equal to the registration's machine id and TenMay the
    # machine name bounded to 30 characters; chunks are at most 100 rows; and the statement text is
    # one constant string across every batch size.
    """
    **Validates: Requirements 14.1, 14.2, 14.3, 14.4, 14.9, 14.11**
    """
    logs = [
        AttendanceLog(pin=str(700 + i), timestamp=dt.datetime(2026, 8, 7, 8, 0, i % 60))
        for i in range(batch_size)
    ]
    long_name = "Nha may chinh - toa nha van phong trung tam quan ly"  # > 30 characters
    db = RecordingDatabase()
    store = SqlServerAttendanceStore(cast(ConnectionFactory, db))

    inserted = store.add_attendance(logs, machine_id=MACHINE_ID, machine_name=long_name)

    calls = db.matching("CheckInOut_add")
    assert inserted == batch_size
    assert all(len(call.rows) <= BATCH_SIZE for call in calls), "no chunk exceeds BATCH_SIZE"
    assert sum(len(call.rows) for call in calls) == batch_size

    statements = {call.sql for call in calls}
    assert len(statements) == 1, "the statement text must be one constant string across every batch size"

    for call in calls:
        for row in call.rows:
            pin, ngaycham, giocham, kieucham, nguoncham, masomay, tenmay = row
            assert isinstance(pin, int)
            assert kieucham == "1"
            assert nguoncham == ""
            assert ngaycham == giocham.date()
            assert masomay == MACHINE_ID
            assert tenmay == long_name[:30]
            assert len(tenmay) <= 30


# ── Property 30 ──────────────────────────────────────────────────────────────────────────────


def test_property_30_a_pin_the_legacy_key_cannot_hold_is_archived_but_never_projected(logs: Any) -> None:
    # Feature: adms-attendance-system, Property 30: A PIN the legacy key cannot hold is archived but
    # never projected. For all PIN strings that are not integers, the punch appears in the raw
    # archive with its original PIN text and is absent from CheckInOut, and the skipped count is
    # logged.
    """
    **Validates: Requirements 14.5, 18.3**
    """
    batch = [
        AttendanceLog(pin="ABC123", timestamp=dt.datetime(2026, 8, 7, 8, 0, 0)),
        AttendanceLog(pin="710", timestamp=dt.datetime(2026, 8, 7, 8, 1, 0)),
        AttendanceLog(pin="", timestamp=dt.datetime(2026, 8, 7, 8, 2, 0)),
    ]

    db = RecordingDatabase()
    store = SqlServerAttendanceStore(cast(ConnectionFactory, db), log=logs.logger)
    inserted = store.add_attendance(batch, machine_id=MACHINE_ID, machine_name=MACHINE_NAME)

    projected_pins = {row[0] for call in db.matching("CheckInOut_add") for row in call.rows}
    assert projected_pins == {710}
    assert inserted == 1

    db2 = RecordingDatabase()
    store2 = SqlServerAttendanceStore(cast(ConnectionFactory, db2))
    store2.archive_attlog("SERIALX", batch)

    archived_pins = {row[1] for call in db2.matching("ADMS_ATTLOG_RAW") for row in call.rows}
    assert {"ABC123", "710", ""} <= archived_pins, "every PIN, numeric or not, is archived verbatim"
    assert "ABC123" not in projected_pins
    assert "" not in {str(p) for p in projected_pins}

    warnings = logs.of_level("WARN")
    matching = [w for w in warnings if w.get("count") == 2]
    assert matching, "the skipped non-numeric-PIN count must be logged"


# ── Property 31 ──────────────────────────────────────────────────────────────────────────────


def test_property_31_nothing_updated_or_deleted_and_no_value_reaches_statement_text() -> None:
    # Feature: adms-attendance-system, Property 31: Nothing is ever updated or deleted in the legacy
    # tables, and no value reaches statement text. For all request kinds, no statement issued against
    # CheckInOut or NHANVIEN is an UPDATE or a DELETE; and no value taken from a request appears
    # anywhere in statement text -- every one is a bound parameter.
    """
    **Validates: Requirements 14.10, 15.10, 17.10**
    """
    hostile_name = "Nguyen'; DROP TABLE NHANVIEN; --"
    hostile_card = "1234567890'--"
    hostile_template = "abcd=='; DELETE FROM dbo.TEMPLATE; --"

    db = RecordingDatabase()
    attendance_store = SqlServerAttendanceStore(cast(ConnectionFactory, db))
    employee_store = SqlServerEmployeeStore(cast(ConnectionFactory, db))
    template_store = SqlServerTemplateStore(cast(ConnectionFactory, db))

    batch = [
        AttendanceLog(pin="720", timestamp=dt.datetime(2026, 8, 7, 8, 0, 0), reserved1=hostile_name)
    ]
    attendance_store.add_attendance(batch, machine_id=MACHINE_ID, machine_name=hostile_name)
    attendance_store.archive_attlog("SERIALX", batch)
    attendance_store.existing_punch_keys(
        MACHINE_ID, dt.datetime(2026, 8, 7), dt.datetime(2026, 8, 8)
    )

    employee_store.upsert_employees(
        [DeviceUser(pin="721", name=hostile_name, card=hostile_card)]
    )
    employee_store.missing_employee_pins({721, 722})

    template_store.save_fingerprints(
        [FingerTemplate(pin="723", finger_id=0, template=hostile_template)]
    )
    template_store.save_faces([FaceTemplate(pin="724", face_id=0, template=hostile_template)])

    assert db.calls, "sanity: the drive above must have issued at least one statement"

    for call in db.calls:
        first_word = call.sql.split(" ", 1)[0].upper() if call.sql else ""
        if first_word in ("UPDATE", "DELETE"):
            assert "CheckInOut" not in call.sql, f"a bare {first_word} touched CheckInOut: {call.sql!r}"
            assert "NHANVIEN" not in call.sql, f"a bare {first_word} touched NHANVIEN: {call.sql!r}"

        for hostile in (hostile_name, hostile_card, hostile_template):
            assert hostile not in call.statement, (
                f"a request-supplied value leaked into statement text: {call.statement!r}"
            )


# ── Property 32 ──────────────────────────────────────────────────────────────────────────────


def test_property_32_employee_upsert_never_overwrites_hr_code_and_is_idempotent() -> None:
    # Feature: adms-attendance-system, Property 32: An employee upsert never overwrites an HR code,
    # and is idempotent. For any set of device users, applying it twice leaves NHANVIEN in the state
    # one application leaves; for any pre-existing employee, MaNhanVien is byte-identical afterwards;
    # and for any newly inserted employee, MaNhanVien is that user's PIN bounded to 20 characters.
    """
    **Validates: Requirements 15.1, 15.2, 15.3, 15.11**
    """
    users = [DeviceUser(pin="730", name="Tran Van A"), DeviceUser(pin="731", name="Le Thi B")]

    db = RecordingDatabase()
    SqlServerEmployeeStore(cast(ConnectionFactory, db)).upsert_employees(users)

    db2 = RecordingDatabase()
    SqlServerEmployeeStore(cast(ConnectionFactory, db2)).upsert_employees(users)

    assert [c.sql for c in db.calls] == [c.sql for c in db2.calls], "applying the same set twice"
    assert [c.params for c in db.calls] == [c.params for c in db2.calls], "must produce the same calls"

    merge_calls = db.matching("MERGE")
    assert merge_calls, "sanity: the upsert must issue a MERGE"
    for call in merge_calls:
        update_clause = call.sql.split("WHEN MATCHED THEN", 1)[1].split("WHEN NOT MATCHED", 1)[0]
        assert "MaNhanVien" not in update_clause, "the UPDATE branch must never overwrite the HR code"

    for call in merge_calls:
        for row in call.rows:
            # index 6 = INSERT MaChamCong (the PIN), index 7 = INSERT MaNhanVien
            assert row[7] == str(row[6]), "a newly inserted employee's MaNhanVien is the PIN"
            assert len(row[7]) <= 20


# ── Property 33 ──────────────────────────────────────────────────────────────────────────────


def test_property_33_employee_writes_respect_every_column_bound_and_enable_convention() -> None:
    # Feature: adms-attendance-system, Property 33: Employee writes respect every column bound and
    # the live enable convention. For any device user, the device name is written to both
    # TenChamCong and TenNhanVien bounded to 100 characters, the card is bounded to 20, and
    # UserEnable is written as the text True or False; and for all stored UserEnable values, both
    # the True/False and 1/0 conventions are read, with blank or null read as disabled.
    """
    **Validates: Requirements 15.4, 15.5, 15.6, 15.7**
    """
    long_name = "A" * 150
    long_card = "C" * 40  # over the corrected 20-character bound, not the earlier (wrong) 50

    db = RecordingDatabase()
    store = SqlServerEmployeeStore(cast(ConnectionFactory, db))
    users = [
        DeviceUser(pin="740", name=long_name, card=long_card, enabled=True),
        DeviceUser(pin="741", name=long_name, card=long_card, enabled=False),
    ]
    store.upsert_employees(users)

    rows = [row for call in db.matching("MERGE") for row in call.rows]
    assert len(rows) == 2

    for row in rows:
        # (pin, UPDATE TenChamCong, UPDATE TenNhanVien, UPDATE MaThe, UPDATE PhanQuyen,
        #  UPDATE UserEnable, INSERT MaChamCong, INSERT MaNhanVien, INSERT TenChamCong,
        #  INSERT TenNhanVien, INSERT MaThe, INSERT PhanQuyen, INSERT UserEnable)
        assert len(row[1]) <= 100 and len(row[2]) <= 100, "TenChamCong/TenNhanVien bounded to 100"
        assert len(row[8]) <= 100 and len(row[9]) <= 100
        assert len(row[3]) <= 20, "MaThe must be bounded to 20, not 50"
        assert len(row[10]) <= 20

    enabled_row = next(r for r in rows if r[6] == 740)
    disabled_row = next(r for r in rows if r[6] == 741)
    assert enabled_row[5] == "True" and enabled_row[12] == "True"
    assert disabled_row[5] == "False" and disabled_row[12] == "False"

    # The reading half: format_enabled/parse_enabled are what a future read of UserEnable must agree
    # with, for either convention live data actually holds.
    assert format_enabled(True) == "True"
    assert format_enabled(False) == "False"
    for truthy in ("1", "true", "True", "TRUE", "yes", "y"):
        assert parse_enabled(truthy) is True, truthy
    for falsy in ("0", "false", "False", "no", "n", "", None, "   ", "junk"):
        assert parse_enabled(falsy) is False, falsy


# ── Property 34 ──────────────────────────────────────────────────────────────────────────────


def test_property_34_users_the_key_cannot_hold_are_skipped_and_repeats_collapsed() -> None:
    # Feature: adms-attendance-system, Property 34: Users the key cannot hold are skipped, and
    # repeats within a batch are collapsed. For all sets of device users, those whose PIN is not an
    # integer are skipped and counted, and PINs repeated within one batch are reduced to their last
    # occurrence -- so the merge's source never matches one target row twice.
    """
    **Validates: Requirements 15.8, 15.9**
    """
    users = [
        DeviceUser(pin="ABC", name="Not numeric"),
        DeviceUser(pin="750", name="First"),
        DeviceUser(pin="750", name="Second"),  # repeat within the batch -- last occurrence wins
        DeviceUser(pin="", name="Blank pin"),
        DeviceUser(pin="  ", name="Whitespace-only pin"),
    ]

    db = RecordingDatabase()
    store = SqlServerEmployeeStore(cast(ConnectionFactory, db))
    affected = store.upsert_employees(users)

    rows = [row for call in db.matching("MERGE") for row in call.rows]
    assert affected == 1
    assert len(rows) == 1
    assert rows[0][6] == 750
    assert rows[0][1] == "Second", "the last occurrence within the batch must win"


# ── Property 40 ──────────────────────────────────────────────────────────────────────────────


def test_property_40_every_derived_template_column_is_derived_as_specified() -> None:
    # Feature: adms-attendance-system, Property 40: Every derived template column is derived as
    # specified. For all fingerprint records, a validity flag of 0 is written as 1 while a duress
    # flag of 3 passes through unchanged, and FingerVersion is '10'; for all face records, ChieuDai
    # is the device-reported size when that is positive and the payload length otherwise; and for
    # all records, the denormalised columns are populated while EnrollName is left blank.
    """
    **Validates: Requirements 16.6, 16.7, 16.8, 16.9**
    """
    assert FINGER_VERSION == "10"

    db = RecordingDatabase()
    store = SqlServerTemplateStore(cast(ConnectionFactory, db))
    fingers = [
        FingerTemplate(pin="760", finger_id=0, template="abcd==", valid=0),  # validity 0 -> Flag=1
        FingerTemplate(pin="760", finger_id=1, template="efgh==", valid=3),  # duress passes through
    ]
    store.save_fingerprints(fingers)

    finger_rows = [row for call in db.matching("INSERT INTO", "TEMPLATE") for row in call.rows]
    by_finger_id = {row[1]: row for row in finger_rows}
    # (pin, FingerID, FingerTemplate, Flag, FingerVersion, EnrollNumber, EnrollName, Privilige,
    #  enPassword, EMachineNumber)
    assert by_finger_id[0][3] == 1, "validity 0 must be coerced to Flag=1"
    assert by_finger_id[1][3] == 3, "duress flag 3 must pass through unchanged"
    for row in finger_rows:
        assert row[4] == FINGER_VERSION
        assert row[5] == row[0], "EnrollNumber must be populated with the PIN"
        assert row[6] == "", "EnrollName must be left blank"

    db2 = RecordingDatabase()
    store2 = SqlServerTemplateStore(cast(ConnectionFactory, db2))
    faces = [
        FaceTemplate(pin="761", face_id=0, template="xyz1", size=500),  # positive reported size wins
        FaceTemplate(pin="761", face_id=1, template="xyz12345", size=0),  # falls back to payload length
        FaceTemplate(pin="761", face_id=2, template="xyzTemplate", size=-4),  # negative also falls back
    ]
    store2.save_faces(faces)

    face_rows = [row for call in db2.matching("INSERT INTO", "Face") for row in call.rows]
    by_face_id = {row[1]: row for row in face_rows}
    # (pin, FaceID, FaceTemplate, ChieuDai, EnrollNumber, EnrollName, Privilige, enPassword,
    #  EMachineNumber)
    assert by_face_id[0][3] == 500
    assert by_face_id[1][3] == len("xyz12345")
    assert by_face_id[2][3] == len("xyzTemplate")
    for row in face_rows:
        assert row[4] == row[0], "EnrollNumber must be populated with the PIN"
        assert row[5] == "", "EnrollName must be left blank"


# ── Property 65 ──────────────────────────────────────────────────────────────────────────────

#: A driver error whose text embeds a full DSN, credential and all -- exactly the shape ODBC error
#: text actually takes, and exactly why the connection module never includes str(exc).
_DSN_LEAK = (
    "[Microsoft][ODBC Driver 18 for SQL Server]Login failed for user 'adms_collector'. "
    "DSN=ATTENDANCEDB;SERVER=attendancedb.example.rds.amazonaws.com;UID=adms_collector;PWD=Sup3rSecret!;"
)


def _call_existing_punch_keys(db: RecordingDatabase) -> None:
    SqlServerAttendanceStore(cast(ConnectionFactory, db)).existing_punch_keys(
        MACHINE_ID, dt.datetime(2026, 8, 7), dt.datetime(2026, 8, 8)
    )


def _call_add_attendance(db: RecordingDatabase) -> None:
    SqlServerAttendanceStore(cast(ConnectionFactory, db)).add_attendance(
        [AttendanceLog(pin="771", timestamp=dt.datetime(2026, 8, 7, 8, 0, 0))],
        machine_id=MACHINE_ID,
        machine_name=MACHINE_NAME,
    )


def _call_missing_employee_pins(db: RecordingDatabase) -> None:
    SqlServerEmployeeStore(cast(ConnectionFactory, db)).missing_employee_pins({1, 2, 3})


def _call_upsert_employees(db: RecordingDatabase) -> None:
    SqlServerEmployeeStore(cast(ConnectionFactory, db)).upsert_employees(
        [DeviceUser(pin="772", name="X")]
    )


@pytest.mark.parametrize(
    "call_site",
    [
        _call_existing_punch_keys,
        _call_add_attendance,
        _call_missing_employee_pins,
        _call_upsert_employees,
    ],
    ids=["existing_punch_keys", "add_attendance", "missing_employee_pins", "upsert_employees"],
)
def test_property_65_driver_errors_are_wrapped_before_they_can_speak(
    call_site: Any,
) -> None:
    # Feature: adms-attendance-system, Property 65: Driver errors are wrapped before they can speak.
    # For all driver error texts, including ones embedding a full data source name with a password,
    # the error that leaves the database layer is the collector's own type with a fixed message
    # describing the operation and containing no part of the driver's text.
    """
    **Validates: Requirement 27.8**
    """
    driver_error = RuntimeError(_DSN_LEAK)
    db = RecordingDatabase().fail_on(1, error=driver_error)

    with pytest.raises(AttendanceDbError) as excinfo:
        call_site(db)

    message = str(excinfo.value)
    assert message, "the wrapping error must carry a fixed, non-empty message"
    assert "Sup3rSecret!" not in message
    assert "PWD=" not in message
    assert "attendancedb.example.rds.amazonaws.com" not in message
    assert "adms_collector" not in message
    assert _DSN_LEAK not in message
    # The driver's own exception is preserved as the cause for anyone who chooses to inspect it --
    # it just never renders into the message a caller might log or return.
    assert excinfo.value.__cause__ is driver_error
