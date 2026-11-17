"""
``AdminStore.set_employee_admin`` -- the write path that persists a device-admin change to ATTENDANCEDB
and queues it to every enabled device, driven against the recording cursor so no driver is needed.

The assertions pin the three things the feature exists to guarantee: the privilege written to
``NHANVIEN`` (3 to grant, 0 to revoke), where the device password lands (an existing biometric row,
or a non-empty sentinel placeholder when there is none), and that one ``DATA UPDATE USER`` command is
queued per enabled device -- every value bound, never formatted into the SQL text, and the password
never in an audit row (asserted at the route layer).
"""

from __future__ import annotations

from typing import Any

from tests.conftest import ROWCOUNT_ONLY, RecordingDatabase, Row

from adms.admin.store import AdminStore


def _store(db: RecordingDatabase) -> AdminStore:
    return AdminStore(db)  # type: ignore[arg-type]


def _one_enabled_device() -> Row:
    return Row(SerialNumber="DEV2SERIAL")


# Every ``execute`` consumes one scripted result set, in statement order. The helpers below spell the
# exact sequence each scenario runs so the scripts stay readable: an UPDATE/INSERT yields nothing
# meaningful (``[]`` / ROWCOUNT_ONLY), a SELECT yields its rows.
def _grant_no_password_script(*serials: Row) -> RecordingDatabase:
    # UPDATE NHANVIEN -> [] ; SELECT serials -> serials ; one INSERT per serial -> ROWCOUNT_ONLY
    return RecordingDatabase().script(
        [], list(serials), *([ROWCOUNT_ONLY] * len(serials))
    )


# ── privilege written to NHANVIEN ────────────────────────────────────────────────────────────────


def test_grant_writes_phanquyen_3_bound_not_formatted() -> None:
    db = _grant_no_password_script(_one_enabled_device())
    _store(db).set_employee_admin(
        202120, is_admin=True, password=None, name="OP", card="", created_by="admin",
    )
    update = db.matching("UPDATE", "NHANVIEN")[0]
    assert update.params == (3, 202120)  # 3 == Administrator on this firmware
    assert "202120" not in update.sql and " 3 " not in update.sql  # values bound, not in text


def test_revoke_writes_phanquyen_0() -> None:
    db = _grant_no_password_script(_one_enabled_device())
    _store(db).set_employee_admin(
        202120, is_admin=False, password=None, name="OP", card="", created_by="admin",
    )
    assert db.matching("UPDATE", "NHANVIEN")[0].params == (0, 202120)


# ── device password: update existing rows ────────────────────────────────────────────────────────


def test_password_with_existing_finger_row_updates_and_creates_no_placeholder() -> None:
    db = RecordingDatabase().script(
        [],                         # UPDATE NHANVIEN
        [Row(n=1)],                 # COUNT(*) dbo.TEMPLATE  -> 1
        [Row(n=0)],                 # COUNT(*) dbo.Face      -> 0
        [],                         # UPDATE dbo.TEMPLATE enPassword
        [_one_enabled_device()],    # SELECT enabled serials
        ROWCOUNT_ONLY,              # INSERT command
    )
    result = _store(db).set_employee_admin(
        8888, is_admin=True, password=8888, name="EIGHT", card="", created_by="admin",
    )
    assert db.matching("UPDATE", "dbo.TEMPLATE", "enPassword")  # finger row updated
    assert not db.matching("INSERT INTO", "dbo.TEMPLATE")       # no placeholder inserted
    assert db.matching("UPDATE", "dbo.TEMPLATE", "enPassword")[0].params == (8888, 8888)
    assert result.templates_updated == 1
    assert result.placeholder_created is False


def test_password_with_face_row_only_updates_face_not_finger() -> None:
    db = RecordingDatabase().script(
        [],                         # UPDATE NHANVIEN
        [Row(n=0)],                 # COUNT dbo.TEMPLATE -> 0
        [Row(n=1)],                 # COUNT dbo.Face     -> 1
        [],                         # UPDATE dbo.Face enPassword
        [_one_enabled_device()],
        ROWCOUNT_ONLY,
    )
    result = _store(db).set_employee_admin(
        8888, is_admin=True, password=1234, name="", card="", created_by="admin",
    )
    assert db.matching("UPDATE", "dbo.Face", "enPassword")
    assert not db.matching("UPDATE", "dbo.TEMPLATE")
    assert not db.matching("INSERT INTO", "dbo.TEMPLATE")
    assert result.placeholder_created is False


# ── device password: placeholder when no biometric row ───────────────────────────────────────────


def test_password_with_no_biometric_row_inserts_nonempty_sentinel_placeholder() -> None:
    db = RecordingDatabase().script(
        [],                         # UPDATE NHANVIEN
        [Row(n=0)],                 # COUNT dbo.TEMPLATE -> 0
        [Row(n=0)],                 # COUNT dbo.Face     -> 0
        ROWCOUNT_ONLY,              # INSERT placeholder dbo.TEMPLATE
        [_one_enabled_device()],
        ROWCOUNT_ONLY,
    )
    result = _store(db).set_employee_admin(
        8888, is_admin=True, password=8888, name="", card="", created_by="admin",
    )
    insert = db.matching("INSERT INTO", "dbo.TEMPLATE")[0]
    params = insert.params
    # Column order: MaChamCong, FingerID, FingerTemplate, Flag, FingerVersion,
    #               EnrollNumber, EnrollName, Privilige, enPassword, EMachineNumber
    assert params[0] == 8888
    assert params[2] and params[2].strip()  # FingerTemplate non-empty, so _group_by_pin keeps it
    assert params[8] == 8888                 # enPassword carried on the placeholder
    assert result.placeholder_created is True
    assert result.templates_updated == 0


# ── absent password leaves enPassword untouched ──────────────────────────────────────────────────


def test_absent_password_touches_no_biometric_table() -> None:
    db = _grant_no_password_script(_one_enabled_device())
    _store(db).set_employee_admin(
        202120, is_admin=True, password=None, name="OP", card="", created_by="admin",
    )
    assert not db.matching("dbo.TEMPLATE")
    assert not db.matching("dbo.Face")


# ── one queued command per enabled device ────────────────────────────────────────────────────────


def test_one_update_user_command_queued_per_enabled_device() -> None:
    db = _grant_no_password_script(
        Row(SerialNumber="A"), Row(SerialNumber="B"), Row(SerialNumber="C")
    )
    result = _store(db).set_employee_admin(
        202120, is_admin=True, password=None, name="OP", card="C1", created_by="admin",
    )
    queued = db.matching("INSERT INTO dbo.ADMS_COMMAND")
    assert len(queued) == 3
    assert result.devices_queued == 3
    bodies = [call.params[1] for call in queued]
    assert all(body.startswith("DATA UPDATE USER ") for body in bodies)
    assert all("Pri=3" in body for body in bodies)   # grant -> Pri=3 reaches the wire
    assert {call.params[0] for call in queued} == {"A", "B", "C"}


def test_no_enabled_devices_still_persists_and_queues_nothing() -> None:
    db = _grant_no_password_script()  # UPDATE NHANVIEN -> [] ; SELECT serials -> none
    result = _store(db).set_employee_admin(
        202120, is_admin=True, password=None, name="OP", card="", created_by="admin",
    )
    assert result.devices_queued == 0
    assert not db.matching("INSERT INTO dbo.ADMS_COMMAND")
    assert db.matching("UPDATE", "NHANVIEN")  # the DB change still happened
    assert db.commits == 1                    # one atomic transaction


def test_revoke_queues_pri_0() -> None:
    db = _grant_no_password_script(_one_enabled_device())
    _store(db).set_employee_admin(
        202120, is_admin=False, password=None, name="OP", card="", created_by="admin",
    )
    body: Any = db.matching("INSERT INTO dbo.ADMS_COMMAND")[0].params[1]
    assert "Pri=0" in body
