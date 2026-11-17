"""
Delete fan-out (multi-device-employee-sync, ISO 27001 traceability extension): propagating a user
deletion -- performed either directly against ``NHANVIEN`` (the desktop app, or an operator) or on
a device's own admin menu -- to every other Enabled_Device sharing the Sync_Group.

Three independent things are under test here, matching the three places this feature touches:

* ``fan_out_delete`` / ``reconcile_deletions`` on :class:`~adms.memory.InMemoryRosterSync` --
  behaviour, driven directly against the in-memory adapter the same way
  ``test_service_roster_sync.py`` drives Fan_Out/Backfill.
* :meth:`~adms.db.roster_sync.SqlServerRosterSync._bump_version`'s ``IsDeleted`` flag and
  :meth:`~adms.db.roster_sync.SqlServerRosterSync.reconcile_deletions`'s anti-join statement shape,
  against :class:`~conftest.RecordingDatabase`, matching ``test_adapters_roster_sync.py``'s idiom.
* :class:`~adms.service.AdmsService`'s OPLOG-delete gating: OFF unless BOTH
  ``roster_sync_fanout_deletes`` AND a non-empty ``roster_sync_delete_opcodes`` are configured --
  the two-key gate that exists because the OpCode-to-"delete" mapping is not confirmed against a
  device (see ``Settings.roster_sync_delete_opcodes``'s own docstring).

A device that is caught up by Backfill on a PIN whose version was recorded as a deletion must
receive ``DATA DELETE USERINFO``, never ``DATA UPDATE USER`` -- covered here rather than assumed,
since a deleted PIN's ``NHANVIEN`` row is gone by the time Backfill runs and reading it directly
would just find nothing (a different, wrong behaviour: "skip silently" instead of "tell the device
to delete").
"""

from __future__ import annotations

from typing import cast

from conftest import RecordingDatabase, linked_device, make_settings

from adms.composition import build_fake_service
from adms.db.connection import ConnectionFactory
from adms.db.roster_sync import SqlServerRosterSync
from adms.models import DeviceUser, OperationEvent, UserPrivilege

_SERIAL_A = "DEV0000000A"
_SERIAL_B = "DEV0000000B"
_SERIAL_C = "DEV0000000C"


class _FakeCommands:
    def __init__(self) -> None:
        self.enqueued: list[tuple[str, str]] = []

    def enqueue(self, serial: str, body: str) -> int:
        self.enqueued.append((serial, body))
        return len(self.enqueued)


def _build_enabled_graph(*, devices, settings_overrides=None):
    settings = make_settings(
        roster_sync_enabled=True, roster_sync_fanout_deletes=True, **(settings_overrides or {})
    )
    return build_fake_service(settings, devices=devices)


# ── InMemoryRosterSync.fan_out_delete ────────────────────────────────────────────────────────


def test_fan_out_delete_enqueues_delete_userinfo_for_every_other_enabled_linked_device() -> None:
    origin = linked_device(_SERIAL_A, sync_group="GroupOne")
    peer_b = linked_device(_SERIAL_B, sync_group="GroupOne")
    peer_c = linked_device(_SERIAL_C, sync_group="GroupOne")
    service, stores = _build_enabled_graph(devices=[origin, peer_b, peer_c])

    result = service._roster_sync.fan_out_delete(_SERIAL_A, "GroupOne", 1)

    assert result.targets_notified == 2
    assert result.commands_enqueued == 2
    assert _SERIAL_A not in stores["commands"].pending, "the origin must never be a target of its own delete"
    for serial in (_SERIAL_B, _SERIAL_C):
        bodies = [c.body for c in stores["commands"].pending[serial]]
        assert bodies == ["DATA DELETE USERINFO PIN=1"]


def test_fan_out_delete_never_reaches_a_different_sync_group() -> None:
    origin = linked_device(_SERIAL_A, sync_group="GroupOne")
    other_group = linked_device(_SERIAL_B, sync_group="GroupTwo")
    service, stores = _build_enabled_graph(devices=[origin, other_group])

    result = service._roster_sync.fan_out_delete(_SERIAL_A, "GroupOne", 1)

    assert result.targets_notified == 0
    assert stores["commands"].pending == {}


def test_fan_out_delete_marks_the_version_as_deleted() -> None:
    origin = linked_device(_SERIAL_A, sync_group="GroupOne")
    service, stores = _build_enabled_graph(devices=[origin])

    service._roster_sync.fan_out_delete(_SERIAL_A, "GroupOne", 1)

    assert stores["roster_sync"].deleted[(1, "GroupOne")] is True


# ── InMemoryRosterSync.reconcile_deletions (DB-side trigger) ────────────────────────────────


def test_reconcile_deletions_fans_out_a_delete_for_a_pin_whose_employee_row_is_gone() -> None:
    """
    A PIN this group previously pushed via a live Fan_Out, whose NHANVIEN row has since been
    removed directly (the desktop app, or an operator) -- the DB-side deletion trigger.
    """
    origin = linked_device(_SERIAL_A, sync_group="GroupOne")
    peer_b = linked_device(_SERIAL_B, sync_group="GroupOne")
    service, stores = _build_enabled_graph(devices=[origin, peer_b])

    stores["employees"].employees[1] = DeviceUser(pin="1", name="Nguyen A", privilege=UserPrivilege.USER)
    service._roster_sync.fan_out(_SERIAL_A, "GroupOne", 1)  # a live push, recorded as not-deleted
    del stores["employees"].employees[1]  # the row is gone now -- simulates a direct NHANVIEN delete

    result = service._roster_sync.reconcile_deletions("GroupOne")

    assert result is not None
    assert result.deleted_pins == [1]
    assert result.commands_enqueued >= 1
    bodies = [c.body for c in stores["commands"].pending[_SERIAL_B]]
    assert "DATA DELETE USERINFO PIN=1" in bodies


def test_reconcile_deletions_returns_none_when_nothing_vanished() -> None:
    """Zero-cost guarantee mirroring backfill_if_due's own contract: a group with no deletions
    since the last pass must not enqueue anything or report a false positive."""
    origin = linked_device(_SERIAL_A, sync_group="GroupOne")
    service, stores = _build_enabled_graph(devices=[origin])

    stores["employees"].employees[1] = DeviceUser(pin="1", name="A", privilege=UserPrivilege.USER)
    service._roster_sync.fan_out(_SERIAL_A, "GroupOne", 1)  # still live -- employee row still exists

    result = service._roster_sync.reconcile_deletions("GroupOne")
    assert result is None


def test_reconcile_deletions_ignores_pins_already_flagged_deleted() -> None:
    """A PIN already fanned out as a deletion must not be re-detected and re-fanned-out on every
    subsequent contact -- reconcile_deletions only looks at rows still flagged live (IsDeleted=0)."""
    origin = linked_device(_SERIAL_A, sync_group="GroupOne")
    service, stores = _build_enabled_graph(devices=[origin])

    service._roster_sync.fan_out_delete(_SERIAL_A, "GroupOne", 1)  # already a deletion snapshot

    result = service._roster_sync.reconcile_deletions("GroupOne")
    assert result is None


# ── Backfill of a deleted PIN sends delete_userinfo, not update_user ─────────────────────────


def test_backfill_of_a_deleted_pin_enqueues_delete_userinfo() -> None:
    """The device joins the group AFTER the deletion happened, so it received nothing from
    Fan_Out and depends entirely on Backfill -- same "newly linked device" shape as
    test_backfill_is_due_on_first_contact_for_a_never_backfilled_device in
    test_service_roster_sync.py, adapted to a deletion instead of a live change."""
    origin = linked_device(_SERIAL_A, sync_group="GroupOne")
    service, stores = _build_enabled_graph(devices=[origin])

    service._roster_sync.fan_out_delete(_SERIAL_A, "GroupOne", 1)  # bumps group version to 1

    catching_up = linked_device(_SERIAL_B, sync_group="GroupOne", roster_sync_stamp=0)
    stores["registry"].devices[_SERIAL_B] = catching_up

    result = stores["roster_sync"].backfill_if_due(catching_up)
    assert result is not None
    assert result.enqueued == 1
    bodies = [c.body for c in stores["commands"].pending[_SERIAL_B]]
    assert bodies == ["DATA DELETE USERINFO PIN=1"]


def test_backfill_mixes_updates_and_deletes_correctly_across_pins() -> None:
    """
    A device catching up across a group's history must receive the right command per PIN --
    update for a live PIN's version, delete for a deleted PIN's version -- in version order.

    The catching-up device joins the group AFTER both changes happened (same reasoning as
    test_backfill_of_a_deleted_pin_enqueues_delete_userinfo above): if it were present from the
    start, it would receive both commands directly from the live Fan_Out calls below, and the
    assertions would pass for the wrong reason -- they would be checking Fan_Out's output, not
    Backfill's.
    """
    origin = linked_device(_SERIAL_A, sync_group="GroupOne")
    service, stores = _build_enabled_graph(devices=[origin])

    stores["employees"].employees[1] = DeviceUser(pin="1", name="A", privilege=UserPrivilege.USER)
    service._roster_sync.fan_out(_SERIAL_A, "GroupOne", 1)  # version 1: live
    service._roster_sync.fan_out_delete(_SERIAL_A, "GroupOne", 2)  # version 2: deleted

    catching_up = linked_device(_SERIAL_B, sync_group="GroupOne", roster_sync_stamp=0)
    stores["registry"].devices[_SERIAL_B] = catching_up

    result = stores["roster_sync"].backfill_if_due(catching_up)
    assert result is not None
    assert result.enqueued == 2
    bodies = [c.body for c in stores["commands"].pending[_SERIAL_B]]
    assert bodies == [
        "DATA UPDATE USER PIN=1\tName=A\tPri=0\tPasswd=\tCard=\tGrp=1\tTZ=0000000000000000",
        "DATA DELETE USERINFO PIN=2",
    ]


# ── SqlServerRosterSync: _bump_version(is_deleted=True) statement shape ─────────────────────


def test_bump_version_deleted_flag_travels_in_both_update_and_insert_positions() -> None:
    db = RecordingDatabase(results=[[(1,)]])
    adapter = SqlServerRosterSync(cast(ConnectionFactory, db), commands=_FakeCommands(), settings=make_settings())

    version = adapter._bump_version(42, "GroupOne", is_deleted=True)

    assert version == 1
    version_calls = db.matching("ADMS_DEVICE_ROSTER_VERSION")
    assert len(version_calls) == 1
    # (Pin, SyncGroup, <update RosterVersion>, <update IsDeleted>, <insert RosterVersion>, <insert IsDeleted>)
    assert version_calls[0].params == (42, "GroupOne", 1, 1, 1, 1)


def test_fan_out_delete_statement_renders_delete_userinfo_body() -> None:
    db = RecordingDatabase(
        results=[
            [(1,)],  # _bump_version: sequence MERGE OUTPUT
            [],  # _bump_version: version-snapshot MERGE
            [("SERIAL_B",)],  # _fan_out_targets
        ]
    )
    commands = _FakeCommands()
    adapter = SqlServerRosterSync(cast(ConnectionFactory, db), commands=commands, settings=make_settings())

    result = adapter.fan_out_delete("SERIAL_A", "GroupOne", 999999)

    assert result.targets_notified == 1
    assert result.commands_enqueued == 1
    assert commands.enqueued == [("SERIAL_B", "DATA DELETE USERINFO PIN=999999")]


def test_reconcile_deletions_anti_joins_against_nhanvien_and_filters_is_deleted() -> None:
    """Statement-shape contract: the SELECT must anti-join NHANVIEN (find PINs with no row left)
    and filter to IsDeleted = 0 (never re-detect an already-flagged deletion) -- pinned directly
    because a regression here (e.g. dropping the IsDeleted filter) would only be visible as an
    infinite re-fan-out loop in production, not as an obviously wrong single test."""
    db = RecordingDatabase(results=[[]])  # no vanished PINs
    adapter = SqlServerRosterSync(cast(ConnectionFactory, db), commands=_FakeCommands(), settings=make_settings())

    result = adapter.reconcile_deletions("GroupOne")

    assert result is None
    (call,) = db.calls
    assert "NOT EXISTS" in call.sql
    assert "NHANVIEN" in call.sql
    assert "IsDeleted" in call.sql
    assert "= 0" in call.sql
    assert call.params == ("GroupOne",)


# ── AdmsService: OPLOG-delete gating (device-side trigger) ──────────────────────────────────


def test_oplog_delete_is_fully_off_when_delete_opcodes_is_empty_even_with_fanout_deletes_on() -> None:
    """
    The two-key gate's whole point: roster_sync_fanout_deletes=True alone must NOT enable OPLOG
    delete detection. roster_sync_delete_opcodes defaults to empty precisely because the OpCode
    that means "user deleted" is unconfirmed against a device -- see its own docstring.
    """
    from conftest import WIRE, build_fake

    origin = linked_device(_SERIAL_A, sync_group="GroupOne")
    peer_b = linked_device(_SERIAL_B, sync_group="GroupOne")
    settings = make_settings(
        roster_sync_enabled=True,
        roster_sync_fanout_deletes=True,
        roster_sync_delete_opcodes=(),
    )
    service, stores = build_fake(settings=settings, devices=[origin, peer_b])

    # An OPLOG line whose op_code would match a plausible "delete" value if the gate were open.
    response = service.handle(WIRE.operlog(_SERIAL_A, ["OPLOG\t5\t1\t2026-01-01 00:00:00\t1\t0\t0"]))

    assert response.status == 200
    assert stores["commands"].pending == {}, "no delete opcode configured: nothing must fan out"


def test_oplog_delete_fans_out_when_the_configured_opcode_matches() -> None:
    from conftest import WIRE, build_fake

    origin = linked_device(_SERIAL_A, sync_group="GroupOne")
    peer_b = linked_device(_SERIAL_B, sync_group="GroupOne")
    settings = make_settings(
        roster_sync_enabled=True,
        roster_sync_fanout_deletes=True,
        roster_sync_delete_opcodes=(5,),
    )
    service, stores = build_fake(settings=settings, devices=[origin, peer_b])

    # Positional OPLOG grammar: <op_code> <operator> <time> <obj/param1> ... -- op_code=5 matches
    # the configured OpCode, and the deleted PIN (1) lands in param1 per this module's own
    # positional-parsing convention (see _parse_oplog).
    response = service.handle(WIRE.operlog(_SERIAL_A, ["OPLOG\t5\t1\t2026-01-01 00:00:00\t1\t0\t0"]))

    assert response.status == 200
    bodies = [c.body for c in stores["commands"].pending.get(_SERIAL_B, [])]
    assert "DATA DELETE USERINFO PIN=1" in bodies


def test_oplog_delete_ignores_events_with_a_non_matching_opcode() -> None:
    from conftest import WIRE, build_fake

    origin = linked_device(_SERIAL_A, sync_group="GroupOne")
    peer_b = linked_device(_SERIAL_B, sync_group="GroupOne")
    settings = make_settings(
        roster_sync_enabled=True,
        roster_sync_fanout_deletes=True,
        roster_sync_delete_opcodes=(5,),
    )
    service, stores = build_fake(settings=settings, devices=[origin, peer_b])

    # op_code=9 does not match the configured (5,) tuple.
    response = service.handle(WIRE.operlog(_SERIAL_A, ["OPLOG\t9\t1\t2026-01-01 00:00:00\t1\t0\t0"]))

    assert response.status == 200
    assert stores["commands"].pending == {}


def test_oplog_delete_disabled_when_fanout_deletes_is_false_even_with_opcodes_configured() -> None:
    """The other half of the two-key gate: a configured OpCode alone must not enable this if
    roster_sync_fanout_deletes itself is off -- that flag is the master switch for delete fan-out
    as a whole, covering both triggers."""
    from conftest import WIRE, build_fake

    origin = linked_device(_SERIAL_A, sync_group="GroupOne")
    peer_b = linked_device(_SERIAL_B, sync_group="GroupOne")
    settings = make_settings(
        roster_sync_enabled=True,
        roster_sync_fanout_deletes=False,
        roster_sync_delete_opcodes=(5,),
    )
    service, stores = build_fake(settings=settings, devices=[origin, peer_b])

    response = service.handle(WIRE.operlog(_SERIAL_A, ["OPLOG\t5\t1\t2026-01-01 00:00:00\t1\t0\t0"]))

    assert response.status == 200
    assert stores["commands"].pending == {}


def test_oplog_delete_falls_back_to_operator_pin_when_param1_does_not_parse() -> None:
    """When param1 is not a PIN (e.g. blank or non-numeric), the operator_pin field is tried next
    -- some builds are known to carry a single subject PIN there instead of in param1."""
    from conftest import WIRE, build_fake

    origin = linked_device(_SERIAL_A, sync_group="GroupOne")
    peer_b = linked_device(_SERIAL_B, sync_group="GroupOne")
    settings = make_settings(
        roster_sync_enabled=True,
        roster_sync_fanout_deletes=True,
        roster_sync_delete_opcodes=(5,),
    )
    service, stores = build_fake(settings=settings, devices=[origin, peer_b])

    # Key=Value OPLOG variant: op=5, admin=1 (the operator), no param1 at all.
    response = service.handle(WIRE.operlog(_SERIAL_A, ["OPLOG\top=5\tadmin=1\ttime=2026-01-01 00:00:00"]))

    assert response.status == 200
    bodies = [c.body for c in stores["commands"].pending.get(_SERIAL_B, [])]
    assert "DATA DELETE USERINFO PIN=1" in bodies


def test_oplog_delete_skips_and_logs_when_no_field_parses_as_a_pin() -> None:
    """Neither param1 nor operator_pin parses as an integer -- must be skipped, never guessed
    at, since fanning out a delete for the wrong PIN is irreversible for that person's biometrics
    on every other device in the group."""
    from conftest import WIRE, build_fake

    origin = linked_device(_SERIAL_A, sync_group="GroupOne")
    peer_b = linked_device(_SERIAL_B, sync_group="GroupOne")
    settings = make_settings(
        roster_sync_enabled=True,
        roster_sync_fanout_deletes=True,
        roster_sync_delete_opcodes=(5,),
    )
    service, stores = build_fake(settings=settings, devices=[origin, peer_b])

    response = service.handle(WIRE.operlog(_SERIAL_A, ["OPLOG\top=5\tadmin=\ttime=2026-01-01 00:00:00"]))

    assert response.status == 200
    assert stores["commands"].pending == {}
