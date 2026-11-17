"""
Property tests for ``SqlServerRosterSync`` against :class:`~conftest.RecordingDatabase`, following
the exact idiom ``test_adapters_sql.py`` already uses for the other SQL adapters: construct the
adapter directly against a recording cursor cast to ``ConnectionFactory``, script the reads it
depends on, and assert on the recorded statement text and bound-parameter order rather than on a
real database.

What lives here, and why each earns its place -- following the usual testing strategy
for this feature:

* The version-draw (``_bump_version``): confirms it draws from the SHARED sequence table (never
  increments a per-PIN counter directly), because that shared-sequence property is exactly what
  makes a single scalar Sync_Cursor unambiguous across different PINs -- see
  ``ADMS_DEVICE_ROSTER_SEQUENCE``'s own schema comment for why the earlier per-PIN design was wrong.
* Fan-out target resolution: same-``SyncGroup``, ``Enabled=1``, linked (INNER JOIN MAYCHAMCONG),
  excluding the origin -- confirmed as bound parameters and statement shape, not just behaviour.
* ``RosterSyncStamp`` advance-only-forward: the ``WHERE RosterSyncStamp < ?`` guard is a statement
  contract worth pinning directly, since a regression there (e.g. dropping the guard) would be
  invisible from outside a race condition.
"""

from __future__ import annotations

from typing import Any, cast

from conftest import RecordingDatabase, make_settings

from adms.db.connection import ConnectionFactory
from adms.db.roster_sync import SqlServerRosterSync


class _FakeCommands:
    """Records every ``enqueue`` call, mirroring ``InMemoryCommandQueue``'s recorded shape without
    depending on it -- this file only wants "was enqueue called, with what", not the queue's own
    cooldown/dequeue behaviour, which belongs to ``test_service_commands.py``."""

    def __init__(self) -> None:
        self.enqueued: list[tuple[str, str]] = []

    def enqueue(self, serial: str, body: str) -> int:
        self.enqueued.append((serial, body))
        return len(self.enqueued)


def _employee_row(pin: int = 1, name: str = "Nguyen A") -> Any:
    """One scripted result row shaped like SqlServerRosterSync._read_employee_row's SELECT --
    positional, matching what a real pyodbc row supports via __getitem__."""
    return (pin, name, "12345", 0, "True")


# ── _bump_version draws from the shared sequence, never a per-PIN counter ──────────────────────


def test_bump_version_draws_from_the_shared_sequence_table() -> None:
    # Feature: multi-device-employee-sync, Requirement 26.3
    """
    The MERGE against ADMS_DEVICE_ROSTER_SEQUENCE (keyed on SyncGroup alone) must run before, and
    independently of, the MERGE against ADMS_DEVICE_ROSTER_VERSION (keyed on Pin+SyncGroup) --
    confirming the version comes from one shared counter per group, not from incrementing a
    per-PIN row directly. This is the exact property that makes a single scalar Sync_Cursor
    unambiguous across different PINs (see ADMS_DEVICE_ROSTER_SEQUENCE's own schema comment).
    """
    db = RecordingDatabase(results=[[(1,)]])  # the sequence MERGE's OUTPUT: NextVersion = 1
    adapter = SqlServerRosterSync(cast(ConnectionFactory, db), commands=_FakeCommands(), settings=make_settings())

    version = adapter._bump_version(42, "GroupOne")

    assert version == 1
    sequence_calls = db.matching("ADMS_DEVICE_ROSTER_SEQUENCE")
    version_calls = db.matching("ADMS_DEVICE_ROSTER_VERSION")
    assert len(sequence_calls) == 1, "exactly one MERGE against the shared sequence table"
    assert len(version_calls) == 1, "exactly one MERGE recording the drawn version against this PIN"
    # Order matters: the sequence draw must happen before the per-PIN snapshot is written, since
    # the snapshot's value comes FROM the draw.
    assert db.calls.index(sequence_calls[0]) < db.calls.index(version_calls[0])
    assert sequence_calls[0].params == ("GroupOne",)
    # multi-device-employee-sync delete fan-out: the MERGE now also carries IsDeleted (0 for a
    # live snapshot, since this call went through fan_out -> _bump_version(is_deleted=False)) in
    # both the UPDATE and INSERT parameter positions -- see _bump_version's own docstring for why
    # that flag has to travel with the version rather than being inferred later.
    assert version_calls[0].params == (42, "GroupOne", 1, 0, 1, 0)


def test_bump_version_for_two_different_pins_in_one_group_never_collides() -> None:
    # Feature: multi-device-employee-sync, Requirement 26.3
    """
    Two different PINs changed in the same group must draw two DIFFERENT version numbers -- this
    is what the shared-sequence design exists to guarantee, in contrast to the earlier per-PIN
    design where two PINs both incrementing from 0 could tie at 1.
    """
    db = RecordingDatabase(results=[[(1,)], [(1,)], [(2,)], [(1,)]])
    adapter = SqlServerRosterSync(cast(ConnectionFactory, db), commands=_FakeCommands(), settings=make_settings())

    version_pin_a = adapter._bump_version(1, "GroupOne")
    version_pin_b = adapter._bump_version(2, "GroupOne")

    assert version_pin_a == 1
    assert version_pin_b == 2
    assert version_pin_a != version_pin_b, "two different PINs must never draw the same version"


# ── Fan-out target resolution ───────────────────────────────────────────────────────────────────


def test_fan_out_targets_query_excludes_the_origin_and_scopes_by_group_and_enabled() -> None:
    # Feature: multi-device-employee-sync, Requirement 25.3-25.5, 26.6
    db = RecordingDatabase(results=[[("SERIAL_B",), ("SERIAL_C",)]])
    adapter = SqlServerRosterSync(cast(ConnectionFactory, db), commands=_FakeCommands(), settings=make_settings())

    targets = adapter._fan_out_targets("SERIAL_A", "GroupOne")

    assert targets == ["SERIAL_B", "SERIAL_C"]
    (call,) = db.calls
    assert "Enabled = 1" in call.sql
    assert "SyncGroup = ?" in call.sql
    assert "SerialNumber <> ?" in call.sql
    assert "INNER JOIN MAYCHAMCONG" in call.sql, "must require a link, matching Requirement 25.5"
    assert call.params == ("GroupOne", "SERIAL_A")


# ── RosterSyncStamp advances only forward ───────────────────────────────────────────────────────


def test_advance_stamp_statement_guards_against_moving_backward() -> None:
    # Feature: multi-device-employee-sync, Requirement 27.5
    """
    The UPDATE's own WHERE clause -- not application logic alone -- must guard against a stale
    call moving the stamp backward, so the guarantee holds even under a race between two Backfill
    checks for the same device.
    """
    db = RecordingDatabase()
    adapter = SqlServerRosterSync(cast(ConnectionFactory, db), commands=_FakeCommands(), settings=make_settings())

    adapter._advance_stamp("SERIAL_B", 5)

    (call,) = db.calls
    assert "RosterSyncStamp = ?" in call.sql
    assert "RosterSyncStamp < ?" in call.sql, "the guard must be in the statement, not only in Python"
    assert call.params == (5, "SERIAL_B", 5)


# ── fan_out end to end against the recorder ─────────────────────────────────────────────────────


def test_fan_out_enqueues_update_user_for_every_resolved_target() -> None:
    # Feature: multi-device-employee-sync, Requirement 26.1, 26.4
    #
    # Every execute() consumes one entry from RecordingDatabase's scripted queue regardless of
    # whether the code fetches it -- so _bump_version's TWO statements (the sequence MERGE with
    # OUTPUT, then the version-snapshot MERGE with none) both need an entry, even though only the
    # first is ever read via fetchone().
    db = RecordingDatabase(
        results=[
            [_employee_row(pin=1, name="Nguyen A")],  # _read_employee_row
            [(1,)],  # _bump_version: sequence MERGE's OUTPUT (fetched)
            [],  # _bump_version: version-snapshot MERGE (not fetched, but still consumes an entry)
            [("SERIAL_B",)],  # _fan_out_targets
        ]
    )
    commands = _FakeCommands()
    adapter = SqlServerRosterSync(cast(ConnectionFactory, db), commands=commands, settings=make_settings())

    result = adapter.fan_out("SERIAL_A", "GroupOne", 1)

    assert result.targets_notified == 1
    assert result.commands_enqueued == 1
    assert commands.enqueued == [("SERIAL_B", "DATA UPDATE USER PIN=1\tName=Nguyen A\tPri=0\tPasswd=\tCard=12345\tGrp=1\tTZ=0000000000000000")]


def test_fan_out_returns_zero_targets_when_the_employee_row_is_missing() -> None:
    # Feature: multi-device-employee-sync, Requirement 26.1
    """A PIN with no NHANVIEN row (a race, or a non-numeric PIN that slipped through) means
    nothing to propagate -- not an error, and never a version bump for a row that does not exist."""
    db = RecordingDatabase(results=[[]])  # _read_employee_row finds nothing
    commands = _FakeCommands()
    adapter = SqlServerRosterSync(cast(ConnectionFactory, db), commands=commands, settings=make_settings())

    result = adapter.fan_out("SERIAL_A", "GroupOne", 999)

    assert result.targets_notified == 0
    assert result.commands_enqueued == 0
    assert commands.enqueued == []
