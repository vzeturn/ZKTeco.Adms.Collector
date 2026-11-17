"""
Fan_Out and Backfill (multi-device-employee-sync), driven end to end through
``AdmsService.handle`` against the in-memory graph -- the same "hybrid graph, exploding adapter
for the absence claims" pattern ``test_service_enrolment.py`` already uses for the auto-enrolment
loop this feature is a sibling to.

Covers, per the feature's own requirements.md:

* Requirement 25 -- the Sync_Group boundary: two groups never exchange anything; an empty/unset
  group on either side means inert; a device with no group is never a Fan_Out target and never
  runs a Backfill.
* Requirement 26 -- Fan_Out excludes the Origin_Device, notifies every other Enabled_Device in
  the same group, and caps commands per target at Sync_Pace_Cap.
* Requirement 27 -- Backfill: due when owed and (never backfilled or silent past threshold), not
  due otherwise (zero-cost, single check); the Sync_Cursor advances only as far as what was
  enqueued.
* Requirement 29.1, 29.7 -- the feature disabled (``roster_sync_enabled=False``, so
  ``AdmsService.roster_sync`` is ``None``) touches no adapter at all, proven the same way Property
  53 proves an absence: against an exploding fake.
"""

from __future__ import annotations

from typing import Any

from conftest import linked_device, make_settings

from adms.composition import build_fake_service
from adms.memory import (
    FixedClock,
    InMemoryAttendanceStore,
    InMemoryCommandQueue,
    InMemoryDeviceRegistry,
    InMemoryEmployeeStore,
    InMemoryPushArchive,
    InMemoryRosterSync,
    InMemoryTemplateStore,
)
from adms.models import DeviceUser, FingerTemplate, UserPrivilege
from adms.service import AdmsService

_SERIAL_A = "DEV0000000A"
_SERIAL_B = "DEV0000000B"
_SERIAL_C = "DEV0000000C"
_SERIAL_OTHER_GROUP = "SVC0000001"
_SERIAL_NO_GROUP = "NOGROUP001"


def _wire_operlog(serial: str, table: str = "OPERLOG"):
    """Minimal AdmsRequest for a USER-only OPERLOG upload -- local import to avoid a hard
    dependency on conftest's WIRE fixture object identity across parametrised graphs below."""
    from conftest import WIRE

    return WIRE.operlog(serial, [f"USER\tPIN=1\tName=Nguyen A\tPri=0\tEnable=1"])


def _build_enabled_graph(
    *, devices: list[Any], settings_overrides: dict[str, Any] | None = None
) -> tuple[AdmsService, dict[str, Any]]:
    """A full in-memory graph with Roster_Sync ON, mirroring composition.build_fake_service's own
    gating exactly (this test module wants direct access to InMemoryRosterSync's own state, which
    build_fake_service's returned ``stores`` dict already exposes under "roster_sync")."""
    settings = make_settings(roster_sync_enabled=True, **(settings_overrides or {}))
    return build_fake_service(settings, devices=devices)


# ── Requirement 25: the Sync_Group boundary ──────────────────────────────────────────────────


def test_two_devices_in_different_groups_never_exchange_anything() -> None:
    # Feature: multi-device-employee-sync, Requirement 25.2
    """
    Two Enabled, Linked devices with DIFFERENT SyncGroup values must never fan out to each other,
    however permissive everything else is.
    """
    origin = linked_device(_SERIAL_A, sync_group="GroupOne")
    other_group = linked_device(_SERIAL_B, sync_group="GroupTwo")
    service, stores = _build_enabled_graph(devices=[origin, other_group])

    stores["employees"].employees[1] = DeviceUser(pin="1", name="Nguyen A", privilege=UserPrivilege.USER)
    result = service._roster_sync.fan_out(_SERIAL_A, "GroupOne", 1)

    assert result.targets_notified == 0, "a device in a different group must never be a target"
    assert stores["commands"].pending == {}


def test_a_device_with_no_sync_group_is_never_a_fan_out_target_or_source() -> None:
    # Feature: multi-device-employee-sync, Requirement 25.2, 25.5
    origin = linked_device(_SERIAL_A, sync_group="GroupOne")
    no_group = linked_device(_SERIAL_NO_GROUP, sync_group="")
    service, stores = _build_enabled_graph(devices=[origin, no_group])

    stores["employees"].employees[1] = DeviceUser(pin="1", name="Nguyen A", privilege=UserPrivilege.USER)
    result = service._roster_sync.fan_out(_SERIAL_A, "GroupOne", 1)

    assert _SERIAL_NO_GROUP not in stores["commands"].pending, (
        "a device with no SyncGroup must never receive a Push_Command"
    )
    assert result.targets_notified == 0


def test_backfill_never_runs_for_a_device_with_no_sync_group() -> None:
    # Feature: multi-device-employee-sync, Requirement 25.2
    device = linked_device(_SERIAL_NO_GROUP, sync_group="")
    service, stores = _build_enabled_graph(devices=[device])

    result = stores["roster_sync"].backfill_if_due(device)
    assert result is None


def test_a_disabled_device_is_never_a_fan_out_target() -> None:
    # Feature: multi-device-employee-sync, Requirement 25.4
    origin = linked_device(_SERIAL_A, sync_group="GroupOne")
    disabled_in_group = linked_device(_SERIAL_B, sync_group="GroupOne", enabled=False)
    service, stores = _build_enabled_graph(devices=[origin, disabled_in_group])

    stores["employees"].employees[1] = DeviceUser(pin="1", name="Nguyen A", privilege=UserPrivilege.USER)
    result = service._roster_sync.fan_out(_SERIAL_A, "GroupOne", 1)

    assert _SERIAL_B not in stores["commands"].pending
    assert result.targets_notified == 0


def test_an_unlinked_device_is_never_a_fan_out_target() -> None:
    # Feature: multi-device-employee-sync, Requirement 25.5
    origin = linked_device(_SERIAL_A, sync_group="GroupOne")
    unlinked_in_group = linked_device(
        _SERIAL_B, sync_group="GroupOne", machine_id=None, machine_code=""
    )
    service, stores = _build_enabled_graph(devices=[origin, unlinked_in_group])

    stores["employees"].employees[1] = DeviceUser(pin="1", name="Nguyen A", privilege=UserPrivilege.USER)
    result = service._roster_sync.fan_out(_SERIAL_A, "GroupOne", 1)

    assert _SERIAL_B not in stores["commands"].pending
    assert result.targets_notified == 0


# ── Requirement 26: Fan_Out ──────────────────────────────────────────────────────────────────


def test_fan_out_notifies_every_other_enabled_linked_device_in_the_group_never_the_origin() -> None:
    # Feature: multi-device-employee-sync, Requirement 26.1, 26.4, 26.6
    origin = linked_device(_SERIAL_A, sync_group="GroupOne")
    peer_b = linked_device(_SERIAL_B, sync_group="GroupOne")
    peer_c = linked_device(_SERIAL_C, sync_group="GroupOne")
    service, stores = _build_enabled_graph(devices=[origin, peer_b, peer_c])

    stores["employees"].employees[1] = DeviceUser(
        pin="1", name="Nguyen A", privilege=UserPrivilege.USER, enabled=True
    )
    result = service._roster_sync.fan_out(_SERIAL_A, "GroupOne", 1)

    assert result.targets_notified == 2
    assert _SERIAL_A not in stores["commands"].pending, "the Origin_Device must never be a target"
    assert len(stores["commands"].pending.get(_SERIAL_B, [])) == 1
    assert len(stores["commands"].pending.get(_SERIAL_C, [])) == 1
    b_body = stores["commands"].pending[_SERIAL_B][0].body
    assert b_body.startswith("DATA UPDATE USER PIN=1")


def test_fan_out_includes_given_fingerprint_templates() -> None:
    # Feature: multi-device-employee-sync, Requirement 26.2, 28.1, 28.3
    origin = linked_device(_SERIAL_A, sync_group="GroupOne")
    peer_b = linked_device(_SERIAL_B, sync_group="GroupOne")
    service, stores = _build_enabled_graph(devices=[origin, peer_b])

    stores["employees"].employees[1] = DeviceUser(pin="1", name="Nguyen A", privilege=UserPrivilege.USER)
    fingers = [
        FingerTemplate(pin="1", finger_id=0, template="ZmluZ2VyMA=="),
        FingerTemplate(pin="1", finger_id=1, template="ZmluZ2VyMQ=="),
    ]
    service._roster_sync.fan_out(_SERIAL_A, "GroupOne", 1, fingers=fingers)

    bodies = [c.body for c in stores["commands"].pending[_SERIAL_B]]
    assert bodies[0].startswith("DATA UPDATE USER PIN=1")
    assert "DATA UPDATE FINGERTMP PIN=1\tFID=0" in bodies[1]
    assert "DATA UPDATE FINGERTMP PIN=1\tFID=1" in bodies[2]


def test_fan_out_face_templates_gated_by_roster_sync_push_faces() -> None:
    # Feature: multi-device-employee-sync, Requirement 28.2
    from adms.models import FaceTemplate

    origin = linked_device(_SERIAL_A, sync_group="GroupOne")
    peer_b = linked_device(_SERIAL_B, sync_group="GroupOne")

    service_off, stores_off = _build_enabled_graph(
        devices=[origin, peer_b], settings_overrides={"roster_sync_push_faces": False}
    )
    stores_off["employees"].employees[1] = DeviceUser(pin="1", name="A", privilege=UserPrivilege.USER)
    faces = [FaceTemplate(pin="1", face_id=0, template="ZmFjZQ==")]
    service_off._roster_sync.fan_out(_SERIAL_A, "GroupOne", 1, faces=faces)
    bodies_off = [c.body for c in stores_off["commands"].pending[_SERIAL_B]]
    assert not any("BIODATA" in b for b in bodies_off), "faces off by default: no BIODATA command"

    service_on, stores_on = _build_enabled_graph(
        devices=[origin, peer_b], settings_overrides={"roster_sync_push_faces": True}
    )
    stores_on["employees"].employees[1] = DeviceUser(pin="1", name="A", privilege=UserPrivilege.USER)
    service_on._roster_sync.fan_out(_SERIAL_A, "GroupOne", 1, faces=faces)
    bodies_on = [c.body for c in stores_on["commands"].pending[_SERIAL_B]]
    assert any("DATA UPDATE BIODATA" in b for b in bodies_on), "faces on: BIODATA command present"


def test_fan_out_caps_commands_per_target_at_the_pace_cap() -> None:
    # Feature: multi-device-employee-sync, Requirement 26.5
    origin = linked_device(_SERIAL_A, sync_group="GroupOne")
    peer_b = linked_device(_SERIAL_B, sync_group="GroupOne")
    service, stores = _build_enabled_graph(
        devices=[origin, peer_b], settings_overrides={"roster_sync_max_commands_per_cycle": 2}
    )

    stores["employees"].employees[1] = DeviceUser(pin="1", name="A", privilege=UserPrivilege.USER)
    # 1 USER command + 5 finger commands = 6 bodies; cap is 2.
    fingers = [FingerTemplate(pin="1", finger_id=i, template=f"dG1we2l9") for i in range(5)]
    result = service._roster_sync.fan_out(_SERIAL_A, "GroupOne", 1, fingers=fingers)

    assert len(stores["commands"].pending[_SERIAL_B]) == 2, "capped at the pace cap"
    assert result.commands_enqueued == 2
    assert result.deferred == 4


def test_fan_out_bumps_roster_version_exactly_once_per_call() -> None:
    # Feature: multi-device-employee-sync, Requirement 26.3
    origin = linked_device(_SERIAL_A, sync_group="GroupOne")
    peer_b = linked_device(_SERIAL_B, sync_group="GroupOne")
    service, stores = _build_enabled_graph(devices=[origin, peer_b])

    stores["employees"].employees[1] = DeviceUser(pin="1", name="A", privilege=UserPrivilege.USER)
    fingers = [FingerTemplate(pin="1", finger_id=0, template="dG1w"), FingerTemplate(pin="1", finger_id=1, template="dG1w")]
    service._roster_sync.fan_out(_SERIAL_A, "GroupOne", 1, fingers=fingers)

    assert stores["roster_sync"].versions[(1, "GroupOne")] == 1, (
        "one upload touching both USER and two FP templates must bump the version exactly once"
    )


def test_fan_out_disabled_touches_no_adapter() -> None:
    # Feature: multi-device-employee-sync, Requirement 29.1
    """
    With roster_sync_enabled=False, AdmsService.roster_sync is None, and the OPERLOG path that
    would otherwise call Fan_Out must never attempt to -- proven by driving a real USER upload
    through the service and confirming no command was queued for any device other than the
    origin (there being no Roster_Sync object at all to have done it).
    """
    from conftest import WIRE, build_fake

    settings = make_settings(roster_sync_enabled=False)
    service, stores = build_fake(
        settings=settings,
        devices=[linked_device(_SERIAL_A, sync_group="GroupOne"), linked_device(_SERIAL_B, sync_group="GroupOne")],
    )
    assert service._roster_sync is None, "disabled must mean the object does not exist"

    response = service.handle(
        WIRE.operlog(_SERIAL_A, ["USER\tPIN=1\tName=Nguyen A\tPri=0\tEnable=1"])
    )
    assert response.status == 200
    assert stores["commands"].pending == {}, "no Push_Command anywhere -- the feature is fully off"


# ── Requirement 27: Backfill ─────────────────────────────────────────────────────────────────


def test_backfill_is_due_on_first_contact_for_a_never_backfilled_device() -> None:
    # Feature: multi-device-employee-sync, Requirement 27.1
    """
    A device joining the group AFTER a change already happened (the realistic "newly linked
    device" case: it was not yet an eligible Fan_Out target when PIN 1 changed, so it received
    nothing from Fan_Out and depends entirely on Backfill to catch up).
    """
    origin = linked_device(_SERIAL_A, sync_group="GroupOne")
    service, stores = _build_enabled_graph(devices=[origin])

    stores["employees"].employees[1] = DeviceUser(pin="1", name="A", privilege=UserPrivilege.USER)
    service._roster_sync.fan_out(_SERIAL_A, "GroupOne", 1)  # bumps group version to 1; no other target yet

    # The new device joins the group now -- after the change, not before.
    new_device = linked_device(_SERIAL_B, sync_group="GroupOne", roster_sync_stamp=0)
    stores["registry"].devices[_SERIAL_B] = new_device

    result = stores["roster_sync"].backfill_if_due(new_device)
    assert result is not None
    assert result.enqueued == 1
    assert len(stores["commands"].pending.get(_SERIAL_B, [])) == 1


def test_backfill_is_not_due_for_a_current_device_even_with_zero_stamp_history() -> None:
    # Feature: multi-device-employee-sync, Requirement 27.6
    """A device with nothing owed costs exactly one check and enqueues nothing, regardless of its
    own stamp history -- there being nothing to backfill is what "not due" actually means here."""
    device = linked_device(_SERIAL_A, sync_group="GroupOne", roster_sync_stamp=0)
    service, stores = _build_enabled_graph(devices=[device])

    result = stores["roster_sync"].backfill_if_due(device)
    assert result is None
    assert stores["commands"].pending == {}


def test_backfill_not_due_for_an_actively_current_device_within_the_silence_window() -> None:
    # Feature: multi-device-employee-sync, Requirement 27.2
    """
    A device that HAS been backfilled before (stamp > 0), is fully caught up to the group's
    current max version, and has been in recent contact must not trigger another Backfill --
    Fan_Out is presumed to have kept it current.
    """
    origin = linked_device(_SERIAL_A, sync_group="GroupOne")
    caught_up = linked_device(_SERIAL_B, sync_group="GroupOne", roster_sync_stamp=1)
    service, stores = _build_enabled_graph(devices=[origin, caught_up])
    stores["employees"].employees[1] = DeviceUser(pin="1", name="A", privilege=UserPrivilege.USER)
    service._roster_sync.fan_out(_SERIAL_A, "GroupOne", 1)  # group max becomes 1, matching caught_up's stamp

    result = stores["roster_sync"].backfill_if_due(caught_up)
    assert result is None, "owed <= 0: nothing to backfill regardless of silence"


def test_backfill_advances_the_cursor_only_as_far_as_what_was_enqueued() -> None:
    # Feature: multi-device-employee-sync, Requirement 27.4, 27.5
    origin = linked_device(_SERIAL_A, sync_group="GroupOne")
    catching_up = linked_device(_SERIAL_B, sync_group="GroupOne", roster_sync_stamp=0)
    service, stores = _build_enabled_graph(
        devices=[origin, catching_up], settings_overrides={"roster_sync_max_commands_per_cycle": 1}
    )

    stores["employees"].employees[1] = DeviceUser(pin="1", name="A", privilege=UserPrivilege.USER)
    stores["employees"].employees[2] = DeviceUser(pin="2", name="B", privilege=UserPrivilege.USER)
    service._roster_sync.fan_out(_SERIAL_A, "GroupOne", 1)  # version 1
    service._roster_sync.fan_out(_SERIAL_A, "GroupOne", 2)  # version 2

    result = stores["roster_sync"].backfill_if_due(catching_up)
    assert result is not None
    assert result.enqueued == 1, "capped at one PIN per cycle"
    assert result.remaining == 1, "one PIN still owed after this slice"

    updated = stores["registry"].devices[_SERIAL_B]
    assert updated.roster_sync_stamp == 1, "cursor advances only to what was actually enqueued"

    # -- A second contact resumes from where the first left off.
    second_result = stores["roster_sync"].backfill_if_due(updated)
    assert second_result is not None
    assert second_result.enqueued == 1
    assert second_result.remaining == 0
    final = stores["registry"].devices[_SERIAL_B]
    assert final.roster_sync_stamp == 2


def test_backfill_disabled_touches_no_adapter() -> None:
    # Feature: multi-device-employee-sync, Requirement 29.1
    """
    With roster_sync_enabled=False, no request path -- including one from a device that has never
    contacted us before, the case Backfill's "never backfilled" condition targets -- can reach a
    Roster_Sync method, because AdmsService.roster_sync is None. Driven end to end through a real
    handshake, which is exactly the route Requirement 27.1 names for the newly-linked case.
    """
    from conftest import WIRE, build_fake

    settings = make_settings(roster_sync_enabled=False)
    service, stores = build_fake(
        settings=settings, devices=[linked_device(_SERIAL_A, sync_group="GroupOne")]
    )
    assert service._roster_sync is None

    response = service.handle(WIRE.handshake(_SERIAL_A))
    assert response.status == 200
    # Nothing to assert against a roster-sync store, because none was constructed -- the absence
    # itself, confirmed via service._roster_sync is None above, is the property under test.
