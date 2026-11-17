"""
Property tests for the command downlink -- ``AdmsService._get_request`` / ``_device_cmd`` and
``adms.memory.InMemoryCommandQueue`` -- against the in-memory graph.

Two properties live here, neither of which has a home in the design's enumerated ``tests/``
layout: ``test_commands_codec.py`` (task 7.7) covers ``render_commands`` / ``parse_acks`` as pure
functions, but nothing there drives the queue itself or the service routes built on it.

* **Property 43** is about the queue's delivery discipline: a command handed out by one poll must
  never be handed out again, polls come back in ``CommandId`` order, a poll never exceeds the
  configured maximum, an acknowledgement can only ever close a command its own serial owns, and
  ``enqueue`` refuses a body with nothing in it.
* **Property 44** is the one row-of-the-matrix carve-out from ``test_service_authz.py``'s
  authorisation properties: an *unlinked* device's poll must still succeed, because failing it
  would take the device offline exactly when an operator is trying to see it in order to link it.

**Scope note, stated once here rather than implied:** the at-most-once and ordering halves below
are exercised entirely against :class:`~adms.memory.InMemoryCommandQueue`, i.e. Python dict/list
bookkeeping with no locking of any kind. The real queue's ``READPAST`` clause -- skipping a row
another transaction holds instead of blocking on it -- is a real-engine locking behaviour this
in-memory fake has no equivalent of at all, and it is **not exercised anywhere in this file**.
That half of Requirement 9.3 belongs to task 14.3, against two concurrent sessions on the actual
SQL Server engine. Nothing below should be read as having exercised row-locking; it has only
exercised the claim-on-read *bookkeeping* the fake models.
"""

from __future__ import annotations

from typing import Any

import pytest
from conftest import (
    MACHINE_ID,
    SERIAL_LINKED,
    linked_device,
    make_settings,
    unlinked_device,
)

from adms.memory import InMemoryCommandQueue
from adms.models import CommandAck

# ── Property 43: Delivery is at most once, and an acknowledgement reaches only its own device's
#    commands ──────────────────────────────────────────────────────────────────────────────────


def _parse_dispatched(body: str) -> list[tuple[int, str]]:
    """
    ``getrequest``'s response body back into ``[(id, command_body), ...]``, in wire order.

    ``"OK"`` (the empty-queue case) parses to an empty list rather than being special-cased by
    callers -- this file is not re-testing Property 42's render shape, only reading it back.
    """
    if body == "OK":
        return []
    lines = [line for line in body.split("\r\n") if line]
    dispatched: list[tuple[int, str]] = []
    for line in lines:
        assert line.startswith("C:"), f"not a C:<id>:<body> line: {line!r}"
        _, id_text, command_body = line.split(":", 2)
        dispatched.append((int(id_text), command_body))
    return dispatched


def test_property_43_delivery_is_at_most_once_and_ack_scoped_by_serial(fake: Any, wire: Any) -> None:
    # Feature: adms-attendance-system, Property 43: Delivery is at most once, and an
    # acknowledgement reaches only its own device's commands. Against the in-memory queue: two
    # consecutive polls never return the same command; a poll returns at most the configured
    # maximum, in ascending CommandId order; an acknowledgement from a different serial than the
    # command's owner updates nothing; and queueing a blank or whitespace command body is
    # refused. READPAST row-locking is integration-only (task 14.3) and is not exercised here --
    # see the module docstring.

    # -- Part A: at-most-once delivery, ascending CommandId order, and capped at the configured
    # maximum. Seven commands queued, a per-poll cap of three: three polls exhaust the queue with
    # no id repeated, dropped or reordered, and a fourth poll (nothing left) renders "OK" rather
    # than a zero-length body.
    settings = make_settings(max_commands_per_poll=3)
    service, stores = fake(settings=settings, devices=[linked_device()])
    enqueued_ids = [stores["commands"].enqueue(SERIAL_LINKED, f"CMD{i}") for i in range(7)]

    first_poll = _parse_dispatched(service.handle(wire.getrequest(SERIAL_LINKED)).body)
    second_poll = _parse_dispatched(service.handle(wire.getrequest(SERIAL_LINKED)).body)
    third_poll = _parse_dispatched(service.handle(wire.getrequest(SERIAL_LINKED)).body)
    fourth_poll = service.handle(wire.getrequest(SERIAL_LINKED))

    assert [cid for cid, _ in first_poll] == enqueued_ids[:3], "not capped, or not in ascending order"
    assert [cid for cid, _ in second_poll] == enqueued_ids[3:6], "not capped, or not in ascending order"
    assert [cid for cid, _ in third_poll] == enqueued_ids[6:7], "not capped, or not in ascending order"
    assert fourth_poll.status == 200
    assert fourth_poll.body == "OK", "an exhausted queue must render OK, never a zero-length body"

    delivered = (
        [cid for cid, _ in first_poll] + [cid for cid, _ in second_poll] + [cid for cid, _ in third_poll]
    )
    assert delivered == enqueued_ids, "a command was delivered twice, dropped, or reordered across polls"
    assert len(set(delivered)) == len(delivered), "the same CommandId was returned by more than one poll"

    # -- Part B: an acknowledgement from a different serial than the command's owner updates
    # nothing. Modelled with two distinct linked devices sharing one CommandId space -- exactly
    # the situation that would let a misconfigured or malicious device try to close a command it
    # was never sent, by guessing or replaying another device's id.
    owner = linked_device()
    stranger = linked_device(serial="CJXX204960444", machine_id=MACHINE_ID + 1, machine_name="Khac")
    scoped_service, scoped_stores = fake(devices=[owner, stranger])
    owned_id = scoped_stores["commands"].enqueue(owner.serial, "INFO")
    dispatched_to_owner = _parse_dispatched(
        scoped_service.handle(wire.getrequest(owner.serial)).body
    )
    assert [cid for cid, _ in dispatched_to_owner] == [owned_id], "setup: not dispatched to its owner"

    rows_updated = scoped_stores["commands"].ack(
        stranger.serial, [CommandAck(command_id=owned_id, return_code=0, command="INFO")]
    )
    assert rows_updated == 0, (
        f"an acknowledgement from {stranger.serial!r} updated command {owned_id}, which was "
        f"queued for {owner.serial!r} -- one device closed a command it was never sent"
    )

    # The owner's own acknowledgement of the same command, by contrast, is accepted -- confirming
    # the zero above is scoping, not a queue that rejects every acknowledgement.
    own_rows_updated = scoped_stores["commands"].ack(
        owner.serial, [CommandAck(command_id=owned_id, return_code=0, command="INFO")]
    )
    assert own_rows_updated == 1, "the owning serial's own acknowledgement must be accepted"

    # -- Part C: queueing a blank or whitespace-only command body is refused, matching
    # SqlServerCommandQueue.enqueue's own contract -- an operator's typo must not queue a command
    # a device would render as nothing at all.
    queue = InMemoryCommandQueue()
    for blank_body in ("", "   ", "\t\n  ", "\r\n"):
        with pytest.raises(ValueError):
            queue.enqueue(SERIAL_LINKED, blank_body)


# ── Property 44: An unlinked device's command poll succeeds ─────────────────────────────────

#: Every case is an enabled-but-unlinked registration; the claim is "any", not one blessed shape
#: of it, so stamps, timezone offset and the presence of already-queued commands all vary.
_UNLINKED_POLL_CASES: list[dict[str, Any]] = [
    {"id": "freshly seen, no commands queued", "overrides": {}, "queue_first": False},
    {
        "id": "commands already queued before the device was ever linked",
        "overrides": {},
        "queue_first": True,
    },
    {
        "id": "nonzero stamps and a non-default timezone offset, still unlinked",
        "overrides": {"attlog_stamp": "500", "operlog_stamp": "12", "timezone_offset": 3},
        "queue_first": False,
    },
]


@pytest.mark.parametrize(
    "case", _UNLINKED_POLL_CASES, ids=[c["id"] for c in _UNLINKED_POLL_CASES]
)
def test_property_44_unlinked_device_command_poll_succeeds(
    case: dict[str, Any], fake: Any, wire: Any
) -> None:
    # Feature: adms-attendance-system, Property 44: An unlinked device's command poll succeeds.
    # For any enabled but unlinked registration, GET /iclock/getrequest answers status 200 with
    # body "OK" -- never an error and never a leaked command -- because the poll that keeps the
    # session alive must not fail while an operator is trying to link the device.
    registration = unlinked_device(**case["overrides"])
    service, stores = fake(devices=[registration])
    if case["queue_first"]:
        # Queued before the device is linked -- must not be dispatched, and must not turn the
        # poll into anything other than a bare OK.
        stores["commands"].enqueue(registration.serial, "INFO")

    response = service.handle(wire.getrequest(registration.serial))

    assert response.status == 200, case["id"]
    assert response.body == "OK", case["id"]
