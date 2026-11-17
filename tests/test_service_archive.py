"""
The archive's own claims, and the log's own claims -- what the collector keeps about a request it
has already answered, against the in-memory graph.

Two properties live here, neither with a home in the design's enumerated ``tests/`` layout: both
are about record-keeping *after* the device has been told ``OK``, rather than about the response
itself. Property 52 is the archive's contract -- what ``ADMS_PUSH_LOG``, ``ADMS_ATTLOG_RAW``,
``ADMS_OPERLOG`` and ``ADMS_USERPIC`` (:class:`~adms.memory.InMemoryPushArchive` and
:class:`~adms.memory.InMemoryAttendanceStore` here) actually hold, redacted and bounded. Property
70 is the log's contract -- that a question about one upload or one failed acknowledgement is
answerable from the structured log alone, with no database query.

Every case drives ``AdmsService.handle`` end to end against the fake graph, exactly like this
file's siblings (``test_service_attlog.py``, ``test_service_operlog.py``): the claim is about what
the *service* archives and logs, not about a store's own internals.
"""

from __future__ import annotations

from typing import Any

from conftest import (
    SERIAL_LINKED,
    linked_device,
    make_settings,
)

# ── Property 52 ──────────────────────────────────────────────────────────────────────────────


def test_property_52_the_archive_records_what_arrived_redacted_and_bounded(
    fake: Any, wire: Any
) -> None:
    # Feature: adms-attendance-system, Property 52: The archive records what arrived, redacted and
    # bounded
    """
    For any upload, the archived envelope carries the serial, route, table, query string, body and
    record count, and a parsed punch's status, verify mode, work code and both reserved fields
    survive into the raw archive; an operation whose timestamp did not parse is still recorded with
    a null time and its original line; a photo is stored as the device's own base64 text; for all
    query strings, any parameter named key, token, secret, password or pwd is redacted while SN is
    kept; for all body lengths, a body over the configured limit is clipped and carries a marker
    naming the original length; and with raw-body archiving disabled, no envelope row is written
    while every other write still happens.

    **Validates: Requirements 18.1, 18.2, 18.6, 18.7, 18.9, 18.10, 18.11**
    """
    settings = make_settings(enroll_query_enabled=False)

    # -- The envelope's fields: serial, route, table, query string, body and record count, exactly
    # as the request carried them.
    service, stores = fake(settings=settings, devices=[linked_device()])
    rows = [wire.punch(940, "2026-08-07 08:40:00")]
    request = wire.attlog(SERIAL_LINKED, rows, stamp="8888")
    response = service.handle(request)

    assert response.status == 200
    envelope = stores["archive"].requests[-1]
    assert envelope["serial"] == SERIAL_LINKED
    assert envelope["route"] == request.path == "/iclock/cdata"
    assert envelope["table"] == "ATTLOG"
    assert f"SN={SERIAL_LINKED}" in envelope["query"]
    assert envelope["body"] == wire.rows(rows).decode("utf-8")
    assert envelope["record_count"] == 1

    # -- A parsed punch's status, verify mode, work code and both reserved fields survive into the
    # raw archive, byte-for-byte, even though CheckInOut has no column for any of them.
    punch_service, punch_stores = fake(settings=settings, devices=[linked_device()])
    punch_response = punch_service.handle(
        wire.attlog(
            SERIAL_LINKED,
            [
                wire.punch(
                    941,
                    "2026-08-07 08:41:00",
                    status=5,
                    verify=2,
                    work_code=7,
                    reserved1="R1",
                    reserved2="R2",
                )
            ],
        )
    )
    assert punch_response.status == 200
    archived_logs = [log for serial, log in punch_stores["attendance"].archived if serial == SERIAL_LINKED]
    assert len(archived_logs) == 1
    archived_log = archived_logs[0]
    assert archived_log.status == 5
    assert archived_log.verify == 2
    assert archived_log.work_code == 7
    assert archived_log.reserved1 == "R1"
    assert archived_log.reserved2 == "R2"

    # -- An operation whose timestamp did not parse is still recorded, with a null time and its
    # original line preserved -- an OPLOG line is always produced, never rejected, per
    # Requirement 7.10.
    oplog_line = "OPLOG\t5\t101\tnotatimestamp\tobjX\tp1\tp2\tp3"
    oplog_service, oplog_stores = fake(settings=settings, devices=[linked_device()])
    oplog_response = oplog_service.handle(wire.operlog(SERIAL_LINKED, [oplog_line]))

    assert oplog_response.status == 200
    operations = [event for serial, event in oplog_stores["archive"].operations if serial == SERIAL_LINKED]
    assert len(operations) == 1
    assert operations[0].timestamp is None, "an unparseable OPLOG timestamp must archive as null, not raise"
    assert operations[0].raw == oplog_line, "the original line must survive verbatim"

    # -- A photo is stored as the device's own base64 text, never decoded or re-encoded.
    photo_service, photo_stores = fake(settings=settings, devices=[linked_device()])
    photo_response = photo_service.handle(
        wire.operlog(
            SERIAL_LINKED,
            ["USERPIC\tPIN=970\tFileName=pic.jpg\tSize=6\tContent=YWJjZGVm"],
        )
    )
    assert photo_response.status == 200
    photos = [photo for serial, photo in photo_stores["archive"].photos if serial == SERIAL_LINKED]
    assert len(photos) == 1
    assert photos[0].content == "YWJjZGVm", "the base64 text must survive unchanged, padding included"

    # -- Any query parameter named key, token, secret, password or pwd is redacted, case-insensitively
    # and regardless of position, while SN and every other parameter stay readable.
    redaction_service, redaction_stores = fake(settings=settings, devices=[linked_device()])
    redaction_request = wire.attlog(
        SERIAL_LINKED,
        [wire.punch(942, "2026-08-07 08:42:00")],
        token="abc123",
        key="shh",
        SECRET="top",
        password="pwd1",
        PWD="pwd2",
        Other="visible",
    )
    redaction_response = redaction_service.handle(redaction_request)

    assert redaction_response.status == 200
    redacted_query = redaction_stores["archive"].requests[-1]["query"]
    for raw_secret in ("abc123", "shh", "top", "pwd1", "pwd2"):
        assert raw_secret not in redacted_query, f"{raw_secret!r} must not survive into the archive"
    assert f"SN={SERIAL_LINKED}" in redacted_query, "SN must be kept, not redacted"
    assert "Other=visible" in redacted_query, "a non-credential parameter must stay readable"
    assert "token=***REDACTED***" in redacted_query
    assert "key=***REDACTED***" in redacted_query
    assert "SECRET=***REDACTED***" in redacted_query
    assert "password=***REDACTED***" in redacted_query
    assert "PWD=***REDACTED***" in redacted_query

    # -- A body over the configured limit is clipped and carries a marker naming the original
    # length.
    clip_settings = make_settings(enroll_query_enabled=False, archive_body_limit=20)
    clip_service, clip_stores = fake(settings=clip_settings, devices=[linked_device()])
    clip_rows = [wire.punch(943 + i, f"2026-08-07 08:{43 + i:02d}:00") for i in range(4)]
    full_body = wire.rows(clip_rows).decode("utf-8")
    assert len(full_body) > 20, "the fixture body must actually exceed the configured limit"
    clip_response = clip_service.handle(wire.attlog(SERIAL_LINKED, clip_rows))

    assert clip_response.status == 200
    clipped_body = clip_stores["archive"].requests[-1]["body"]
    assert clipped_body == full_body[:20] + f"\u2026[truncated, {len(full_body)} chars]"

    # -- With raw-body archiving disabled, no envelope row is written, while every other write --
    # the parsed archive, the punch insert and the stamp advance -- still happens.
    disabled_settings = make_settings(enroll_query_enabled=False, archive_raw_bodies=False)
    disabled_service, disabled_stores = fake(settings=disabled_settings, devices=[linked_device()])
    disabled_response = disabled_service.handle(
        wire.attlog(SERIAL_LINKED, [wire.punch(950, "2026-08-07 08:50:00")], stamp="7777")
    )

    assert disabled_response.status == 200
    assert disabled_response.body == "OK: 1"
    assert disabled_stores["archive"].requests == [], "no envelope row must be written"
    assert len(disabled_stores["attendance"].archived) == 1, "the parsed-record archive still runs"
    assert len(disabled_stores["attendance"].rows) == 1, "the punch is still inserted"
    assert disabled_stores["registry"].devices[SERIAL_LINKED].attlog_stamp == "7777", (
        "the stamp still advances"
    )


# ── Property 70 ──────────────────────────────────────────────────────────────────────────────


def test_property_70_every_upload_and_every_command_failure_is_answerable_from_the_log_alone(
    fake: Any, wire: Any, logs: Any
) -> None:
    # Feature: adms-attendance-system, Property 70: Every upload and every command failure is
    # answerable from the log alone
    """
    For any upload, one line records the serial, path, table and record counts -- for ATTLOG the
    counts sent, usable, inserted, suppressed as duplicate and archived, consistent with each other;
    for OPERLOG the counts of users upserted, fingerprints written, faces written, operations
    archived, photos archived and lines unparsed; and for any acknowledgement reporting a failure,
    one warning records the command identifier, return code and command name.

    **Validates: Requirements 5.13, 7.13, 9.13, 28.12**
    """
    # -- ATTLOG: a batch mixing an already-stored punch, a genuinely new punch and one unparseable
    # line. Sent must equal usable plus rejected (the rejected count comes from this same request's
    # own warning line, read back from the log alongside it); usable must equal inserted plus
    # suppressed-as-duplicate; and archived -- the parsed-record archive, which runs before dedup --
    # must equal usable, because every parsed punch is archived regardless of whether it turns out
    # to be a duplicate.
    settings = make_settings(enroll_query_enabled=False)
    service, stores = fake(settings=settings, devices=[linked_device()], log=logs.logger)

    seed = service.handle(wire.attlog(SERIAL_LINKED, [wire.punch(960, "2026-08-07 08:00:00")]))
    assert seed.body == "OK: 1"

    response = service.handle(
        wire.attlog(
            SERIAL_LINKED,
            [
                wire.punch(960, "2026-08-07 08:00:00"),  # already stored -- a duplicate
                wire.punch(961, "2026-08-07 08:01:00"),  # genuinely new
                "BADLINE\tnotatimestamp",  # unusable -- no parseable timestamp
            ],
        )
    )
    assert response.status == 200
    assert response.body == "OK: 3", "sent is every line, usable and rejected alike"

    stored_records = [r for r in logs.of_level("INFO") if r.get("msg") == "ATTLOG stored."]
    assert stored_records, "one line must record the ATTLOG counts"
    record = stored_records[-1]
    rejected_warnings = [
        w for w in logs.of_level("WARN") if "ATTLOG lines were unusable" in w.get("msg", "")
    ]
    assert rejected_warnings, "the rejected line must be named in its own warning"
    rejected_count = rejected_warnings[-1]["rejected"]

    assert record["sent"] == 3
    assert record["usable"] == 2
    assert record["inserted"] == 1
    assert record["duplicates"] == 1, "suppressed as duplicate"
    assert record["archived"] == 2

    assert record["sent"] == record["usable"] + rejected_count, "sent = usable + rejected"
    assert record["usable"] == record["inserted"] + record["duplicates"], (
        "usable = inserted + suppressed as duplicate"
    )
    assert record["archived"] == record["usable"], "every parsed punch is archived, dedup or not"

    # -- OPERLOG: a batch mixing a USER, an FP, a FACE, a USERPIC and one line no tag recognises.
    # The logged counts must sum back to the record count the device was told it sent.
    operlog_service, operlog_stores = fake(settings=settings, devices=[linked_device()], log=logs.logger)
    operlog_response = operlog_service.handle(
        wire.operlog(
            SERIAL_LINKED,
            [
                "USER\tPIN=970\tName=Le Van F\tPri=0",
                "FP\tPIN=970\tFID=0\tSize=4\tValid=1\tTMP=YWJj",
                "FACE\tPIN=970\tFID=0\tSIZE=4\tVALID=1\tTMP=ZGVm",
                "USERPIC\tPIN=970\tFileName=p.jpg\tSize=4\tContent=Z2hp",
                "GARBAGE_TAG\tsomething",
            ],
        )
    )
    assert operlog_response.status == 200
    assert operlog_response.body == "OK: 5"

    operlog_records = [r for r in logs.of_level("INFO") if r.get("msg") == "OPERLOG stored."]
    assert operlog_records, "one line must record the OPERLOG counts"
    operlog_record = operlog_records[-1]

    assert operlog_record["sent"] == 5
    assert operlog_record["users"] == 1
    assert operlog_record["employees_upserted"] == 1
    assert operlog_record["fingers"] == 1
    assert operlog_record["faces"] == 1
    assert operlog_record["operations"] == 0
    assert operlog_record["photos"] == 1
    assert operlog_record["unparsed"] == 1
    assert (
        operlog_record["users"]
        + operlog_record["fingers"]
        + operlog_record["faces"]
        + operlog_record["photos"]
        + operlog_record["operations"]
        + operlog_record["unparsed"]
        == operlog_record["sent"]
    ), "the per-kind counts must sum back to the record count the device was told it sent"

    # -- A failed acknowledgement logs the command identifier, return code and command name, at
    # warning level.
    ack_service, ack_stores = fake(settings=settings, devices=[linked_device()], log=logs.logger)
    command_id = ack_stores["commands"].enqueue(SERIAL_LINKED, "INFO")

    ack_response = ack_service.handle(
        wire.devicecmd(SERIAL_LINKED, [wire.ack(command_id, return_code=-3, command="INFO")])
    )
    assert ack_response.status == 200
    assert ack_response.body == "OK"

    failure_warnings = [
        w for w in logs.of_level("WARN") if w.get("msg") == "Device reported command failures."
    ]
    assert failure_warnings, "a failed acknowledgement must produce a warning"
    failure = failure_warnings[-1]["failures"][0]
    assert failure == {"id": command_id, "return": -3, "cmd": "INFO"}
