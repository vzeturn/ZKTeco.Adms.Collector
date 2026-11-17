"""
The orchestrator: one ADMS request in, one device-facing response out.

Transport-neutral by design — it takes an :class:`~adms.models.AdmsRequest` and knows nothing
about API Gateway, so :mod:`adms.handler` and ``tools/local_server.py`` share the same code path
and the same behaviour.

The ordering rules that everything else here follows
----------------------------------------------------
1. **Authorise before parsing.** The serial allow-list is checked before a body is decoded, so
   an unregistered caller cannot spend our CPU or fill the archive.
2. **Commit before acknowledging.** A 2xx tells the device it may erase those records from its
   buffer. Nothing returns 2xx until the write has committed.
3. **Advance the stamp last.** The stamp is the device's resumption cursor; moving it ahead of
   durable storage is the same mistake as (2) in slow motion.
4. **Report the count the device sent, not the count we stored.** Duplicate suppression and
   skipped non-numeric PINs make those differ routinely, and firmware reads a short count as
   partial rejection and resends.
5. **Archive first, project second.** The verbatim body is stored before the interpreted rows,
   so a parsing bug is recoverable by replay rather than being a permanent loss.
"""

from __future__ import annotations

import datetime as dt

from .errors import (
    AdmsError,
    AttendanceDbError,
    DeviceDisabledError,
    DeviceNotLinkedError,
    DeviceNotRegisteredError,
    ProtocolError,
)
from .models import (
    AdmsRequest,
    AdmsResponse,
    AttendanceLog,
    DeviceRegistration,
    OperationEvent,
    PushBatch,
)
from .logging_setup import NullLogger
from .ports import (
    AttendanceStore,
    Clock,
    CommandQueue,
    DeviceRegistry,
    EmployeeStore,
    Logger,
    PushArchive,
    RosterSync,
    TemplateStore,
)
from .protocol import (
    Route,
    build_handshake,
    decode_body,
    parse_acks,
    parse_attlog,
    parse_operlog,
    parse_options,
    render_commands,
    resolve,
    split_lines,
)
from .protocol import commands as cmd
from .protocol import responses

__all__ = ["AdmsService"]

#: Routes that do not identify a device and therefore skip the allow-list.
_ANONYMOUS_ROUTES = (Route.HEALTH, Route.UNKNOWN)


class AdmsService:
    """
    Handles the ``/iclock/*`` conversation.

    Dependencies are ports (:mod:`adms.ports`), injected by :mod:`adms.composition`. Stateless
    apart from them, so one instance is safely reused across requests.
    """

    __slots__ = (
        "_registry",
        "_attendance",
        "_employees",
        "_templates",
        "_commands",
        "_archive",
        "_clock",
        "_log",
        "_settings",
        "_roster_sync",
    )

    def __init__(
        self,
        *,
        registry: DeviceRegistry,
        attendance: AttendanceStore,
        employees: EmployeeStore,
        templates: TemplateStore,
        commands: CommandQueue,
        archive: PushArchive,
        clock: Clock,
        settings,
        log: Logger | None = None,
        roster_sync: RosterSync | None = None,
    ) -> None:
        self._registry = registry
        self._attendance = attendance
        self._employees = employees
        self._templates = templates
        self._commands = commands
        self._archive = archive
        self._clock = clock
        self._settings = settings
        self._log = log or NullLogger()
        # multi-device-employee-sync: None means the feature is fully absent from this instance --
        # every call site below no-ops when it is None, which is how ADMS_ROSTER_SYNC_ENABLED=false
        # is enforced at the composition root (composition.py does not construct a
        # SqlServerRosterSync when the setting is off) rather than with a scattered flag check.
        self._roster_sync = roster_sync

    # ── Entry point ──────────────────────────────────────────────────────────────────────

    def handle(self, request: AdmsRequest) -> AdmsResponse:
        """
        Handle a request, converting failures into the status the device should see.

        Never raises. An escaping exception would become an API Gateway 502 with an HTML body —
        which some firmware treats as a *successful* delivery because it only checks that bytes
        came back, and that loses punches. Every path therefore ends in a deliberate status.
        """
        try:
            return self._dispatch(request)
        except AdmsError as exc:
            # Expected, classified failures. A 401 from an unregistered device during commissioning is
            # routine and a 503 is not, so they are logged at different severities -- and only the 5xx
            # carries a traceback.
            #
            # Withholding the traceback from 4xx is not cosmetic. An unregistered device retries every
            # ErrorDelay seconds indefinitely, so a single mis-configured serial would otherwise write a
            # multi-kilobyte stack trace to the log a few times a minute, forever, and bury everything
            # else. The reason is already in the 'reason' field; the stack that produced a deliberate
            # raise adds nothing.
            if exc.status >= 500:
                self._log.error(
                    "Request refused.",
                    exc,
                    serial=request.serial,
                    path=request.path,
                    status=exc.status,
                )
            else:
                self._log.warn(
                    "Request refused.",
                    None,
                    serial=request.serial,
                    path=request.path,
                    status=exc.status,
                    reason=f"{type(exc).__name__}: {exc}",
                )
            return responses.error(_public_message(exc), status=exc.status)
        except Exception as exc:  # noqa: BLE001 - last line of defence, see docstring
            self._log.error("Unhandled failure.", exc, serial=request.serial, path=request.path)
            # 500, so the device retries and keeps its records.
            return responses.error("Server Error", status=500)

    def _dispatch(self, request: AdmsRequest) -> AdmsResponse:
        resolved = resolve(request.method, request.path, path_secret=self._settings.path_secret)

        if not resolved.authorized:
            # Answered identically to an unknown path: confirming that a secret-prefix scheme
            # exists would tell a scanner exactly what to look for.
            self._log.warn("Rejected request with missing or wrong path secret.", path=request.path)
            return responses.not_found()

        if resolved.route is Route.HEALTH:
            return responses.ok()

        if resolved.route is Route.UNKNOWN:
            self._log.info("Unknown route.", path=request.path, method=request.method)
            return responses.not_found()

        serial = request.serial
        if not serial:
            raise ProtocolError("Request carries no SN parameter.")

        registration = self._authorize(serial, request)

        # Best-effort heartbeat. Wrapped because a failure to record last-seen must not cost us a
        # batch of punches — the data write below is the part that matters.
        try:
            self._registry.record_contact(
                serial, seen_at=self._clock.utc_now(), source_ip=request.source_ip
            )
        except Exception as exc:  # noqa: BLE001
            self._log.warn("Could not record device contact.", exc, serial=serial)

        # multi-device-employee-sync, Requirement 27.1-27.2: checked on EVERY route, not only the
        # handshake, because a device's first contact after a long outage need not be a fresh
        # handshake -- it could resume mid-conversation from whatever its own retry loop remembers.
        # Placed after record_contact (so LastSeenUtc reflects THIS contact, not the stale one the
        # due-check is deciding against) and before every route branch, so one call site covers
        # them all uniformly. Best-effort: never blocks or fails the request it rode in on.
        if self._roster_sync is not None and registration.is_linked and registration.sync_group:
            self._maybe_backfill(registration)
            # DB-side delete detection: best-effort, and cheap when there is nothing to
            # reconcile -- reconcile_deletions is one anti-join query per call, returning None
            # immediately when no PIN this group ever pushed has lost its NHANVIEN row since the
            # last pass. Riding the same per-contact cadence as Backfill rather than a separate
            # schedule, because ADMS has no cron of its own: every device contact is this
            # service's only recurring "tick".
            if self._settings.roster_sync_fanout_deletes and self._settings.roster_sync_reconcile_deletes:
                self._maybe_reconcile_deletions(registration.sync_group)

        if resolved.route is Route.HANDSHAKE:
            return self._handshake(registration)
        if resolved.route is Route.PUSH_DATA:
            return self._push_data(request, registration)
        if resolved.route is Route.GET_REQUEST:
            return self._get_request(registration)
        if resolved.route is Route.DEVICE_CMD:
            return self._device_cmd(request, registration)
        if resolved.route is Route.QUERY_DATA:
            return self._query_data(request, registration)
        if resolved.route is Route.FILE_DATA:
            return self._file_data(request, registration)
        if resolved.route is Route.PING:
            return responses.ok()

        return responses.not_found()

    # ── Authorisation ────────────────────────────────────────────────────────────────────

    def _authorize(self, serial: str, request: AdmsRequest) -> DeviceRegistration:
        """
        Resolve the serial against ``ADMS_DEVICE``.

        The whole security model of an ADMS endpoint lives in these few lines: the protocol has
        no credential, so "is this serial on the list" is the only gate. A registered device is
        served whether it is enabled or not -- ``enabled`` is an operator label, not a data gate,
        so toggling a device off never drops the punches it has already recorded. Only an
        *unregistered* serial is refused, which keeps unknown hardware out of the attendance DB.

        Deliberate: pushes are accepted from any registered device regardless of enabled,
        superseding an older rule that refused ``Enabled = 0`` with 401. ``DeviceDisabledError`` remains defined in errors.py for exactly this history but
        is intentionally unused by this method.
        """
        registration = self._registry.find(serial)

        if registration is None:
            if self._settings.auto_register_devices:
                # Recorded as disabled so it surfaces in the operator UI. Deliberately does not
                # grant access — see DeviceRegistry.register_pending.
                try:
                    self._registry.register_pending(
                        serial, seen_at=self._clock.utc_now(), source_ip=request.source_ip
                    )
                    self._log.info("Recorded unknown device as pending.", serial=serial)
                except Exception as exc:  # noqa: BLE001
                    self._log.warn("Could not record pending device.", exc, serial=serial)
            raise DeviceNotRegisteredError(f"Serial {serial!r} is not registered.")

        return registration

    @staticmethod
    def _require_link(registration: DeviceRegistration) -> int:
        """
        The machine's ``IDMCC``, or fail.

        Without it there is no value for ``CheckInOut.MaSoMay``, and inventing one would file
        punches against the wrong machine — worse than refusing and letting the device retry.
        """
        if not registration.is_linked or registration.machine_id is None:
            raise DeviceNotLinkedError(
                f"Serial {registration.serial!r} is enabled but not linked to a MAYCHAMCONG row."
            )
        return registration.machine_id

    # ── Route handlers ───────────────────────────────────────────────────────────────────

    def _handshake(self, registration: DeviceRegistration) -> AdmsResponse:
        """
        Answer ``GET /iclock/cdata`` with the device's operating parameters.

        Answered even when the device is not yet linked to a ``MAYCHAMCONG`` row. That is
        intentional: a device that completes its handshake shows up as online and reports its
        firmware, which is exactly the state an operator needs in order to link it. Its data
        pushes still fail with 503 until the link exists, so nothing is stored against a guess
        and nothing is lost.

        ``timezone_offset`` is deliberately left unset here, not passed as
        ``settings.utc_offset_hours``. ``build_handshake`` falls back to
        ``registration.timezone_offset`` (``ADMS_DEVICE.TimeZoneOffset``) whenever no explicit
        offset is supplied, so the per-device stored value is what wins, and the global setting
        is only the fallback a row inherits until someone edits it. That makes Requirement
        23.13's stated reason for the column ("an estate can span time zones") true in practice
        rather than merely in the schema.

        The cost: the emitted ``TimeZone`` now varies per row of a table an operator edits by
        hand, so a wrong value in one ``ADMS_DEVICE`` row silently changes what one device is
        told about its own clock offset — there is no cross-check against the global setting or
        against any other device. This is a no-op for every device seeded so far, since the
        column defaults to 7 and ``ADMS_UTC_OFFSET_HOURS`` also defaults to 7; it only matters
        once a device's stored offset and the site setting actually diverge.
        """
        body = build_handshake(
            registration,
            server_version=self._settings.server_version,
            delay=self._settings.poll_delay,
            error_delay=self._settings.error_delay,
            trans_times=self._settings.trans_times,
            trans_interval=self._settings.trans_interval,
            trans_flag=self._settings.trans_flag,
            realtime=self._settings.realtime,
            timezone_offset=None,
            extra=self._settings.extra_options,
        )
        self._log.info(
            "Handshake served.",
            serial=registration.serial,
            machine_id=registration.machine_id,
            linked=registration.is_linked,
        )
        return responses.text(body)

    def _push_data(self, request: AdmsRequest, registration: DeviceRegistration) -> AdmsResponse:
        """Dispatch ``POST /iclock/cdata`` on its ``table`` parameter."""
        table = (request.q("table") or "").strip().upper()
        stamp = request.q("Stamp", "stamp")
        body = decode_body(request.body)

        if table == "OPTIONS":
            return self._device_options(request, registration, body)
        if table == "ATTLOG":
            return self._attlog(request, registration, body, stamp)
        if table == "OPERLOG":
            return self._operlog(request, registration, body, stamp)
        if table in ("ATTPHOTO", "USERPIC", "BIOPHOTO"):
            return self._photo_table(registration, table, body, stamp, request)

        # An unrecognised table is acknowledged and archived rather than refused. Refusing would
        # wedge the device: firmware retries the same body forever, and everything queued behind
        # it — including ATTLOG — waits. Archiving keeps the payload for whoever adds support.
        count = len(split_lines(body))
        self._archive_request(request, registration, table or "UNKNOWN", body, count)
        self._log.warn(
            "Acknowledged an unsupported table; body archived only.",
            serial=registration.serial,
            table=table,
            records=count,
        )
        return responses.ok_count(count)

    def _device_options(
        self, request: AdmsRequest, registration: DeviceRegistration, body: str
    ) -> AdmsResponse:
        """
        Store the device's self-description.

        No link required — this is metadata about the device itself, and it is precisely what an
        operator reads (firmware, model, capacity) while deciding which ``MAYCHAMCONG`` row the
        serial belongs to.
        """
        info = parse_options(body, serial=registration.serial)
        try:
            self._registry.record_contact(
                registration.serial,
                seen_at=self._clock.utc_now(),
                source_ip=request.source_ip,
                info=info,
            )
        except Exception as exc:  # noqa: BLE001
            self._log.warn("Could not store device options.", exc, serial=registration.serial)

        self._archive_request(request, registration, "options", body, len(info.values))
        self._log.info(
            "Device options received.",
            serial=registration.serial,
            device_name=info.device_name,
            firmware=info.firmware,
            options=len(info.values),
        )
        # 'OK' rather than 'OK: n' — this is not a record upload and some firmware treats a
        # counted reply here as a protocol error.
        return responses.ok()

    def _attlog(
        self, request: AdmsRequest, registration: DeviceRegistration, body: str, stamp: str
    ) -> AdmsResponse:
        """
        The punch upload. The one path where a mistake destroys data that exists nowhere else.
        """
        machine_id = self._require_link(registration)
        logs, rejected = parse_attlog(body)
        sent = len(logs) + len(rejected)

        if rejected:
            # Counted in the acknowledgement, so the device moves on, but recorded loudly: an
            # unparseable punch line is either a dead device clock or firmware we do not yet
            # understand, and both need a human.
            self._log.warn(
                "Some ATTLOG lines were unusable (no PIN or no valid timestamp).",
                serial=registration.serial,
                rejected=len(rejected),
                sample=rejected[0][:200],
            )
            self._safe_archive_unparsed(registration.serial, "ATTLOG", rejected)

        if not logs:
            self._log.info("ATTLOG upload contained no usable punches.", serial=registration.serial, sent=sent)
            return responses.ok_count(sent)

        # Archive before projecting: if the dedup or insert below has a bug, the raw punches are
        # already durable and replayable.
        #
        # Both archives, not one. ADMS_ATTLOG_RAW holds the parsed record, which is what a replay into
        # CheckInOut needs. ADMS_PUSH_LOG holds the body as sent, which is the only thing that helps
        # when the PARSER is what was wrong -- and a parser bug is invisible in the parsed copy by
        # definition. This was missed in the first implementation: the two payload kinds most worth
        # replaying were the two that had no verbatim copy.
        self._archive_request(request, registration, "ATTLOG", body, sent)
        archived = self._attendance.archive_attlog(registration.serial, logs)

        inserted = self._insert_punches(logs, machine_id, registration.machine_name)

        # Only now is it safe to move the cursor.
        self._advance_stamp(registration.serial, "ATTLOG", stamp)

        # Close the enrolment loop: a punch from someone the roster does not know means the roster is
        # behind what the devices know, and the device can be asked. Deliberately after the stamp, and
        # wrapped, so nothing about enrolment can cost us an acknowledged punch.
        requested = self._request_missing_employees(registration, logs)

        self._log.info(
            "ATTLOG stored.",
            serial=registration.serial,
            machine_id=machine_id,
            sent=sent,
            usable=len(logs),
            inserted=inserted,
            duplicates=len(logs) - inserted,
            archived=archived,
            enrolment_requested=requested,
        )
        return responses.ok_count(sent)

    def _request_missing_employees(
        self, registration: DeviceRegistration, logs: list[AttendanceLog]
    ) -> int:
        """
        For every PIN in this batch with no ``NHANVIEN`` row, queue a request to the device for that
        user's record and fingerprints. Returns how many PINs were newly asked about.

        Why this exists
        ---------------
        A punch is accepted even when the PIN is unknown -- refusing it would discard attendance because
        the roster lagged, which is the wrong trade. But that leaves an orphan row that no report can
        attribute, and previously the only cure was for someone to notice and pull the roster by hand.
        Now the arrival of an unattributable punch is itself the trigger to go and get the person.

        It also makes ``dbo.TEMPLATE`` self-healing. Enrolment data lives on the hardware, so a lost or
        wiped template table refills as people use the readers, without re-enrolling anyone's fingers.

        The cooldown is what makes this safe rather than a runaway
        ---------------------------------------------------------
        ADMS has no synchronous request. Asking means appending to ``ADMS_COMMAND`` and waiting for the
        device's next poll, which is up to ``poll_delay`` seconds away. In that window the same unknown
        person will very likely punch again -- and again after that, if they are genuinely absent from
        the device too. Without a cooldown each punch would queue two more commands and the queue would
        grow without bound while never succeeding.

        So a PIN this device was already asked about within ``enroll_query_cooldown`` is skipped,
        counting commands in **any** status. Only counting outstanding ones would still loop forever
        against a device that cannot answer.

        Best-effort throughout: the punches are already committed and acknowledged, and no failure here
        may change that.
        """
        if not self._settings.enroll_query_enabled:
            return 0

        pins = {log.numeric_pin for log in logs}
        pins.discard(None)
        if not pins:
            return 0

        try:
            missing = self._employees.missing_employee_pins(pins)  # type: ignore[arg-type]
            if not missing:
                return 0

            since = self._clock.utc_now() - self._settings.enroll_query_cooldown
            already = self._commands.pins_with_recent_request(registration.serial, missing, since)
            to_ask = sorted(missing - already)

            if already:
                self._log.debug(
                    "Skipped enrolment requests still inside the cooldown.",
                    serial=registration.serial,
                    pins=sorted(already),
                )
            if not to_ask:
                return 0

            # Capped per batch. A device coming back from a long outage can carry hundreds of unknown
            # PINs, and turning that into hundreds of queued commands would swamp its command channel
            # and delay everything else. The rest are picked up on subsequent batches, because the
            # cooldown only suppresses PINs actually asked about.
            capped = to_ask[: self._settings.enroll_query_max_per_batch]

            # The wording is passed through from configuration rather than baked in, because the
            # accepted table token differs across firmware builds and this is the one part of the
            # enrolment path never verified against hardware. Blank -- the default -- means the
            # documented spelling; a site that sees a negative ADMS_COMMAND.ReturnCode corrects it with
            # ADMS_QUERY_USERINFO_COMMAND / ADMS_QUERY_FINGERTMP_COMMAND instead of a code change.
            for pin in capped:
                self._commands.enqueue(
                    registration.serial,
                    cmd.query_user_info(str(pin), self._settings.query_userinfo_command),
                )
                if self._settings.enroll_query_include_fingerprints:
                    self._commands.enqueue(
                        registration.serial,
                        cmd.query_fingerprints(str(pin), self._settings.query_fingertmp_command),
                    )

            self._log.info(
                "Queued enrolment requests for PINs the roster does not know.",
                serial=registration.serial,
                pins=capped,
                deferred=len(to_ask) - len(capped),
                fingerprints=self._settings.enroll_query_include_fingerprints,
            )
            return len(capped)
        except Exception as exc:  # noqa: BLE001
            self._log.warn(
                "Could not queue enrolment requests; the punches are already stored.",
                exc,
                serial=registration.serial,
            )
            return 0

    def _insert_punches(self, logs: list[AttendanceLog], machine_id: int, machine_name: str) -> int:
        """
        Insert punches, suppressing ones already stored.

        The existing-key window is derived from the batch itself — ``[min, max + 1s)`` — rather
        than the whole day the desktop app uses. A push batch spans seconds, so the tight bound
        turns the dedup lookup into an index seek over a handful of rows instead of a scan of
        every punch that machine recorded today.

        Both writers dedupe on the same ``(MaChamCong, GioCham)`` key, which is what lets this
        service and the desktop tool run against one database without doubling anything up.
        """
        stamps = [log.timestamp for log in logs]
        window_start = min(stamps)
        window_end = max(stamps) + dt.timedelta(seconds=1)

        existing = self._attendance.existing_punch_keys(machine_id, window_start, window_end)
        return self._attendance.add_attendance(
            logs,
            machine_id=machine_id,
            machine_name=machine_name,
            existing_keys=existing,
        )

    def _operlog(
        self, request: AdmsRequest, registration: DeviceRegistration, body: str, stamp: str
    ) -> AdmsResponse:
        """
        Users, templates and device operations.

        Requires a link even though ``NHANVIEN`` and the template tables have no machine column:
        an unlinked serial is an unverified claim about which site it belongs to, and a roster is
        not something to accept on an unverified claim.
        """
        self._require_link(registration)
        batch = parse_operlog(body, serial=registration.serial, stamp=stamp)

        # Verbatim copy before interpreting, for the same reason as ATTLOG: this is the payload whose
        # grammar is most likely to change with firmware, so the body as sent is what makes a future
        # parser fix applicable retroactively.
        self._archive_request(request, registration, "OPERLOG", body, batch.record_count)

        written = self._persist_operlog(registration, batch)

        self._advance_stamp(registration.serial, "OPERLOG", stamp)

        self._log.info(
            "OPERLOG stored.",
            serial=registration.serial,
            sent=batch.record_count,
            users=len(batch.users),
            employees_upserted=written["employees"],
            fingers=written["fingers"],
            faces=written["faces"],
            operations=written["operations"],
            photos=len(batch.photos),
            unparsed=len(batch.unparsed),
        )
        return responses.ok_count(batch.record_count)

    def _persist_operlog(self, registration: DeviceRegistration, batch: PushBatch) -> dict[str, int]:
        """
        Write the parts of an ``OPERLOG`` batch that ATTENDANCEDB has a home for.

        ``BIODATA`` is folded into the fingerprint and face sets first, so firmware that sends
        the unified envelope produces the same rows as firmware that sends ``FP``/``FACE``.
        Types with no column (palm, visible-light face) are counted and archived, never silently
        dropped — an unexplained gap between "device uploaded 40" and "DB has 12" is the kind of
        thing that costs a day to diagnose.
        """
        fingers = list(batch.fingers)
        faces = list(batch.faces)
        unsupported_bio = 0

        for bio in batch.biodata:
            if bio.bio_type == bio.TYPE_FINGERPRINT:
                fingers.append(bio.as_finger())
            elif bio.bio_type == bio.TYPE_FACE:
                faces.append(bio.as_face())
            else:
                unsupported_bio += 1

        if unsupported_bio:
            self._log.info(
                "Biometric types with no ATTENDANCEDB column were archived only.",
                serial=registration.serial,
                count=unsupported_bio,
            )

        employees = self._employees.upsert_employees(batch.users) if batch.users else 0
        written_fingers = self._templates.save_fingerprints(fingers) if fingers else 0
        written_faces = self._templates.save_faces(faces) if faces else 0

        # multi-device-employee-sync, Requirement 26.1-26.2, 26.9: after the writes above commit
        # (this method runs inside _operlog's already-committed transaction by the time it
        # returns), never before -- Fan_Out is a side effect of an already-durable change, never
        # a precondition for one.
        if self._roster_sync is not None and registration.sync_group and (batch.users or fingers or faces):
            self._fan_out_roster_changes(registration, batch.users, fingers, faces)

        # Delete fan-out, device side: a device's own OPLOG reporting a delete operation. Gated
        # on ADMS_ROSTER_SYNC_DELETE_OPCODES being non-empty as well as the two flags above --
        # see Settings.roster_sync_delete_opcodes' own docstring for why an empty list (the
        # default) must disable this regardless of roster_sync_fanout_deletes: the OpCode-to-
        # "delete" mapping is not confirmed against a device, and a wrong guess here would
        # fan out a deletion nothing asked for.
        if (
            self._roster_sync is not None
            and registration.sync_group
            and self._settings.roster_sync_fanout_deletes
            and self._settings.roster_sync_delete_opcodes
            and batch.operations
        ):
            self._fan_out_device_deletes(registration, batch.operations)

        # Archives are best-effort: they are diagnostic value, and losing a photo row must not
        # cost the roster write that already succeeded.
        operations = 0
        if batch.operations:
            try:
                operations = self._archive.archive_operations(registration.serial, batch.operations)
            except Exception as exc:  # noqa: BLE001
                self._log.warn("Could not archive device operations.", exc, serial=registration.serial)
        if batch.photos:
            try:
                self._archive.archive_photos(registration.serial, batch.photos)
            except Exception as exc:  # noqa: BLE001
                self._log.warn("Could not archive user photos.", exc, serial=registration.serial)
        if batch.unparsed:
            self._log.warn(
                "OPERLOG contained record kinds this version does not parse.",
                serial=registration.serial,
                count=len(batch.unparsed),
                sample=batch.unparsed[0][:200],
            )
            self._safe_archive_unparsed(registration.serial, "OPERLOG", batch.unparsed)

        return {
            "employees": employees,
            "fingers": written_fingers,
            "faces": written_faces,
            "operations": operations,
        }

    def _photo_table(
        self,
        registration: DeviceRegistration,
        table: str,
        body: str,
        stamp: str,
        request: AdmsRequest,
    ) -> AdmsResponse:
        """
        Attendance and enrollment photos.

        Archived only — ATTENDANCEDB has no image column. Acknowledged all the same, because a
        device that cannot hand off its photo queue eventually stops uploading *anything*.
        """
        count = len(split_lines(body)) or 1
        self._archive_request(request, registration, table, body, count)
        self._advance_stamp(registration.serial, "ATTPHOTO", stamp)
        self._log.info("Photo payload archived.", serial=registration.serial, table=table, records=count)
        return responses.ok_count(count)

    def _get_request(self, registration: DeviceRegistration) -> AdmsResponse:
        """
        Hand the device its queued commands.

        An unlinked device gets ``OK`` (nothing queued) rather than an error: this is the poll
        that keeps the session alive, and failing it would take the device offline just when an
        operator is trying to see it in order to link it.
        """
        if not registration.is_linked:
            return responses.ok()

        commands = self._commands.dequeue(registration.serial, self._settings.max_commands_per_poll)
        if commands:
            self._log.info(
                "Dispatched commands.",
                serial=registration.serial,
                count=len(commands),
                ids=[c.command_id for c in commands],
            )
        return responses.text(render_commands(commands))

    def _device_cmd(self, request: AdmsRequest, registration: DeviceRegistration) -> AdmsResponse:
        """Record command results."""
        acks = parse_acks(decode_body(request.body))
        if not acks:
            # Not an error: some firmware polls this path with an empty body.
            return responses.ok()

        updated = self._commands.ack(registration.serial, acks)
        failures = [a for a in acks if not a.succeeded]
        if failures:
            self._log.warn(
                "Device reported command failures.",
                serial=registration.serial,
                failures=[{"id": a.command_id, "return": a.return_code, "cmd": a.command} for a in failures],
            )
        self._log.info(
            "Command acks recorded.", serial=registration.serial, acks=len(acks), updated=updated
        )
        return responses.ok()

    def _query_data(self, request: AdmsRequest, registration: DeviceRegistration) -> AdmsResponse:
        """
        Results of a server-issued query command (``DATA QUERY``, ``GET OPTIONS``).

        The body reuses the ``OPERLOG`` grammar, so it is parsed and persisted the same way. The
        distinction that matters is *why* the data arrived — solicited here, spontaneous there —
        which is recorded in the archive's route field.
        """
        self._require_link(registration)
        query_type = (request.q("type") or "").strip()
        body = decode_body(request.body)

        if query_type.lower() == "options":
            return self._device_options(request, registration, body)

        batch = parse_operlog(body, table=f"QUERY:{query_type or 'unknown'}", serial=registration.serial)
        self._archive_request(request, registration, f"QUERY:{query_type}", body, batch.record_count)
        written = self._persist_operlog(registration, batch)

        self._log.info(
            "Query results stored.",
            serial=registration.serial,
            query_type=query_type,
            sent=batch.record_count,
            **written,
        )
        return responses.ok_count(batch.record_count)

    def _file_data(self, request: AdmsRequest, registration: DeviceRegistration) -> AdmsResponse:
        """Binary uploads (photo files, firmware blobs). Acknowledged, archived, not interpreted."""
        size = len(request.body)
        self._archive_request(request, registration, "FILE", f"<{size} bytes>", 1)
        self._log.info("File payload acknowledged.", serial=registration.serial, bytes=size)
        return responses.ok()

    # ── Shared helpers ───────────────────────────────────────────────────────────────────

    def _advance_stamp(self, serial: str, table: str, stamp: str) -> None:
        """
        Move the resumption cursor, after the data it covers is committed.

        Best-effort on failure. A stamp that fails to advance makes the device re-send records we
        already hold, which dedup absorbs. The reverse — advancing past data we did not store —
        is unrecoverable, which is why this is called last and never speculatively.
        """
        if not stamp:
            return
        try:
            self._registry.advance_stamp(serial, table, stamp)
        except Exception as exc:  # noqa: BLE001
            self._log.warn(
                "Could not advance the resumption stamp; the device will re-send and dedup will "
                "absorb it.",
                exc,
                serial=serial,
                table=table,
            )

    def _archive_request(
        self,
        request: AdmsRequest,
        registration: DeviceRegistration,
        table: str,
        body: str,
        record_count: int,
    ) -> None:
        """Store the verbatim payload, subject to the configured size cap. Best-effort."""
        if not self._settings.archive_raw_bodies:
            return
        try:
            limit = self._settings.archive_body_limit
            clipped = body if len(body) <= limit else body[:limit] + f"…[truncated, {len(body)} chars]"
            self._archive.archive_request(
                serial=registration.serial,
                route=request.path,
                table=table,
                query=_query_for_log(request),
                body=clipped,
                record_count=record_count,
            )
        except Exception as exc:  # noqa: BLE001
            self._log.warn("Could not archive the raw request body.", exc, serial=registration.serial)

    def _safe_archive_unparsed(self, serial: str, table: str, lines: list[str]) -> None:
        try:
            self._archive.archive_unparsed(serial, table, lines)
        except Exception as exc:  # noqa: BLE001
            self._log.warn("Could not archive unparsed lines.", exc, serial=serial)

    # ── multi-device-employee-sync ──────────────────────────────────────────────────────────

    def _fan_out_roster_changes(
        self,
        registration: DeviceRegistration,
        users,
        fingers,
        faces,
    ) -> None:
        """
        Fan_Out entry point (Requirement 26). Called only after the ``NHANVIEN``/template writes
        it is reporting on have already committed -- see the call site in ``_persist_operlog``.

        Never raises into the caller (Requirement 26.7, 26.9): the upload that triggered this is
        already committed and will be acknowledged regardless of what happens here. One PIN's
        Fan_Out failure is logged and does not stop the rest of the batch.
        """
        fingers_by_pin: dict[int, list] = {}
        for finger in fingers:
            pin = _to_int(finger.pin)
            if pin is not None:
                fingers_by_pin.setdefault(pin, []).append(finger)

        faces_by_pin: dict[int, list] = {}
        for face in faces:
            pin = _to_int(face.pin)
            if pin is not None:
                faces_by_pin.setdefault(pin, []).append(face)

        pins: set[int] = set()
        for user in users:
            numeric = user.numeric_pin
            if numeric is not None:
                pins.add(numeric)
        pins.update(fingers_by_pin)
        pins.update(faces_by_pin)

        for pin in sorted(pins):
            try:
                result = self._roster_sync.fan_out(
                    registration.serial,
                    registration.sync_group,
                    pin,
                    fingers=fingers_by_pin.get(pin, []),
                    faces=faces_by_pin.get(pin, []),
                )
            except Exception as exc:  # noqa: BLE001
                self._log.warn(
                    "Could not fan out a roster change.", exc, serial=registration.serial, pin=pin
                )
                continue

            # Requirement 30.4: zero-command Fan_Outs (no eligible targets, or the PIN vanished
            # before Fan_Out could read it) are DEBUG, not INFO, so an estate with only one device
            # per group -- where every Fan_Out enqueues nothing -- does not dominate the log.
            if result.commands_enqueued or result.targets_notified:
                self._log.info(
                    "Fanned out a roster change.",
                    serial=registration.serial,
                    pin=pin,
                    targets=result.targets_notified,
                    commands=result.commands_enqueued,
                    deferred=result.deferred,
                )
            else:
                self._log.debug(
                    "Fan_Out found nothing to do.", serial=registration.serial, pin=pin
                )

    def _fan_out_device_deletes(
        self, registration: DeviceRegistration, operations: list[OperationEvent]
    ) -> None:
        """
        Delete fan-out, device side. Only reached when ``ADMS_ROSTER_SYNC_DELETE_OPCODES`` is
        non-empty (checked at the call site), i.e. an operator has confirmed at least one real
        OpCode against this estate's own ``ADMS_OPERLOG`` data.

        NOT VERIFIED AGAINST FIRMWARE BEYOND THE OPERATOR-SUPPLIED OPCODE ITSELF. Which field
        carries the deleted user's PIN is inferred from this module's own OPLOG grammar comment
        (``OPLOG <op> <admin> <time> <obj> <p1> <p2> <p3>``, where positional parsing places the
        object field into ``param1``) -- ``param1`` is tried first, falling back to
        ``operator_pin`` only because some builds are known to put a single subject PIN there
        instead. An event where neither field parses as a PIN is skipped and logged, never
        guessed at with the admin's own PIN, which would fan out a deletion for the wrong person.
        """
        opcodes = self._settings.roster_sync_delete_opcodes
        for event in operations:
            if event.op_code not in opcodes:
                continue

            pin = _to_int(event.param1) or _to_int(event.operator_pin)
            if pin is None:
                self._log.warn(
                    "OPLOG matched a configured delete OpCode but no field parsed as a PIN.",
                    serial=registration.serial,
                    op_code=event.op_code,
                    raw=event.raw[:200],
                )
                continue

            try:
                result = self._roster_sync.fan_out_delete(registration.serial, registration.sync_group, pin)
            except Exception as exc:  # noqa: BLE001
                self._log.warn(
                    "Could not fan out a device-side deletion.", exc, serial=registration.serial, pin=pin
                )
                continue

            self._log.info(
                "Fanned out a device-side deletion.",
                serial=registration.serial,
                pin=pin,
                op_code=event.op_code,
                targets=result.targets_notified,
                commands=result.commands_enqueued,
            )

    def _maybe_backfill(self, registration: DeviceRegistration) -> None:
        """
        Backfill entry point (Requirement 27). Called on every route for a Linked_Device with a
        Sync_Group, before the route handler -- see the call site in ``_dispatch``.

        ``backfill_if_due`` itself decides whether anything is actually owed (Requirement 27.6's
        zero-cost guarantee); this wrapper's only job is to make that call best-effort so it can
        never block or fail the request it rode in on.
        """
        try:
            result = self._roster_sync.backfill_if_due(registration)
        except Exception as exc:  # noqa: BLE001
            self._log.warn("Could not check/run Backfill.", exc, serial=registration.serial)
            return

        if result is None:
            return

        if result.enqueued:
            self._log.info(
                "Backfilled a device.",
                serial=result.serial,
                enqueued=result.enqueued,
                remaining=result.remaining,
            )
        else:
            self._log.debug(
                "Backfill was due but had nothing left to enqueue.",
                serial=result.serial,
                remaining=result.remaining,
            )

    def _maybe_reconcile_deletions(self, sync_group: str) -> None:
        """
        DB-side delete detection entry point. Called on every route for a Linked_Device with a
        Sync_Group, alongside Backfill -- see the call site in ``_dispatch``. Best-effort: never
        blocks or fails the request it rode in on.
        """
        try:
            result = self._roster_sync.reconcile_deletions(sync_group)
        except Exception as exc:  # noqa: BLE001
            self._log.warn("Could not run DB-side delete reconciliation.", exc, sync_group=sync_group)
            return

        if result is None:
            return

        self._log.info(
            "Reconciled DB-side deletions.",
            sync_group=result.sync_group,
            pins=result.deleted_pins,
            commands_enqueued=result.commands_enqueued,
        )


def _to_int(pin: str) -> int | None:
    """Same tolerant PIN parsing every model's own ``numeric_pin`` property already applies,
    for the template models (``FingerTemplate``/``FaceTemplate``) whose ``pin`` field is a bare
    string rather than a property -- multi-device-employee-sync's own read, not a duplicate of
    logic those models are missing."""
    try:
        return int(pin.strip())
    except (AttributeError, ValueError):
        return None


def _query_for_log(request: AdmsRequest) -> str:
    """
    Rebuild the query string for the archive.

    ``SN`` is kept (it is the device identity, and the archive is keyed by it anyway) but any
    parameter whose name hints at a credential is redacted — a deployment that puts a token in
    the device's URL should not have it land in a table people query casually.
    """
    parts = []
    for key, value in request.query.items():
        if key.lower() in ("key", "token", "secret", "password", "pwd"):
            value = "***REDACTED***"
        parts.append(f"{key}={value}")
    return "&".join(parts)


def _public_message(exc: AdmsError) -> str:
    """
    The body a device sees for a failure.

    Fixed phrases, never ``str(exc)``. Devices write the body to a log an installer can read, and
    it is the one place an internal detail could cross onto an untrusted network.
    """
    if isinstance(exc, (DeviceNotRegisteredError, DeviceDisabledError)):
        return "Unauthorized"
    if isinstance(exc, DeviceNotLinkedError):
        return "Device Not Configured"
    if isinstance(exc, AttendanceDbError):
        return "Storage Unavailable"
    if isinstance(exc, ProtocolError):
        return "Bad Request"
    return "Server Error"
