"""
Server → device commands: rendering the ``getrequest`` reply and parsing the ``devicecmd`` ack.

This is the only channel that pushes *down* to a device in ADMS mode, and it is strictly
pull-based: the server cannot initiate anything. A queued command waits until the device's next
``getrequest`` poll, so the ``Delay`` value in the handshake is the worst-case latency.

Wire format
-----------
Reply to ``GET /iclock/getrequest?SN=..``, one command per line::

    C:<id>:<body>

``OK`` (no commands) when the queue is empty. The device then acks each one with a POST to
``/iclock/devicecmd``::

    ID=<id>&Return=<code>&CMD=<name>

``Return`` is ``>= 0`` on success. Several acks may share one body, separated by newlines.

The builders below cover the commands that make sense for a collector whose database is the
source of truth for the roster. They are intentionally a small set: this service's job is
receiving, and every command it can issue is one an operator could otherwise be surprised by.
"""

from __future__ import annotations

import datetime as dt

from ..models import CommandAck, DeviceCommand, DeviceUser
from .text import split_lines, to_int

__all__ = [
    "render_commands",
    "parse_acks",
    "check",
    "reboot",
    "clear_log",
    "clear_data",
    "info",
    "set_time",
    "update_user",
    "update_fingertmp",
    "update_facetmp",
    "delete_userinfo",
    "delete_user",
    "unlock_door",
    "query_user_info",
    "query_fingerprints",
    "DEFAULT_QUERY_USERINFO",
    "DEFAULT_QUERY_FINGERTMP",
]

#: The wording used when no override is configured. Named constants rather than literals inside the
#: builders so that ``Settings.query_userinfo_command`` / ``query_fingertmp_command`` have something to
#: fall back to that a reader, a test and task 16.2's firmware note can all point at.
DEFAULT_QUERY_USERINFO = "DATA QUERY USERINFO PIN={pin}"
DEFAULT_QUERY_FINGERTMP = "DATA QUERY FINGERTMP PIN={pin}"


# ── Rendering / acking ───────────────────────────────────────────────────────────────────


def render_commands(commands: list[DeviceCommand]) -> str:
    """
    Render a ``getrequest`` reply.

    An empty queue must answer ``OK``, not an empty body: a zero-length response reads as a
    connection failure to some firmware, which then backs off as if the server were down.
    """
    if not commands:
        return "OK"
    return "\r\n".join(command.render() for command in commands) + "\r\n"


def parse_acks(body: str) -> list[CommandAck]:
    """
    Parse a ``devicecmd`` body into acks.

    Tolerates both separators seen in the wild — one ack per line, or several joined by ``&``
    on a single line — by treating ``&`` as a field separator and starting a new ack whenever
    an ``ID=`` appears. Unparseable fragments are skipped rather than raising: the ack is
    bookkeeping, and rejecting the POST would make the device resend acks in a loop instead of
    getting on with the next command.
    """
    acks: list[CommandAck] = []

    for line in split_lines(body):
        current: dict[str, str] = {}
        for pair in line.split("&"):
            key, _, value = pair.partition("=")
            key = key.strip().lower()
            if not key:
                continue
            if key == "id" and current:
                _append_ack(acks, current)
                current = {}
            current[key] = value.strip()
        if current:
            _append_ack(acks, current)

    return acks


def _append_ack(acks: list[CommandAck], fields: dict[str, str]) -> None:
    if "id" not in fields:
        return
    command_id = to_int(fields.get("id"), -1)
    if command_id < 0:
        return
    acks.append(
        CommandAck(
            command_id=command_id,
            # A missing Return is treated as failure (-1). Assuming success for an ack that
            # never said so would mark commands Done that may never have run.
            return_code=to_int(fields.get("return"), -1),
            command=fields.get("cmd", ""),
        )
    )


# ── Command bodies ───────────────────────────────────────────────────────────────────────
#
# These return the body only; the id is assigned by the queue on enqueue, because the id must
# be the ADMS_COMMAND identity value for the ack to correlate.


def check() -> str:
    """Ask the device to re-sync its data with the server. Harmless, useful as a liveness poke."""
    return "CHECK"


def reboot() -> str:
    """Restart the device. Punches already buffered survive; in-flight enrollment does not."""
    return "REBOOT"


def clear_log() -> str:
    """
    Erase the device's attendance buffer.

    Destructive and rarely correct: the buffer is the safety net that lets a device survive an
    outage of this service. Only issue it against a device whose punches are confirmed stored.
    """
    return "CLEAR LOG"


def clear_data() -> str:
    """Erase users, templates *and* logs. The full wipe — effectively a factory reset of data."""
    return "CLEAR DATA"


def info() -> str:
    """Ask the device to re-upload its ``options`` self-description."""
    return "INFO"


def set_time(when: dt.datetime) -> str:
    """
    Set the device clock.

    Deliberately explicit rather than automatic on handshake: every timestamp in ATTENDANCEDB is
    local wall-clock, so moving a device's clock retroactively changes how its punches line up
    with everyone else's. ``when`` is naive local site time.
    """
    return f"SET OPTIONS DateTime={_zk_datetime(when)}"


def _zk_datetime(when: dt.datetime) -> int:
    """
    Encode a datetime in ZKTeco's packed integer form.

    ``((year-2000)*12*31 + (month-1)*31 + (day-1)) * 24*60*60 + hour*3600 + minute*60 + second``
    — the vendor's own encoding, which assumes 31-day months by design.
    """
    days = ((when.year - 2000) * 12 * 31) + ((when.month - 1) * 31) + (when.day - 1)
    return days * 86400 + when.hour * 3600 + when.minute * 60 + when.second


def _render_query(template: str, pin: str) -> str:
    """
    Substitute ``pin`` into an enrolment query template.

    ``str.replace`` rather than ``str.format`` or an f-string, and this is the whole reason the
    placeholder is spelled ``{pin}`` and still handled by hand: the template is operator-supplied free
    text, and a stray ``{`` from a copy-paste would make ``format`` raise ``KeyError`` or
    ``ValueError``. That exception would land inside the ATTLOG request path -- after the punches are
    already committed -- and turn a wording typo into a failed upload. ``str.replace`` cannot raise.

    A template with no placeholder gets ``PIN=<pin>`` appended, so an operator may write either
    ``DATA QUERY USER PIN={pin}`` or just ``DATA QUERY USER`` and get the same command. Both forms are
    accepted because the vendor guide shows the filter as a trailing clause, and asking someone to
    remember our placeholder syntax to correct a firmware incompatibility is one more thing to get
    wrong at the moment they are already debugging.
    """
    text = template.strip()
    if "{pin}" in text:
        return text.replace("{pin}", pin)
    return f"{text} PIN={pin}"


def query_user_info(pin: str, template: str = "") -> str:
    """
    Ask the device to upload one user's record.

    The device answers by POSTing to ``/iclock/querydata?SN=..&type=..&cmdid=..`` with the same
    ``USER ...`` grammar it uses for ``OPERLOG``, which is why no new parser was needed to receive it.

    Used by the auto-enrolment loop: a punch from a PIN with no ``NHANVIEN`` row triggers this, so the
    roster fills itself from whatever the devices already know instead of waiting for someone to notice.

    ``template`` is the wording to render, in one of two accepted forms: a string containing the literal
    placeholder ``{pin}``, which is replaced with ``pin``, or a string with no placeholder, which gets
    `` PIN=<pin>`` appended -- so an operator correcting a wording does not have to know which of the two
    this function expects. A blank ``template`` (the default) falls back to
    :data:`DEFAULT_QUERY_USERINFO`. In production the caller passes
    ``Settings.query_userinfo_command``, which is exactly the override the NOT VERIFIED note below asks
    for: a site whose firmware wants a different table token is corrected by configuration, not a code
    change. Rendering never raises, even against a template holding a stray ``{`` left over from a
    copy-paste -- see :func:`_render_query`, which is why this is safe to call from inside the ATTLOG
    request path after punches are already committed.

    NOT VERIFIED AGAINST FIRMWARE. The vendor guide documents ``DATA QUERY`` with a table name and a
    filter, and this is the spelling the reference ADMS server uses, but the accepted table token
    differs across builds (``USERINFO`` / ``USER`` / ``userinfo``). Override with
    ADMS_QUERY_USERINFO_COMMAND if a site's devices want something else -- and watch
    ``ADMS_COMMAND.ReturnCode`` after the first attempt: a negative value means the device rejected the
    wording, not that the user is absent.
    """
    return _render_query(template or DEFAULT_QUERY_USERINFO, pin)


def query_fingerprints(pin: str, template: str = "") -> str:
    """
    Ask the device to upload one user's fingerprint templates.

    Enrolment data lives on the hardware, so this is what makes ``dbo.TEMPLATE`` recoverable without
    re-enrolling anyone: the device is the source of truth and can be asked again.

    ``template`` takes the same two accepted forms as :func:`query_user_info`: a string with a literal
    ``{pin}`` placeholder that gets substituted, or a string with none, which gets `` PIN=<pin>``
    appended. A blank ``template`` falls back to :data:`DEFAULT_QUERY_FINGERTMP`. In production the
    caller passes ``Settings.query_fingertmp_command``. Rendering never raises, including against a
    template containing a stray ``{`` -- see :func:`_render_query`.

    Same caveat as :func:`query_user_info` about the table token; override with
    ADMS_QUERY_FINGERTMP_COMMAND.
    """
    return _render_query(template or DEFAULT_QUERY_FINGERTMP, pin)


def update_user(user: DeviceUser) -> str:
    """
    Create or update a user on the device (``DATA UPDATE USER``).

    Field order follows the vendor format. ``Name`` is sent as-is; the device stores whatever
    fits its own name length limit and truncates the rest, which is preferable to us guessing
    a per-model limit and truncating twice.
    """
    fields = [
        f"PIN={user.pin}",
        f"Name={user.name}",
        f"Pri={int(user.privilege)}",
        f"Passwd={user.password}",
        f"Card={user.card}",
        f"Grp={user.group or '1'}",
        f"TZ={user.timezone or '0000000000000000'}",
    ]
    return "DATA UPDATE USER " + "\t".join(fields)


def update_fingertmp(pin: str, finger_id: int, template: str, *, size: int | None = None, valid: int = 1) -> str:
    """
    Push one fingerprint template to a device (``DATA UPDATE FINGERTMP``).

    VERIFIED AGAINST FIRMWARE (Ver 6.60). A real template from ``dbo.TEMPLATE``,
    pushed with this exact field order, was accepted (``ReturnCode=0``); the same PIN queried
    back straight afterwards echoed the identical base64 payload, and the existing
    ``OPERLOG``/``querydata`` pipeline wrote it into ``dbo.TEMPLATE`` unmodified. This is the one
    push-direction command in this module with an end-to-end hardware confirmation behind it, not
    just a vendor-guide spelling.

    ``size`` defaults to the template string's own length, matching what a device's own ``FP``
    upload reports when it does not know a better value (see ``operlog.py``'s ``_parse_finger``,
    which does the same on the read side).
    """
    resolved_size = size if size is not None else len(template)
    fields = [
        f"PIN={pin}",
        f"FID={finger_id}",
        f"Size={resolved_size}",
        f"Valid={valid}",
        f"TMP={template}",
    ]
    return "DATA UPDATE FINGERTMP " + "\t".join(fields)


def update_facetmp(pin: str, face_id: int, template: str, *, size: int | None = None, valid: int = 1) -> str:
    """
    Push one face template to a device (``DATA UPDATE BIODATA``).

    NOT VERIFIED AGAINST FIRMWARE. ``dbo.Face`` held no rows when
    :func:`update_fingertmp` above was verified, so there was no real face template to push and
    confirm a round trip with. The field names (``PIN``/``FID``/``SIZE``/``VALID``/``TMP``) mirror
    what ``operlog.py``'s ``_parse_face`` already reads on the way in, on the theory that the
    upload and download grammars are symmetric the way ``update_fingertmp``'s were -- but that is
    an inference from this module's own read side, not a confirmed fact about any device's
    firmware. Gated behind ``ADMS_ROSTER_SYNC_PUSH_FACES`` (default off) for exactly this reason.
    """
    resolved_size = size if size is not None else len(template)
    fields = [
        f"PIN={pin}",
        f"FID={face_id}",
        f"SIZE={resolved_size}",
        f"VALID={valid}",
        f"TMP={template}",
    ]
    return "DATA UPDATE BIODATA " + "\t".join(fields)


def delete_userinfo(pin: str) -> str:
    """
    Delete one user and their templates from a device (``DATA DELETE USERINFO``).

    VERIFIED AGAINST FIRMWARE (Ver 6.60). ``DATA DELETE USER`` -- this module's
    previous wording, kept below only as a deprecated alias -- was rejected outright
    (``ReturnCode=-1004``) by a device. ``DATA DELETE USERINFO`` was accepted
    (``ReturnCode=0``), and a follow-up query for the same PIN came back with nothing, confirming
    the user record was actually gone rather than merely acknowledged.
    """
    return f"DATA DELETE USERINFO PIN={pin}"


def delete_user(pin: str) -> str:
    """
    Deprecated alias for :func:`delete_userinfo`.

    Kept only so an import of the old name does not break; a repository-wide search found no
    caller of this name at the time it was deprecated, so this is precautionary, not a migration
    for a known call site. Renders :func:`delete_userinfo`'s wording, not the literal
    ``DATA DELETE USER`` this function used to render -- that wording is confirmed rejected by
    real firmware (see :func:`delete_userinfo`'s docstring), and nothing in this codebase should
    ever enqueue it again, including through this alias.
    """
    return delete_userinfo(pin)


def unlock_door(seconds: int = 5) -> str:
    """
    Open the door for ``seconds``.

    Included because access-control models are the same hardware family, but note this is a
    physical-security action: whatever enqueues it needs a stronger authorisation story than
    the collector itself has.
    """
    return f"AC_UNLOCK={max(1, seconds)}"
