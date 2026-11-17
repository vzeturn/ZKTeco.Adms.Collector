"""
Handshake response builder — the reply to ``GET /iclock/cdata?SN=..&options=all``.

This single response configures the device for the whole session. Getting it wrong is the most
common reason a correctly-wired device uploads nothing at all, and the failure is silent: the
device just sits there. The body is bare ``Key=Value`` lines after a mandatory first line::

    GET OPTION FROM: <serial>
    Stamp=...
    ...

Design notes that matter:

* **The first line is not optional and its shape is exact.** Firmware string-matches
  ``GET OPTION FROM:``; a JSON body, an HTML error page or even a leading blank line makes the
  device treat the server as broken.
* **Two stamp vocabularies are emitted.** Pre-2.2 firmware reads ``Stamp``/``OpStamp``/
  ``PhotoStamp``; 2.4+ reads ``ATTLOGStamp``/``OPERLOGStamp``/``ATTPHOTOStamp``. Devices
  ignore keys they do not know, so sending both is how one server supports a mixed estate
  without sniffing versions.
* **Stamps are resumption cursors, not counters.** The device uses the value we echo to decide
  what it still owes us. Echoing a stamp *ahead* of what we actually stored tells the device
  those records are safely filed and it may discard them, so the stored stamp is only advanced
  after a successful commit (see :mod:`adms.service`).
* **``Realtime=1`` is what makes this a live feed** rather than a batch drop at
  ``TransTimes``. Without it, punches arrive twice a day.
"""

from __future__ import annotations

from ..models import DeviceRegistration

__all__ = ["build_handshake", "DEFAULT_TRANS_FLAG"]

#: Which record kinds the device should upload. Order and spelling are copied from the vendor's
#: own ADMS server: firmware does a substring match per token, so an unexpected token is
#: harmless but a misspelled one silently disables that record kind.
#:
#: ``AttPhoto``/``UserPic`` are included even though ATTENDANCEDB has nowhere to store an image —
#: they are archived only. The alternative, omitting them, means an operator investigating a
#: disputed punch finds no photo was ever collected.
DEFAULT_TRANS_FLAG = (
    "TransData AttLog OpLog AttPhoto EnrollUser ChgUser EnrollFP ChgFP FPImag UserPic"
)


def build_handshake(
    registration: DeviceRegistration,
    *,
    server_version: str = "2.4.1",
    delay: int = 10,
    error_delay: int = 30,
    trans_times: str = "00:00;14:00",
    trans_interval: int = 1,
    trans_flag: str = DEFAULT_TRANS_FLAG,
    realtime: bool = True,
    encrypt: bool = False,
    timezone_offset: int | None = None,
    extra: dict[str, str] | None = None,
) -> str:
    """
    Render the handshake body for a registered device.

    ``delay`` is the poll interval for ``getrequest`` in seconds and therefore the worst-case
    latency of a queued command. ``error_delay`` is how long the device waits after a non-2xx
    reply — the retry that protects unacknowledged punches.

    Lines are joined with CRLF: that is what the vendor server emits, and while most firmware
    accepts bare LF, some older builds do not.
    """
    tz = registration.timezone_offset if timezone_offset is None else timezone_offset

    lines = [
        f"GET OPTION FROM: {registration.serial}",
        # Legacy stamp names (pre-2.2 firmware).
        f"Stamp={registration.attlog_stamp}",
        f"OpStamp={registration.operlog_stamp}",
        f"PhotoStamp={registration.attphoto_stamp}",
        # Modern stamp names (pushver 2.4+).
        f"ATTLOGStamp={registration.attlog_stamp}",
        f"OPERLOGStamp={registration.operlog_stamp}",
        f"ATTPHOTOStamp={registration.attphoto_stamp}",
        f"ErrorDelay={error_delay}",
        f"Delay={delay}",
        f"TransTimes={trans_times}",
        f"TransInterval={trans_interval}",
        f"TransFlag={trans_flag}",
        f"TimeZone={tz}",
        f"Realtime={1 if realtime else 0}",
        f"Encrypt={1 if encrypt else 0}",
        f"ServerVer={server_version}",
    ]

    # Device clock synchronisation is deliberately NOT sent. Some firmware honours a
    # 'CurrentTime' option here, which would silently rewrite the clock of every device that
    # connects. The whole schema records local wall-clock, so a one-hour server/site mismatch
    # would corrupt attendance rather than fix it — clock setting stays a deliberate,
    # per-device command (see adms.protocol.commands.set_time).

    for key, value in (extra or {}).items():
        lines.append(f"{key}={value}")

    return "\r\n".join(lines) + "\r\n"
