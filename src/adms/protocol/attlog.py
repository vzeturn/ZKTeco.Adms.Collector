"""
``table=ATTLOG`` parser — the punch upload, and the only payload whose loss is unrecoverable.

Positional layout, tab separated::

    PIN  Timestamp  Status  Verify  WorkCode  Reserved1  Reserved2  [MaskFlag  Temperature]

Only the first two fields are guaranteed. Everything after ``Verify`` varies by firmware
generation — the trailing mask/temperature pair arrived with the 2020 health-screening models —
so the parser reads what is present and defaults the rest instead of validating arity.

A few builds send the same data as ``Key=Value`` fields. Both forms are accepted, decided per
line, because a single upload from a mixed-firmware estate can contain either.
"""

from __future__ import annotations

from ..models import AttendanceLog, VerifyMode
from .text import parse_kv, parse_timestamp, split_fields, split_lines, to_int

__all__ = ["parse_attlog"]


def parse_attlog(body: str) -> tuple[list[AttendanceLog], list[str]]:
    """
    Parse an ``ATTLOG`` body.

    Returns ``(logs, rejected)``. A line lands in ``rejected`` only when it has no usable PIN
    or no usable timestamp — a punch that cannot be attributed to a person at a point in time
    has nowhere to go in ``CheckInOut``. Rejected lines are still **counted** in the ``OK: n``
    reply and archived verbatim: withholding the acknowledgement would make the device resend
    the same unparseable line forever, blocking every good punch queued behind it.
    """
    logs: list[AttendanceLog] = []
    rejected: list[str] = []

    for line in split_lines(body):
        log = _parse_line(line)
        if log is None:
            rejected.append(line)
        else:
            logs.append(log)

    return logs, rejected


def _parse_line(line: str) -> AttendanceLog | None:
    fields = split_fields(line)
    if not fields:
        return None

    # Key=Value form: detected by the first field carrying a '=' rather than by scanning the
    # whole line, because Reserved fields in the positional form occasionally contain one.
    if "=" in fields[0]:
        return _parse_kv_line(fields)
    return _parse_positional_line(fields)


def _parse_positional_line(fields: list[str]) -> AttendanceLog | None:
    if len(fields) < 2:
        return None

    pin = fields[0].strip()
    if not pin:
        return None

    timestamp = parse_timestamp(fields[1])
    if timestamp is None:
        return None

    def at(index: int, default: str = "") -> str:
        return fields[index].strip() if len(fields) > index else default

    return AttendanceLog(
        pin=pin,
        timestamp=timestamp,
        status=to_int(at(2), 0),
        verify=VerifyMode.parse(at(3, "-1")),
        work_code=to_int(at(4), 0),
        reserved1=at(5),
        reserved2=at(6),
    )


def _parse_kv_line(fields: list[str]) -> AttendanceLog | None:
    kv = parse_kv(fields)

    pin = (kv.get("pin") or kv.get("userid") or kv.get("enrollnumber") or "").strip()
    if not pin:
        return None

    timestamp = parse_timestamp(kv.get("time") or kv.get("datetime") or kv.get("checktime") or "")
    if timestamp is None:
        return None

    return AttendanceLog(
        pin=pin,
        timestamp=timestamp,
        status=to_int(kv.get("status"), 0),
        verify=VerifyMode.parse(kv.get("verify", "-1")),
        work_code=to_int(kv.get("workcode"), 0),
        reserved1=kv.get("reserved1", ""),
        reserved2=kv.get("reserved2", ""),
    )
