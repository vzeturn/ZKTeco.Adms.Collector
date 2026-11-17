"""
``table=OPERLOG`` parser — everything about the device that is not a punch.

Unlike ``ATTLOG``, each line is **tagged** with its record kind, and one body routinely mixes
kinds (creating a user uploads a ``USER`` line, its ``FP`` lines and an ``OPLOG`` line in a
single POST). Layouts, by tag::

    USER     PIN=..  Name=..  Pri=..  Passwd=..  Card=..  Grp=..  TZ=..  Verify=..  ViceCard=..
    FP       PIN=..  FID=..   Size=..  Valid=..  TMP=<base64>
    FACE     PIN=..  FID=..   SIZE=..  VALID=..  TMP=<base64>
    BIODATA  Pin=..  No=..    Index=.. Valid=..  Duress=..  Type=..  MajorVer=..  MinorVer=..
             Format=..  Tmp=<base64>
    USERPIC  PIN=..  FileName=..  Size=..  Content=<base64>
    OPLOG    <op>  <admin>  <time>  <obj>  <p1>  <p2>  <p3>

``BIODATA`` is the pushver 2.4+ envelope that supersedes ``FP``/``FACE``; firmware sends one
family or the other, occasionally both during a transition, so all three are supported.

Unrecognised tags (``SMS``, ``USER_SMS``, ``WORKCODE``, ``BIOPHOTO`` and whatever ships next)
are returned as unparsed rather than discarded, so the acknowledged count still matches what
the device sent and the raw line survives in the archive for diagnosis.
"""

from __future__ import annotations

from ..models import (
    BioTemplate,
    DeviceUser,
    FaceTemplate,
    FingerTemplate,
    OperationEvent,
    PushBatch,
    UserPrivilege,
    UserPhoto,
)
from .text import parse_kv, parse_timestamp, split_fields, split_lines, to_bool, to_int

__all__ = ["parse_operlog"]


def parse_operlog(body: str, *, table: str = "OPERLOG", serial: str = "", stamp: str = "") -> PushBatch:
    """Parse an ``OPERLOG`` body into a :class:`~adms.models.PushBatch`."""
    users: list[DeviceUser] = []
    fingers: list[FingerTemplate] = []
    faces: list[FaceTemplate] = []
    biodata: list[BioTemplate] = []
    photos: list[UserPhoto] = []
    operations: list[OperationEvent] = []
    unparsed: list[str] = []

    for line in split_lines(body):
        fields = split_fields(line)
        if not fields:
            continue

        # The tag is the leading token of the first field: 'USER PIN=1' arrives as one
        # tab-field whose head is the tag and whose tail is the first Key=Value pair.
        head, _, remainder = fields[0].partition(" ")
        tag = head.strip().upper()
        rest = [remainder.strip(), *fields[1:]] if remainder.strip() else list(fields[1:])

        if tag == "USER":
            parsed_user = _parse_user(rest)
            (users.append(parsed_user) if parsed_user else unparsed.append(line))
        elif tag == "FP":
            parsed_fp = _parse_finger(rest)
            (fingers.append(parsed_fp) if parsed_fp else unparsed.append(line))
        elif tag == "FACE":
            parsed_face = _parse_face(rest)
            (faces.append(parsed_face) if parsed_face else unparsed.append(line))
        elif tag == "BIODATA":
            parsed_bio = _parse_biodata(rest)
            (biodata.append(parsed_bio) if parsed_bio else unparsed.append(line))
        elif tag in ("USERPIC", "BIOPHOTO"):
            parsed_pic = _parse_photo(rest)
            (photos.append(parsed_pic) if parsed_pic else unparsed.append(line))
        elif tag == "OPLOG":
            operations.append(_parse_oplog(rest, line))
        else:
            unparsed.append(line)

    return PushBatch(
        table=table,
        serial=serial,
        stamp=stamp,
        users=users,
        fingers=fingers,
        faces=faces,
        biodata=biodata,
        photos=photos,
        operations=operations,
        unparsed=unparsed,
    )


def _parse_user(fields: list[str]) -> DeviceUser | None:
    kv = parse_kv(fields)
    pin = (kv.get("pin") or "").strip()
    if not pin:
        return None

    # 'Enable'/'Disable' is absent on most firmware; to_bool's default of True is what keeps a
    # user that simply did not report the flag from being written as disabled.
    return DeviceUser(
        pin=pin,
        name=kv.get("name", "").strip(),
        privilege=UserPrivilege.parse(kv.get("pri", "0")),
        password=kv.get("passwd", ""),
        # ViceCard is the secondary credential slot on dual-reader models; used only when the
        # primary Card field is empty so we never overwrite the real card with a spare.
        card=(kv.get("card") or kv.get("vicecard") or "").strip(),
        group=kv.get("grp", ""),
        timezone=kv.get("tz", ""),
        verify_mode=to_int(kv.get("verify"), -1),
        enabled=to_bool(kv.get("enable") or kv.get("enabled"), True),
    )


def _parse_finger(fields: list[str]) -> FingerTemplate | None:
    kv = parse_kv(fields)
    pin = (kv.get("pin") or "").strip()
    template = kv.get("tmp", "")
    # A template row with no payload is meaningless and, worse, would overwrite a good stored
    # template with an empty string on the next replace-all write.
    if not pin or not template:
        return None

    return FingerTemplate(
        pin=pin,
        finger_id=to_int(kv.get("fid"), 0),
        template=template,
        size=to_int(kv.get("size"), len(template)),
        valid=to_int(kv.get("valid"), 1),
    )


def _parse_face(fields: list[str]) -> FaceTemplate | None:
    kv = parse_kv(fields)
    pin = (kv.get("pin") or "").strip()
    template = kv.get("tmp", "")
    if not pin or not template:
        return None

    return FaceTemplate(
        pin=pin,
        face_id=to_int(kv.get("fid"), 0),
        template=template,
        size=to_int(kv.get("size"), len(template)),
        valid=to_int(kv.get("valid"), 1),
    )


def _parse_biodata(fields: list[str]) -> BioTemplate | None:
    kv = parse_kv(fields)
    pin = (kv.get("pin") or "").strip()
    template = kv.get("tmp", "")
    if not pin or not template:
        return None

    return BioTemplate(
        pin=pin,
        template=template,
        bio_type=to_int(kv.get("type"), 0),
        no=to_int(kv.get("no"), 0),
        index=to_int(kv.get("index"), 0),
        valid=to_int(kv.get("valid"), 1),
        duress=to_int(kv.get("duress"), 0),
        major_ver=kv.get("majorver", ""),
        minor_ver=kv.get("minorver", ""),
        fmt=kv.get("format", ""),
    )


def _parse_photo(fields: list[str]) -> UserPhoto | None:
    kv = parse_kv(fields)
    pin = (kv.get("pin") or "").strip()
    if not pin:
        return None

    content = kv.get("content", "")
    return UserPhoto(
        pin=pin,
        filename=kv.get("filename", ""),
        size=to_int(kv.get("size"), len(content)),
        content=content,
    )


def _parse_oplog(fields: list[str], raw: str) -> OperationEvent:
    """
    Parse an ``OPLOG`` line.

    Field order is not stable across firmware — some builds put the operator PIN second and
    the timestamp third, others swap them — so instead of trusting positions we take the first
    field that parses as a timestamp and the first *other* numeric field as the operator.
    Always returns an event: an op log is an audit breadcrumb, and a half-understood
    breadcrumb with its raw line attached beats none.
    """
    kv = parse_kv(fields)

    # Key=Value variant, seen on newer access-control firmware.
    if "op" in kv or "operation" in kv:
        return OperationEvent(
            op_code=to_int(kv.get("op") or kv.get("operation"), 0),
            operator_pin=(kv.get("admin") or kv.get("pin") or "").strip(),
            timestamp=parse_timestamp(kv.get("time") or kv.get("optime") or ""),
            param1=kv.get("param1", ""),
            param2=kv.get("param2", ""),
            param3=kv.get("param3", ""),
            raw=raw,
        )

    positional = [f.strip() for f in fields if f.strip()]
    timestamp = None
    timestamp_at = -1
    for index, value in enumerate(positional):
        candidate = parse_timestamp(value)
        if candidate is not None:
            timestamp, timestamp_at = candidate, index
            break

    remaining = [v for i, v in enumerate(positional) if i != timestamp_at]
    op_code = to_int(remaining[0], 0) if remaining else 0
    operator = remaining[1] if len(remaining) > 1 else ""
    tail = remaining[2:5] + ["", "", ""]

    return OperationEvent(
        op_code=op_code,
        operator_pin=operator,
        timestamp=timestamp,
        param1=tail[0],
        param2=tail[1],
        param3=tail[2],
        raw=raw,
    )
