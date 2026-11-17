"""
Wire-text primitives shared by every parser.

ADMS bodies are line-oriented plain text with tab-separated fields, most of them in
``Key=Value`` form. The awkward parts this module exists to absorb:

* **Encoding is not declared.** Devices send no usable charset. Modern firmware uses UTF-8,
  Chinese-market firmware uses GBK, and older units emit Latin-1. Names are the only field
  that cares, so decoding must never fail — a mojibake name is recoverable, a rejected batch
  loses punches.
* **Line endings vary** between ``\\r\\n``, ``\\n`` and (rarely) a bare ``\\r``.
* **Field separators vary.** Tabs are the norm, but some builds use ``,`` between options and
  a few use multiple spaces where a tab belongs.
"""

from __future__ import annotations

import datetime as dt

__all__ = [
    "decode_body",
    "split_lines",
    "split_fields",
    "parse_kv",
    "to_int",
    "to_bool",
    "parse_timestamp",
]

#: Tried in order. UTF-8 first (strict, so a wrong guess fails fast rather than producing
#: plausible garbage), then GBK, then Latin-1 which cannot fail and therefore terminates the
#: chain.
_ENCODINGS = ("utf-8", "gbk", "latin-1")


def decode_body(raw: bytes | str) -> str:
    """Decode a request body to text, never raising."""
    if isinstance(raw, str):
        return raw
    if not raw:
        return ""
    for encoding in _ENCODINGS:
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    # Unreachable via _ENCODINGS (latin-1 accepts every byte), but an explicit floor beats
    # relying on that invariant holding if the list is ever edited.
    return raw.decode("utf-8", errors="replace")


def split_lines(text: str) -> list[str]:
    """Non-empty logical records, whitespace-trimmed, in arrival order."""
    return [line.strip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n") if line.strip()]


def split_fields(line: str) -> list[str]:
    """
    Split one record into fields.

    Tabs win when present. Only when a line contains no tab at all do we fall back to runs of
    two-or-more spaces: single spaces are legal *inside* a value (``Name=Nguyen Van A``), so
    splitting on one space would shred names.
    """
    if "\t" in line:
        return [f.strip() for f in line.split("\t")]
    if "  " in line:
        import re

        return [f.strip() for f in re.split(r"\s{2,}", line)]
    return [line.strip()]


def parse_kv(fields: list[str] | str) -> dict[str, str]:
    """
    Turn ``Key=Value`` fields into a dict with lower-cased keys.

    Keys are lower-cased because firmware disagrees on capitalisation for the *same* field
    (``PIN``/``Pin``, ``Size``/``SIZE``, ``TMP``/``Tmp``); callers look up one spelling.

    Splits on the first ``=`` only — base64 template payloads are ``=``-padded, so splitting
    on all of them would truncate every template. A field without ``=`` is kept under the
    positional key ``"_0"``, ``"_1"``… so leading bare tokens (an ``OPLOG`` op code, for
    instance) are still reachable.
    """
    if isinstance(fields, str):
        fields = split_fields(fields)

    out: dict[str, str] = {}
    positional = 0
    for raw in fields:
        if not raw:
            continue
        if "=" in raw:
            key, _, value = raw.partition("=")
            key = key.strip().lower()
            if key:
                out[key] = value.strip()
                continue
        out[f"_{positional}"] = raw.strip()
        positional += 1
    return out


def to_int(raw: object, default: int = 0) -> int:
    """
    Lenient int parse.

    Tolerates the decimal form some firmware uses for integral fields (``"1.0"`` for a
    finger index) by truncating through float, and treats blank as the default.
    """
    if raw is None:
        return default
    text = str(raw).strip()
    if not text:
        return default
    try:
        return int(text)
    except ValueError:
        try:
            return int(float(text))
        except ValueError:
            return default


def to_bool(raw: object, default: bool = True) -> bool:
    """
    Parse a device flag.

    Accepts the whole spread seen in the wild: ``1``/``0``, ``true``/``false``, ``yes``/``no``,
    ``Y``/``N``. Blank means "device did not say", which is the default — for
    ``USER.Enabled`` that must be *enabled*, since treating an unstated flag as disabled would
    lock users out of the door on the next mirror-down.
    """
    if raw is None:
        return default
    text = str(raw).strip().lower()
    if not text:
        return default
    if text in ("1", "true", "yes", "y", "on", "enable", "enabled"):
        return True
    if text in ("0", "false", "no", "n", "off", "disable", "disabled"):
        return False
    return default


#: Accepted timestamp layouts, most common first. ``%Y-%m-%d %H:%M:%S`` covers virtually all
#: traffic; the rest are firmware oddities. Date-only forms land at midnight.
_TIMESTAMP_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y%m%d%H%M%S",
    "%Y-%m-%d",
)


def parse_timestamp(raw: str) -> dt.datetime | None:
    """
    Parse a device timestamp into a **naive local** datetime, or ``None`` if unusable.

    ``None`` is a real outcome, not an edge case: devices with a dead RTC emit
    ``2000-00-00 00:00:00`` and similar impossible dates. Such a punch cannot be filed against
    a day, so callers drop it — the same choice ``ZkDevice.BuildLog`` makes when the SDK hands
    it an invalid date.

    Fractional seconds are trimmed rather than parsed; ATTENDANCEDB's ``DATETIME`` cannot
    represent them and punch dedup compares to the second.
    """
    if not raw:
        return None
    text = str(raw).strip()
    if not text:
        return None
    if "." in text:
        text = text.split(".", 1)[0].strip()

    for fmt in _TIMESTAMP_FORMATS:
        try:
            return dt.datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None
