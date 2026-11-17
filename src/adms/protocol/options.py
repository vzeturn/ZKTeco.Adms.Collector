"""
``table=options`` parser — the device's self-description, uploaded right after handshake.

The body is a flat list of ``Key=Value`` pairs describing firmware version, platform, user and
template capacity, fingerprint algorithm version and so on. Separator is inconsistent: some
firmware uses newlines, some commas, some tabs. Vendor keys are prefixed with ``~``
(``~DeviceName``, ``~SerialNumber``).

Everything is kept as strings in a mapping rather than mapped onto columns — the key set
differs per model and grows with each firmware release, and none of it drives logic. It is
stored so that when a site reports odd behaviour, the exact firmware build is already on file
instead of requiring someone to walk to the device.
"""

from __future__ import annotations

from ..models import DeviceInfo

__all__ = ["parse_options"]


def parse_options(body: str, *, serial: str = "") -> DeviceInfo:
    """Parse an ``options`` body into a :class:`~adms.models.DeviceInfo`."""
    values: dict[str, str] = {}

    # Normalise every plausible separator to newline first, then split once. Commas are
    # replaced only outside of nothing in particular — no option value in the wild contains a
    # comma, and treating one as a separator is safer than merging two options into one key.
    normalized = body.replace("\r\n", "\n").replace("\r", "\n").replace("\t", "\n").replace(",", "\n")

    for chunk in normalized.split("\n"):
        token = chunk.strip()
        if not token or "=" not in token:
            continue
        key, _, value = token.partition("=")
        key = key.strip()
        if key:
            values[key] = value.strip()

    # The device repeats its serial in the body on most firmware; prefer the query-string value
    # the caller already validated against the allow-list, and fall back to the body only when
    # the query string had none.
    resolved = serial or values.get("~SerialNumber", "") or values.get("SerialNumber", "")
    return DeviceInfo(serial=resolved.strip(), values=values)
