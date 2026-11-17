"""
Canonical device-facing responses.

Centralised because the exact bytes matter and are easy to get subtly wrong. Three rules hold
everywhere:

1. **``OK: <n>`` after a data upload, where ``n`` is the record count the device sent.** Not
   the number we stored — those differ whenever duplicates are suppressed or a non-numeric PIN
   is skipped, and firmware that sees a smaller number than it sent concludes the batch was
   partially rejected and resends it.
2. **2xx means "the device may now forget these records".** So a 2xx is only ever produced
   after a successful commit.
3. **Plain text, no framing.** No JSON, no HTML, no ``<`` anywhere — devices scan the body
   with a hand-rolled parser.
"""

from __future__ import annotations

from ..models import AdmsResponse

__all__ = ["ok", "ok_count", "text", "error", "not_found", "unauthorized"]


def ok() -> AdmsResponse:
    """Bare acknowledgement, used for handshake side-channels, pings and empty command queues."""
    return AdmsResponse(body="OK")


def ok_count(count: int) -> AdmsResponse:
    """
    Acknowledge a data upload of ``count`` records.

    ``count`` must be what the *device* sent. Negative values are clamped to 0 to avoid
    emitting something no firmware expects.
    """
    return AdmsResponse(body=f"OK: {max(0, count)}")


def text(body: str, status: int = 200) -> AdmsResponse:
    return AdmsResponse(body=body, status=status)


def error(message: str, status: int = 500) -> AdmsResponse:
    """
    An error reply.

    The body is a short, fixed phrase — never an exception string. Devices log the body to a
    file an installer can read, and it is also the one place a stack trace or connection detail
    could escape to an untrusted network. Diagnostics belong in the logs, keyed by request id.
    """
    return AdmsResponse(body=message, status=status)


def not_found() -> AdmsResponse:
    return AdmsResponse(body="Not Found", status=404)


def unauthorized() -> AdmsResponse:
    """
    Refuse an unregistered or disabled device.

    401 rather than 200 on purpose: it makes the device **keep** its records and retry, so
    linking the serial later recovers the full backlog. See
    :class:`adms.errors.DeviceNotRegisteredError`.
    """
    return AdmsResponse(body="Unauthorized", status=401)
