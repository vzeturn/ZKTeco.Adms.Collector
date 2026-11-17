"""
Error types for the collector.

Every exception carries an HTTP status, because the status is what a ZKTeco device actually
reacts to and it is the only lever we have over device behaviour:

* ``2xx`` — the device considers the batch delivered and **erases those records from its own
  buffer**. Never return 2xx for data we failed to store; that is how punches vanish.
* ``4xx`` / ``5xx`` — the device keeps the records and retries after ``ErrorDelay`` seconds.
  A device holds tens of thousands of punches, so days of retrying is safe. Failing loudly is
  therefore the correct response to *any* uncertainty about persistence.

That asymmetry is why nothing in this codebase swallows a database error.
"""

from __future__ import annotations

__all__ = [
    "AdmsError",
    "ProtocolError",
    "DeviceNotRegisteredError",
    "DeviceDisabledError",
    "DeviceNotLinkedError",
    "AttendanceDbError",
    "ConfigError",
]


class AdmsError(Exception):
    """Base class. ``status`` is the HTTP status to return to the device."""

    status: int = 500

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        if status is not None:
            self.status = status


class ProtocolError(AdmsError):
    """
    A request that does not parse as ADMS at all — unknown route, missing ``SN``.

    400 rather than a retry-worthy 5xx: replaying a malformed request cannot fix it.
    """

    status = 400


class DeviceNotRegisteredError(AdmsError):
    """
    The serial number is not in ``ADMS_DEVICE``.

    401 is chosen over a silent ``OK`` on purpose. ADMS has no authentication whatsoever —
    any host that can reach the endpoint can POST anything — so the serial allow-list is the
    only thing standing between the endpoint and an arbitrary writer. An unknown device must
    therefore be refused, and refusing with 401 also means the device *keeps* its punches:
    once an operator links the serial, the backlog uploads on the next retry with nothing
    lost.
    """

    status = 401


class DeviceDisabledError(AdmsError):
    """A known serial an operator has switched off. Same retry-preserving 401."""

    status = 401


class DeviceNotLinkedError(AdmsError):
    """
    Registered and enabled, but ``ADMS_DEVICE.MaMCC`` does not resolve to a ``MAYCHAMCONG``
    row — so we have no ``IDMCC`` to write as ``CheckInOut.MaSoMay``.

    503, not 401: the device is trusted and the fault is ours (half-finished configuration).
    The distinction is what makes a monitoring alarm on this class actionable.
    """

    status = 503


class AttendanceDbError(AdmsError):
    """
    The database is unreachable or rejected a command.

    Wraps the driver error so no connection string, credential or server name reaches a log
    line or an HTTP body. 503 keeps the device retrying until the database is back.
    """

    status = 503


class ConfigError(AdmsError):
    """Missing or unusable configuration. Fatal — a retry will hit the same wall."""

    status = 500
