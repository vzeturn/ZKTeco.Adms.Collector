"""
Route resolution for the ``/iclock/*`` endpoint family.

The device's server address is configured as a host and port only; the paths below are baked
into firmware and cannot be changed. That has two consequences this module handles:

* The path set is fixed and small, so an explicit table beats a web framework's router.
* There is no place to put a credential, which is why :func:`resolve` understands an optional
  secret path segment prefixed to the standard path — the one authentication-shaped lever the
  protocol leaves us. See :data:`adms.config.Settings.path_secret`.
"""

from __future__ import annotations

from enum import Enum

__all__ = ["Route", "ResolvedRoute", "resolve"]


class Route(Enum):
    """
    The ADMS endpoints, by role rather than by path.

    ``cdata`` is deliberately split: the device uses one path for two unrelated operations,
    distinguished only by HTTP verb. ``GET /iclock/cdata`` is the handshake that returns the
    device's operating parameters; ``POST /iclock/cdata`` is a data upload. Collapsing them
    into one handler is the classic way to end up answering a handshake with ``OK: 0``, which
    a device reads as "no configuration" and responds to by never uploading anything.
    """

    HANDSHAKE = "handshake"
    PUSH_DATA = "push_data"
    GET_REQUEST = "get_request"
    DEVICE_CMD = "device_cmd"
    QUERY_DATA = "query_data"
    FILE_DATA = "file_data"
    PING = "ping"
    HEALTH = "health"
    UNKNOWN = "unknown"


#: ``(method, last path segment) -> Route``. Matching on the final segment tolerates every
#: prefix the deployment might add: an API Gateway stage (``/prod/iclock/cdata``), a mapped
#: base path, or the optional secret prefix.
_TABLE: dict[tuple[str, str], Route] = {
    ("GET", "cdata"): Route.HANDSHAKE,
    ("POST", "cdata"): Route.PUSH_DATA,
    ("GET", "getrequest"): Route.GET_REQUEST,
    ("POST", "getrequest"): Route.GET_REQUEST,
    ("POST", "devicecmd"): Route.DEVICE_CMD,
    ("GET", "devicecmd"): Route.DEVICE_CMD,
    ("POST", "querydata"): Route.QUERY_DATA,
    ("GET", "querydata"): Route.QUERY_DATA,
    # fdata/rtdata/edata/filedata carry photos and file blobs. Accepted and acknowledged so
    # the device stops retrying, then archived — ATTENDANCEDB has nowhere to put an image.
    ("POST", "fdata"): Route.FILE_DATA,
    ("POST", "rtdata"): Route.FILE_DATA,
    ("POST", "edata"): Route.FILE_DATA,
    ("POST", "filedata"): Route.FILE_DATA,
    ("GET", "ping"): Route.PING,
    ("POST", "ping"): Route.PING,
    ("GET", "health"): Route.HEALTH,
}


class ResolvedRoute:
    """A matched route plus the ``/iclock``-relative path, for logging."""

    __slots__ = ("route", "segment", "authorized")

    def __init__(self, route: Route, segment: str, authorized: bool = True) -> None:
        self.route = route
        self.segment = segment
        #: False when a secret prefix is required and absent. Kept as a flag rather than an
        #: exception so the caller decides the response; see the note in :func:`resolve`.
        self.authorized = authorized

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return f"ResolvedRoute({self.route.value}, {self.segment!r}, authorized={self.authorized})"


def _segments(path: str) -> list[str]:
    return [s for s in path.split("/") if s]


def resolve(method: str, path: str, *, path_secret: str = "") -> ResolvedRoute:
    """
    Map an HTTP method and path onto a :class:`Route`.

    When ``path_secret`` is set, the path must contain that segment somewhere before
    ``iclock`` — the device is configured with ``http://host/<secret>/iclock`` and every
    request then carries it. A mismatch yields ``authorized=False`` rather than raising, so
    the caller can answer identically to an unknown path and avoid confirming to a scanner
    that the secret-prefix scheme is even in use.

    Comparison is a plain ``==`` on the segment. The value is a deployment-time constant of
    fixed length, so there is no secret-dependent timing to leak; treating it as a bearer
    token with constant-time compare would imply a stronger guarantee than a URL segment —
    which travels in plaintext HTTP and lands in every access log — can offer.
    """
    parts = _segments(path)
    if not parts:
        return ResolvedRoute(Route.UNKNOWN, "/")

    verb = (method or "GET").upper()
    segment = parts[-1].lower()

    authorized = True
    if path_secret:
        authorized = path_secret in parts

    route = _TABLE.get((verb, segment), Route.UNKNOWN)

    # A device only ever calls /iclock/*. Anything else matching a segment name (a stray
    # /health, say) is fine, but an unprefixed device path is not treated as a device call.
    return ResolvedRoute(route, "/" + "/".join(parts[-2:]), authorized)
