"""
WSGI adapter -- the on-premises hosting entry point (IIS + waitress).

Its whole job is translating a WSGI ``environ`` into an :class:`~adms.models.AdmsRequest`, handing
that to :class:`~adms.service.AdmsService`, and turning the reply back into a WSGI response. The
service, the protocol parsers and the SQL adapters know nothing about the host; only this file and
:mod:`adms.config` do, which is the payoff of keeping hosting knowledge in one module.

Hosting shape
-------------
IIS does not run Python. It reverse-proxies to a process we own, via **AspNetCoreModuleV2** (ANCM,
out-of-process), and that process is :mod:`adms.hosting.serve` running ``waitress``. So IIS owns port
80, request logging,
auto-start and process recycling, while this module only ever sees a normal WSGI call.

Why waitress rather than wfastcgi: waitress is pure Python, needs no compilation on Windows, and is a
real WSGI server rather than a FastCGI bridge that has been semi-maintained for a decade. It also
means the exact same application object can be served by ``wsgiref`` in a test, which is how the
smoke test exercises this file without IIS.

What this deliberately does NOT do
----------------------------------
No authentication, no TLS termination, no rate limiting. Those belong to IIS and the network. See the
security section of the README: the ADMS protocol carries no credential, so the controls that matter
are the serial allow-list in ``ADMS_DEVICE`` and keeping the site on a device-only network segment.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable
from urllib.parse import parse_qsl

from .models import AdmsRequest, AdmsResponse
from .service import AdmsService

__all__ = ["AdmsWsgiApp", "build_request", "create_app"]

#: Cap on a request body read from the socket. ATTPHOTO and template uploads are the large ones and
#: run to a few megabytes; 32 MB is far above anything observed and still bounds the damage from a
#: malformed Content-Length. Devices are unauthenticated, so an unbounded read would be a trivial
#: way to exhaust the worker's memory.
MAX_BODY_BYTES = 32 * 1024 * 1024


def build_request(environ: dict[str, Any]) -> AdmsRequest:
    """
    Translate a WSGI ``environ`` into an :class:`~adms.models.AdmsRequest`.

    Known divergence (V3): this reads up to :data:`MAX_BODY_BYTES` (32 MiB) off the socket via
    :func:`_read_body` *before* ``AdmsService`` ever sees the request, i.e. before the serial
    allow-list in ``ADMS_DEVICE`` is consulted. Requirement 12.1's claim that the registry is
    consulted before a body is *decoded* still holds -- nothing parses these bytes until
    ``AdmsService`` authorises the request -- but the stronger preamble claim that an
    unregistered caller "cannot spend our CPU or fill the archive" is only half true: it cannot
    fill the archive, and it can make this worker allocate up to the bound.

    This is deliberate and bounded, not an oversight, and it is not changed here. Moving the read
    to after authorisation would mean ``AdmsService`` reading from ``environ['wsgi.input']``
    itself -- i.e. the service owning the socket -- which is exactly the hosting knowledge this
    module exists to keep out of it (see the module docstring). The bound is what keeps the cost
    of the early read fixed and small rather than unbounded.
    """
    method = (environ.get("REQUEST_METHOD") or "GET").upper()

    # PATH_INFO is already URL-decoded by the server. SCRIPT_NAME is prepended because IIS may host
    # the app under a virtual directory, and routes.resolve matches on the trailing segments -- but
    # an AdmsPathSecret lives in the prefix, so the prefix has to survive.
    path = (environ.get("SCRIPT_NAME") or "") + (environ.get("PATH_INFO") or "/")

    query = dict(parse_qsl(environ.get("QUERY_STRING") or "", keep_blank_values=True))

    body = _read_body(environ)

    headers = {
        key[5:].replace("_", "-").lower(): value
        for key, value in environ.items()
        if key.startswith("HTTP_")
    }
    for key in ("CONTENT_TYPE", "CONTENT_LENGTH"):
        if environ.get(key):
            headers[key.replace("_", "-").lower()] = environ[key]

    return AdmsRequest(
        method=method,
        path=path,
        query=query,
        body=body,
        headers=headers,
        source_ip=_client_ip(environ, headers),
    )


def _read_body(environ: dict[str, Any]) -> bytes:
    """
    Read the request body, bounded by :data:`MAX_BODY_BYTES`.

    A missing or unparseable ``CONTENT_LENGTH`` yields an empty body rather than an error: several
    firmware builds send a bodyless POST to ``devicecmd`` when they have nothing to acknowledge, and
    the service already treats that as a normal no-op.
    """
    stream = environ.get("wsgi.input")
    if stream is None:
        return b""

    raw_length = environ.get("CONTENT_LENGTH") or ""
    try:
        length = int(raw_length)
    except (TypeError, ValueError):
        return b""

    if length <= 0:
        return b""
    return stream.read(min(length, MAX_BODY_BYTES))


def _client_ip(environ: dict[str, Any], headers: dict[str, str]) -> str:
    """
    Best-effort client address, for diagnostics only -- never for authorisation.

    Behind IIS + AspNetCoreModuleV2 the connection arrives from localhost, so ``REMOTE_ADDR`` is
    ``127.0.0.1`` and the real device address is in ``X-Forwarded-For``. The leftmost entry is the
    original client. Trusting a header would be unacceptable for an access decision; it is fine here
    because this value only ever reaches a log line and the ``ADMS_PUSH_LOG`` archive.
    """
    forwarded = headers.get("x-forwarded-for", "")
    if forwarded:
        first = forwarded.split(",")[0].strip()
        if first:
            # IIS appends the source port to XFF entries (1.2.3.4:52341); strip it, but leave IPv6
            # alone since colons are part of the address there.
            if first.count(":") == 1:
                first = first.split(":")[0]
            return first
    return str(environ.get("REMOTE_ADDR") or "")


class AdmsWsgiApp:
    """
    Callable WSGI application wrapping one :class:`~adms.service.AdmsService`.

    A class rather than a closure so the service is inspectable from a hosting script and so the
    instance can be reused across requests -- waitress serves concurrently from a thread pool, and
    the service is stateless apart from its adapters.
    """

    __slots__ = ("_service", "_log")

    def __init__(self, service: AdmsService, log=None) -> None:
        self._service = service
        self._log = log

    def __call__(
        self,
        environ: dict[str, Any],
        start_response: Callable[[str, list[tuple[str, str]]], Any],
    ) -> Iterable[bytes]:
        try:
            request = build_request(environ)
        except Exception as exc:  # noqa: BLE001
            # A body that cannot even be read must not become a 500 with an HTML page: some firmware
            # treats any response it receives as a successful delivery and then erases the punches it
            # just uploaded. Answer with a deliberate plain-text status instead.
            if self._log is not None:
                self._log.error("Could not read the request.", exc)
            return self._emit(start_response, AdmsResponse(body="Bad Request", status=400))

        response = self._service.handle(request)
        return self._emit(start_response, response)

    @staticmethod
    def _emit(
        start_response: Callable[[str, list[tuple[str, str]]], Any],
        response: AdmsResponse,
    ) -> Iterable[bytes]:
        payload = response.encode()
        start_response(
            f"{response.status} {_reason(response.status)}",
            [
                # No charset parameter: devices scan the body with a hand-rolled parser and some
                # firmware rejects a content type it does not recognise verbatim.
                ("Content-Type", response.content_type),
                ("Content-Length", str(len(payload))),
                # A cached 'OK: 1' in an intermediate proxy would make a device believe every later
                # upload succeeded, so caching is refused explicitly rather than left to defaults.
                ("Cache-Control", "no-store"),
                # IIS adds its own Server header; this keeps our own build detail off the wire.
                ("X-Content-Type-Options", "nosniff"),
            ],
        )
        return [payload]


_REASONS = {
    200: "OK",
    400: "Bad Request",
    401: "Unauthorized",
    404: "Not Found",
    500: "Internal Server Error",
    503: "Service Unavailable",
}


def _reason(status: int) -> str:
    return _REASONS.get(status, "OK" if 200 <= status < 300 else "Error")


def create_app(service: AdmsService | None = None, log=None) -> AdmsWsgiApp:
    """
    Build the WSGI application, composing the real service when none is supplied.

    Composition happens on first call rather than at import time so a configuration error surfaces as
    a logged 503 from a running site instead of an IIS 502 with no explanation.
    """
    if service is None:
        from .composition import get_logger, get_service

        service = get_service()
        log = log or get_logger()
    return AdmsWsgiApp(service, log=log)
