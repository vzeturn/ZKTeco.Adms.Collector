"""
Property tests for ``adms.protocol.routes`` -- the totality, table agreement and Path_Secret
contracts of :func:`~adms.protocol.routes.resolve`.

``adms.protocol.routes`` is pure: no I/O, no database, no clock. Nothing in ``tests/conftest.py``
is needed here -- no fixture from the harness is imported, and none should be, because inventing
one would duplicate a contract this module does not have.

Table-driven parametrisation over deliberately hostile fixed inputs, per the design's Testing
Strategy: no ``hypothesis``. Each property below is implemented by exactly one test function, and
each carries the ``# Feature: adms-attendance-system, Property N: <claim>`` comment the design
requires so a failure names the claim that broke.
"""

from __future__ import annotations

import pytest

from adms.models import AdmsResponse
from adms.protocol.responses import not_found
from adms.protocol.routes import ResolvedRoute, Route, resolve

# ── An independently hand-maintained oracle ─────────────────────────────────────────────────
#
# Deliberately re-typed from the design document's routing table rather than imported from
# ``adms.protocol.routes``'s private ``_TABLE``. Testing the real function against a copy of its
# own lookup table would prove nothing except that the function returns what it returns; testing
# it against an independently authored oracle is what actually catches a typo or a dropped row.

_ORACLE: dict[tuple[str, str], Route] = {
    ("GET", "cdata"): Route.HANDSHAKE,
    ("POST", "cdata"): Route.PUSH_DATA,
    ("GET", "getrequest"): Route.GET_REQUEST,
    ("POST", "getrequest"): Route.GET_REQUEST,
    ("GET", "devicecmd"): Route.DEVICE_CMD,
    ("POST", "devicecmd"): Route.DEVICE_CMD,
    ("GET", "querydata"): Route.QUERY_DATA,
    ("POST", "querydata"): Route.QUERY_DATA,
    ("POST", "fdata"): Route.FILE_DATA,
    ("POST", "rtdata"): Route.FILE_DATA,
    ("POST", "edata"): Route.FILE_DATA,
    ("POST", "filedata"): Route.FILE_DATA,
    ("GET", "ping"): Route.PING,
    ("POST", "ping"): Route.PING,
    ("GET", "health"): Route.HEALTH,
}


def _expected_route(method: str, path: str) -> Route:
    """The oracle's answer for a request, mirroring ``resolve``'s own documented contract."""
    verb = (method or "GET").upper()
    segments = [s for s in path.split("/") if s]
    if not segments:
        return Route.UNKNOWN
    return _ORACLE.get((verb, segments[-1].lower()), Route.UNKNOWN)


# ── Property 1 ───────────────────────────────────────────────────────────────────────────────

#: Deliberately hostile: empty method, empty path, unicode segments, a thousands-of-segments
#: path, traversal sequences, NUL bytes, a stray '?' that a naive implementation might mistake
#: for a query separator, casing variation in both method and segment, and every table entry.
_TOTALITY_AND_TABLE_CASES: list[tuple[str, str]] = [
    # Every table entry, exact casing.
    ("GET", "/iclock/cdata"),
    ("POST", "/iclock/cdata"),
    ("GET", "/iclock/getrequest"),
    ("POST", "/iclock/getrequest"),
    ("GET", "/iclock/devicecmd"),
    ("POST", "/iclock/devicecmd"),
    ("GET", "/iclock/querydata"),
    ("POST", "/iclock/querydata"),
    ("POST", "/iclock/fdata"),
    ("POST", "/iclock/rtdata"),
    ("POST", "/iclock/edata"),
    ("POST", "/iclock/filedata"),
    ("GET", "/iclock/ping"),
    ("POST", "/iclock/ping"),
    ("GET", "/iclock/health"),
    # Casing tolerance: method and segment are both matched case-insensitively.
    ("get", "/iclock/CData"),
    ("Post", "/ICLOCK/CDATA"),
    ("gEt", "/iclock/Health"),
    ("POST", "/iclock/FdAtA"),
    # No table entry at all -- a method that exists nowhere, and a segment that exists nowhere.
    ("GET", "/iclock/unknownthing"),
    ("DELETE", "/iclock/cdata"),
    ("PUT", "/iclock/health"),
    ("HEAD", "/iclock/getrequest"),
    # A trailing slash leaves the final *non-empty* segment unchanged.
    ("GET", "/iclock/ping/"),
    ("POST", "/iclock/cdata///"),
    # Hostile totality inputs. These must resolve to *some* Route without raising; several also
    # happen to still agree with the table via the shared _expected_route derivation.
    ("", ""),
    ("", "/"),
    ("GET", ""),
    ("", "/iclock/cdata"),  # empty method defaults to GET, per routes.py
    ("GET", "/\u65e5\u672c\u8a9e/cdata"),  # unicode prefix segment, ASCII final segment
    ("POST", "/h\u00e9llo/w\u00f6rld/cdata"),
    ("GET", "/\u65e5\u672c\u8a9e"),  # unicode *final* segment -- matches nothing
    ("GET", "/../../etc/cdata"),
    ("POST", "/a/../../etc/passwd/cdata"),
    ("GET", "/" + "s/" * 2500 + "cdata"),  # thousands of segments; a short id keeps the node name sane
    ("POST", "/" * 500 + "cdata"),
    ("weird\x00method", "/iclock/cdata"),
    ("GET", "/iclock/cdata\x00"),
    ("GET", "/iclock/cdata?ignored=becausequeryisseparate"),
    ("GET", "   "),
    (" GET ", "/iclock/cdata"),
]


@pytest.mark.parametrize(("method", "path"), _TOTALITY_AND_TABLE_CASES)
def test_property_1_route_resolution_total_and_agrees_with_table(method: str, path: str) -> None:
    # Feature: adms-attendance-system, Property 1: Route resolution is total and agrees with the
    # table -- for all methods and paths, resolve returns a member of Route without raising, equal
    # to the table entry for (upper(method), lower(final segment)) when one exists and UNKNOWN
    # otherwise; GET cdata and POST cdata never resolve to the same Route.

    # GET /cdata and POST /cdata are checked on every case, not only a dedicated one: the split
    # is the whole reason this route exists, so every parametrised run re-affirms it holds.
    assert resolve("GET", "/iclock/cdata").route != resolve("POST", "/iclock/cdata").route

    resolved = resolve(method, path)

    # Totality: a Route came back, whatever the input, and nothing raised getting here.
    assert isinstance(resolved.route, Route)

    # Table agreement, against the independently authored oracle.
    assert resolved.route == _expected_route(method, path)


# ── Property 2 ───────────────────────────────────────────────────────────────────────────────

#: Hostile prefixes: empty, an API Gateway-style stage, a virtual directory, a would-be secret,
#: unicode, traversal, a very long single segment, numeric segments, encoded/space-bearing text,
#: pre-existing double slashes, and a deep nonsense chain.
_PREFIXES: list[str] = [
    "",
    "prod",
    "api/v1",
    "SECRETXYZ",
    "\u65e5\u672c\u8a9e/virtualdir",
    "..",
    "../../etc",
    "a" * 400,
    "12345/67890",
    "with space/and%20encoded",
    "//already//double//",
    "/".join(["deep"] * 300),
]

#: (method, final segment) pairs to prove invariant, including one that resolves to nothing --
#: prefix invariance does not stop holding just because the route itself is UNKNOWN.
_TAILS: list[tuple[str, str]] = [
    ("GET", "cdata"),
    ("POST", "cdata"),
    ("GET", "getrequest"),
    ("POST", "devicecmd"),
    ("GET", "querydata"),
    ("POST", "fdata"),
    ("GET", "ping"),
    ("GET", "health"),
    ("GET", "totally-unmatched-segment"),
]


def _prefixed_path(prefix: str, tail: str) -> str:
    return f"/{tail}" if not prefix else f"/{prefix}/{tail}"


@pytest.mark.parametrize("prefix", _PREFIXES)
@pytest.mark.parametrize(("method", "tail"), _TAILS)
def test_property_2_route_invariant_to_everything_before_the_last_two_segments(
    method: str, tail: str, prefix: str
) -> None:
    # Feature: adms-attendance-system, Property 2: Route resolution is invariant to everything
    # before the last two segments -- for any resolvable path and any sequence of preceding
    # segments (stage prefix, virtual directory, secret prefix, nonsense), the resolved Route is
    # unchanged.
    baseline = resolve(method, f"/{tail}").route
    prefixed = resolve(method, _prefixed_path(prefix, tail)).route
    assert prefixed == baseline


# ── Property 3 ───────────────────────────────────────────────────────────────────────────────


def _dispatch_gate(resolved: ResolvedRoute) -> AdmsResponse | None:
    """
    The two 404-producing branches of the design's ``handleRequest`` pseudocode, reproduced here
    using only the pure protocol layer (``routes`` and ``responses``) so the "identical to an
    unknown path" half of Property 3 is demonstrable with no service and no adapter:

        IF NOT resolved.authorized THEN RETURN Response(404, 'Not Found')
        IF resolved.route = UNKNOWN THEN RETURN Response(404, 'Not Found')

    Returns ``None`` when neither branch would fire -- a request this gate would let through.
    """
    if not resolved.authorized or resolved.route is Route.UNKNOWN:
        return not_found()
    return None


#: (secret, path, expected authorized) -- exact-segment matches, substring-only near-misses,
#: case sensitivity, unicode, and traversal segments that happen to collide with the secret text.
_AUTHZ_CASES: list[tuple[str, str, bool]] = [
    ("", "/iclock/cdata", True),
    ("", "", True),
    ("", "/../../etc/cdata", True),
    ("SEC1", "/SEC1/iclock/cdata", True),
    ("SEC1", "/iclock/SEC1/cdata", True),
    ("SEC1", "/mySEC1thing/iclock/cdata", False),  # substring at the end of a longer segment
    ("SEC1", "/SEC1X/iclock/cdata", False),  # substring at the start of a longer segment
    ("SEC1", "/xSEC1x/iclock/cdata", False),  # substring in the middle of a longer segment
    ("SEC1", "/iclock/cdata", False),  # secret configured but absent from the path entirely
    ("Secret", "/secret/iclock/cdata", False),  # case mismatch: plain == is case-sensitive
    ("Secret", "/Secret/iclock/cdata", True),
    ("tok\U0001f600en", "/tok\U0001f600en/iclock/cdata", True),  # unicode secret, exact segment
    ("tok\U0001f600en", "/tok\U0001f600enX/iclock/cdata", False),  # unicode secret, substring only
    ("..", "/../iclock/cdata", True),  # a traversal token used as the (hostile) secret itself
]


@pytest.mark.parametrize(("secret", "path", "expected_authorized"), _AUTHZ_CASES)
def test_property_3_path_secret_required_and_indistinguishable_from_unknown(
    secret: str, path: str, expected_authorized: bool
) -> None:
    # Feature: adms-attendance-system, Property 3: A configured path secret is required, and its
    # absence is indistinguishable from an unknown path -- authorised iff the secret is empty or
    # appears as an exact path segment (a secret occurring only as a substring of a segment does
    # not authorise); for all unauthorised requests the response is byte-identical to the
    # response for an unknown path.
    resolved = resolve("GET", path, path_secret=secret)

    assert resolved.authorized is expected_authorized

    if resolved.authorized:
        return

    denied = _dispatch_gate(resolved)
    reference = _dispatch_gate(ResolvedRoute(Route.UNKNOWN, "/", authorized=True))

    assert denied is not None
    assert reference is not None
    assert (denied.status, denied.encode()) == (reference.status, reference.encode())
