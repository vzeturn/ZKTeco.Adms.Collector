"""
The request pipeline for the admin console: the one module that knows about HTTP.

Composition, routing, the middleware chain and the handlers all live here. Everything below the
handlers is pure and testable: ``ui`` produces HTML with no knowledge of routing, ``auth`` holds the
security arithmetic with no knowledge of a request, and ``store`` is the only thing that talks to the
database. This file wires the three together in the fixed order a request meets them -- parse, static
short-circuit, session, route, force-password-change, CSRF, authorize, handle, finalize -- so a route
added later cannot silently skip a stage.

The pipeline is built up across the plan's waves. Task 4.1 lands the parsing, the route table, the
static routes and the uniform finaliser; the session, CSRF, authorization and handler stages arrive in
tasks 4.3 through 8.3. The ``__call__`` skeleton already threads every stage so those tasks only fill
in a method, never re-shape the flow.
"""

from __future__ import annotations

import base64
import binascii
import re
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, quote, urlsplit

from adms.admin import auth, ui
from adms.errors import AttendanceDbError

if TYPE_CHECKING:
    from adms.admin.auth import Principal
    from adms.admin.store import AdminStore, UserRow
    from adms.config import Settings

__all__ = [
    "COMMAND_ALLOWLIST", "GENERIC_FAILURE", "AdminWsgiApp", "Request", "Response", "Route",
    "create_app",
]

#: One message for every sign-in failure -- unknown user, wrong password, disabled or locked account
#: all read the same, so the form never discloses which accounts exist (D9).
GENERIC_FAILURE = "Incorrect username or password."

#: Shown when the double-submit CSRF check fails (stale/expired form, missing cookie, cross-origin
#: source) -- distinct from GENERIC_FAILURE so a valid password is never misreported as wrong. It
#: reveals nothing about credentials, so it leaks no account information.
EXPIRED_FORM_FAILURE = "This form expired. Reload the page and sign in again."

#: The only command strings the console will ever queue: value -> is-it-destructive. Free text never
#: reaches a device -- a POST whose ``command`` is not a key here is refused. The destructive members
#: erase data on the device itself and are admin-only and confirmed; the safe members are operator work.
#: Kept in lockstep with ``ui._COMMAND_MENU``: ui names the choices, this decides policy (design D7).
COMMAND_ALLOWLIST: dict[str, bool] = {
    "REBOOT": False,
    "INFO": False,
    "CHECK": False,
    "DATA QUERY USERINFO": False,
    "SET OPTION": False,
    "CLEAR DATA": True,
    "CLEAR LOG": True,
    "CLEAR PHOTO": True,
}

#: The base session-cookie name. Over TLS it gains the ``__Host-`` prefix, which pins the cookie to
#: this exact host with no ``Domain`` and demands ``Secure`` -- a guarantee the prefix cannot give over
#: plain HTTP, so the name is conditional. Configured from ``ADMS_ADMIN_SESSION_COOKIE`` in serve.py.
_SESSION_COOKIE = "adms_console"

#: Short-lived cookie carrying the anonymous CSRF secret for the sign-in form (double-submit pattern).
#: Like the session cookie it gains the ``__Host-`` prefix only over TLS.
_LOGIN_CSRF_COOKIE = "adms_login_csrf"

#: The idle window only slides when it is at least this stale, so a burst of requests is one write, not
#: one per request. ``last_seen`` is derived as ``expires_utc - SESSION_IDLE_TIMEOUT``.
_TOUCH_THROTTLE = timedelta(seconds=60)

#: Spent on every failed sign-in so an unknown username costs the same PBKDF2 work as a real one.
_DUMMY_SALT = b"\x00" * 16

#: A browser form is small. Bounding the body before it is parsed turns a malformed or hostile
#: ``Content-Length`` from an easy memory-exhaustion into a truncated read.
MAX_FORM_BYTES = 64 * 1024
#: A well-formed form has a handful of fields; hundreds is an attempt to make the parser churn.
MAX_FORM_FIELDS = 200

#: The one path-parameter shape the router understands: enough for a serial or an integer id and
#: nothing that can smuggle a slash, a space or a path traversal.
_PARAM_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")

#: The username shape accepted for a new console user, matching the desktop tool's APP_USER.Username.
_USERNAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")

#: On every response. ``default-src 'none'`` with no ``script-src`` at all is possible only because
#: the console ships no JavaScript (D11): an escaping slip becomes "the page looks wrong", not a
#: stolen session.
_SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    (
        "Content-Security-Policy",
        "default-src 'none'; style-src 'self'; img-src 'self' data:; "
        "form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    ),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
)


@dataclass(frozen=True, slots=True)
class Request:
    method: str
    path: str
    query: dict[str, str]
    form: dict[str, str]
    cookies: dict[str, str]
    headers: dict[str, str]
    ip: str
    user_agent: str


@dataclass(frozen=True, slots=True)
class Response:
    status: int = 200
    body: bytes = b""
    content_type: str = "text/html; charset=utf-8"
    headers: tuple[tuple[str, str], ...] = ()

    def with_header(self, name: str, value: str) -> Response:
        return replace(self, headers=(*self.headers, (name, value)))


@dataclass(frozen=True, slots=True)
class Route:
    method: str
    pattern: str
    handler: str
    requires: str  # "" anonymous | "view" | "operate" | "administer"
    csrf: bool


# ── the route table ──────────────────────────────────────────────────────────────────────────────
# First match wins, so the concrete path precedes its ``{name}`` sibling. ``requires`` and ``csrf``
# are read centrally in ``__call__``; a handler never repeats them, which is what lets the authz and
# CSRF property tests drive themselves straight from this table.

_ROUTES: tuple[Route, ...] = (
    Route("GET", "/assets/console.css", "_stylesheet", "", False),
    Route("GET", "/healthz", "_healthz", "", False),
    Route("GET", "/sign-in", "get_sign_in", "", False),
    Route("POST", "/sign-in", "post_sign_in", "", False),
    Route("POST", "/sign-out", "post_sign_out", "view", True),
    Route("GET", "/change-password", "get_change_password", "view", False),
    Route("POST", "/change-password", "post_change_password", "view", True),
    Route("GET", "/", "get_dashboard", "view", False),
    Route("GET", "/devices", "get_devices", "view", False),
    Route("GET", "/devices/{serial}", "get_device", "view", False),
    Route("GET", "/devices/{serial}/confirm", "get_device_confirm", "operate", False),
    Route("POST", "/devices/{serial}/enable", "post_device_enable", "operate", True),
    Route("POST", "/devices/{serial}/disable", "post_device_disable", "operate", True),
    Route("POST", "/devices/{serial}/link", "post_device_link", "operate", True),
    Route("POST", "/devices/{serial}/commands", "post_device_command", "operate", True),
    Route(
        "POST",
        "/devices/{serial}/commands/{command_id}/cancel",
        "post_command_cancel",
        "operate",
        True,
    ),
    Route("GET", "/roster-sync", "get_roster_sync", "view", False),
    Route("GET", "/activity", "get_activity", "view", False),
    Route("GET", "/users", "get_users", "administer", False),
    Route("POST", "/users", "post_user_create", "administer", True),
    Route("POST", "/users/{user_id}/update", "post_user_update", "administer", True),
    Route("POST", "/users/{user_id}/reset-password", "post_user_reset", "administer", True),
    Route("POST", "/users/{user_id}/unlock", "post_user_unlock", "administer", True),
    Route("POST", "/users/{user_id}/delete", "post_user_delete", "administer", True),
    Route("GET", "/sessions", "get_sessions", "administer", False),
    Route("POST", "/sessions/{user_id}/revoke", "post_session_revoke", "administer", True),
    Route("GET", "/employees", "get_employees", "administer", False),
    Route("POST", "/employees/lookup", "post_employee_lookup", "administer", True),
    Route("POST", "/employees/{pin}/grant-admin", "post_employee_grant", "administer", True),
    Route("POST", "/employees/{pin}/revoke-admin", "post_employee_revoke", "administer", True),
    Route("GET", "/audit", "get_audit", "view", False),
)


class AdminWsgiApp:
    """
    Callable WSGI application for the console.

    A class rather than a closure so the store is inspectable and the instance can be reused across
    the waitress thread pool -- the app itself holds no per-request state.
    """

    __slots__ = ("_clock", "_log", "_secure_cookies", "_settings", "_store")

    def __init__(
        self,
        store: AdminStore,
        *,
        settings: Settings,
        log: Any = None,
        secure_cookies: bool = False,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._store = store
        self._settings = settings
        self._log = log
        self._secure_cookies = secure_cookies
        self._clock = clock or (lambda: datetime.now(UTC))

    # ── WSGI entry ─────────────────────────────────────────────────────────────────────────────

    def __call__(
        self,
        environ: dict[str, Any],
        start_response: Callable[[str, list[tuple[str, str]]], Any],
    ) -> Iterable[bytes]:
        response = self._handle(environ)
        payload = response.body
        headers = self._finalize(response)
        start_response(f"{response.status} {_reason(response.status)}", headers)
        return [payload]

    def _handle(self, environ: dict[str, Any]) -> Response:
        request = self._parse_request(environ)
        now = self._clock()

        # 1. Static asset, before any session work: no cookie, no database, cacheable.
        if request.method == "GET" and request.path == "/assets/console.css":
            return self._stylesheet(request)
        if request.method == "GET" and request.path == "/healthz":
            return self._healthz(request)

        # A database failure anywhere below is reported as unavailability, not as a crash: the store
        # wraps every failure as AttendanceDbError, and we answer a clean 503 whose page never carries
        # the underlying message -- so a running site returns 503, not an opaque IIS 502 (Property 40).
        try:
            # 2. Session (task 4.3 fills in _load_principal).
            principal = self._load_principal(request, now)

            # 3. Route.
            route, params = self._match_route(request.method, request.path)
            if route is None:
                return self._error(404, "Not found", "No page lives at this address.")

            # 4. Anonymous vs authenticated (task 4.5).
            # 5. Forced password change (task 4.3).
            # 6. CSRF (task 4.5).
            # 7. Authorization (task 4.5).
            # 8. Handle (tasks 6-8).
            return self._dispatch(route, params, request, principal, now)
        except AttendanceDbError:
            return self._error(503, "Service unavailable",
                               "The console cannot reach the database right now. Try again shortly.")

    # ── parsing ────────────────────────────────────────────────────────────────────────────────

    def _parse_request(self, environ: dict[str, Any]) -> Request:
        method = (environ.get("REQUEST_METHOD") or "GET").upper()
        path = (environ.get("SCRIPT_NAME") or "") + (environ.get("PATH_INFO") or "/")
        query = dict(parse_qsl(environ.get("QUERY_STRING") or "", keep_blank_values=True))

        headers = {
            key[5:].replace("_", "-").lower(): value
            for key, value in environ.items()
            if key.startswith("HTTP_")
        }
        for key in ("CONTENT_TYPE", "CONTENT_LENGTH"):
            if environ.get(key):
                headers[key.replace("_", "-").lower()] = environ[key]

        form = _parse_form(environ) if method == "POST" else {}
        cookies = _parse_cookies(headers.get("cookie", ""))
        return Request(
            method=method,
            path=path,
            query=query,
            form=form,
            cookies=cookies,
            headers=headers,
            ip=_client_ip(environ, headers),
            user_agent=headers.get("user-agent", ""),
        )

    # ── routing ────────────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _match_route(method: str, path: str) -> tuple[Route | None, dict[str, str]]:
        """First match wins. Returns the route and any captured path parameters, or ``(None, {})``."""
        for route in _ROUTES:
            if route.method != method:
                continue
            params = _match_pattern(route.pattern, path)
            if params is not None:
                return route, params
        return None, {}

    # ── static routes ──────────────────────────────────────────────────────────────────────────

    def _stylesheet(self, request: Request) -> Response:
        etag = f'"{ui.STYLESHEET_ETAG}"'
        if request.headers.get("if-none-match", "") == etag:
            return Response(status=304, body=b"", content_type="text/css; charset=utf-8")
        return Response(
            status=200,
            body=ui.STYLESHEET.encode("utf-8"),
            content_type="text/css; charset=utf-8",
            headers=(("ETag", etag), ("Cache-Control", "public, max-age=3600")),
        )

    def _healthz(self, _request: Request) -> Response:
        # Deliberately does not touch the database: an unauthenticated probe cannot generate load.
        return Response(status=200, body=b"ok", content_type="text/plain; charset=utf-8")

    # ── stages filled in by later waves ─────────────────────────────────────────────────────────

    def _load_principal(self, request: Request, now: datetime) -> Principal | None:
        """
        Read the session cookie, validate the row against both deadlines, and build a Principal.

        Returns ``None`` -- indistinguishably -- for an absent, malformed, unknown, expired or
        disabled-owner cookie. A row that exists but is dead is deleted on the way out, so a stale
        cookie cannot keep a dead row alive. On success the idle window slides, but only once every
        :data:`_TOUCH_THROTTLE` so a busy tab is not a write per request.
        """
        token = request.cookies.get(self._cookie_name())
        if not token:
            return None
        digest = auth.token_hash(token)
        row = self._store.load_session(digest)
        if row is None:
            return None
        if not row.is_enabled or not auth.is_session_live(now, row.created_utc, row.expires_utc):
            self._store.delete_session(digest)
            return None

        last_seen = row.expires_utc - auth.SESSION_IDLE_TIMEOUT
        if now - last_seen >= _TOUCH_THROTTLE:
            self._store.touch_session(digest, now + auth.SESSION_IDLE_TIMEOUT, now)

        from adms.admin.auth import Principal

        return Principal(
            user_id=row.user_id,
            username=row.username,
            display_name=row.display_name,
            role=row.role if auth.Role.is_valid(row.role) else auth.Role.VIEWER,
            must_change_password=row.must_change_password,
            csrf_secret=row.csrf_secret,
        )

    # ── authentication ───────────────────────────────────────────────────────────────────────────

    def _authenticate(
        self, username: str, password: str, ip: str, user_agent: str, now: datetime
    ) -> tuple[str | None, str]:
        """
        Verify a credential and, on success, open a session. See design's ``authenticate``.

        Every failure path spends one PBKDF2 derivation and returns the one :data:`GENERIC_FAILURE`
        string, so neither timing nor wording reveals which accounts exist. A locked account records
        no new failure, so hammering it cannot extend its own lock. A stale hash is upgraded in place.
        """
        normalised = username.strip().lower()
        user = self._store.find_user(normalised)

        if user is None or not user.is_enabled or self._is_locked(user, now):
            auth.hash_password(password, _DUMMY_SALT)  # equal CPU on every miss
            detail = ("unknown user" if user is None
                      else "disabled" if not user.is_enabled else "locked")
            self._store.audit(username=normalised, action="sign_in", detail=detail, ip=ip,
                              succeeded=False)
            return None, GENERIC_FAILURE

        material = self._store.password_material(user.user_id)
        if material is None or not auth.verify_password(password, *material):
            attempts = user.failed_attempts + 1
            self._store.record_login_failure(user.user_id, auth.lockout_until(now, attempts))
            self._store.audit(username=normalised, action="sign_in", detail="bad password", ip=ip,
                              succeeded=False)
            return None, GENERIC_FAILURE

        if material[2] < auth.PBKDF2_ITERATIONS:
            new_salt = auth.new_salt()
            self._store.set_password(user.user_id, new_salt,
                                     auth.hash_password(password, new_salt),
                                     auth.PBKDF2_ITERATIONS, user.must_change_password)

        token = auth.new_session_token()
        self._store.create_session(
            token_hash=auth.token_hash(token),
            user_id=user.user_id,
            expires_utc=now + auth.SESSION_IDLE_TIMEOUT,
            ip=ip,
            user_agent=user_agent,
            csrf_secret=auth.new_csrf_secret(),
        )
        self._store.record_login_success(user.user_id, now, ip)
        self._store.audit(username=normalised, action="sign_in", ip=ip, succeeded=True)
        return token, ""

    @staticmethod
    def _is_locked(user: Any, now: datetime) -> bool:
        return user.locked_until_utc is not None and user.locked_until_utc > now

    # ── the session cookie ───────────────────────────────────────────────────────────────────────

    def _cookie_name(self) -> str:
        return f"__Host-{_SESSION_COOKIE}" if self._secure_cookies else _SESSION_COOKIE

    def _set_cookie(self, token: str) -> str:
        attrs = [f"{self._cookie_name()}={token}", "Path=/", "HttpOnly", "SameSite=Lax"]
        if self._secure_cookies:
            attrs.append("Secure")
        return "; ".join(attrs)  # no Max-Age: a session cookie; the server holds the real deadlines

    def _clear_cookie(self) -> str:
        attrs = [f"{self._cookie_name()}=", "Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=0"]
        if self._secure_cookies:
            attrs.append("Secure")
        return "; ".join(attrs)

    # ── the sign-in CSRF cookie (double-submit) ──────────────────────────────────────────────────
    # The sign-in POST has no session, so it cannot use the session's CSRF secret like every other
    # guarded form does. Instead we mint an anonymous secret, hand it out in this short-lived cookie,
    # and embed a token derived from it in the form's hidden field. On POST the cookie secret must
    # validate the submitted token. This is stateless and, unlike the Origin/Referer check it
    # replaces, works on plain HTTP -- where browsers omit both headers on a same-origin form POST.

    def _login_csrf_cookie_name(self) -> str:
        return f"__Host-{_LOGIN_CSRF_COOKIE}" if self._secure_cookies else _LOGIN_CSRF_COOKIE

    def _set_login_csrf_cookie(self, secret: bytes) -> str:
        value = base64.urlsafe_b64encode(secret).decode("ascii").rstrip("=")
        attrs = [f"{self._login_csrf_cookie_name()}={value}", "Path=/", "HttpOnly", "SameSite=Lax"]
        if self._secure_cookies:
            attrs.append("Secure")
        return "; ".join(attrs)

    def _clear_login_csrf_cookie(self) -> str:
        attrs = [f"{self._login_csrf_cookie_name()}=", "Path=/", "HttpOnly",
                 "SameSite=Lax", "Max-Age=0"]
        if self._secure_cookies:
            attrs.append("Secure")
        return "; ".join(attrs)

    def _login_csrf_secret(self, request: Request) -> bytes | None:
        raw = request.cookies.get(self._login_csrf_cookie_name(), "")
        if not raw:
            return None
        try:
            return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        except (ValueError, binascii.Error):
            return None

    def _dispatch(
        self,
        route: Route,
        params: dict[str, str],
        request: Request,
        principal: Principal | None,
        now: datetime,
    ) -> Response:
        """
        Anonymous/forced-change/CSRF/authz gates, then handler invocation. Stage 4 (anonymous) and
        stage 5 (forced password change) land here in task 4.3; CSRF and authorization arrive in task
        4.5. Until a handler exists the route resolves to a 'not built yet' page rather than an
        unhandled attribute error, so the pipeline stays total from the first wave.
        """
        # 4. Anonymous vs authenticated: a guarded route needs a session.
        if route.requires and principal is None:
            if request.method == "GET":
                return _redirect(_next_url(request.path))
            return self._error(401, "Session ended", "Your session ended. Sign in again.")

        # 5. Forced password change, enforced centrally so a new route cannot bypass it.
        if (principal is not None and principal.must_change_password
                and request.path not in ("/change-password", "/sign-out")):
            return _redirect("/change-password")

        # 6. CSRF, for every POST that carries a session. /sign-in has none and is guarded by the
        # same-origin check inside its own handler instead.
        if request.method == "POST" and route.csrf:
            assert principal is not None  # stage 4 rejected anonymous callers of a guarded route
            if not auth.verify_csrf_token(principal.csrf_secret, request.form.get("csrf_token", "")):
                self._store.audit(username=principal.username, action="csrf_reject",
                                  target=route.pattern, ip=request.ip, succeeded=False)
                return self._error(400, "This form expired", "Reload the page and try again.")

        # 7. Authorization: the route's capability requirement against the principal's role.
        if route.requires and not _permits(principal, route.requires):
            assert principal is not None
            self._store.audit(username=principal.username, action="denied",
                              target=route.pattern, ip=request.ip, succeeded=False)
            return self._error(403, "Not permitted", "This account cannot use that action.")

        # 8. Handle. Handlers land in tasks 6-8; until one exists the route resolves to a 404 rather
        # than an unhandled attribute error, so the pipeline stays total from the first wave.
        handler = getattr(self, route.handler, None)
        if handler is None:
            return self._error(404, "Not found", "No page lives at this address.")
        response = handler(request, principal, params, now)

        # One structured log line per real operator action -- every request that reached this far
        # already cleared authentication (stage 4), so this is "someone with a session did
        # something," never a bare unauthenticated probe or a 401/403/404 that never got here.
        # This single call site is deliberately the only one in the whole console: instrumenting
        # every handler individually would risk a route being added later without its own log line
        # and going dark. It is also an activity signal an idle-detection monitor can key on: an
        # operator actively clicking through pages must never look idle, and this line proves it.
        if principal is not None and self._log is not None:
            self._log.info(
                "Console request handled.",
                user=principal.username,
                method=request.method,
                path=request.path,
                status=response.status,
            )
        return response

    # ── sign-in, sign-out and the forced-change form ─────────────────────────────────────────────

    def get_sign_in(
        self, request: Request, _principal: Principal | None, _params: dict[str, str],
        _now: datetime,
    ) -> Response:
        next_url = _safe_next(request.query.get("next", ""))
        # The login-csrf cookie is idempotent: reuse the secret an earlier GET already set, and only
        # mint+set a fresh one when none is present or it fails to decode. A second GET (refresh,
        # prefetch, another tab) must NOT rotate the cookie out from under a form the user is still
        # filling in, or the first page's token would fail the double-submit check and the user would
        # be told, misleadingly, that the password is wrong.
        existing = self._login_csrf_secret(request)
        secret = existing if existing is not None else auth.new_csrf_secret()
        page = _html(ui.sign_in_page(next_url=next_url, csrf=auth.csrf_token(secret)))
        if existing is None:
            return page.with_header("Set-Cookie", self._set_login_csrf_cookie(secret))
        return page

    def post_sign_in(
        self, request: Request, _principal: Principal | None, _params: dict[str, str],
        now: datetime,
    ) -> Response:
        # The sign-in form is guarded by a double-submit CSRF token: the secret rides in a cookie set
        # by GET /sign-in and a token derived from it rides in a hidden field. Both must be present and
        # agree. This works on plain HTTP, where the Origin/Referer check it replaced fails because the
        # browser sends neither header on a same-origin form POST. When those headers ARE present we
        # still reject a cross-origin source as defence in depth.
        secret = self._login_csrf_secret(request)
        token_ok = secret is not None and auth.verify_csrf_token(
            secret, request.form.get("csrf_token", ""))
        if not token_ok or not self._same_origin_if_stated(request):
            return self._reissue_sign_in(request, EXPIRED_FORM_FAILURE)
        next_url = _safe_next(request.form.get("next", ""))
        token, message = self._authenticate(
            request.form.get("username", ""), request.form.get("password", ""),
            request.ip, request.user_agent, now,
        )
        if token is None:
            return self._reissue_sign_in(request, message, username=request.form.get("username", ""))
        return (
            _redirect(next_url or "/")
            .with_header("Set-Cookie", self._set_cookie(token))
            .with_header("Set-Cookie", self._clear_login_csrf_cookie())
        )

    def _reissue_sign_in(self, request: Request, error: str, *, username: str = "") -> Response:
        """Re-render the sign-in form with a fresh CSRF secret/cookie after a rejected attempt."""
        next_url = _safe_next(request.form.get("next", ""))
        secret = auth.new_csrf_secret()
        page = _html(ui.sign_in_page(
            error=error, username=username, next_url=next_url, csrf=auth.csrf_token(secret),
        ))
        return page.with_header("Set-Cookie", self._set_login_csrf_cookie(secret))

    def post_sign_out(
        self, request: Request, _principal: Principal | None, _params: dict[str, str],
        _now: datetime,
    ) -> Response:
        token = request.cookies.get(self._cookie_name())
        if token:
            self._store.delete_session(auth.token_hash(token))
        return _redirect("/sign-in").with_header("Set-Cookie", self._clear_cookie())

    def get_change_password(
        self, _request: Request, principal: Principal | None, _params: dict[str, str],
        _now: datetime,
    ) -> Response:
        assert principal is not None  # guarded route: stage 4 rejected anonymous callers
        return _html(ui.change_password_page(
            problems=[], forced=principal.must_change_password,
            csrf=auth.csrf_token(principal.csrf_secret),
        ))

    def post_change_password(
        self, request: Request, principal: Principal | None, _params: dict[str, str],
        now: datetime,
    ) -> Response:
        """
        Change your own password. The current one must be given, the new one must clear the policy.

        On success every session is revoked and one fresh session is issued so the changer stays signed
        in while every other cookie -- and any attacker riding one -- dies. A wrong current password or a
        policy failure re-renders the form in place (200) and writes nothing; the rejected password is
        never reflected back.
        """
        assert principal is not None
        current = request.form.get("current", "")
        new_password = request.form.get("new_password", "")

        material = self._store.password_material(principal.user_id)
        if material is None or not auth.verify_password(current, *material):
            self._store.audit(username=principal.username, action="password.change",
                              detail="wrong current", ip=request.ip, succeeded=False)
            return _html(ui.change_password_page(
                problems=["Your current password is not correct."],
                forced=principal.must_change_password,
                csrf=auth.csrf_token(principal.csrf_secret),
            ))
        problems = auth.password_problems(new_password, principal.username)
        if problems:
            return _html(ui.change_password_page(
                problems=problems, forced=principal.must_change_password,
                csrf=auth.csrf_token(principal.csrf_secret),
            ))

        salt = auth.new_salt()
        self._store.set_password(principal.user_id, salt,
                                 auth.hash_password(new_password, salt),
                                 auth.PBKDF2_ITERATIONS, False)
        # Revoke everything, then re-open one session for the changer alone.
        self._store.delete_sessions_for_user(principal.user_id)
        token = auth.new_session_token()
        self._store.create_session(
            token_hash=auth.token_hash(token), user_id=principal.user_id,
            expires_utc=now + auth.SESSION_IDLE_TIMEOUT, ip=request.ip,
            user_agent=request.user_agent, csrf_secret=auth.new_csrf_secret(),
        )
        self._store.audit(username=principal.username, action="password.change",
                          ip=request.ip, succeeded=True)
        return _redirect("/").with_header("Set-Cookie", self._set_cookie(token))

    # ── read-only pages (task 6.1) ───────────────────────────────────────────────────────────────

    def get_dashboard(
        self, _request: Request, principal: Principal | None, _params: dict[str, str],
        _now: datetime,
    ) -> Response:
        assert principal is not None
        return _html(ui.dashboard(
            self._store.summary(), self._store.devices(), principal,
            offset_hours=self._settings.utc_offset_hours,
        ))

    def get_devices(
        self, _request: Request, principal: Principal | None, _params: dict[str, str],
        _now: datetime,
    ) -> Response:
        assert principal is not None
        return _html(ui.device_list(
            self._store.devices(), principal, offset_hours=self._settings.utc_offset_hours,
        ))

    def get_device(
        self, _request: Request, principal: Principal | None, params: dict[str, str],
        _now: datetime,
    ) -> Response:
        assert principal is not None
        device = self._store.device(params["serial"])
        if device is None:
            return self._error(404, "Unknown device", "No device has that serial number.")
        return _html(ui.device_detail(
            device, self._store.machines(), self._store.commands(serial=device.serial),
            self._store.recent_punches(serial=device.serial), principal,
            auth.csrf_token(principal.csrf_secret), offset_hours=self._settings.utc_offset_hours,
        ))

    # ── device operations (task 7.1) ─────────────────────────────────────────────────────────────

    def get_device_confirm(
        self, _request: Request, principal: Principal | None, params: dict[str, str],
        _now: datetime,
    ) -> Response:
        """The one interstitial: a server-rendered 'disable this device?' page, no JavaScript."""
        assert principal is not None
        device = self._store.device(params["serial"])
        if device is None:
            return self._error(404, "Unknown device", "No device has that serial number.")
        return _html(ui.confirm_page(
            title="Disable device",
            prompt=f"Disable {device.serial}? It will stop accepting pushes until re-enabled.",
            action=f"/devices/{device.serial}/disable",
            hidden={}, csrf=auth.csrf_token(principal.csrf_secret),
        ))

    def post_device_enable(
        self, request: Request, principal: Principal | None, params: dict[str, str],
        _now: datetime,
    ) -> Response:
        return self._set_enabled(request, principal, params["serial"], enabled=True)

    def post_device_disable(
        self, request: Request, principal: Principal | None, params: dict[str, str],
        _now: datetime,
    ) -> Response:
        return self._set_enabled(request, principal, params["serial"], enabled=False)

    def _set_enabled(
        self, request: Request, principal: Principal | None, serial: str, *, enabled: bool,
    ) -> Response:
        assert principal is not None
        if self._store.device(serial) is None:
            return self._error(404, "Unknown device", "No device has that serial number.")
        self._store.set_device_enabled(serial, enabled)
        self._store.audit(username=principal.username,
                          action="device.enable" if enabled else "device.disable",
                          target=serial, ip=request.ip, succeeded=True)
        return _redirect(f"/devices/{serial}")

    def post_device_link(
        self, request: Request, principal: Principal | None, params: dict[str, str],
        _now: datetime,
    ) -> Response:
        assert principal is not None
        serial = params["serial"]
        if self._store.device(serial) is None:
            return self._error(404, "Unknown device", "No device has that serial number.")
        code = request.form.get("machine_code", "").strip()
        # An empty code unlinks. A non-empty code must name a real machine, else the link is refused
        # rather than silently persisting a code that points nowhere.
        if code and code not in {m["code"] for m in self._store.machines()}:
            return self._error(400, "Unknown machine", "That machine code is not in the list.")
        self._store.link_device(serial, code)
        self._store.audit(username=principal.username, action="device.link", target=serial,
                          detail=code, ip=request.ip, succeeded=True)
        return _redirect(f"/devices/{serial}")

    def post_device_command(
        self, request: Request, principal: Principal | None, params: dict[str, str],
        _now: datetime,
    ) -> Response:
        """Queue one allow-listed command; destructive ones are admin-only and pass a confirm page."""
        assert principal is not None
        serial = params["serial"]
        device = self._store.device(serial)
        if device is None:
            return self._error(404, "Unknown device", "No device has that serial number.")
        if not device.enabled:
            return self._error(400, "Device disabled", "Enable the device before queuing a command.")

        value = request.form.get("command", "")
        if value not in COMMAND_ALLOWLIST:
            return self._error(400, "Unknown command", "That command is not on the allow-list.")

        destructive = COMMAND_ALLOWLIST[value]
        if destructive and not principal.can_send_destructive_command:
            self._store.audit(username=principal.username, action="denied", target=serial,
                              detail=value, ip=request.ip, succeeded=False)
            return self._error(403, "Not permitted", "This account cannot send destructive commands.")

        if destructive and request.form.get("confirm") != "1":
            return _html(ui.confirm_page(
                title="Send destructive command",
                prompt=f"Queue '{value}' for {serial}? This erases data on the device and cannot be undone.",
                action=f"/devices/{serial}/commands",
                hidden={"command": value, "confirm": "1"},
                csrf=auth.csrf_token(principal.csrf_secret),
            ))

        self._store.enqueue_command(serial, value, principal.username)
        self._store.audit(username=principal.username, action="device.command", target=serial,
                          detail=value, ip=request.ip, succeeded=True)
        return _redirect(f"/devices/{serial}")

    def post_command_cancel(
        self, request: Request, principal: Principal | None, params: dict[str, str],
        _now: datetime,
    ) -> Response:
        """Cancel a command, but only while it is still pending; a no-op cancel is not an error."""
        assert principal is not None
        serial = params["serial"]
        command_id = _int_param(params["command_id"])
        if command_id is None:  # the route regex admits non-digits; a non-numeric id is just unknown
            return self._error(404, "Unknown command", "No command has that id.")
        cancelled = self._store.cancel_command(command_id)
        self._store.audit(username=principal.username, action="device.command.cancel", target=serial,
                          detail=params["command_id"], ip=request.ip, succeeded=cancelled)
        return _redirect(f"/devices/{serial}")

    def get_roster_sync(
        self, _request: Request, principal: Principal | None, _params: dict[str, str],
        _now: datetime,
    ) -> Response:
        """multi-device-employee-sync: per-device Backfill status and the delete fan-out audit
        trail. Read-only, like /activity and /audit -- see ui.roster_sync_page's own docstring."""
        assert principal is not None
        return _html(ui.roster_sync_page(
            self._store.roster_sync_status(), self._store.recent_deletions(), principal,
            offset_hours=self._settings.utc_offset_hours,
        ))

    def get_activity(
        self, request: Request, principal: Principal | None, _params: dict[str, str],
        _now: datetime,
    ) -> Response:
        assert principal is not None
        # Tab selection is total: any value -- including an absent or unknown one -- resolves to a
        # stream, because ``activity_page`` treats every non-{uploads,unparsed} tab as ``punches``.
        return _html(ui.activity_page(
            request.query.get("tab", "punches"),
            self._store.recent_punches(), self._store.recent_uploads(), self._store.unparsed(),
            principal, offset_hours=self._settings.utc_offset_hours,
        ))

    def get_audit(
        self, _request: Request, principal: Principal | None, _params: dict[str, str],
        _now: datetime,
    ) -> Response:
        assert principal is not None
        return _html(ui.audit_page(
            self._store.recent_audit(), principal, offset_hours=self._settings.utc_offset_hours,
        ))

    # ── users, the last-admin guard (task 8.1) ───────────────────────────────────────────────────

    def get_users(
        self, _request: Request, principal: Principal | None, _params: dict[str, str],
        _now: datetime,
    ) -> Response:
        assert principal is not None
        return _html(ui.users_page(
            self._store.list_users(), principal, auth.csrf_token(principal.csrf_secret),
            offset_hours=self._settings.utc_offset_hours,
        ))

    def post_user_create(
        self, request: Request, principal: Principal | None, _params: dict[str, str],
        _now: datetime,
    ) -> Response:
        """Create a user with a temporary password they must change on first sign-in."""
        assert principal is not None
        username = request.form.get("username", "").strip()
        display_name = request.form.get("display_name", "").strip() or username
        role = request.form.get("role", "")
        password = request.form.get("password", "")

        if not _USERNAME_RE.fullmatch(username):
            return self._error(400, "Invalid username", "Use 1-64 letters, digits, dot, dash or underscore.")
        if not auth.Role.is_valid(role):
            return self._error(400, "Invalid role", "Choose viewer, operator or admin.")
        if self._store.find_user(username) is not None:
            return self._error(400, "Username taken", "Another user already has that username.")
        if auth.password_problems(password, username):
            # The rejected password is never reflected back; only that it was unacceptable.
            return self._error(400, "Weak password", "That password does not meet the policy.")

        salt = auth.new_salt()
        self._store.create_user(
            username=username, display_name=display_name, role=role, salt=salt,
            password_hash=auth.hash_password(password, salt), iterations=auth.PBKDF2_ITERATIONS,
            must_change_password=True, created_by=principal.username,
        )
        self._store.audit(username=principal.username, action="user.create", target=username,
                          detail=role, ip=request.ip, succeeded=True)
        return _redirect("/users")

    def post_user_update(
        self, request: Request, principal: Principal | None, params: dict[str, str],
        _now: datetime,
    ) -> Response:
        assert principal is not None
        user = self._user_or_none(params)
        if user is None:
            return self._error(404, "Unknown user", "No user has that id.")
        role = request.form.get("role", "")
        if not auth.Role.is_valid(role):
            return self._error(400, "Invalid role", "Choose viewer, operator or admin.")
        display_name = request.form.get("display_name", "").strip() or user.username
        enabled = request.form.get("enabled") == "1"

        # The last enabled admin cannot be demoted or disabled, or the console locks itself out.
        loses_admin = user.role == "admin" and user.is_enabled and (role != "admin" or not enabled)
        if loses_admin and self._store.count_enabled_admins() <= 1:
            return self._error(400, "Last administrator", "The console must keep one enabled admin.")

        self._store.update_user(user.user_id, display_name=display_name, role=role, is_enabled=enabled)
        # Disabling a user ends their sessions so a revoked account cannot keep riding a live cookie.
        if not enabled:
            self._store.delete_sessions_for_user(user.user_id)
        self._store.audit(username=principal.username, action="user.update", target=user.username,
                          detail=role, ip=request.ip, succeeded=True)
        return _redirect("/users")

    def post_user_unlock(
        self, request: Request, principal: Principal | None, params: dict[str, str],
        _now: datetime,
    ) -> Response:
        assert principal is not None
        user = self._user_or_none(params)
        if user is None:
            return self._error(404, "Unknown user", "No user has that id.")
        self._store.unlock_user(user.user_id)
        self._store.audit(username=principal.username, action="user.unlock", target=user.username,
                          ip=request.ip, succeeded=True)
        return _redirect("/users")

    def post_user_reset(
        self, request: Request, principal: Principal | None, params: dict[str, str],
        _now: datetime,
    ) -> Response:
        """
        Reset another user's password to a temporary one they must change on first sign-in.

        The reset ends that user's sessions and is audited -- but the audit row never carries the
        password. A password below the policy is refused before anything is written.
        """
        assert principal is not None
        user = self._user_or_none(params)
        if user is None:
            return self._error(404, "Unknown user", "No user has that id.")
        password = request.form.get("password", "")
        if auth.password_problems(password, user.username):
            return self._error(400, "Weak password", "That password does not meet the policy.")

        salt = auth.new_salt()
        self._store.set_password(user.user_id, salt, auth.hash_password(password, salt),
                                 auth.PBKDF2_ITERATIONS, True)
        self._store.delete_sessions_for_user(user.user_id)
        self._store.audit(username=principal.username, action="user.reset", target=user.username,
                          ip=request.ip, succeeded=True)
        return _redirect("/users")

    def post_user_delete(
        self, request: Request, principal: Principal | None, params: dict[str, str],
        _now: datetime,
    ) -> Response:
        assert principal is not None
        user = self._user_or_none(params)
        if user is None:
            return self._error(404, "Unknown user", "No user has that id.")
        if user.user_id == principal.user_id:
            return self._error(400, "Cannot delete yourself", "Ask another admin to remove your account.")
        if user.role == "admin" and user.is_enabled and self._store.count_enabled_admins() <= 1:
            return self._error(400, "Last administrator", "The console must keep one enabled admin.")
        self._store.delete_user(user.user_id)  # the store deletes the user's sessions first
        self._store.audit(username=principal.username, action="user.delete", target=user.username,
                          ip=request.ip, succeeded=True)
        return _redirect("/users")

    def _user_or_none(self, params: dict[str, str]) -> UserRow | None:
        user_id = _guid_param(params["user_id"])
        return self._store.get_user(user_id) if user_id is not None else None

    # ── sessions (task 8.3) ──────────────────────────────────────────────────────────────────────

    def get_sessions(
        self, _request: Request, principal: Principal | None, _params: dict[str, str],
        _now: datetime,
    ) -> Response:
        assert principal is not None
        return _html(ui.sessions_page(
            self._store.active_sessions(), principal, auth.csrf_token(principal.csrf_secret),
            offset_hours=self._settings.utc_offset_hours,
        ))

    def post_session_revoke(
        self, request: Request, principal: Principal | None, params: dict[str, str],
        _now: datetime,
    ) -> Response:
        """
        End every session belonging to a user. Revoking your own user signs you out: the cookie is
        cleared and the response redirects to sign-in, so a self-revoke cannot keep riding a dead cookie.
        """
        assert principal is not None
        user_id = _guid_param(params["user_id"])
        if user_id is None or self._store.get_user(user_id) is None:
            return self._error(404, "Unknown user", "No user has that id.")
        self._store.delete_sessions_for_user(user_id)
        self._store.audit(username=principal.username, action="session.revoke",
                          detail=user_id, ip=request.ip, succeeded=True)
        if user_id == principal.user_id:
            return _redirect("/sign-in").with_header("Set-Cookie", self._clear_cookie())
        return _redirect("/sessions")

    # ── employees (device-admin rights) ──────────────────────────────────────────────────────────

    def get_employees(
        self, _request: Request, principal: Principal | None, _params: dict[str, str],
        _now: datetime,
    ) -> Response:
        """The lookup form. No employee is loaded until an admin enters a PIN."""
        assert principal is not None
        return _html(ui.employees_page(principal, auth.csrf_token(principal.csrf_secret)))

    def post_employee_lookup(
        self, request: Request, principal: Principal | None, _params: dict[str, str],
        _now: datetime,
    ) -> Response:
        assert principal is not None
        pin = _pin_or_none(request.form.get("pin", ""))
        if pin is None:
            return self._error(400, "Invalid PIN", "A PIN is one to nine digits.")
        employee = self._store.get_employee(pin)
        if employee is None:
            return self._error(404, "Unknown employee", "No employee has that PIN.")
        return _html(ui.employees_page(
            principal, auth.csrf_token(principal.csrf_secret), employee=employee,
        ))

    def post_employee_grant(
        self, request: Request, principal: Principal | None, params: dict[str, str],
        _now: datetime,
    ) -> Response:
        return self._set_employee_admin(request, principal, params, is_admin=True)

    def post_employee_revoke(
        self, request: Request, principal: Principal | None, params: dict[str, str],
        _now: datetime,
    ) -> Response:
        return self._set_employee_admin(request, principal, params, is_admin=False)

    def _set_employee_admin(
        self, request: Request, principal: Principal | None, params: dict[str, str], *, is_admin: bool
    ) -> Response:
        assert principal is not None
        pin = _pin_or_none(params["pin"])
        if pin is None:
            return self._error(400, "Invalid PIN", "A PIN is one to nine digits.")
        employee = self._store.get_employee(pin)
        if employee is None:
            return self._error(404, "Unknown employee", "No employee has that PIN.")

        # An empty field means "leave any existing password alone", so a plain grant never blanks it.
        raw_pw = request.form.get("password", "").strip()
        password: int | None = None
        if raw_pw:
            password = _device_password_or_none(raw_pw)
            if password is None:
                # The rejected value is never reflected back; only that it was unacceptable.
                return self._error(400, "Invalid password", "A device password is one to eight digits.")

        result = self._store.set_employee_admin(
            pin, is_admin=is_admin, password=password, name=employee.name, card=employee.card,
            created_by=principal.username,
        )
        # The audit row records the act and the target, never the password.
        self._store.audit(
            username=principal.username,
            action="employee.grant_admin" if is_admin else "employee.revoke_admin",
            target=str(pin), ip=request.ip, succeeded=True,
        )
        updated = self._store.get_employee(pin) or employee
        return _html(ui.employees_page(
            principal, auth.csrf_token(principal.csrf_secret), employee=updated, result=result,
        ))

    def _same_origin_if_stated(self, request: Request) -> bool:
        """
        Defence in depth for the sign-in POST: if the browser sent an Origin or Referer, its host must
        match this request's host. When neither is present -- as browsers do on a same-origin form POST
        over plain HTTP -- there is nothing to check, so this passes and the double-submit CSRF token is
        the sole guard. That token is what actually prevents forged sign-ins.
        """
        host = request.headers.get("host", "")
        source = request.headers.get("origin", "") or request.headers.get("referer", "")
        # ``Origin: null`` is an opaque origin -- some browser contexts send it on a same-site form POST.
        # It names no host, so there is nothing to compare; treat it like an absent header and let the
        # double-submit token be the sole guard, as for a plain-HTTP form that omits Origin entirely.
        if not source or source == "null":
            return True
        return bool(host) and urlsplit(source).netloc == host

    # ── error page + finalise ────────────────────────────────────────────────────────────────────

    def _error(self, status: int, heading: str, detail: str) -> Response:
        return Response(
            status=status,
            body=ui.error_page(status=status, heading=heading, detail=detail).encode("utf-8"),
        )

    def _finalize(self, response: Response) -> list[tuple[str, str]]:
        headers = [("Content-Type", response.content_type), *_SECURITY_HEADERS]
        supplied = {name.lower() for name, _ in response.headers}
        if "cache-control" not in supplied:
            headers.append(("Cache-Control", "no-store"))
        headers.extend(response.headers)
        headers.append(("Content-Length", str(len(response.body))))
        return headers


def _match_pattern(pattern: str, path: str) -> dict[str, str] | None:
    """
    Match a route pattern against a path, capturing ``{name}`` segments.

    A parameter segment must match :data:`_PARAM_RE` in full, so a value carrying a slash, a space or
    a traversal never becomes a clean parameter and never reaches a handler or the database.
    """
    p_parts = pattern.split("/")
    a_parts = path.split("/")
    if len(p_parts) != len(a_parts):
        return None
    params: dict[str, str] = {}
    for expected, actual in zip(p_parts, a_parts, strict=False):
        if expected.startswith("{") and expected.endswith("}"):
            if not _PARAM_RE.fullmatch(actual):
                return None
            params[expected[1:-1]] = actual
        elif expected != actual:
            return None
    return params


def _parse_form(environ: dict[str, Any]) -> dict[str, str]:
    stream = environ.get("wsgi.input")
    if stream is None:
        return {}
    try:
        length = int(environ.get("CONTENT_LENGTH") or "0")
    except (TypeError, ValueError):
        return {}
    if length <= 0:
        return {}
    raw = stream.read(min(length, MAX_FORM_BYTES))
    pairs = parse_qsl(raw.decode("utf-8", "replace"), keep_blank_values=True)
    form: dict[str, str] = {}
    for key, value in pairs:
        if len(form) >= MAX_FORM_FIELDS and key not in form:
            break
        form[key] = value
    return form


def _parse_cookies(header: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in header.split(";"):
        name, _, value = part.strip().partition("=")
        if name:
            cookies[name] = value
    return cookies


def _client_ip(environ: dict[str, Any], headers: dict[str, str]) -> str:
    """Left-most X-Forwarded-For entry, port stripped; diagnostics only, never an access decision."""
    forwarded = headers.get("x-forwarded-for", "")
    if forwarded:
        first = forwarded.split(",")[0].strip()
        if first:
            if first.count(":") == 1:  # IIS appends :port on IPv4; leave IPv6 colons alone
                first = first.split(":")[0]
            return first
    return str(environ.get("REMOTE_ADDR") or "")


_REASONS = {
    200: "OK", 303: "See Other", 304: "Not Modified", 400: "Bad Request",
    401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 500: "Internal Server Error",
    503: "Service Unavailable",
}


def _reason(status: int) -> str:
    return _REASONS.get(status, "OK" if 200 <= status < 300 else "Error")


def _redirect(location: str) -> Response:
    return Response(status=303, headers=(("Location", location),))


def _next_url(path: str) -> str:
    return "/sign-in?next=" + quote(path, safe="")


def _permits(principal: Principal | None, requires: str) -> bool:
    """Map a route's capability requirement onto the principal's role capabilities."""
    if principal is None:
        return False
    return {
        "view": principal.can_view,
        "operate": principal.can_operate,
        "administer": principal.can_administer,
    }.get(requires, False)


def _int_param(value: str) -> int | None:
    """A path id as an int, or None. The route regex admits letters, so a non-numeric id is not fatal."""
    return int(value) if value.isdigit() else None


def _pin_or_none(value: str) -> int | None:
    """An employee PIN (``NHANVIEN.MaChamCong``): one to nine digits, or None. Bounds it below int32."""
    text = value.strip()
    return int(text) if text.isdigit() and 1 <= len(text) <= 9 else None


def _device_password_or_none(value: str) -> int | None:
    """
    A device unlock password: one to eight digits with a positive value, or None.

    The firmware and the desktop push path both treat ``enPassword <= 0`` as "no password", so a
    leading-zero or all-zero value is rejected rather than silently meaning "clear it".
    """
    text = value.strip()
    if not (text.isdigit() and 1 <= len(text) <= 8):
        return None
    password = int(text)
    return password if password > 0 else None


def _guid_param(value: str) -> str | None:
    """
    A path id as a canonical GUID string, or None if it is not a well-formed GUID.

    ``APP_USER.UserId`` is a ``uniqueidentifier``. Parsing through :class:`uuid.UUID` both rejects a
    malformed id before it reaches SQL and canonicalises the casing/braces, so ``/users/<garbage>``
    is a clean 404 rather than a driver error.
    """
    try:
        return str(uuid.UUID(value))
    except (ValueError, AttributeError):
        return None


def _html(markup: str) -> Response:
    return Response(status=200, body=markup.encode("utf-8"))


def _safe_next(candidate: str) -> str:
    """
    Accept ``next`` only when it is a local absolute path, never an off-site or scheme-relative URL.

    A ``//host`` or ``http://host`` target would turn the login redirect into an open redirect, so
    anything that is not a bare ``/path`` is dropped and the caller falls back to ``/``.
    """
    if not candidate.startswith("/") or candidate.startswith("//"):
        return ""
    split = urlsplit(candidate)
    if split.scheme or split.netloc:
        return ""
    return candidate


def create_app(store: AdminStore | None = None, **kw: Any) -> AdminWsgiApp:
    """
    Build the WSGI application, composing the real store when none is supplied.

    Composition on first call rather than at import time so a configuration error surfaces as a logged
    503 from a running site instead of an opaque IIS 502.
    """
    if store is None:
        # The real store, logger and settings are composed in adms.admin.serve (task 10.1), which is
        # the only caller that runs without an injected store. Until then this path is unused: every
        # test supplies a FakeStore, so there is no composition module to import yet.
        raise RuntimeError("create_app requires a store until adms.admin.serve is built")
    return AdminWsgiApp(store, **kw)
