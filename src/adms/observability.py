"""
Error reporting to Sentry.

Off unless ``ADMS_SENTRY_DSN`` is set, and ``sentry_sdk`` is imported only then: a site that never
configures a DSN runs exactly the code it ran before this module existed.

What reaches Sentry is deliberately narrow, because everything this service handles is either
personal data (employee PINs, names, punch times, biometric templates) or a credential (the device
serial is the whole of the ADMS "authentication", and ``ADMS_PATH_SECRET`` rides in the URL):

* ``send_default_pii=False`` and no local variables in stack frames -- a frame in the ATTLOG parser
  holds the upload body.
* No request block at all: no headers, no query string (it carries ``SN=``), no body, no client IP.
* No breadcrumbs, no ``extra``, no user.
* Exception and log messages pass through :func:`scrub_text`, which removes connection-string
  credentials (the same rule as the JSON log), ``key=value`` pairs that name a person or a device,
  any tab-separated record line (how ATTLOG/OPERLOG rows look), row values SQL Server echoes in its
  errors, quoted fragments carrying a digit, and bare device serials.
* Transaction names are route templates: a path segment carrying a digit or the path secret becomes
  ``*``, so ``/devices/ABC123`` and ``/<secret>/iclock/cdata`` cannot leak a serial or the secret.

Reporting never raises into the caller. A failure to report is logged once to stdout and dropped --
the device must still get its status code.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from . import __version__
from .logging_setup import scrub

if TYPE_CHECKING:
    from .config import Settings

__all__ = [
    "init_sentry",
    "is_enabled",
    "report_error",
    "route_template",
    "scrub_event",
    "scrub_text",
    "send_test_event",
]

#: ``key=value`` pairs that identify a person or a device, in the spellings the ADMS grammar and our
#: own log messages use. Matched up to the next separator.
_IDENTIFIER_PATTERN = re.compile(
    r"(?i)\b(pin|name|card|passwd|password|privilege|sn|serial|userid|user_id|emp(?:loyee)?_?(?:id|code)?"
    r"|machamcong|hoten)\s*=\s*[^\s;&,\t]*"
)
#: A tab-separated record line: every ATTLOG/OPERLOG/USER row the device uploads looks like this.
_RECORD_LINE_PATTERN = re.compile(r"[^\n]*\t[^\n]*")
#: SQL Server echoes row values in its messages: "The duplicate key value is (1042, 2026-11-22 ...)",
#: "converting the nvarchar value 'abc' to data type int". Those values are the attendance rows.
_SQL_VALUE_PATTERN = re.compile(r"(?i)(\bvalue(?: is)?\s*)(\([^)]*\)|'[^']*'|N'[^']*')")
#: Any quoted fragment carrying a digit is data (a PIN, a serial, a time), not an identifier name.
_QUOTED_DATA_PATTERN = re.compile(r"'[^'\n]*\d[^'\n]*'")
#: A ZKTeco serial on its own, e.g. CQZ7233460123: a few capitals then eight or more digits.
_SERIAL_PATTERN = re.compile(r"\b[A-Z]{2,6}\d{8,}\b")
_MAX_TEXT = 1000

_enabled = False
_path_secret = ""


def is_enabled() -> bool:
    return _enabled


def scrub_text(value: object) -> object:
    """Redact credentials, identifiers and record lines from a string; other types pass through."""
    if not isinstance(value, str):
        return value
    text = str(scrub(value))
    if _path_secret:
        text = text.replace(_path_secret, "***")
    text = _RECORD_LINE_PATTERN.sub("[record redacted]", text)
    text = _IDENTIFIER_PATTERN.sub(lambda m: f"{m.group(1)}=***", text)
    text = _SQL_VALUE_PATTERN.sub(lambda m: f"{m.group(1)}(***)", text)
    text = _QUOTED_DATA_PATTERN.sub("'***'", text)
    text = _SERIAL_PATTERN.sub("***", text)
    return text[:_MAX_TEXT]


def route_template(path: str, path_secret: str = "") -> str:
    """``/devices/ABC123`` -> ``/devices/*``; the path secret and any segment with a digit become ``*``."""
    segments = []
    for segment in path.split("/"):
        if segment and ((path_secret and segment == path_secret) or any(ch.isdigit() for ch in segment)):
            segments.append("*")
        else:
            segments.append(segment)
    return "/".join(segments) or "/"


def scrub_event(event: dict[str, Any], _hint: object = None) -> dict[str, Any]:
    """``before_send``: strip everything that could carry personal data or a credential."""
    for key in ("request", "user", "extra", "breadcrumbs"):
        event.pop(key, None)

    for exc in (event.get("exception") or {}).get("values") or []:
        if "value" in exc:
            exc["value"] = scrub_text(exc["value"])
        for frame in (exc.get("stacktrace") or {}).get("frames") or []:
            frame.pop("vars", None)

    for thread in (event.get("threads") or {}).get("values") or []:
        for frame in (thread.get("stacktrace") or {}).get("frames") or []:
            frame.pop("vars", None)

    logentry = event.get("logentry")
    if isinstance(logentry, dict):
        logentry.pop("params", None)
        for key in ("message", "formatted"):
            if key in logentry:
                logentry[key] = scrub_text(logentry[key])
    if "message" in event:
        event["message"] = scrub_text(event["message"])
    return event


def _scrub_transaction(event: dict[str, Any], _hint: object = None) -> dict[str, Any]:
    """``before_send_transaction``: name by route template, then drop request data like an error."""
    url = ((event.get("request") or {}).get("url")) or ""
    if url:
        event["transaction"] = route_template(urlsplit(url).path, _path_secret)
    trace_data = ((event.get("contexts") or {}).get("trace") or {}).get("data")
    for data in [trace_data, *[span.get("data") for span in event.get("spans") or []]]:
        if isinstance(data, dict):
            for key in [k for k in data if k.startswith(("http.", "url.", "client.", "server.address"))]:
                data.pop(key, None)
    return scrub_event(event)


def init_sentry(settings: Settings, *, component: str, log: Any = None) -> bool:
    """
    Start the SDK for this process when a DSN is configured. Returns whether reporting is on.

    ``component`` names the process (``collector``, ``console``) and becomes a tag, so one Sentry
    project can tell the two apart.
    """
    global _enabled, _path_secret
    if not settings.sentry_dsn:
        return False
    try:
        import sentry_sdk

        _path_secret = settings.path_secret
        sentry_sdk.init(
            dsn=settings.sentry_dsn,
            environment=settings.sentry_environment or "production",
            release=f"adms-attendance@{__version__}",
            send_default_pii=False,
            include_local_variables=False,
            max_breadcrumbs=0,
            traces_sample_rate=settings.sentry_traces_sample_rate,
            before_send=scrub_event,
            before_send_transaction=_scrub_transaction,
        )
        sentry_sdk.set_tag("component", component)
        _enabled = True
    except Exception as exc:  # noqa: BLE001 - reporting must never stop the service starting
        _enabled = False
        if log is not None:
            log.warn("Sentry could not start; continuing without error reporting.", exc)
        return False
    if log is not None:
        log.info(
            "Sentry error reporting on.",
            environment=settings.sentry_environment,
            traces_sample_rate=settings.sentry_traces_sample_rate,
        )
    return True


def report_error(message: str, exc: BaseException | None = None) -> None:
    """Send one ERROR to Sentry. A no-op when reporting is off; never raises."""
    if not _enabled:
        return
    try:
        import sentry_sdk

        if exc is not None:
            with sentry_sdk.new_scope() as scope:
                scope.set_context("log", {"message": scrub_text(message)})
                sentry_sdk.capture_exception(exc)
        else:
            sentry_sdk.capture_message(str(scrub_text(message)), level="error")
    except Exception:  # noqa: BLE001 - the JSON log already holds the error; reporting is extra
        pass


class SentryTestError(RuntimeError):
    """Raised on purpose by ``--sentry-test`` so an operator can see one event arrive."""


def send_test_event(settings: Settings, *, component: str, log: Any = None) -> str | None:
    """Initialise, send one test exception, flush. Returns the event id, or None when not sent."""
    if not init_sentry(settings, component=component, log=log):
        return None
    import sentry_sdk

    try:
        raise SentryTestError("ADMS Sentry test event (sent on purpose by --sentry-test)")
    except SentryTestError as exc:
        event_id = sentry_sdk.capture_exception(exc)
    sentry_sdk.flush(timeout=10)
    return event_id


def init_from_environment(*, component: str, log: Any = None) -> bool:
    """:func:`init_sentry` from the process environment, for the ``serve`` entry points."""
    from .config import load_settings

    try:
        settings = load_settings()
    except Exception:  # noqa: BLE001 - the start-up path that follows reports a bad configuration
        return False
    return init_sentry(settings, component=component, log=log)


def run_sentry_test(*, component: str, log: Any = None) -> int:
    """``--sentry-test``: send one event and print its id. Exit 0 when sent, 1 otherwise."""
    from .config import load_settings

    try:
        settings = load_settings()
    except Exception as exc:  # noqa: BLE001
        print(f"sentry: configuration is invalid - {exc}")
        return 1
    if not settings.sentry_dsn:
        print("sentry: ADMS_SENTRY_DSN is not set; nothing sent.")
        return 1
    event_id = send_test_event(settings, component=component, log=log)
    if not event_id:
        print("sentry: the SDK did not start (is sentry-sdk installed?); nothing sent.")
        return 1
    print(f"sentry: test event sent, id {event_id} (environment {settings.sentry_environment})")
    return 0
