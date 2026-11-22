"""
Tests for ``adms.observability`` -- error reporting to Sentry.

The property that matters is the negative one: **nothing personal and no credential leaves the host.**
Every test that reaches the real SDK swaps its transport for :class:`CaptureTransport`, a hand-written
fake that keeps envelopes in memory, so the suite sends nothing over the network and can assert on
exactly the JSON Sentry would have received.
"""

from __future__ import annotations

import io
import json
from typing import Any

import pytest

from adms import observability
from adms.config import Settings, load_settings
from adms.errors import ConfigError
from adms.logging_setup import JsonLogger

sentry_sdk = pytest.importorskip("sentry_sdk")
from sentry_sdk.transport import Transport  # noqa: E402

DSN = "https://publickey@o0.ingest.de.sentry.io/0"
# Kept far from the code that raises them, so Sentry's source-context lines (our own code, which is
# public) cannot be what carries them into an event in the end-to-end test.
PARSE_ERROR = "cannot parse 'USER PIN=1042\tName=Nguyen Van A'"
LOG_MESSAGE = "ATTLOG parse failed for SN=CQZ7233460123"
DEVICE_SERIAL = "CQZ7233460123"
SECRET = "s3cretpath"


class CaptureTransport(Transport):
    """Keeps every envelope's JSON items; sends nothing."""

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self.items: list[dict[str, Any]] = []

    def capture_envelope(self, envelope: Any) -> None:
        for item in envelope.items:
            payload = item.payload.json
            if payload is not None:
                self.items.append(payload)

    def flush(self, timeout: float, callback: Any = None) -> None:  # noqa: ARG002 - SDK signature
        return None

    def kill(self) -> None:
        return None


@pytest.fixture
def transport(monkeypatch: pytest.MonkeyPatch):
    """Start reporting through the real SDK with an in-memory transport; tear it down after."""
    capture = CaptureTransport()
    real_init = sentry_sdk.init

    def init_with_capture(**kwargs: Any) -> Any:
        return real_init(transport=capture, **kwargs)

    monkeypatch.setattr(sentry_sdk, "init", init_with_capture)
    settings = Settings(sql_connection="x", sentry_dsn=DSN, path_secret=SECRET, sentry_traces_sample_rate=1.0)
    assert observability.init_sentry(settings, component="collector")
    yield capture
    sentry_sdk.get_client().close()


@pytest.fixture(autouse=True)
def _reporting_off_after_each_test():
    """Module state set by init_sentry is reset by assignment, not monkeypatch: undo would restore it."""
    yield
    observability._enabled = False
    observability._path_secret = ""


def _events(capture: CaptureTransport) -> list[dict[str, Any]]:
    return [item for item in capture.items if item.get("type") != "transaction" and "event_id" in item]


# ---- Configuration ------------------------------------------------------------------------------


def test_reporting_is_off_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("ADMS_SENTRY_DSN", "ADMS_SENTRY_ENVIRONMENT", "ADMS_SENTRY_TRACES_SAMPLE_RATE"):
        monkeypatch.delenv(name, raising=False)
    settings = load_settings()
    assert settings.sentry_dsn == ""
    assert settings.sentry_environment == "production"
    assert settings.sentry_traces_sample_rate == 0.02
    assert observability.init_sentry(settings, component="collector") is False
    assert observability.is_enabled() is False


def test_settings_read_the_sentry_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADMS_SENTRY_DSN", DSN)
    monkeypatch.setenv("ADMS_SENTRY_ENVIRONMENT", "staging")
    monkeypatch.setenv("ADMS_SENTRY_TRACES_SAMPLE_RATE", "0.1")
    settings = load_settings()
    assert (settings.sentry_dsn, settings.sentry_environment, settings.sentry_traces_sample_rate) == (
        DSN,
        "staging",
        0.1,
    )


@pytest.mark.parametrize("raw", ["abc", "-0.1", "1.5"])
def test_a_sample_rate_outside_zero_to_one_fails_fast(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    monkeypatch.setenv("ADMS_SENTRY_TRACES_SAMPLE_RATE", raw)
    with pytest.raises(ConfigError, match="ADMS_SENTRY_TRACES_SAMPLE_RATE"):
        load_settings()


def test_init_passes_the_privacy_options(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}
    monkeypatch.setattr(sentry_sdk, "init", lambda **kwargs: seen.update(kwargs))
    monkeypatch.setattr(sentry_sdk, "set_tag", lambda *_: None)
    try:
        assert observability.init_sentry(Settings(sentry_dsn=DSN), component="console")
    finally:
        observability._enabled = False
    assert seen["send_default_pii"] is False
    assert seen["include_local_variables"] is False
    assert seen["max_breadcrumbs"] == 0
    assert seen["environment"] == "production"
    assert seen["traces_sample_rate"] == 0.02
    assert seen["before_send"] is observability.scrub_event


def test_an_sdk_that_fails_to_start_never_stops_the_service(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(**_: Any) -> None:
        raise RuntimeError("bad dsn")

    monkeypatch.setattr(sentry_sdk, "init", boom)
    stream = io.StringIO()
    assert (
        observability.init_sentry(
            Settings(sentry_dsn=DSN), component="collector", log=JsonLogger(stream=stream)
        )
        is False
    )
    assert observability.is_enabled() is False
    assert "Sentry could not start" in stream.getvalue()


# ---- Scrubbing ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "must_not_contain"),
    [
        ("bad line 'USER PIN=1042\tName=Nguyen Van A\tPri=0'", ["1042", "Nguyen"]),
        ("1042\t2026-11-22 08:15:00\t0\t1", ["1042", "08:15"]),
        ("unknown device SN=CQZ7233460123", ["CQZ7233460123"]),
        ("serial=CQZ7233460123 rejected", ["CQZ7233460123"]),
        ("login failed: PWD=hunter2;UID=sa", ["hunter2"]),
        ("employee_id=88 name=Tran", ["88", "Tran"]),
        (
            "Violation of PRIMARY KEY constraint 'PK_X'. "
            "The duplicate key value is (1042, 2026-11-22 08:15:00).",
            ["1042", "08:15"],
        ),
        ("Conversion failed when converting the nvarchar value 'A1042' to data type int.", ["A1042"]),
        ("device CQZ7233460123 rejected", ["CQZ7233460123"]),
        ("KeyError: 'row 1042'", ["1042"]),
    ],
)
def test_scrub_text_removes_identifiers_records_and_credentials(
    raw: str, must_not_contain: list[str]
) -> None:
    scrubbed = observability.scrub_text(raw)
    for fragment in must_not_contain:
        assert fragment not in scrubbed


def test_scrub_text_keeps_a_plain_message_readable() -> None:
    assert observability.scrub_text("Database unavailable after 3 retries.") == (
        "Database unavailable after 3 retries."
    )


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/iclock/cdata", "/iclock/cdata"),
        (f"/{SECRET}/iclock/getrequest", "/*/iclock/getrequest"),
        ("/devices/CQZ7233460123", "/devices/*"),
        ("/", "/"),
    ],
)
def test_route_template_hides_serials_and_the_path_secret(path: str, expected: str) -> None:
    assert observability.route_template(path, SECRET) == expected


def test_scrub_event_drops_request_user_extra_and_frame_vars() -> None:
    event = {
        "request": {"query_string": "SN=CQZ7233460123", "data": "1042\t2026-11-22"},
        "user": {"ip_address": "10.0.0.5"},
        "extra": {"sys.argv": ["serve"]},
        "breadcrumbs": {"values": [{"message": "PIN=1042"}]},
        "exception": {
            "values": [
                {
                    "type": "ValueError",
                    "value": "bad PIN=1042",
                    "stacktrace": {"frames": [{"function": "parse", "vars": {"body": "1042\tx"}}]},
                }
            ]
        },
        "logentry": {"message": "SN=CQZ7233460123", "params": ["1042"]},
    }
    scrubbed = observability.scrub_event(event)
    text = json.dumps(scrubbed)
    for fragment in ("CQZ7233460123", "1042", "10.0.0.5", "sys.argv"):
        assert fragment not in text
    assert scrubbed["exception"]["values"][0]["type"] == "ValueError"


# ---- End to end through the real SDK ------------------------------------------------------------


def test_a_logged_error_reaches_sentry_without_personal_data(transport: CaptureTransport) -> None:
    log = JsonLogger(stream=io.StringIO(), error_sink=observability.report_error, serial=DEVICE_SERIAL)
    try:
        raise ValueError(PARSE_ERROR)
    except ValueError as exc:
        log.error(LOG_MESSAGE, exc)
    sentry_sdk.flush()

    events = _events(transport)
    assert len(events) == 1
    event = events[0]
    text = json.dumps(event, ensure_ascii=False)
    for fragment in ("CQZ7233460123", "1042", "Nguyen", SECRET):
        assert fragment not in text
    assert event["exception"]["values"][-1]["type"] == "ValueError"
    assert event["tags"]["component"] == "collector"
    assert event["environment"] == "production"
    assert "request" not in event and "user" not in event


def test_a_logged_error_without_exception_becomes_a_message(transport: CaptureTransport) -> None:
    JsonLogger(stream=io.StringIO(), error_sink=observability.report_error).error("Database unavailable.")
    sentry_sdk.flush()
    events = _events(transport)
    assert [e.get("message") or e.get("logentry", {}).get("message") for e in events] == [
        "Database unavailable."
    ]
    assert events[0]["level"] == "error"


def test_warnings_are_not_reported(transport: CaptureTransport) -> None:
    JsonLogger(stream=io.StringIO(), error_sink=observability.report_error).warn("Device slow.")
    sentry_sdk.flush()
    assert _events(transport) == []


def test_a_traced_request_is_named_by_route_and_carries_no_query(transport: CaptureTransport) -> None:
    from adms.wsgi import with_error_reporting

    def app(_environ: dict[str, Any], start_response: Any) -> list[bytes]:
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"OK"]

    wrapped = with_error_reporting(app)
    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": f"/{SECRET}/iclock/getrequest",
        "QUERY_STRING": "SN=CQZ7233460123",
        "SERVER_NAME": "adms.local",
        "SERVER_PORT": "80",
        "REMOTE_ADDR": "10.0.0.5",
        "wsgi.url_scheme": "http",
        "wsgi.input": io.BytesIO(b""),
    }
    list(wrapped(environ, lambda *_: None))
    sentry_sdk.flush()

    transactions = [item for item in transport.items if item.get("type") == "transaction"]
    assert len(transactions) == 1
    text = json.dumps(transactions[0])
    for fragment in ("CQZ7233460123", SECRET, "10.0.0.5"):
        assert fragment not in text
    assert transactions[0]["transaction"] == "/*/iclock/getrequest"


def test_wrapping_is_a_no_op_when_reporting_is_off() -> None:
    from adms.wsgi import with_error_reporting

    def app(*_: Any) -> list[bytes]:
        return []

    assert with_error_reporting(app) is app


def test_sentry_test_flag_needs_a_dsn(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("ADMS_SENTRY_DSN", raising=False)
    assert observability.run_sentry_test(component="collector") == 1
    assert "ADMS_SENTRY_DSN is not set" in capsys.readouterr().out


def test_sentry_test_flag_sends_one_event(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    capture = CaptureTransport()
    real_init = sentry_sdk.init
    monkeypatch.setattr(sentry_sdk, "init", lambda **kwargs: real_init(transport=capture, **kwargs))
    monkeypatch.setenv("ADMS_SENTRY_DSN", DSN)
    try:
        assert observability.run_sentry_test(component="collector") == 0
    finally:
        sentry_sdk.get_client().close()
        observability._enabled = False
    assert "test event sent" in capsys.readouterr().out
    events = _events(capture)
    assert [e["exception"]["values"][-1]["type"] for e in events] == ["SentryTestError"]
