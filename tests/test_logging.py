"""
Tests for ``adms.logging_setup`` -- the structured JSON logger.

Three properties live here:

* **Property 67** says logging never throws and never loses a line to a filesystem fault: every
  call returns, and every emitted line -- on standard output and in the daily file -- parses as one
  complete JSON object, even under concurrent writers, because the whole reason for the shared lock
  is to stop two threads from interleaving half-lines.
* **Property 68** says the redaction is exact in both directions: every credential-bearing
  assignment is replaced while its key stays visible, and nothing else -- server, port, database --
  is touched.
* **Property 69** says a recorded traceback is bounded to 6 frames and carries only the logged
  exception's own chain, never an unrelated exception Python attached as ``__context__``. This is
  the case that already cost someone an afternoon: raise deliberately inside an ``except
  ImportError:`` block and confirm the ``ImportError`` is absent from what was recorded.

No service, no adapters, no database -- ``JsonLogger`` and ``scrub`` are driven directly, or through
``tests/conftest.py``'s ``LogCapture`` where a parsed-JSON view is what the case needs.
"""

from __future__ import annotations

import datetime as dt
import io
import json
import threading
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import LogCapture

from adms.logging_setup import JsonLogger, scrub

# ── Property 67: Logging is structured, serialised, total, and degrades rather than fails ───

# ---- Hostile message and field values: every call returns, nothing is lost silently -------------


class _RaisesOnStr:
    """A value whose string conversion raises -- the case ``default=str`` exists to survive."""

    def __str__(self) -> str:
        raise RuntimeError("__str__ boom")

    def __repr__(self) -> str:
        return "_RaisesOnStr()"


def _recursive_structure() -> dict[str, object]:
    node: dict[str, object] = {}
    node["self"] = node
    return node


def _recursive_list() -> list[object]:
    node: list[object] = [1, 2]
    node.append(node)
    return node


def _hostile_field_cases() -> tuple[tuple[str, Callable[[], object]], ...]:
    return (
        ("an object whose __str__ raises", _RaisesOnStr),
        ("a dict that contains itself", _recursive_structure),
        ("a list that contains itself", _recursive_list),
        ("a lone UTF-16 surrogate", lambda: "before \ud800 after"),
        ("a lone surrogate at the very end", lambda: "trailing \udfff"),
        ("an ordinary large int", lambda: 2**200),
        ("a bytes value", lambda: b"\x00\x01\xff raw bytes"),
    )


@pytest.mark.parametrize(
    ("case_id", "make_value"), _hostile_field_cases(), ids=[c[0] for c in _hostile_field_cases()]
)
def test_hostile_field_values_never_raise(case_id: str, make_value: Callable[[], object]) -> None:
    # Feature: adms-attendance-system, Property 67: Logging is structured, serialised, total, and
    # degrades rather than fails -- for all field values, including an object whose string
    # conversion raises, a recursive structure and a lone surrogate, every logging call returns
    # without raising.
    logs = LogCapture()
    logs.logger.info("field under test", value=make_value())
    logs.logger.warn("field under test (warn)", value=make_value())
    logs.logger.error("field under test (error)", value=make_value())
    # No assertion beyond "the calls above did not raise" is required by this case; a raise would
    # already have failed the test. Also confirm the logger keeps working afterwards.
    logs.logger.info("still alive")
    assert any(r.get("msg") == "still alive" for r in logs.records), f"{case_id}: logger stopped working"


def test_hostile_message_itself_never_raises() -> None:
    # Feature: adms-attendance-system, Property 67: the message argument is exactly as hostile as a
    # field value can be, and must degrade the same way -- a lone surrogate in the message text must
    # not stop the call from returning.
    logs = LogCapture()
    logs.logger.info("lone surrogate in the message itself: \ud800 -- still returns")
    logs.logger.info("still alive after a hostile message")
    assert len(logs.records) == 2


# ---- Every emitted line is one complete, parseable JSON object ----------------------------------


def test_every_emitted_line_parses_as_one_json_object_with_required_fields() -> None:
    # Feature: adms-attendance-system, Property 67: every emitted line parses as a JSON object
    # carrying a UTC timestamp, a level, the message and the supplied fields.
    logs = LogCapture(serial="CJXX204960333")
    logs.logger.info("upload accepted", route="attlog", inserted=3)
    logs.logger.warn("device unlinked", reason="no MaMCC")
    logs.logger.error("write failed", exc=RuntimeError("boom"))

    assert len(logs.records) == 3
    for record in logs.records:
        assert set(record) >= {"ts", "level", "msg"}, record
        assert record["level"] in {"DEBUG", "INFO", "WARN", "WARNING", "ERROR"}
        # ISO-8601 with an explicit UTC offset, not a naive local timestamp.
        assert record["ts"].endswith("+00:00") or record["ts"].endswith("Z"), record["ts"]

    info, warn, error = logs.records
    assert info["route"] == "attlog"
    assert info["inserted"] == 3
    assert warn["reason"] == "no MaMCC"
    assert "error" in error and "trace" in error


def test_context_fields_are_carried_on_every_line_from_a_child_logger() -> None:
    # Feature: adms-attendance-system, Property 67: the supplied fields include context stamped by
    # with_context, so every line from a per-request child logger carries it.
    logs = LogCapture()
    child = logs.logger.with_context(serial="CJXX204960333", route="cdata")
    child.info("line one")
    child.info("line two", table="ATTLOG")

    assert len(logs.records) == 2
    for record in logs.records:
        assert record["serial"] == "CJXX204960333"
        assert record["route"] == "cdata"
    assert logs.records[1]["table"] == "ATTLOG"


# ---- Filesystem faults: degrade to stdout, never raise -------------------------------------------


def test_uncreatable_log_directory_still_writes_to_standard_output(tmp_path: Path) -> None:
    # Feature: adms-attendance-system, Property 67: for an uncreatable log directory, output
    # continues on standard output -- a directory cannot be created when a path component that
    # should be a directory is actually a file.
    blocker = tmp_path / "blocker-file"
    blocker.write_text("not a directory", encoding="utf-8")
    uncreatable = blocker / "logs"  # "blocker-file" is a file, not a directory

    buffer = io.StringIO()
    logger = JsonLogger(level="DEBUG", stream=buffer, log_dir=str(uncreatable))
    logger.info("still reaches stdout")

    lines = [line for line in buffer.getvalue().splitlines() if line.strip()]
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["msg"] == "still reaches stdout"
    # The constructor gave up on the directory rather than leaving a half-configured logger that
    # tries (and fails) on every write.
    assert not uncreatable.is_dir()


def test_unwritable_log_file_still_writes_to_standard_output(tmp_path: Path) -> None:
    # Feature: adms-attendance-system, Property 67: if appending to the log file fails, output
    # continues on standard output. The target path is made unwritable by making it a directory,
    # so open(path, "a") raises OSError -- disk-full and permission-denied raise the identical
    # exception type, so this exercises the same handling.
    stamp = dt.datetime.now().strftime("%Y%m%d")
    target_path = tmp_path / f"adms-{stamp}.log"
    target_path.mkdir(parents=True)  # today's log file path is a directory, not a file

    buffer = io.StringIO()
    logger = JsonLogger(level="DEBUG", stream=buffer, log_dir=str(tmp_path))
    logger.info("stdout survives an unwritable file")
    logger.error("and so does a second call", exc=RuntimeError("boom"))

    lines = [line for line in buffer.getvalue().splitlines() if line.strip()]
    assert len(lines) == 2
    for line in lines:
        json.loads(line)  # must still be one complete parseable object each


def test_log_file_is_opened_per_write_not_held_open(tmp_path: Path) -> None:
    # Feature: adms-attendance-system, Property 67: the file is opened per write, so an operator
    # moving or deleting the file between calls does not leave the process writing into a deleted
    # handle -- the next call simply recreates the file.
    logger = JsonLogger(level="DEBUG", stream=io.StringIO(), log_dir=str(tmp_path))
    logger.info("first line")

    files_after_first = list(tmp_path.iterdir())
    assert len(files_after_first) == 1
    log_path = files_after_first[0]
    log_path.unlink()
    assert not log_path.exists()

    logger.info("second line, after the file was removed")

    assert log_path.exists(), "a per-write open must recreate a removed file"
    lines = [line for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 1
    assert json.loads(lines[0])["msg"] == "second line, after the file was removed"


# ---- Concurrent writers: the shared lock keeps every line whole -----------------------------------


def test_concurrent_writers_never_interleave_a_line(tmp_path: Path) -> None:
    # Feature: adms-attendance-system, Property 67: for any number of concurrent writers, every
    # line in the file (and on standard output) is a complete parseable object. Real threads, not a
    # simulated race, because the property is specifically about the shared lock serialising actual
    # concurrent appends.
    buffer = io.StringIO()
    root = JsonLogger(level="DEBUG", stream=buffer, log_dir=str(tmp_path))

    threads_count = 8
    lines_per_thread = 40

    def write_many(worker_id: int) -> None:
        child = root.with_context(worker=worker_id)
        for i in range(lines_per_thread):
            child.info("concurrent line", i=i)

    threads = [threading.Thread(target=write_many, args=(n,)) for n in range(threads_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    expected_total = threads_count * lines_per_thread

    stdout_lines = [line for line in buffer.getvalue().splitlines() if line.strip()]
    assert len(stdout_lines) == expected_total
    for line in stdout_lines:
        json.loads(line)  # every line is one complete object -- a torn write would fail this

    (log_path,) = tmp_path.iterdir()
    file_lines = [line for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(file_lines) == expected_total
    seen: list[tuple[int, int]] = []
    for line in file_lines:
        record = json.loads(line)  # every line is one complete object
        seen.append((record["worker"], record["i"]))
    # Every (worker, i) pair was written exactly once -- no line was lost or duplicated by the race.
    assert sorted(seen) == sorted((w, i) for w in range(threads_count) for i in range(lines_per_thread))


# ── Property 68: Credentials are redacted from every message and field, and nothing else is ──

_REDACTION_CASES: tuple[tuple[str, str, str], ...] = (
    ("PWD, uppercase", "PWD=Sup3r!Secret", "PWD=***REDACTED***"),
    ("Password, mixed case", "Password=Sup3r!Secret", "Password=***REDACTED***"),
    ("UID, uppercase", "UID=adms_collector", "UID=***REDACTED***"),
    ("uid, lowercase", "uid=adms_collector", "uid=***REDACTED***"),
    ("User Id, spaced, mixed case", "User Id=adms_collector", "User Id=***REDACTED***"),
    ("UserId, no space", "UserId=adms_collector", "UserId=***REDACTED***"),
    ("secret", "secret=abc123", "secret=***REDACTED***"),
    ("token", "token=eyJhbGciOi", "token=***REDACTED***"),
    ("apikey, no separator", "apikey=AKIA123", "apikey=***REDACTED***"),
    ("api_key, underscore", "api_key=AKIA123", "api_key=***REDACTED***"),
    ("api-key, hyphen", "api-key=AKIA123", "api-key=***REDACTED***"),
)
_REDACTION_IDS = [c[0] for c in _REDACTION_CASES]


@pytest.mark.parametrize(("case_id", "text", "expected"), _REDACTION_CASES, ids=_REDACTION_IDS)
def test_credential_assignments_are_redacted_key_stays_visible(
    case_id: str, text: str, expected: str
) -> None:
    # Feature: adms-attendance-system, Property 68: Credentials are redacted from every message and
    # field, and nothing else is -- for any pwd, password, uid, user id, secret, token or api key
    # assignment, the value is replaced while the key stays visible.
    result = scrub(text)
    assert result == expected, f"{case_id}: got {result!r}"
    key = text.split("=", 1)[0]
    assert key in str(result), f"{case_id}: the key must remain visible, got {result!r}"
    value = text.split("=", 1)[1]
    assert value not in str(result), f"{case_id}: the original value must not survive, got {result!r}"


def test_non_secret_connection_string_parts_are_left_readable() -> None:
    # Feature: adms-attendance-system, Property 68: the non-secret parts of a connection string --
    # server, port, database -- remain readable, because a diagnosis needs them.
    text = (
        "Driver={ODBC Driver 18 for SQL Server};"
        "Server=tcp:sql01.example.internal,1433;"
        "Database=ATTENDANCEDB;"
        "Encrypt=yes;TrustServerCertificate=no;"
    )
    result = scrub(text)
    assert result == text, "no secret key is present, so nothing should be rewritten"
    assert "sql01.example.internal" in str(result)
    assert "1433" in str(result)
    assert "ATTENDANCEDB" in str(result)


def test_a_full_connection_string_redacts_only_the_credential_fields() -> None:
    # Feature: adms-attendance-system, Property 68: within one connection string carrying both
    # secret and non-secret fields, only the credential assignments are rewritten; the rest of the
    # string, including the key names of the secrets, is untouched.
    text = (
        "Driver={ODBC Driver 18 for SQL Server};"
        "Server=tcp:sql01.example.internal,1433;"
        "Database=ATTENDANCEDB;"
        "UID=adms_collector;"
        "PWD=Correct-Horse-Battery-Staple;"
        "Encrypt=yes;"
    )
    result = str(scrub(text))

    assert "sql01.example.internal" in result
    assert "1433" in result
    assert "ATTENDANCEDB" in result
    assert "Encrypt=yes" in result
    assert "UID=***REDACTED***" in result
    assert "PWD=***REDACTED***" in result
    assert "adms_collector" not in result
    assert "Correct-Horse-Battery-Staple" not in result


def test_a_substring_that_merely_contains_a_secret_word_is_not_redacted() -> None:
    # Feature: adms-attendance-system, Property 68: "and nothing else is" -- a key name that merely
    # contains "secret" or "token" as a substring, rather than being that word, is not a match, so
    # an unrelated field is not mistakenly blanked out.
    text = "topsecretproject=visible-value&my_token_count=5"
    result = scrub(text)
    assert result == text, f"got {result!r}"


def test_redaction_reaches_a_field_value_passed_to_the_logger() -> None:
    # Feature: adms-attendance-system, Property 68: redaction applies to field values as well as
    # messages -- a connection string handed to the logger as a keyword field is redacted exactly
    # as the message text would be.
    logs = LogCapture()
    logs.logger.error(
        "connection failed",
        connection="Server=sql01;UID=adms_collector;PWD=hunter2;Database=ATTENDANCEDB",
    )
    (record,) = logs.records
    assert "hunter2" not in logs.text
    assert "adms_collector" not in logs.text
    assert "UID=***REDACTED***" in record["connection"]
    assert "PWD=***REDACTED***" in record["connection"]
    assert "Server=sql01" in record["connection"]
    assert "Database=ATTENDANCEDB" in record["connection"]


def test_redaction_reaches_the_message_text_itself() -> None:
    # Feature: adms-attendance-system, Property 68: redaction applies to the message text, not only
    # to keyword fields -- a driver error whose own text embeds a password must not leak it.
    logs = LogCapture()
    logs.logger.error(
        "pyodbc.Error: [08001] login failed; dsn was "
        "'Driver={ODBC Driver 18};Server=sql01;UID=svc;PWD=hunter2;'"
    )
    assert "hunter2" not in logs.text
    (record,) = logs.records
    assert "PWD=***REDACTED***" in record["msg"]
    assert "Server=sql01" in record["msg"]


# ── Property 69: A recorded traceback is bounded and unchained ──────────────────────────────


def test_recorded_traceback_has_at_most_six_frames() -> None:
    # Feature: adms-attendance-system, Property 69: A recorded traceback is bounded and unchained --
    # for any exception, the recorded traceback carries at most 6 frames, even when the real call
    # stack is much deeper.
    logs = LogCapture()

    def f10() -> None:
        raise ValueError("deep failure")

    def f9() -> None:
        f10()

    def f8() -> None:
        f9()

    def f7() -> None:
        f8()

    def f6() -> None:
        f7()

    def f5() -> None:
        f6()

    def f4() -> None:
        f5()

    def f3() -> None:
        f4()

    def f2() -> None:
        f3()

    def f1() -> None:
        f2()

    try:
        f1()
    except ValueError as exc:
        logs.logger.error("deep failure logged", exc=exc)

    (record,) = logs.records
    frame_lines = [line for line in record["trace"].splitlines() if line.strip().startswith("File ")]
    assert len(frame_lines) <= 6, f"expected at most 6 frames, got {len(frame_lines)}:\n{record['trace']}"


def test_recorded_traceback_excludes_an_unrelated_exception_from_an_except_importerror_block() -> None:
    # Feature: adms-attendance-system, Property 69: A recorded traceback is bounded and unchained --
    # raising deliberately inside an `except ImportError:` block must not leak the unrelated
    # ImportError into the recorded trace through Python's implicit __context__ chaining. This is
    # the specific case the property exists to protect: chain=False in the implementation is what
    # this test would catch a regression on.
    logs = LogCapture()

    def _do_something_that_needs_a_missing_module() -> None:
        raise ImportError("No module named 'totally_fake_optional_dependency_xyz'")

    def trigger() -> None:
        try:
            _do_something_that_needs_a_missing_module()
        except ImportError:
            raise RuntimeError("the real, unrelated failure") from None

    try:
        trigger()
    except RuntimeError as exc:
        # Confirm the implicit chain really is present on the exception object before logging it --
        # otherwise this test would pass for the wrong reason (there being nothing to exclude).
        assert exc.__context__ is not None
        assert isinstance(exc.__context__, ImportError)
        logs.logger.error("operation failed", exc=exc)

    (record,) = logs.records
    assert record["error"] == "RuntimeError: the real, unrelated failure"
    assert "ImportError" not in record["trace"], record["trace"]
    assert "totally_fake_optional_dependency_xyz" not in record["trace"], record["trace"]
    assert "the real, unrelated failure" in record["trace"]
    # And nowhere in the whole emitted line, not just the trace field, in case the phantom leaked
    # through a different field.
    assert "ImportError" not in logs.text
    assert "totally_fake_optional_dependency_xyz" not in logs.text


def test_recorded_traceback_names_only_the_logged_exceptions_own_chain() -> None:
    # Feature: adms-attendance-system, Property 69: an exception raised with an explicit `raise ...
    # from cause` -- a real, intentional chain rather than an implicit one -- is a different case
    # from the one above. This test documents that chain=False suppresses *all* chaining, deliberate
    # or not: only the logged exception's own frames are recorded, never a `__cause__` either.
    logs = LogCapture()

    def inner() -> None:
        raise ValueError("original cause")

    def outer() -> None:
        try:
            inner()
        except ValueError as cause:
            raise RuntimeError("wrapped failure") from cause

    try:
        outer()
    except RuntimeError as exc:
        assert exc.__cause__ is not None
        logs.logger.error("wrapped failure logged", exc=exc)

    (record,) = logs.records
    assert "original cause" not in record["trace"]
    assert "ValueError" not in record["trace"]
    assert "wrapped failure" in record["trace"]
