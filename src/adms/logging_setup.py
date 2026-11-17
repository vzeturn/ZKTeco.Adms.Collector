"""
Structured JSON logging.

One JSON object per line, so a log aggregator can query fields directly
(``fields serial, route, inserted | filter route = "push_data"``) instead of regex-scraping
prose. The desktop app's ``FileLogger`` writes one line per event for the same reason; the
format differs because the reader does.

Two properties are non-negotiable:

* **Logging never throws.** A logger that raises inside an error path turns a recoverable
  failure into a lost batch of punches. Every method swallows its own faults.
* **Secrets never reach a log line.** Message text and field values pass through
  :func:`scrub`, which redacts the password-bearing fragments of a connection string. This is
  defence in depth — no call site is supposed to log a connection string in the first place —
  but "supposed to" has a poor track record, and a driver error message often embeds the DSN it
  was handed.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import sys
import threading
import traceback
from typing import IO

__all__ = ["JsonLogger", "NullLogger", "scrub", "build_logger"]

_LEVELS = {"DEBUG": 10, "INFO": 20, "WARN": 30, "WARNING": 30, "ERROR": 40}

#: Connection-string fragments that carry credentials, in every spelling the ODBC and
#: ADO.NET families accept. Matched case-insensitively up to the next ``;`` or end of string.
_SECRET_PATTERN = re.compile(
    r"(?i)\b(pwd|password|uid|user\s*id|secret|token|apikey|api[_-]?key)\s*=\s*[^;\"'\s]*"
)


def scrub(value: object) -> object:
    """
    Redact credential-bearing fragments from a value.

    Only strings are rewritten; other types pass through and are serialised by
    :func:`json.dumps` with ``default=str``. Redaction keeps the *key* visible
    (``PWD=***REDACTED***``) because knowing a password was present, and where, is useful, while
    the value never is.
    """
    if isinstance(value, str):
        return _SECRET_PATTERN.sub(lambda m: f"{m.group(1)}=***REDACTED***", value)
    return value


class JsonLogger:
    """
    Line-per-event JSON logger.

    Writes to stdout and, when ``log_dir`` is set, appends to a daily file
    ``adms-yyyyMMdd.log`` -- the same one-file-per-day shape as the desktop pull tool's ``FileLogger``, so an
    operator looking for yesterday's problem knows where to look.

    Under IIS, stdout is captured by AspNetCoreModuleV2 into its own log, which rotates on process
    recycle rather than by date. That is fine for start-up diagnostics but poor for "what happened at
    08:15 last Tuesday", which is why the dated file exists as well.

    No ``logging`` module: its configuration is global and shared with any library in the process, and
    a stray ``basicConfig`` elsewhere would silently change this format.

    Writes are serialised by a lock. Waitress serves from a thread pool, and two threads appending to
    the same file without one produces interleaved half-lines that no JSON parser will read.
    """

    __slots__ = ("_threshold", "_stream", "_context", "_log_dir", "_lock")

    def __init__(
        self,
        level: str = "INFO",
        stream: IO[str] | None = None,
        log_dir: str = "",
        _lock: object = None,
        **context: object,
    ) -> None:
        self._threshold = _LEVELS.get(level.upper(), 20)
        self._stream = stream or sys.stdout
        self._log_dir = log_dir or ""
        #: Shared with children so all writers to one file serialise against the same lock.
        self._lock = _lock or threading.Lock()
        #: Fields stamped on every line -- serial, route, and so on.
        self._context = {k: v for k, v in context.items() if v is not None}

        if self._log_dir:
            try:
                os.makedirs(self._log_dir, exist_ok=True)
            except OSError:
                # An unwritable directory must not stop the service starting; stdout still works.
                self._log_dir = ""

    def with_context(self, **fields: object) -> "JsonLogger":
        """A child logger carrying extra fields. Cheap; make one per request."""
        merged = {**self._context, **fields}
        child = JsonLogger.__new__(JsonLogger)
        child._threshold = self._threshold
        child._stream = self._stream
        child._log_dir = self._log_dir
        child._lock = self._lock
        child._context = {k: v for k, v in merged.items() if v is not None}
        return child

    def debug(self, message: str, **fields: object) -> None:
        self._write("DEBUG", message, None, fields)

    def info(self, message: str, **fields: object) -> None:
        self._write("INFO", message, None, fields)

    def warn(self, message: str, exc: BaseException | None = None, **fields: object) -> None:
        self._write("WARN", message, exc, fields)

    def error(self, message: str, exc: BaseException | None = None, **fields: object) -> None:
        self._write("ERROR", message, exc, fields)

    def _write(self, level: str, message: str, exc: BaseException | None, fields: dict[str, object]) -> None:
        if _LEVELS[level] < self._threshold:
            return
        try:
            record: dict[str, object] = {
                "ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds"),
                "level": level,
                "msg": scrub(message),
                **{k: scrub(v) for k, v in self._context.items()},
                **{k: scrub(v) for k, v in fields.items()},
            }
            if exc is not None:
                record["error"] = scrub(f"{type(exc).__name__}: {exc}")
                # Only the trace tail, and only this exception's own chain. limit=6 keeps a retryable
                # database blip from costing a multi-kilobyte frame dump.
                #
                # chain=False matters more than it looks: Python links __context__ to whatever exception
                # happened to be in flight in an enclosing frame, so without this a deliberate raise
                # inside an `except ImportError:` block reports the unrelated ImportError as its cause
                # and sends whoever reads the log chasing a phantom.
                record["trace"] = scrub(
                    "".join(
                        traceback.format_exception(
                            type(exc), exc, exc.__traceback__, limit=6, chain=False
                        )
                    ).strip()
                )
            line = json.dumps(record, ensure_ascii=False, default=str)

            with self._lock:
                print(line, file=self._stream, flush=True)
                if self._log_dir:
                    self._append_file(line)
        except Exception:  # noqa: BLE001 - a logger that raises is worse than one that is silent
            pass

    def _append_file(self, line: str) -> None:
        """
        Append one line to today's file. Opened per write rather than held open, so log rotation or
        an operator moving the file cannot leave the process writing into a deleted handle.
        """
        try:
            stamp = dt.datetime.now().strftime("%Y%m%d")
            path = os.path.join(self._log_dir, f"adms-{stamp}.log")
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except OSError:
            # Disk full, permissions, or a locked file. stdout already has the line.
            pass


class NullLogger:
    """Discards everything. Default for library-style use, mirroring ``NullLogger.Instance``."""

    __slots__ = ()

    def debug(self, message: str, **fields: object) -> None: ...

    def info(self, message: str, **fields: object) -> None: ...

    def warn(self, message: str, exc: BaseException | None = None, **fields: object) -> None: ...

    def error(self, message: str, exc: BaseException | None = None, **fields: object) -> None: ...


def build_logger(level: str = "INFO", log_dir: str = "", **context: object) -> JsonLogger:
    return JsonLogger(level=level, log_dir=log_dir, **context)
