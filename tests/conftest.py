"""
The pytest harness for the collector suite.

Every fixture here is built on :func:`adms.composition.build_fake_service` or on a recording cursor,
so the whole suite runs with **no database, no ODBC driver and no network listener**. That is not a
convenience: the one thing this service must never do is lose a punch, and a suite that needs
infrastructure is a suite that gets skipped on the day it would have caught that.

``tools/smoke_test.py`` is deliberately not imported, wrapped or refactored into fixtures. It is the
byte-level firmware contract -- ``OK: 3`` and ``OK: 2`` tell a device to erase different records --
and its value is precisely that it has not changed. Duplication between the two is intentional.

What lives here, and why each earns its place:

* **The in-memory graph** (:func:`build_fake`) with builders for a linked, an unlinked, a disabled and
  an unregistered device. Those four states are the entire authorisation matrix, so they are named
  once rather than re-spelled per test.
* **Request builders** producing real :class:`~adms.models.AdmsRequest` objects with tab-separated
  bodies as bytes. Bodies are bytes because decoding is part of what is under test; a test that hands
  the service a ``str`` skips the encoding chain the devices actually exercise.
* **A recording cursor** (:class:`RecordingDatabase`) capturing statement text and bound parameters in
  order, answering reads from a scripted queue, able to raise on the *n*th call. This is what makes
  the SQL adapters testable with no driver installed.
* **An exploding adapter set** whose every port method raises, for the properties that assert a call
  was never made. Asserting an absence needs something that screams when the absence is violated.
* **A log capture** that parses each emitted line back from JSON, and a settings factory.

Fixtures are the supported entry point; the underlying functions are module level so a test module may
also use them at collection time for parametrisation.
"""

from __future__ import annotations

import datetime as dt
import io
import json
import sys
import uuid
from collections import deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

# The package lives under src/ and is not installed during development. pyproject's
# [tool.pytest.ini_options] pythonpath covers the normal invocation; this repeats it so the harness
# still imports when pytest is pointed at a single file from another directory.
_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from adms.admin import auth as admin_auth  # noqa: E402
from adms.admin.store import (  # noqa: E402
    AuditRow,
    DeletionEventRow,
    DeviceRow,
    EmployeeRow,
    GrantResult,
    RosterSyncRow,
    SessionRow,
    UserRow,
)
from adms.composition import build_fake_service  # noqa: E402
from adms.config import Settings  # noqa: E402
from adms.errors import AttendanceDbError  # noqa: E402
from adms.logging_setup import JsonLogger, NullLogger  # noqa: E402
from adms.memory import FixedClock  # noqa: E402
from adms.models import AdmsRequest, DeviceRegistration  # noqa: E402
from adms.service import AdmsService  # noqa: E402

__all__ = [
    "FAST_ITERATIONS",
    "MACHINE_ID",
    "MACHINE_NAME",
    "ROWCOUNT_ONLY",
    "SERIAL_DISABLED",
    "SERIAL_LINKED",
    "SERIAL_UNLINKED",
    "SERIAL_UNREGISTERED",
    "SOURCE_IP",
    "WIRE",
    "Call",
    "ClientResponse",
    "ExplodedError",
    "ExplodingAdapter",
    "FakeStore",
    "LogCapture",
    "NoResultSetError",
    "RecordingConnection",
    "RecordingCursor",
    "RecordingDatabase",
    "Row",
    "StoreCall",
    "WsgiClient",
    "build_exploding",
    "build_fake",
    "default_devices",
    "disabled_device",
    "linked_device",
    "make_settings",
    "unlinked_device",
    "unregistered_device",
]

# ── Identities the whole suite shares ────────────────────────────────────────────────────────

#: Registered, enabled and linked to a MAYCHAMCONG row. The only state in which data is accepted.
SERIAL_LINKED = "CJXX204960333"
#: Registered and enabled, but no MaMCC that resolves -- so there is no IDMCC for CheckInOut.MaSoMay.
#: Data pushes must answer 503, and that is a linking task, not a security event.
SERIAL_UNLINKED = "UNLINKED0001"
#: Known to the allow-list and switched off by an operator. 401, like an unknown serial.
SERIAL_DISABLED = "DISABLED0001"
#: Absent from ADMS_DEVICE entirely. Never handed to the registry -- that absence is the point.
SERIAL_UNREGISTERED = "NOTREGISTERED9"

MACHINE_ID = 7
MACHINE_NAME = "Cong chinh"

#: Devices sit on a site-local segment, so a private address is the realistic case. It authorises
#: nothing, which is itself a property (7).
SOURCE_IP = "10.0.0.9"


# ── Settings ─────────────────────────────────────────────────────────────────────────────────


def make_settings(**overrides: Any) -> Settings:
    """
    Build :class:`~adms.config.Settings` for a test.

    ``sql_connection`` is populated so nothing in a test can reach
    :func:`~adms.config.resolve_connection_string`'s registry branch and read a real host's DPAPI
    blob. ``auto_register_devices`` defaults off, because on is the interesting case and a default
    that quietly writes rows makes "the registry was not touched" hard to assert.
    """
    base: dict[str, Any] = {
        "sql_connection": "fake",
        "utc_offset_hours": 7,
        "path_secret": "",
        "auto_register_devices": False,
        "archive_raw_bodies": True,
    }
    base.update(overrides)
    return Settings(**base)


# ── Registrations ────────────────────────────────────────────────────────────────────────────


def linked_device(serial: str = SERIAL_LINKED, **overrides: Any) -> DeviceRegistration:
    """A device an operator has finished commissioning."""
    fields: dict[str, Any] = {
        "serial": serial,
        "enabled": True,
        "machine_code": "MCC00001",
        "machine_id": MACHINE_ID,
        "machine_name": MACHINE_NAME,
    }
    fields.update(overrides)
    return DeviceRegistration(**fields)


def unlinked_device(serial: str = SERIAL_UNLINKED, **overrides: Any) -> DeviceRegistration:
    """Found us, trusted, but not yet mapped onto a machine. The half-finished configuration state."""
    fields: dict[str, Any] = {
        "serial": serial,
        "enabled": True,
        "machine_code": "",
        "machine_id": None,
    }
    fields.update(overrides)
    return DeviceRegistration(**fields)


def disabled_device(serial: str = SERIAL_DISABLED, **overrides: Any) -> DeviceRegistration:
    """
    Switched off deliberately.

    Linked on purpose: a disabled row must be refused because it is disabled, not because it happens
    to lack a machine id, and giving it an id is the only way a test can tell those apart.
    """
    fields: dict[str, Any] = {
        "serial": serial,
        "enabled": False,
        "machine_code": "MCC00009",
        "machine_id": 9,
        "machine_name": "Tam ngung",
    }
    fields.update(overrides)
    return DeviceRegistration(**fields)


def unregistered_device(serial: str = SERIAL_UNREGISTERED, **overrides: Any) -> DeviceRegistration:
    """
    The registration an unregistered serial *would* have.

    Never passed to the registry. It exists so a test can build the row it expects auto-registration
    to create, and so the serial is named in one place instead of spelled out per test.
    """
    fields: dict[str, Any] = {
        "serial": serial,
        "enabled": False,
        "machine_code": "",
        "machine_id": None,
    }
    fields.update(overrides)
    return DeviceRegistration(**fields)


def default_devices() -> list[DeviceRegistration]:
    """The three registered states. The unregistered one is absent by definition."""
    return [linked_device(), unlinked_device(), disabled_device()]


# ── The in-memory graph ──────────────────────────────────────────────────────────────────────

FakeGraph = tuple[AdmsService, dict[str, Any]]


def build_fake(
    settings: Settings | None = None,
    devices: list[DeviceRegistration] | None = None,
    *,
    log: Any = None,
) -> FakeGraph:
    """
    Wire the in-memory graph, returning ``(service, stores)``.

    ``devices=None`` means the three default states; ``devices=[]`` means an empty allow-list, so
    every serial is unregistered. The distinction is load-bearing and is why this is not a truthiness
    check.

    The logger defaults to :class:`~adms.logging_setup.NullLogger` rather than the process logger, so
    running the suite does not print a few thousand JSON lines and does not populate
    :mod:`adms.composition`'s module-level cache. A test that asserts on log output passes
    ``log=LogCapture().logger``.
    """
    return build_fake_service(
        settings or make_settings(),
        devices=default_devices() if devices is None else devices,
        log=log or NullLogger(),
    )


# ── The exploding adapter set ────────────────────────────────────────────────────────────────


class ExplodedError(AssertionError):
    """
    Raised by :class:`ExplodingAdapter` when a port method is called at all.

    An :class:`AssertionError` rather than a plain exception on purpose: the service converts every
    ``Exception`` on a data path into a status, so a subclass of ``Exception`` would be swallowed and
    the test would see a bland 500 instead of the name of the call that should never have happened.
    """


class ExplodingAdapter:
    """
    An adapter every one of whose methods raises.

    Needed by the properties that assert a call was **never** made -- anonymous routes touching no
    adapter, an unlinked device's upload refused before anything is parsed. Asserting an absence
    against a permissive fake proves nothing; asserting it against this one names the violated call.
    """

    __slots__ = ("_name", "calls")

    def __init__(self, name: str) -> None:
        self._name = name
        #: Attempted calls, so a failure report can list them in order.
        self.calls: list[str] = []

    def __getattr__(self, item: str) -> Callable[..., Any]:
        if item.startswith("__"):
            raise AttributeError(item)

        def explode(*_args: object, **_kwargs: object) -> Any:
            self.calls.append(item)
            raise ExplodedError(f"{self._name}.{item}() was called on a path that must touch no adapter")

        return explode


def build_exploding(settings: Settings | None = None, *, log: Any = None) -> FakeGraph:
    """
    A service whose every port raises, returning ``(service, stores)``.

    The clock is real (fixed) rather than exploding: it is not an adapter, it reaches no external
    system, and the routes under test legitimately read it.
    """
    resolved = settings or make_settings()
    stores: dict[str, Any] = {
        name: ExplodingAdapter(name)
        for name in ("registry", "attendance", "employees", "templates", "commands", "archive")
    }
    service = AdmsService(
        registry=stores["registry"],
        attendance=stores["attendance"],
        employees=stores["employees"],
        templates=stores["templates"],
        commands=stores["commands"],
        archive=stores["archive"],
        clock=FixedClock(utc_offset_hours=resolved.utc_offset_hours),
        settings=resolved,
        log=log or NullLogger(),
    )
    return service, stores


# ── Request builders ─────────────────────────────────────────────────────────────────────────

#: One wire record: either a finished line, or the fields to join with tabs.
WireRow = str | Sequence[object]


def encode_rows(rows: Iterable[WireRow] | str | bytes) -> bytes:
    """
    Render records as a tab-separated, newline-terminated body in UTF-8.

    ``bytes`` pass through untouched, which is how a test feeds deliberately undecodable input. A
    ``str`` is encoded as given, so a test can supply its own line endings -- some firmware sends
    ``\\r\\n`` and one build sends a bare ``\\r``, and that is worth being able to express.
    """
    if isinstance(rows, bytes):
        return rows
    if isinstance(rows, str):
        return rows.encode("utf-8")

    lines: list[str] = []
    for row in rows:
        if isinstance(row, str):
            lines.append(row)
        else:
            lines.append("\t".join("" if f is None else str(f) for f in row))
    if not lines:
        return b""
    return ("\n".join(lines) + "\n").encode("utf-8")


def wire_request(
    method: str,
    path: str,
    *,
    body: Iterable[WireRow] | str | bytes = b"",
    query: Mapping[str, str] | None = None,
    headers: Mapping[str, str] | None = None,
    source_ip: str = SOURCE_IP,
    **extra_query: str,
) -> AdmsRequest:
    """
    The general builder. The named ones below are this with the route's own query keys filled in.

    Query parameters can be given either as a mapping or as keywords; the named builders use the
    mapping form because a keyword like ``options`` or ``type`` would otherwise collide with this
    signature's own.
    """
    return AdmsRequest(
        method=method,
        path=path,
        query={**(query or {}), **extra_query},
        body=encode_rows(body),
        headers=dict(headers or {}),
        source_ip=source_ip,
    )


def punch(
    pin: object,
    timestamp: object,
    *,
    status: object = 0,
    verify: object = 1,
    work_code: object = 0,
    reserved1: str = "",
    reserved2: str = "",
) -> list[object]:
    """
    One ATTLOG record's fields, in the order firmware sends them.

    ``timestamp`` takes a ``datetime`` or a raw string, because half the interesting cases are strings
    no ``datetime`` can hold -- ``0000-00-00 00:00:00`` from a dead RTC, or plain rubbish.
    """
    stamp = timestamp.strftime("%Y-%m-%d %H:%M:%S") if isinstance(timestamp, dt.datetime) else timestamp
    return [pin, stamp, status, verify, work_code, reserved1, reserved2]


def handshake(serial: str, **query: str) -> AdmsRequest:
    """``GET /iclock/cdata`` -- the request that configures a device for its whole working life."""
    params: dict[str, str] = {"SN": serial, "options": "all", "pushver": "2.4.1"}
    params.update(query)
    return wire_request("GET", "/iclock/cdata", query=params)


def attlog(
    serial: str,
    rows: Iterable[WireRow] | str | bytes,
    *,
    stamp: str = "9999",
    **query: str,
) -> AdmsRequest:
    """``POST /iclock/cdata?table=ATTLOG`` -- the punch upload."""
    params: dict[str, str] = {"SN": serial, "table": "ATTLOG", "Stamp": stamp}
    params.update(query)
    return wire_request("POST", "/iclock/cdata", body=rows, query=params)


def operlog(
    serial: str,
    rows: Iterable[WireRow] | str | bytes,
    *,
    stamp: str = "55",
    **query: str,
) -> AdmsRequest:
    """``POST /iclock/cdata?table=OPERLOG`` -- users, templates and device operations."""
    params: dict[str, str] = {"SN": serial, "table": "OPERLOG", "Stamp": stamp}
    params.update(query)
    return wire_request("POST", "/iclock/cdata", body=rows, query=params)


def options(
    serial: str,
    values: Mapping[str, str] | Iterable[WireRow] | str | bytes,
    *,
    separator: str = "\r\n",
    **query: str,
) -> AdmsRequest:
    """
    ``POST /iclock/cdata?table=options`` -- the device's self-description.

    A mapping is rendered as ``Key=Value`` lines joined with CRLF, which is what firmware sends here
    even where it uses bare newlines elsewhere.
    """
    params: dict[str, str] = {"SN": serial, "table": "options"}
    params.update(query)
    body: Iterable[WireRow] | str | bytes
    if isinstance(values, Mapping):
        body = separator.join(f"{k}={v}" for k, v in values.items()) + separator
    else:
        body = values
    return wire_request("POST", "/iclock/cdata", body=body, query=params)


def getrequest(serial: str, **query: str) -> AdmsRequest:
    """``GET /iclock/getrequest`` -- the poll that both delivers commands and keeps the device alive."""
    params: dict[str, str] = {"SN": serial}
    params.update(query)
    return wire_request("GET", "/iclock/getrequest", query=params)


def ack(command_id: object, return_code: object = 0, command: str = "INFO") -> str:
    """One acknowledgement line, in the ``ID=..&Return=..&CMD=..`` form devices send."""
    return f"ID={command_id}&Return={return_code}&CMD={command}"


def devicecmd(serial: str, acks: Iterable[WireRow] | str | bytes = (), **query: str) -> AdmsRequest:
    """``POST /iclock/devicecmd`` -- command results coming back."""
    params: dict[str, str] = {"SN": serial}
    params.update(query)
    return wire_request("POST", "/iclock/devicecmd", body=acks, query=params)


def querydata(
    serial: str,
    rows: Iterable[WireRow] | str | bytes = (),
    *,
    query_type: str = "userinfo_and_fp",
    **query: str,
) -> AdmsRequest:
    """
    ``POST /iclock/querydata`` -- the answer to a command we issued.

    Same grammar as OPERLOG; the difference that matters is that the data was solicited, which is
    what the archive's route field records.
    """
    params: dict[str, str] = {"SN": serial, "type": query_type}
    params.update(query)
    return wire_request("POST", "/iclock/querydata", body=rows, query=params)


def filedata(
    serial: str,
    body: Iterable[WireRow] | str | bytes = b"",
    *,
    path: str = "/iclock/fdata",
    **query: str,
) -> AdmsRequest:
    """
    ``POST /iclock/fdata`` and its siblings -- photos and file blobs.

    ``path`` is a parameter because ``fdata``, ``rtdata``, ``edata`` and ``filedata`` all land on the
    same route, and which one a given firmware uses is not something we get to choose.
    """
    params: dict[str, str] = {"SN": serial}
    params.update(query)
    return wire_request("POST", path, body=body, query=params)


class _Wire:
    """
    Namespace of the request builders.

    One fixture instead of nine, so a test's signature stays about what it is testing.
    """

    __slots__ = ()

    request = staticmethod(wire_request)
    rows = staticmethod(encode_rows)
    punch = staticmethod(punch)
    ack = staticmethod(ack)
    handshake = staticmethod(handshake)
    attlog = staticmethod(attlog)
    operlog = staticmethod(operlog)
    options = staticmethod(options)
    getrequest = staticmethod(getrequest)
    devicecmd = staticmethod(devicecmd)
    querydata = staticmethod(querydata)
    filedata = staticmethod(filedata)


WIRE = _Wire()


# ── The recording cursor ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Call:
    """One statement the layer under test handed the driver."""

    #: ``"execute"`` or ``"executemany"``.
    kind: str
    #: Statement text exactly as passed, so a test can assert no value was formatted into it.
    statement: str
    #: Bound values: the parameter tuple for ``execute``, the list of tuples for ``executemany``.
    params: Any

    @property
    def sql(self) -> str:
        """The statement with runs of whitespace collapsed, so assertions survive re-indentation."""
        return " ".join(self.statement.split())

    @property
    def is_many(self) -> bool:
        return self.kind == "executemany"

    @property
    def rows(self) -> list[Any]:
        """Parameter tuples, one per row, whichever call form produced them."""
        return list(self.params) if self.is_many else [self.params]


class _RowcountOnly:
    """Sentinel for a result set that reports a rowcount and exposes no columns."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "ROWCOUNT_ONLY"


#: Script this where a statement produces no columns -- an INSERT before the SELECT that reads
#: ``SCOPE_IDENTITY()`` back. ``db.commands.enqueue`` steps past exactly that with ``nextset()``, and a
#: fake with no way to express it cannot exercise the enqueue path at all.
ROWCOUNT_ONLY = _RowcountOnly()


class NoResultSetError(RuntimeError):
    """Fetching from a rowcount-only result set. The driver raises here too; so should the fake."""


class Row:
    """
    One scripted result row.

    Answers both ``row[0]`` and ``row.SerialNumber``, because the adapters use both --
    ``registry.find`` reads columns by name, ``employees.missing_employee_pins`` by index -- and a
    fake supporting only one form silently decides which adapters can be tested.
    """

    __slots__ = ("_columns", "_values")

    def __init__(self, **columns: Any) -> None:
        self._columns = tuple(columns)
        self._values = tuple(columns.values())

    @property
    def columns(self) -> tuple[str, ...]:
        return self._columns

    @property
    def values(self) -> tuple[Any, ...]:
        return self._values

    def __getitem__(self, index: int | str) -> Any:
        if isinstance(index, str):
            return self._values[self._columns.index(index)]
        return self._values[index]

    def __getattr__(self, name: str) -> Any:
        try:
            return object.__getattribute__(self, "_values")[
                object.__getattribute__(self, "_columns").index(name)
            ]
        except ValueError:
            raise AttributeError(name) from None

    def __len__(self) -> int:
        return len(self._values)

    def __iter__(self) -> Any:
        return iter(self._values)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Row):
            return self._values == other.values
        if isinstance(other, tuple | list):
            return self._values == tuple(other)
        return NotImplemented

    def __repr__(self) -> str:
        pairs = ", ".join(f"{k}={v!r}" for k, v in zip(self._columns, self._values, strict=True))
        return f"Row({pairs})"


#: A scripted result set: rows, or the rowcount-only sentinel.
ResultSet = Sequence[Any] | _RowcountOnly

_GENERIC_DESCRIPTION = [("value", None, None, None, None, None, True)]


class RecordingCursor:
    """
    A cursor that records what it was asked to do and answers reads from a script.

    Deliberately not a mock. The SQL adapters are worth testing for exactly three things -- the
    statement text is constant, every value is bound rather than formatted in, and the parameters are
    in the verified order -- and all three are properties of the recorded call list.
    """

    __slots__ = ("_current", "_db", "closed")

    def __init__(self, db: RecordingDatabase) -> None:
        self._db = db
        self._current: ResultSet = ()
        self.closed = False

    # ── The surface the adapters use ──────────────────────────────────────────────────────

    @property
    def description(self) -> list[tuple[Any, ...]] | None:
        """``None`` for a rowcount-only set, which is what ``nextset()`` loops on."""
        if isinstance(self._current, _RowcountOnly):
            return None
        first = self._current[0] if self._current else None
        if isinstance(first, Row):
            return [(name, None, None, None, None, None, True) for name in first.columns]
        return list(_GENERIC_DESCRIPTION)

    def execute(self, statement: str, *params: Any) -> RecordingCursor:
        self._current = self._db.record("execute", statement, _one_param_set(params))
        return self

    def executemany(self, statement: str, seq_of_params: Iterable[Any]) -> None:
        self._current = self._db.record("executemany", statement, list(seq_of_params))

    def fetchall(self) -> list[Any]:
        if isinstance(self._current, _RowcountOnly):
            raise NoResultSetError("No results. The previous statement produced a rowcount only.")
        rows, self._current = list(self._current), ()
        return rows

    def fetchone(self) -> Any:
        if isinstance(self._current, _RowcountOnly):
            raise NoResultSetError("No results. The previous statement produced a rowcount only.")
        if not self._current:
            return None
        rows = list(self._current)
        head, self._current = rows[0], rows[1:]
        return head

    def nextset(self) -> bool:
        """Advance to the next scripted result set. ``False`` when the script is exhausted."""
        following = self._db.next_result()
        if following is None:
            return False
        self._current = following
        return True

    def close(self) -> None:
        self.closed = True


def _one_param_set(params: tuple[Any, ...]) -> Any:
    """
    Normalise ``execute`` parameters.

    ``pyodbc`` accepts both ``execute(sql, (a, b))`` and ``execute(sql, a, b)``, and the adapters use
    the first while ad-hoc code tends to use the second. Recording them identically means an assertion
    on bound values does not depend on which form the call site happened to pick.
    """
    if not params:
        return ()
    if len(params) == 1 and isinstance(params[0], tuple | list):
        return tuple(params[0])
    return params


class RecordingConnection:
    """The connection surface :func:`adms.db.connection.transaction` needs, and nothing more."""

    __slots__ = ("_db", "timeout")

    def __init__(self, db: RecordingDatabase) -> None:
        self._db = db
        self.timeout = 0

    def cursor(self) -> RecordingCursor:
        cursor = RecordingCursor(self._db)
        self._db.cursors.append(cursor)
        return cursor

    def commit(self) -> None:
        self._db.commits += 1

    def rollback(self) -> None:
        self._db.rollbacks += 1

    def close(self) -> None:
        self._db.closes += 1


class RecordingDatabase:
    """
    Stands in for :class:`adms.db.ConnectionFactory`, so an adapter can be constructed and driven with
    no ODBC driver present.

    It records every statement and every bound parameter **in order**, across every cursor the
    adapter opens, because ordering is the design: archive before project, commit before acknowledge,
    advance the stamp last. A per-cursor log would lose exactly the relationship worth asserting.

    Reads come from a scripted queue rather than a per-statement mapping. A statement-keyed script
    would have to match on SQL text, which is the thing under test -- so the script would have to be
    edited whenever the SQL was reformatted, and would stop failing when it should.
    """

    __slots__ = (
        "_connection",
        "_error",
        "_fail_at",
        "_results",
        "calls",
        "closes",
        "commits",
        "connections",
        "cursors",
        "rollbacks",
    )

    def __init__(
        self,
        *,
        results: Iterable[ResultSet] = (),
        fail_on_call: int | None = None,
        error: BaseException | None = None,
    ) -> None:
        #: Every execute/executemany, in order, including the one that was told to fail.
        self.calls: list[Call] = []
        self.cursors: list[RecordingCursor] = []
        self.commits = 0
        self.rollbacks = 0
        self.closes = 0
        self.connections = 0
        self._results: deque[ResultSet] = deque(results)
        self._connection: RecordingConnection | None = None
        self._fail_at = fail_on_call
        self._error = error

    # ── The ConnectionFactory surface ─────────────────────────────────────────────────────

    def get(self) -> RecordingConnection:
        """One connection, reused. Per-thread caching is Property 62's subject, not this one's."""
        self.connections += 1
        if self._connection is None:
            self._connection = RecordingConnection(self)
        return self._connection

    def close(self) -> None:
        self.closes += 1

    # ── Scripting ─────────────────────────────────────────────────────────────────────────

    def script(self, *result_sets: ResultSet) -> RecordingDatabase:
        """Queue result sets, consumed one per statement (and one per ``nextset()``)."""
        self._results.extend(result_sets)
        return self

    def fail_on(self, ordinal: int, error: BaseException | None = None) -> RecordingDatabase:
        """
        Raise on the ``ordinal``-th statement, counting from 1.

        This is how "no 2xx precedes a commit" is tested without a database: fail each data-carrying
        write in turn and watch what the service does with it.
        """
        self._fail_at = ordinal
        self._error = error
        return self

    # ── Internals the cursor calls ────────────────────────────────────────────────────────

    def record(self, kind: str, statement: str, params: Any) -> ResultSet:
        call = Call(kind=kind, statement=statement, params=params)
        # Recorded before the failure is raised, deliberately: what was attempted is as diagnostic as
        # what succeeded, and a test asserting a rollback wants to see the statement that caused it.
        self.calls.append(call)
        if self._fail_at is not None and len(self.calls) == self._fail_at:
            raise self._error or RuntimeError(
                f"the recording cursor was told to fail on call {self._fail_at}"
            )
        following = self.next_result()
        return () if following is None else following

    def next_result(self) -> ResultSet | None:
        return self._results.popleft() if self._results else None

    # ── Reading back what happened ────────────────────────────────────────────────────────

    @property
    def statements(self) -> list[str]:
        """Every statement, whitespace-collapsed, in order."""
        return [call.sql for call in self.calls]

    def matching(self, *fragments: str) -> list[Call]:
        """Calls whose statement contains every fragment, compared case-insensitively."""
        return [call for call in self.calls if all(f.lower() in call.sql.lower() for f in fragments)]

    def params_of(self, index: int = 0) -> Any:
        return self.calls[index].params

    def __repr__(self) -> str:
        return (
            f"RecordingDatabase(calls={len(self.calls)}, commits={self.commits}, "
            f"rollbacks={self.rollbacks})"
        )


# ── Log capture ──────────────────────────────────────────────────────────────────────────────


class LogCapture:
    """
    A real :class:`~adms.logging_setup.JsonLogger` writing to a buffer, read back as parsed JSON.

    The real logger, not a fake one: the claims worth testing are that every line parses as one JSON
    object, that credentials are redacted and that a traceback is bounded and unchained, and all three
    are properties of the actual implementation. A fake would assert the test's own idea of the format.

    ``level`` defaults to DEBUG so nothing is filtered out before a test can see it.
    """

    __slots__ = ("buffer", "logger")

    def __init__(self, level: str = "DEBUG", **context: object) -> None:
        self.buffer = io.StringIO()
        logger = JsonLogger(level=level, stream=self.buffer)
        #: Context is attached through with_context rather than the constructor, because the
        #: constructor's **context sits behind two positional parameters and a mapping splatted into it
        #: would land on log_dir -- which would put a test's log file somewhere on disk.
        self.logger = logger.with_context(**context) if context else logger

    @property
    def lines(self) -> list[str]:
        return [line for line in self.buffer.getvalue().splitlines() if line.strip()]

    @property
    def records(self) -> list[dict[str, Any]]:
        """
        Every line parsed as JSON.

        Parsing is not defended: a line that will not parse is the failure Property 67 exists to
        catch, and it should surface as the error it is rather than as an empty list.
        """
        return [json.loads(line) for line in self.lines]

    def of_level(self, level: str) -> list[dict[str, Any]]:
        return [r for r in self.records if r.get("level") == level.upper()]

    @property
    def messages(self) -> list[str]:
        return [str(r.get("msg", "")) for r in self.records]

    @property
    def text(self) -> str:
        """The raw buffer, for asserting that a value appears nowhere in any line."""
        return self.buffer.getvalue()


# ── Fixtures ─────────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def settings_factory() -> Callable[..., Settings]:
    """``settings_factory(poll_delay=5)`` -- test defaults plus the overrides that matter."""
    return make_settings


@pytest.fixture
def fake() -> Callable[..., FakeGraph]:
    """``service, stores = fake()`` -- the in-memory graph, no database anywhere."""
    return build_fake


@pytest.fixture
def exploding() -> Callable[..., FakeGraph]:
    """``service, stores = exploding()`` -- every port raises, for asserting a call never happened."""
    return build_exploding


@pytest.fixture
def wire() -> _Wire:
    """The request builders: ``wire.attlog(SERIAL_LINKED, [wire.punch(101, "2026-08-07 08:00:00")])``."""
    return WIRE


@pytest.fixture
def recorder() -> RecordingDatabase:
    """A fresh recording cursor factory, ready to be handed to a SQL adapter."""
    return RecordingDatabase()


@pytest.fixture
def logs() -> LogCapture:
    """A JSON log capture. Pass ``log=logs.logger`` when building a graph, then read ``logs.records``."""
    return LogCapture()


@pytest.fixture
def devices() -> list[DeviceRegistration]:
    """The three registered states, as a list a test may extend before building a graph."""
    return default_devices()


# ══ Admin console harness ══════════════════════════════════════════════════════════════════════
#
# A second, self-contained harness for the admin-console suite (``test_auth_*``, ``test_ui_*``,
# ``test_app_*``, ``test_serve``). It shares nothing with the collector fixtures above except this
# file: the console has its own store surface (:class:`adms.admin.store.AdminStore`), its own WSGI
# app, and no overlap in HTTP routes.
#
# Three pieces, following the usual testing strategy:
#
# * :class:`FakeStore` -- every :class:`AdminStore` method, backed by in-memory dicts and recording
#   every call in order. ``app.py`` depends only on this surface, so the whole handler layer runs
#   with no database and no ODBC driver. Recording is how "this action wrote an audit row" is proven.
# * :class:`WsgiClient` -- builds a WSGI ``environ`` with ``wsgiref.util.setup_testing_defaults`` and
#   calls the app object directly, keeping cookies between calls. No ``webtest``, no ``httpx``.
# * :func:`fast_hashing` -- swaps the 600k PBKDF2 count for a low one, because the sign-in path derives
#   on every call including failures and 600k is ~0.2-0.5 s each. Two tests keep the real cost.


#: The iteration count the console tests hash with. Low enough that a suite deriving on every sign-in
#: attempt stays fast; the real 600k is exercised only by the two tests that assert it explicitly.
FAST_ITERATIONS = 1_000


@dataclass(frozen=True, slots=True)
class StoreCall:
    """One method the handler layer invoked on the store, with its keyword arguments."""

    method: str
    kwargs: dict[str, Any]


class FakeStore:
    """
    In-memory stand-in for :class:`adms.admin.store.AdminStore`.

    Holds users, sessions, audit rows, devices, machines and commands in dicts, and appends a
    :class:`StoreCall` for every method entered. A handler test asserts on both: the visible state
    change *and* that the audit call was made. Reads return the store's own frozen row types so a
    handler cannot tell this from the real adapter.

    Not a mock: the methods have real behaviour (lockout counters increment, the last-admin count is
    computed, sessions are deleted on user delete) because the handlers depend on that behaviour, and a
    mock that returned canned values would let a broken handler pass.
    """

    def __init__(self) -> None:
        self.calls: list[StoreCall] = []
        self.users: dict[str, UserRow] = {}
        self._material: dict[str, tuple[bytes, bytes, int]] = {}
        self.sessions: dict[bytes, dict[str, Any]] = {}
        self.audit_rows: list[AuditRow] = []
        self._device_rows: dict[str, DeviceRow] = {}
        self._machines: list[dict] = []
        #: pin -> EmployeeRow, plus which pins own a biometric row and any device password set.
        self._employees: dict[int, EmployeeRow] = {}
        self._biometric_pins: set[int] = set()
        self.device_passwords: dict[int, int] = {}
        self.commands_by_id: dict[int, dict] = {}
        self._summary: dict = {}
        self._punches: list[dict] = []
        self._uploads: list[dict] = []
        self._unparsed: list[dict] = []
        #: multi-device-employee-sync test fixtures. Empty by default so a test that never calls
        #: set_roster_sync_status/set_recent_deletions sees the same "feature inert" state as a
        #: fresh database with no device in a Sync_Group yet.
        self._roster_sync_rows: list[RosterSyncRow] = []
        self._deletion_rows: list[DeletionEventRow] = []
        self._next_command_id = 1
        #: Overridable so a test can force a store error and assert the handler answers 503 not 500.
        self.raise_on: set[str] = set()

    # ── recording ─────────────────────────────────────────────────────────────────────────
    def _record(self, method: str, **kwargs: Any) -> None:
        self.calls.append(StoreCall(method=method, kwargs=kwargs))
        if method in self.raise_on:
            raise AttendanceDbError(f"FakeStore was told to fail {method}().")

    def calls_to(self, method: str) -> list[StoreCall]:
        return [c for c in self.calls if c.method == method]

    def audited(self, action: str) -> list[AuditRow]:
        return [r for r in self.audit_rows if r.action == action]

    # ── seeding helpers (not part of the AdminStore surface) ──────────────────────────────
    def add_user(
        self,
        *,
        username: str,
        password: str,
        role: str = "admin",
        display_name: str = "",
        is_enabled: bool = True,
        must_change_password: bool = False,
        iterations: int = FAST_ITERATIONS,
    ) -> UserRow:
        uid = str(uuid.uuid4())
        salt = admin_auth.new_salt()
        self._material[uid] = (salt, admin_auth.hash_password(password, salt, iterations), iterations)
        row = UserRow(
            user_id=uid,
            username=username,
            display_name=display_name or username,
            role=role,
            is_enabled=is_enabled,
            must_change_password=must_change_password,
            failed_attempts=0,
            locked_until_utc=None,
            last_login_utc=None,
            created_utc=dt.datetime(2026, 1, 1),
        )
        self.users[uid] = row
        return row

    def add_device(self, row: DeviceRow) -> None:
        self._device_rows[row.serial] = row

    def add_employee(
        self,
        *,
        pin: int,
        name: str = "",
        card: str = "",
        privilege: int = 0,
        is_enabled: bool = True,
        has_biometrics: bool = False,
    ) -> EmployeeRow:
        row = EmployeeRow(
            pin=pin, name=name, card=card, privilege=privilege, is_enabled=is_enabled
        )
        self._employees[pin] = row
        if has_biometrics:
            self._biometric_pins.add(pin)
        return row

    def set_machines(self, machines: list[dict]) -> None:
        self._machines = list(machines)

    def set_summary(self, summary: dict) -> None:
        self._summary = dict(summary)

    def _replace_user(self, uid: str, **changes: Any) -> None:
        cur = self.users[uid]
        fields = {f: getattr(cur, f) for f in cur.__slots__}
        fields.update(changes)
        self.users[uid] = UserRow(**fields)

    # ── users ─────────────────────────────────────────────────────────────────────────────
    def find_user(self, username: str) -> UserRow | None:
        self._record("find_user", username=username)
        return next((u for u in self.users.values() if u.username == username), None)

    def get_user(self, user_id: str) -> UserRow | None:
        self._record("get_user", user_id=user_id)
        return self.users.get(user_id)

    def list_users(self) -> list[UserRow]:
        self._record("list_users")
        return sorted(self.users.values(), key=lambda u: u.username)

    def count_enabled_admins(self) -> int:
        self._record("count_enabled_admins")
        return sum(1 for u in self.users.values() if u.role == "admin" and u.is_enabled)

    def password_material(self, user_id: str) -> tuple[bytes, bytes, int] | None:
        self._record("password_material", user_id=user_id)
        return self._material.get(user_id)

    def create_user(
        self,
        *,
        username: str,
        display_name: str,
        role: str,
        salt: bytes,
        password_hash: bytes,
        iterations: int,
        must_change_password: bool,
        created_by: str,
    ) -> str:
        self._record(
            "create_user",
            username=username,
            display_name=display_name,
            role=role,
            iterations=iterations,
            must_change_password=must_change_password,
            created_by=created_by,
        )
        uid = str(uuid.uuid4())
        self._material[uid] = (salt, password_hash, iterations)
        self.users[uid] = UserRow(
            user_id=uid,
            username=username,
            display_name=display_name,
            role=role,
            is_enabled=True,
            must_change_password=must_change_password,
            failed_attempts=0,
            locked_until_utc=None,
            last_login_utc=None,
            created_utc=dt.datetime(2026, 1, 1),
        )
        return uid

    def set_password(
        self, user_id: str, salt: bytes, password_hash: bytes, iterations: int, must_change: bool
    ) -> None:
        self._record("set_password", user_id=user_id, iterations=iterations, must_change=must_change)
        self._material[user_id] = (salt, password_hash, iterations)
        self._replace_user(
            user_id, must_change_password=must_change, failed_attempts=0, locked_until_utc=None
        )

    def update_user(
        self, user_id: str, *, display_name: str, role: str, is_enabled: bool
    ) -> None:
        self._record(
            "update_user",
            user_id=user_id,
            display_name=display_name,
            role=role,
            is_enabled=is_enabled,
        )
        self._replace_user(
            user_id, display_name=display_name, role=role, is_enabled=is_enabled
        )

    def delete_user(self, user_id: str) -> None:
        self._record("delete_user", user_id=user_id)
        self.sessions = {t: s for t, s in self.sessions.items() if s["user_id"] != user_id}
        self.users.pop(user_id, None)
        self._material.pop(user_id, None)

    def record_login_success(self, user_id: str, now: dt.datetime, ip: str) -> None:
        self._record("record_login_success", user_id=user_id, now=now, ip=ip)
        self._replace_user(
            user_id,
            last_login_utc=now,
            failed_attempts=0,
            locked_until_utc=None,
        )

    def record_login_failure(self, user_id: str, locked_until: dt.datetime | None) -> int:
        self._record("record_login_failure", user_id=user_id, locked_until=locked_until)
        new_count = self.users[user_id].failed_attempts + 1
        self._replace_user(user_id, failed_attempts=new_count, locked_until_utc=locked_until)
        return new_count

    def unlock_user(self, user_id: str) -> None:
        self._record("unlock_user", user_id=user_id)
        self._replace_user(user_id, failed_attempts=0, locked_until_utc=None)

    # ── sessions ──────────────────────────────────────────────────────────────────────────
    def create_session(
        self,
        *,
        token_hash: bytes,
        user_id: str,
        expires_utc: dt.datetime,
        ip: str,
        user_agent: str,
        csrf_secret: bytes,
    ) -> None:
        self._record("create_session", user_id=user_id, expires_utc=expires_utc)
        self.sessions[token_hash] = {
            "user_id": user_id,
            "expires_utc": expires_utc,
            "created_utc": expires_utc - admin_auth.SESSION_IDLE_TIMEOUT,
            "ip": ip,
            "user_agent": user_agent,
            "csrf_secret": csrf_secret,
        }

    def load_session(self, token_hash: bytes) -> SessionRow | None:
        self._record("load_session")
        s = self.sessions.get(token_hash)
        if s is None:
            return None
        u = self.users.get(s["user_id"])
        if u is None:
            return None
        return SessionRow(
            user_id=u.user_id,
            username=u.username,
            display_name=u.display_name,
            role=u.role,
            is_enabled=u.is_enabled,
            must_change_password=u.must_change_password,
            csrf_secret=s["csrf_secret"],
            created_utc=s["created_utc"],
            expires_utc=s["expires_utc"],
        )

    def touch_session(
        self, token_hash: bytes, expires_utc: dt.datetime, now: dt.datetime
    ) -> None:
        self._record("touch_session", expires_utc=expires_utc, now=now)
        if token_hash in self.sessions:
            self.sessions[token_hash]["expires_utc"] = expires_utc

    def delete_session(self, token_hash: bytes) -> None:
        self._record("delete_session")
        self.sessions.pop(token_hash, None)

    def delete_sessions_for_user(self, user_id: str) -> int:
        self._record("delete_sessions_for_user", user_id=user_id)
        gone = [t for t, s in self.sessions.items() if s["user_id"] == user_id]
        for t in gone:
            del self.sessions[t]
        return len(gone)

    def purge_expired_sessions(self) -> int:
        self._record("purge_expired_sessions")
        return 0

    def active_sessions(self) -> list[dict]:
        self._record("active_sessions")
        out: list[dict] = []
        for s in self.sessions.values():
            u = self.users.get(s["user_id"])
            out.append(
                {
                    "username": u.username if u else "",
                    "display_name": u.display_name if u else "",
                    "ip": s["ip"],
                    "user_agent": s["user_agent"],
                    "created_utc": s["created_utc"],
                    "last_seen_utc": s["created_utc"],
                    "expires_utc": s["expires_utc"],
                    "user_id": s["user_id"],
                }
            )
        return out

    # ── employees ─────────────────────────────────────────────────────────────────────────
    def get_employee(self, pin: int) -> EmployeeRow | None:
        self._record("get_employee", pin=pin)
        return self._employees.get(pin)

    def set_employee_admin(
        self,
        pin: int,
        *,
        is_admin: bool,
        password: int | None,
        name: str,
        card: str,
        created_by: str,
    ) -> GrantResult:
        self._record(
            "set_employee_admin",
            pin=pin, is_admin=is_admin, has_password=password is not None,
            name=name, card=card, created_by=created_by,
        )
        privilege = 3 if is_admin else 0
        cur = self._employees.get(pin)
        if cur is not None:
            self._employees[pin] = EmployeeRow(
                pin=cur.pin, name=cur.name, card=cur.card, privilege=privilege,
                is_enabled=cur.is_enabled,
            )
        templates_updated = 0
        placeholder_created = False
        if password is not None:
            self.device_passwords[pin] = password
            if pin in self._biometric_pins:
                templates_updated = 1
            else:
                placeholder_created = True
                self._biometric_pins.add(pin)
        queued = sum(1 for d in self._device_rows.values() if d.enabled)
        return GrantResult(
            templates_updated=templates_updated,
            placeholder_created=placeholder_created,
            devices_queued=queued,
        )

    # ── audit ─────────────────────────────────────────────────────────────────────────────
    def audit(
        self,
        *,
        username: str,
        action: str,
        target: str = "",
        detail: str = "",
        ip: str = "",
        succeeded: bool = True,
    ) -> None:
        # Records the call but never raises, matching the real store's contract.
        self.calls.append(
            StoreCall(
                method="audit",
                kwargs={
                    "username": username,
                    "action": action,
                    "target": target,
                    "detail": detail,
                    "ip": ip,
                    "succeeded": succeeded,
                },
            )
        )
        self.audit_rows.append(
            AuditRow(
                when_utc=dt.datetime(2026, 1, 1),
                username=username,
                action=action,
                target=target,
                detail=detail,
                ip=ip,
                succeeded=succeeded,
            )
        )

    def recent_audit(self, limit: int = 200) -> list[AuditRow]:
        self._record("recent_audit", limit=limit)
        return list(reversed(self.audit_rows))[:limit]

    # ── devices ───────────────────────────────────────────────────────────────────────────
    def devices(self) -> list[DeviceRow]:
        self._record("devices")
        return list(self._device_rows.values())

    def device(self, serial: str) -> DeviceRow | None:
        self._record("device", serial=serial)
        return self._device_rows.get(serial)

    def set_device_enabled(self, serial: str, enabled: bool) -> None:
        self._record("set_device_enabled", serial=serial, enabled=enabled)

    def link_device(self, serial: str, machine_code: str) -> None:
        self._record("link_device", serial=serial, machine_code=machine_code)

    def machines(self) -> list[dict]:
        self._record("machines")
        return list(self._machines)

    # ── multi-device-employee-sync: Roster_Sync status and delete fan-out audit ─────────────
    def roster_sync_status(self) -> list[RosterSyncRow]:
        self._record("roster_sync_status")
        return list(self._roster_sync_rows)

    def set_roster_sync_status(self, rows: list[RosterSyncRow]) -> None:
        self._roster_sync_rows = list(rows)

    def recent_deletions(self, limit: int = 100) -> list[DeletionEventRow]:
        self._record("recent_deletions", limit=limit)
        return list(self._deletion_rows)[:limit]

    def set_recent_deletions(self, rows: list[DeletionEventRow]) -> None:
        self._deletion_rows = list(rows)

    # ── commands ──────────────────────────────────────────────────────────────────────────
    def enqueue_command(self, serial: str, body: str, created_by: str) -> int:
        self._record("enqueue_command", serial=serial, body=body, created_by=created_by)
        cid = self._next_command_id
        self._next_command_id += 1
        self.commands_by_id[cid] = {
            "id": cid,
            "serial": serial,
            "text": body,
            "status": "Pending",
            "return_code": None,
            "return_cmd": "",
            "created_by": created_by,
            "created_utc": dt.datetime(2026, 1, 1),
            "sent_utc": None,
            "acked_utc": None,
        }
        return cid

    def commands(self, serial: str | None = None, limit: int = 100) -> list[dict]:
        self._record("commands", serial=serial, limit=limit)
        rows = sorted(self.commands_by_id.values(), key=lambda c: c["id"], reverse=True)
        if serial:
            rows = [c for c in rows if c["serial"] == serial]
        return rows[:limit]

    def cancel_command(self, command_id: int) -> bool:
        self._record("cancel_command", command_id=command_id)
        cmd = self.commands_by_id.get(command_id)
        if cmd is None or cmd["status"] != "Pending":
            return False
        del self.commands_by_id[command_id]
        return True

    # ── activity ──────────────────────────────────────────────────────────────────────────
    def summary(self) -> dict:
        self._record("summary")
        keys = (
            "devices", "enabled", "online", "silent", "unlinked",
            "punches_24h", "pending_cmds", "stuck_cmds", "unprojected", "bad_pins",
            "roster_devices", "roster_behind", "deletions_24h",
        )
        return {k: self._summary.get(k, 0) for k in keys}

    def recent_punches(self, limit: int = 100, serial: str | None = None) -> list[dict]:
        self._record("recent_punches", limit=limit, serial=serial)
        rows = self._punches if serial is None else [p for p in self._punches if p["serial"] == serial]
        return rows[:limit]

    def recent_uploads(self, limit: int = 100) -> list[dict]:
        self._record("recent_uploads", limit=limit)
        return self._uploads[:limit]

    def unparsed(self, limit: int = 100) -> list[dict]:
        self._record("unparsed", limit=limit)
        return self._unparsed[:limit]


# ── The WSGI test client ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ClientResponse:
    """The result of one request through :class:`WsgiClient`."""

    status: int
    headers: list[tuple[str, str]]
    body: bytes

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def header(self, name: str) -> str | None:
        """The first header with this name, case-insensitively."""
        low = name.lower()
        return next((v for k, v in self.headers if k.lower() == low), None)

    def headers_named(self, name: str) -> list[str]:
        """Every header with this name -- ``Set-Cookie`` legitimately repeats."""
        low = name.lower()
        return [v for k, v in self.headers if k.lower() == low]

    @property
    def location(self) -> str | None:
        return self.header("Location")


class WsgiClient:
    """
    Calls a WSGI app object directly, keeping cookies between calls. No new dependency.

    :func:`wsgiref.util.setup_testing_defaults` supplies the boilerplate; the request builder overrides
    method, path, query, body and headers, and folds the stored cookie jar into ``HTTP_COOKIE`` so a
    session obtained from a sign-in carries to the next call. It parses ``Set-Cookie`` on the way back,
    honouring ``Max-Age=0`` as a deletion, so sign-out actually forgets the session.
    """

    __slots__ = ("_app", "cookies", "https")

    def __init__(self, app: Any, *, https: bool = False) -> None:
        self._app = app
        #: name -> value. Attribute directives (Path, HttpOnly...) are not modelled; the tests assert on
        #: those from the raw Set-Cookie header instead.
        self.cookies: dict[str, str] = {}
        self.https = https

    def get(self, path: str, **kw: Any) -> ClientResponse:
        return self.request("GET", path, **kw)

    def post(self, path: str, **kw: Any) -> ClientResponse:
        return self.request("POST", path, **kw)

    def request(
        self,
        method: str,
        path: str,
        *,
        query: str = "",
        body: bytes | str = b"",
        form: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> ClientResponse:
        from urllib.parse import urlencode
        from wsgiref.util import setup_testing_defaults

        if form is not None:
            body = urlencode(form).encode("utf-8")
        if isinstance(body, str):
            body = body.encode("utf-8")

        environ: dict[str, Any] = {}
        setup_testing_defaults(environ)
        environ["REQUEST_METHOD"] = method
        environ["PATH_INFO"] = path
        environ["QUERY_STRING"] = query
        environ["wsgi.input"] = io.BytesIO(body)
        environ["CONTENT_LENGTH"] = str(len(body))
        environ["wsgi.url_scheme"] = "https" if self.https else "http"
        header_names = {k.lower() for k in (headers or {})}
        if form is not None and "content-type" not in header_names:
            environ["CONTENT_TYPE"] = "application/x-www-form-urlencoded"
        if self.cookies:
            environ["HTTP_COOKIE"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        for name, value in (headers or {}).items():
            environ["HTTP_" + name.upper().replace("-", "_")] = value

        captured: dict[str, Any] = {}

        def start_response(status: str, response_headers: list[tuple[str, str]], _exc_info=None) -> Any:
            captured["status"] = status
            captured["headers"] = response_headers
            return lambda _data: None

        chunks = self._app(environ, start_response)
        body_out = b"".join(chunks)
        if hasattr(chunks, "close"):
            chunks.close()

        headers_out: list[tuple[str, str]] = captured["headers"]
        self._absorb_cookies(headers_out)
        return ClientResponse(
            status=int(captured["status"].split(" ", 1)[0]),
            headers=headers_out,
            body=body_out,
        )

    def _absorb_cookies(self, headers: list[tuple[str, str]]) -> None:
        for key, value in headers:
            if key.lower() != "set-cookie":
                continue
            first, _, rest = value.partition(";")
            name, _, val = first.strip().partition("=")
            if not name:
                continue
            attrs = rest.lower()
            if "max-age=0" in attrs or "expires=thu, 01 jan 1970" in attrs:
                self.cookies.pop(name, None)
            else:
                self.cookies[name] = val


@pytest.fixture
def store() -> FakeStore:
    """A fresh in-memory admin store, recording every call."""
    return FakeStore()


@pytest.fixture
def fast_hashing(monkeypatch: pytest.MonkeyPatch) -> int:
    """
    Drop the PBKDF2 cost for the suite.

    Patches the module-level default so ``hash_password`` and every caller that omits ``iterations``
    derives with :data:`FAST_ITERATIONS` instead of 600,000. Returns the count so a test can seed a
    user with a matching hash.
    """
    monkeypatch.setattr(admin_auth, "PBKDF2_ITERATIONS", FAST_ITERATIONS)
    return FAST_ITERATIONS
