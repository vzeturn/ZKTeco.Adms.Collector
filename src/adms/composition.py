"""
Composition root -- the one place that knows which adapter satisfies which port.

Hand-wired, no DI container. Same choice as the desktop tool's ``App.xaml.cs``: the graph is small and fixed,
and reading it top to bottom tells you exactly what talks to what.

Built once per worker process and cached at module scope. Waitress serves requests from a thread pool,
so this graph is shared across threads -- which is why :class:`~adms.db.ConnectionFactory` is created
per worker and guarded, not shared as one connection across threads. See its docstring.
"""

from __future__ import annotations

import threading

from .config import Settings, load_settings, resolve_connection_string
from .db import (
    ConnectionFactory,
    SqlServerAttendanceStore,
    SqlServerCommandQueue,
    SqlServerDeviceRegistry,
    SqlServerEmployeeStore,
    SqlServerPushArchive,
    SqlServerRosterSync,
    SqlServerTemplateStore,
)
from .logging_setup import JsonLogger, build_logger
from .ports import SystemClock
from .service import AdmsService

__all__ = ["get_service", "build_service", "build_fake_service", "get_logger", "reset"]

_service: AdmsService | None = None
_logger: JsonLogger | None = None
_factory: ConnectionFactory | None = None

#: Guards first-time construction. Waitress can deliver several requests concurrently to a cold
#: process, and building the graph twice would open two connections and log two startup lines.
_lock = threading.Lock()


def get_logger() -> JsonLogger:
    """The process-wide logger. Built on first use so configuration errors surface as log lines."""
    global _logger
    if _logger is None:
        import os

        _logger = build_logger(
            level=(os.environ.get("ADMS_LOG_LEVEL") or "INFO").upper(),
            log_dir=(os.environ.get("ADMS_LOG_DIR") or ""),
            service="adms-attendance-collector",
        )
    return _logger


def get_service() -> AdmsService:
    """
    The cached service for this process, building it on first use.

    Failures are **not** cached. A start-up that cannot read the registry or reach SQL Server must be
    retried on the next request rather than poisoning the worker for its whole lifetime -- otherwise
    one transient fault turns into refused uploads until someone recycles the app pool.
    """
    global _service
    if _service is not None:
        return _service
    with _lock:
        if _service is None:
            _service = build_service(load_settings(), log=get_logger())
        return _service


def build_service(settings: Settings, *, log=None) -> AdmsService:
    """
    Wire the real graph.

    One :class:`~adms.db.ConnectionFactory` is shared by every adapter, so a single logical operation
    (archive a batch, then insert it) reuses one connection instead of opening several.
    """
    global _factory

    logger = log or get_logger()
    connection_string = resolve_connection_string(settings)

    _factory = ConnectionFactory(
        connection_string,
        query_timeout=settings.sql_query_timeout,
        log=logger,
    )

    commands = SqlServerCommandQueue(_factory, log=logger)

    # multi-device-employee-sync, Requirement 29.1: only constructed when the feature is on --
    # AdmsService gets None otherwise, which is the actual enforcement of "disabled costs
    # nothing" (no object exists to even check a flag on every request).
    roster_sync = None
    if settings.roster_sync_enabled:
        roster_sync = SqlServerRosterSync(_factory, commands=commands, settings=settings, log=logger)

    return AdmsService(
        registry=SqlServerDeviceRegistry(_factory, log=logger),
        attendance=SqlServerAttendanceStore(_factory, log=logger),
        employees=SqlServerEmployeeStore(_factory, log=logger),
        templates=SqlServerTemplateStore(_factory, log=logger),
        commands=commands,
        archive=SqlServerPushArchive(_factory, log=logger),
        clock=SystemClock(utc_offset_hours=settings.utc_offset_hours),
        settings=settings,
        log=logger,
        roster_sync=roster_sync,
    )


def build_fake_service(settings: Settings, *, devices=None, log=None):
    """
    Wire the in-memory graph, returning ``(service, stores)``.

    Used by ``tools/local_server.py --fake`` to serve the full ADMS conversation with no database, and
    by ``tools/smoke_test.py``. ``stores`` is handed back so a caller can inspect what was written --
    which is the whole point when the question is "what does this firmware actually send".
    """
    from .memory import (
        FixedClock,
        InMemoryAttendanceStore,
        InMemoryCommandQueue,
        InMemoryDeviceRegistry,
        InMemoryEmployeeStore,
        InMemoryPushArchive,
        InMemoryRosterSync,
        InMemoryTemplateStore,
    )

    clock = FixedClock(utc_offset_hours=settings.utc_offset_hours)
    registry = InMemoryDeviceRegistry(devices or [])
    employees = InMemoryEmployeeStore()
    templates = InMemoryTemplateStore()
    commands = InMemoryCommandQueue()

    stores = {
        "registry": registry,
        "attendance": InMemoryAttendanceStore(),
        "employees": employees,
        "templates": templates,
        "commands": commands,
        "archive": InMemoryPushArchive(),
    }

    # Mirrors build_service's own gating: None unless the feature is on, so a test exercising the
    # disabled path (Requirement 29.1) gets the same "no object exists" behaviour production does.
    roster_sync = None
    if settings.roster_sync_enabled:
        roster_sync = InMemoryRosterSync(
            employees=employees,
            templates=templates,
            registry=registry,
            commands=commands,
            settings=settings,
            clock=clock,
            log=log,
        )
        stores["roster_sync"] = roster_sync

    service = AdmsService(
        registry=stores["registry"],
        attendance=stores["attendance"],
        employees=stores["employees"],
        templates=stores["templates"],
        commands=stores["commands"],
        archive=stores["archive"],
        clock=clock,
        settings=settings,
        log=log or get_logger(),
        roster_sync=roster_sync,
    )
    return service, stores


def reset() -> None:
    """Drop the cached graph and close the SQL connection. For tests and after rotating a credential."""
    global _service, _factory, _logger
    if _factory is not None:
        _factory.close()
    _service = None
    _factory = None
    _logger = None

    from . import config

    config.reset_cache()
