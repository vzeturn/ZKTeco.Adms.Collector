"""
Composition root for the pull agent -- mirrors :mod:`adms.composition`'s own hand-wired,
no-container style, kept as a separate module because this tool has its own dependency
(``pyzk``) that the push collector's process must never need to have installed.
"""

from __future__ import annotations

from ..config import Settings, load_settings, resolve_connection_string
from ..db import ConnectionFactory, SqlServerAttendanceStore, SqlServerEmployeeStore, SqlServerTemplateStore
from ..logging_setup import JsonLogger, build_logger
from ..ports import SystemClock
from .agent import PullAgent
from .registry import SqlServerPullDeviceRegistry
from .runlog import SqlServerPullRunLog
from .zkclient import PyzkDeviceClient

__all__ = ["build_agent", "get_logger"]

_logger: JsonLogger | None = None


def get_logger() -> JsonLogger:
    """
    The process-wide logger for one CLI invocation.

    A fresh process per run (this is a run-by-hand tool, not a long-lived worker), so this is not
    cached across invocations the way :func:`adms.composition.get_logger` is across requests --
    only within one call to :func:`build_agent`.
    """
    global _logger
    if _logger is None:
        import os

        _logger = build_logger(
            level=(os.environ.get("ADMS_LOG_LEVEL") or "INFO").upper(),
            log_dir=(os.environ.get("ADMS_LOG_DIR") or ""),
            service="adms-pull-agent",
        )
    return _logger


def build_agent(settings: Settings | None = None, *, log=None) -> PullAgent:
    """
    Wire the real graph: SQL adapters for the roster/attendance/run-log, ``pyzk`` for the device
    conversation.

    Shares :class:`~adms.db.ConnectionFactory` construction with the push collector's own
    ``build_service`` (same connection-string resolution, same DPAPI-registry fallback) so a
    single host has one place a database credential is configured, regardless of which of the
    two tools is being run.
    """
    resolved_settings = settings or load_settings()
    logger = log or get_logger()
    connection_string = resolve_connection_string(resolved_settings)

    factory = ConnectionFactory(
        connection_string,
        query_timeout=resolved_settings.sql_query_timeout,
        log=logger,
    )

    return PullAgent(
        client=PyzkDeviceClient(log=logger),
        registry=SqlServerPullDeviceRegistry(factory, log=logger),
        employees=SqlServerEmployeeStore(factory, log=logger),
        attendance=SqlServerAttendanceStore(factory, log=logger),
        templates=SqlServerTemplateStore(factory, log=logger),
        runlog=SqlServerPullRunLog(factory, log=logger),
        clock=SystemClock(utc_offset_hours=resolved_settings.utc_offset_hours),
        log=logger,
    )
