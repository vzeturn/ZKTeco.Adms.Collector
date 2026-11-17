"""
SQL Server adapters for the ports in :mod:`adms.ports`.

Raw ODBC (``pyodbc``), no ORM, every value a bound parameter — the same discipline
the desktop pull tool applies with ``Microsoft.Data.SqlClient``, and for the same reason: ATTENDANCEDB is a
legacy schema this codebase does not own. See :mod:`adms.db.schema` for the locked-versus-owned
table split, and ``sql/adms-schema.sql`` for the tables this service creates.
"""

from __future__ import annotations

from .archive import SqlServerPushArchive
from .attendance import SqlServerAttendanceStore
from .commands import SqlServerCommandQueue
from .connection import ConnectionFactory
from .employees import SqlServerEmployeeStore
from .registry import SqlServerDeviceRegistry
from .roster_sync import SqlServerRosterSync
from .templates import SqlServerTemplateStore

__all__ = [
    "ConnectionFactory",
    "SqlServerDeviceRegistry",
    "SqlServerAttendanceStore",
    "SqlServerEmployeeStore",
    "SqlServerTemplateStore",
    "SqlServerCommandQueue",
    "SqlServerPushArchive",
    "SqlServerRosterSync",
]
