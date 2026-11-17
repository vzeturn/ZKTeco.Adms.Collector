"""
Verbatim archive of what devices sent.

Every write here is **best-effort by contract**: the service wraps these calls and logs failures
rather than failing the request. That is a deliberate ranking — the archive is diagnostic value,
while the punch already written to ``CheckInOut`` is the thing a person gets paid from. Losing an
archive row costs an investigation some evidence; failing the request costs the device its
acknowledgement and re-sends the whole batch.

What it buys, concretely:

* **Replay.** If a parser or mapping bug is found next month, the original bodies are still here.
  Without them the only copy was on a device that erased it the moment we said ``OK``.
* **Evidence.** "The clock says I badged at 07:58" is settled by the raw line, not by a projection.
* **Forward compatibility.** New firmware sends record kinds this version does not understand.
  ``ADMS_UNPARSED`` keeps them decodable instead of discarded.
"""

from __future__ import annotations

from ..models import OperationEvent, UserPhoto
from .connection import BATCH_SIZE, ConnectionFactory, chunked, transaction
from .schema import (
    TABLE_ADMS_OPERLOG,
    TABLE_ADMS_PUSH_LOG,
    TABLE_ADMS_UNPARSED,
    TABLE_ADMS_USERPIC,
)

__all__ = ["SqlServerPushArchive"]


class SqlServerPushArchive:
    """Implements :class:`~adms.ports.PushArchive`."""

    __slots__ = ("_factory", "_log")

    def __init__(self, factory: ConnectionFactory, log=None) -> None:
        self._factory = factory
        self._log = log

    def archive_request(
        self,
        *,
        serial: str,
        route: str,
        table: str,
        query: str,
        body: str,
        record_count: int,
    ) -> None:
        """Store one request envelope plus its (already size-capped) body."""
        sql = f"""
            INSERT INTO {TABLE_ADMS_PUSH_LOG}
                (SerialNumber, Route, TableName, QueryString, Body, RecordCount, ReceivedUtc)
            VALUES (?, ?, ?, ?, ?, ?, SYSUTCDATETIME())
        """
        with transaction(self._factory, what="archive the push request") as cursor:
            cursor.execute(
                sql,
                (serial[:64], route[:200], table[:40], query[:1024], body, record_count),
            )

    def archive_operations(self, serial: str, events: list[OperationEvent]) -> int:
        """
        Store ``OPLOG`` events.

        ``OpTime`` is nullable: an op log whose timestamp did not parse is still worth keeping —
        the raw line carries the original text, and knowing an operation happened at all is most of
        the value. Rejecting it would discard the only trace that, say, a user was deleted on the
        device.
        """
        if not events:
            return 0

        sql = f"""
            INSERT INTO {TABLE_ADMS_OPERLOG}
                (SerialNumber, OpCode, OperatorPin, OpTime, Param1, Param2, Param3, RawLine, ReceivedUtc)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, SYSUTCDATETIME())
        """
        rows = [
            (
                serial[:64],
                event.op_code,
                event.operator_pin[:32],
                event.timestamp,
                event.param1[:64],
                event.param2[:64],
                event.param3[:64],
                event.raw[:512],
            )
            for event in events
        ]

        written = 0
        with transaction(self._factory, what="archive device operations") as cursor:
            for chunk in chunked(rows, BATCH_SIZE):
                cursor.executemany(sql, chunk)
                written += len(chunk)
        return written

    def archive_photos(self, serial: str, photos: list[UserPhoto]) -> int:
        """
        Store enrollment photos.

        Kept as the device's base64 text in ``NVARCHAR(MAX)`` rather than decoded into
        ``VARBINARY``. The point of this table is fidelity — a byte-exact copy of what arrived —
        and decoding introduces a step that can fail on a payload we would then have nothing of.
        Whoever needs the image can decode on read.
        """
        if not photos:
            return 0

        sql = f"""
            INSERT INTO {TABLE_ADMS_USERPIC}
                (SerialNumber, Pin, FileName, ContentSize, ContentBase64, ReceivedUtc)
            VALUES (?, ?, ?, ?, ?, SYSUTCDATETIME())
        """
        rows = [
            (
                serial[:64],
                photo.pin[:32],
                photo.filename[:128],
                photo.size,
                photo.content,
            )
            for photo in photos
        ]

        written = 0
        with transaction(self._factory, what="archive user photos") as cursor:
            for chunk in chunked(rows, BATCH_SIZE):
                cursor.executemany(sql, chunk)
                written += len(chunk)
        return written

    def archive_unparsed(self, serial: str, table: str, lines: list[str]) -> int:
        """
        Store lines the parsers recognised as records but could not classify.

        The table this feeds is the one to query first when a firmware upgrade changes behaviour:
        it answers "what is the device sending that we are ignoring" directly.
        """
        if not lines:
            return 0

        sql = f"""
            INSERT INTO {TABLE_ADMS_UNPARSED} (SerialNumber, TableName, RawLine, ReceivedUtc)
            VALUES (?, ?, ?, SYSUTCDATETIME())
        """
        rows = [(serial[:64], table[:40], line[:1024]) for line in lines]

        written = 0
        with transaction(self._factory, what="archive unparsed lines") as cursor:
            for chunk in chunked(rows, BATCH_SIZE):
                cursor.executemany(sql, chunk)
                written += len(chunk)
        return written
