"""
``dbo.TEMPLATE`` (fingerprints) and ``dbo.Face`` — biometric template storage.

Delete-then-insert per PIN, in one transaction, matching ``SqlServerTemplateStore.SaveTemplates``.
Two reasons, both inherited from the schema and the protocol:

* **Neither table has a primary or unique key.** A MERGE can fault on pre-existing duplicate rows
  (and production data has them). Delete-then-insert is immune.
* **A device uploads a user's biometrics as a complete set.** Merging finger-by-finger would leave
  a finger the user deleted on the device alive in the database forever.

The scope of the delete is one PIN, never the whole table: an ``OPERLOG`` batch describes the users
it mentions and says nothing about anyone else.

Templates are stored as the base64 text the device sent, never re-encoded. ``dbo.TEMPLATE`` holds
``NVARCHAR`` and the desktop app writes the SDK's own string form; a round trip through bytes here
would produce templates the device cannot load back.
"""

from __future__ import annotations

from ..models import FaceTemplate, FingerTemplate
from .connection import ConnectionFactory, transaction
from .schema import FINGER_VERSION, TABLE_FACE, TABLE_FINGER

__all__ = ["SqlServerTemplateStore"]

_FINGER_INSERT = f"""
    INSERT INTO {TABLE_FINGER}
        (MaChamCong, FingerID, FingerTemplate, Flag, FingerVersion,
         EnrollNumber, EnrollName, Privilige, enPassword, EMachineNumber)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

_FACE_INSERT = f"""
    INSERT INTO {TABLE_FACE}
        (MaChamCong, FaceID, FaceTemplate, ChieuDai,
         EnrollNumber, EnrollName, Privilige, enPassword, EMachineNumber)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


class SqlServerTemplateStore:
    """Implements :class:`~adms.ports.TemplateStore`."""

    __slots__ = ("_factory", "_log")

    def __init__(self, factory: ConnectionFactory, log=None) -> None:
        self._factory = factory
        self._log = log

    def save_fingerprints(self, templates: list[FingerTemplate]) -> int:
        """
        Replace the fingerprint set of every PIN present. Returns rows inserted.

        The denormalised columns (``EnrollNumber``, ``EnrollName``, ``Privilige``, ``enPassword``,
        ``EMachineNumber``) exist in the legacy schema and are populated to match what the desktop
        app writes. ``EnrollName`` is left blank here: an ``FP`` line carries no name, and reading
        ``NHANVIEN`` to fill it would add a query per batch for a column nothing reads. The
        unused ``FingerNumber``/``FPData``/``FingerTemplateTimmy`` columns stay NULL, as in
        the desktop tool.
        """
        grouped = _group_by_pin(templates)
        if not grouped:
            return 0

        written = 0
        with transaction(self._factory, what="write fingerprint templates") as cursor:
            for pin, items in grouped.items():
                cursor.execute(f"DELETE FROM {TABLE_FINGER} WHERE MaChamCong = ?", (pin,))
                for template in items:
                    cursor.execute(
                        _FINGER_INSERT,
                        (
                            pin,
                            template.finger_id,
                            template.template,
                            template.normalized_flag,
                            FINGER_VERSION,
                            pin,
                            "",
                            0,
                            0,
                            0,
                        ),
                    )
                    written += 1
        return written

    def read_fingerprints(self, pin: str) -> list[FingerTemplate]:
        """
        Read back one PIN's stored fingerprint templates.

        Not part of :class:`~adms.ports.TemplateStore` -- the push collector never needs to read a
        template back, only write it. Added for :mod:`adms.pull.agent`'s cross-device employee
        sync, which pushes a template it finds already stored (from any prior pull, or from the
        desktop app) to a device that is missing the person, without re-reading the *source*
        device over the network a second time.
        """
        try:
            numeric_pin = int(pin.strip())
        except (AttributeError, ValueError):
            return []

        sql = f"SELECT FingerID, FingerTemplate, Flag FROM {TABLE_FINGER} WHERE MaChamCong = ? ORDER BY FingerID"
        try:
            cursor = self._factory.get().cursor()
            try:
                cursor.execute(sql, (numeric_pin,))
                rows = cursor.fetchall()
            finally:
                cursor.close()
        except Exception as exc:  # noqa: BLE001
            if self._log is not None:
                self._log.warn("Could not read fingerprint templates.", exc, pin=pin)
            return []

        return [
            FingerTemplate(pin=pin, finger_id=int(row[0]), template=row[1] or "", valid=int(row[2] or 1))
            for row in rows
            if row[1]
        ]

    def save_faces(self, templates: list[FaceTemplate]) -> int:
        """
        Replace the face template of every PIN present. Returns rows inserted.

        ``ChieuDai`` takes the device-reported size when it looks sane and the payload length
        otherwise. Some firmware reports 0 there, and the desktop app writes the value into a
        column the SDK later hands back to ``SetUserFaceStr`` as the template length — a zero
        would make the template unusable on write-back.
        """
        grouped = _group_by_pin(templates)
        if not grouped:
            return 0

        written = 0
        with transaction(self._factory, what="write face templates") as cursor:
            for pin, items in grouped.items():
                cursor.execute(f"DELETE FROM {TABLE_FACE} WHERE MaChamCong = ?", (pin,))
                for template in items:
                    length = template.size if template.size > 0 else len(template.template)
                    cursor.execute(
                        _FACE_INSERT,
                        (
                            pin,
                            template.face_id,
                            template.template,
                            length,
                            pin,
                            "",
                            0,
                            0,
                            0,
                        ),
                    )
                    written += 1
        return written


def _group_by_pin(templates: list) -> dict[int, list]:
    """
    Group templates by numeric PIN, preserving order, dropping non-numeric and empty ones.

    Empty payloads are dropped here rather than in the parser as a second line of defence: the
    delete half of delete-then-insert runs first, so a batch that reached this point carrying only
    empty templates would otherwise erase a user's stored biometrics and put nothing back.
    """
    grouped: dict[int, list] = {}
    for template in templates:
        if not template.template:
            continue
        try:
            pin = int(template.pin.strip())
        except (AttributeError, ValueError):
            continue
        grouped.setdefault(pin, []).append(template)
    return grouped
