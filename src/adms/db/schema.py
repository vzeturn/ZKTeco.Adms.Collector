"""
Table and column identifiers, in one place.

Split into two groups, and the distinction is load-bearing:

**Locked (ATTENDANCEDB).** ``MAYCHAMCONG``, ``NHANVIEN``, ``CheckInOut``, ``dbo.TEMPLATE``,
``dbo.Face`` and ``dbo.CheckInOut_add`` belong to the legacy LAYCONG31 system. Names are copied
verbatim from the desktop pull tool so both codebases read the same and drift is visible in a diff.
This service never alters their shape — no added columns, no added constraints, not even an
index. Something else owns them and will be upgraded on its own schedule.

**Owned (ADMS_*).** Created by ``sql/adms-schema.sql``. The ADMS model needs state the legacy
schema has no room for: a serial-to-machine mapping, resumption cursors, a command queue, and a
verbatim archive. Keeping that in separate tables is what makes this deployable against a live
ATTENDANCEDB database without a migration window.
"""

from __future__ import annotations

__all__ = [
    "TABLE_MACHINES",
    "COL_MAMCC",
    "COL_TENMCC",
    "COL_IDMCC",
    "COL_DIACHIIP",
    "COL_PORT",
    "COL_TRANGTHAI",
    "COL_SERIAL",
    "PROC_CHECKINOUT_ADD",
    "TABLE_EMPLOYEES",
    "COL_NV_MACHAMCONG",
    "COL_NV_MANHANVIEN",
    "COL_NV_TENCHAMCONG",
    "COL_NV_TENNHANVIEN",
    "COL_NV_MATHE",
    "COL_NV_PHANQUYEN",
    "COL_NV_USERENABLE",
    "TABLE_PUNCHES",
    "COL_CC_MACHAMCONG",
    "COL_CC_NGAYCHAM",
    "COL_CC_GIOCHAM",
    "COL_CC_MASOMAY",
    "TABLE_FINGER",
    "TABLE_FACE",
    "FINGER_VERSION",
    "KIEU_CHAM",
    "NGUON_CHAM",
    "TABLE_ADMS_DEVICE",
    "TABLE_ADMS_COMMAND",
    "TABLE_ADMS_ATTLOG_RAW",
    "TABLE_ADMS_OPERLOG",
    "TABLE_ADMS_PUSH_LOG",
    "TABLE_ADMS_USERPIC",
    "TABLE_ADMS_UNPARSED",
    "TABLE_ADMS_DEVICE_ROSTER_VERSION",
    "TABLE_ADMS_DEVICE_ROSTER",
    "COL_ROSTER_VERSION_IS_DELETED",
    "format_enabled",
    "parse_enabled",
    "resolve_employee_code",
]

# ── Locked: MAYCHAMCONG (machines) ───────────────────────────────────────────────────────
# Column types below were documented from the inherited schema.
TABLE_MACHINES = "MAYCHAMCONG"
COL_MAMCC = "MaMCC"          # nchar(8), PK (PK_MAYCHAMCONG) — space-padded, always trim
COL_TENMCC = "TenMCC"        # nvarchar(30)
COL_IDMCC = "IDMCC"          # int — becomes CheckInOut.MaSoMay; see the warning below
COL_DIACHIIP = "DiaChiIP"    # nvarchar(20)
COL_PORT = "Port"
COL_TRANGTHAI = "TrangThai"  # bit, NOT int
#: nvarchar(20), and typically populated. The inherited schema may already record each device's
#: serial number, which is the mapping ADMS_DEVICE needs — see dbo.ADMS_SeedDevicesFromMayChamCong.
COL_SERIAL = "Serial"

# WARNING — IDMCC IS NOT A UNIQUE MACHINE IDENTITY IN THIS DATABASE.
# Observed: most configured machines can have IDMCC = 1, and CheckInOut.MaSoMay can be
# 1 on virtually every row, with TenMay carrying the real machine identity. Consequences:
#   * existing_punch_keys(machine_id=1, ...) is effectively unscoped, which is a harmless superset for
#     duplicate detection but means the "per-machine" framing is illusory.
#   * Anything that joins CheckInOut.MaSoMay to MAYCHAMCONG.IDMCC matches several machines at once and
#     is wrong. dbo.vw_ADMS_UnprojectedPunches was rewritten for exactly this reason.
# Fixing the data (giving each machine a distinct IDMCC) is a legacy-system change this service must
# not make on its own, because the desktop app and existing reports read the same column.

# ── Locked: stored procedure ─────────────────────────────────────────────────────────────
# Signature, in this exact order, because add_attendance calls it positionally:
#   1 @MaChamCong int   2 @NgayCham datetime   3 @GioCham datetime   4 @KieuCham nvarchar(10)
#   5 @NguonCham nvarchar(20)   6 @MaSoMay int   7 @TenMay nvarchar(30)
#
# The deployed body DOES deduplicate, contrary to the desktop tool's comments:
#   IF NOT EXISTS (SELECT TOP 1 ... WHERE MaChamCong = @MaChamCong AND GioCham = @GioCham) INSERT ...
# See SqlServerAttendanceStore.existing_punch_keys for why the application still checks as well.
PROC_CHECKINOUT_ADD = "dbo.CheckInOut_add"

# ── Locked: NHANVIEN (employees) ─────────────────────────────────────────────────────────
TABLE_EMPLOYEES = "NHANVIEN"
COL_NV_MACHAMCONG = "MaChamCong"    # int, PK (PK_NHANVIEN_1) — the device PIN
COL_NV_MANHANVIEN = "MaNhanVien"    # nvarchar(20), NOT NULL — the HR code; never overwritten
COL_NV_TENCHAMCONG = "TenChamCong"  # nvarchar(100) — device enroll name
COL_NV_TENNHANVIEN = "TenNhanVien"  # nvarchar(100) — legacy/HR name
COL_NV_MATHE = "MaThe"              # nvarchar(20) — narrower than it looks; truncate at 20
COL_NV_PHANQUYEN = "PhanQuyen"      # int -> UserPrivilege
COL_NV_USERENABLE = "UserEnable"    # nvarchar(10); existing rows typically hold "True", NOT a bit

# ── Locked: CheckInOut (punches) ─────────────────────────────────────────────────────────
# PK is an identity column (ID); there is NO unique constraint on (MaChamCong, GioCham), so the
# procedure's IF NOT EXISTS is the only thing enforcing that key. IX_CheckInOut_GioCham on GioCham is
# what serves the duplicate-detection SELECT.
TABLE_PUNCHES = "CheckInOut"
COL_CC_MACHAMCONG = "MaChamCong"
COL_CC_NGAYCHAM = "NgayCham"
COL_CC_GIOCHAM = "GioCham"
COL_CC_MASOMAY = "MaSoMay"          # int — see the IDMCC warning above

#: Fixed by the LAYCONG31 contract and reproduced exactly, so an ADMS-collected punch is
#: byte-identical to one the desktop app inserted.
#:
#: A NOTE ON FIDELITY. Existing data in this schema can use ``KieuCham`` with several values
#: (for example ``0``, ``1``, ``255``, ``5``) and ``NguonCham`` with site names (for example
#: ``'SITE_A - Office'``), not just the empty string. The pattern this service writes --
#: ``KieuCham='1'``, ``NguonCham=''`` -- is one of those established conventions.
#:
#: So writing these constants is consistent with one established convention rather than the only one,
#: and it means the device's in/out status does not reach ``CheckInOut``. Nothing is lost: the raw
#: status, verify mode and work code are all kept in ``ADMS_ATTLOG_RAW``, so a decision to project them
#: differently can be applied retroactively.
#:
#: Changing them is a reporting-semantics decision for whoever owns attendance reports, not a code
#: cleanup: ``KieuCham`` almost certainly drives in/out classification, and guessing the mapping wrong
#: would silently invert it.
KIEU_CHAM = "1"
NGUON_CHAM = ""

# ── Locked: biometric tables ─────────────────────────────────────────────────────────────
#: Both are HEAPs with no primary key and no unique index, which is exactly why
#: SqlServerTemplateStore replaces per PIN with delete-then-insert: a MERGE can fault on pre-existing
#: duplicate rows, and there is nothing here to stop those existing.
#: Face storage is less exercised than fingerprint storage.
TABLE_FINGER = "dbo.TEMPLATE"
TABLE_FACE = "dbo.Face"
#: Existing rows use algorithm version "10". Column is nvarchar(10).
FINGER_VERSION = "10"

# ── Owned by this service ────────────────────────────────────────────────────────────────
TABLE_ADMS_DEVICE = "dbo.ADMS_DEVICE"
TABLE_ADMS_COMMAND = "dbo.ADMS_COMMAND"
TABLE_ADMS_ATTLOG_RAW = "dbo.ADMS_ATTLOG_RAW"
TABLE_ADMS_OPERLOG = "dbo.ADMS_OPERLOG"
TABLE_ADMS_PUSH_LOG = "dbo.ADMS_PUSH_LOG"
TABLE_ADMS_USERPIC = "dbo.ADMS_USERPIC"
TABLE_ADMS_UNPARSED = "dbo.ADMS_UNPARSED"
#: multi-device-employee-sync. See sql/adms-schema.sql for the full rationale: the authoritative
#: per-(Pin, SyncGroup) version counter, and the diagnostic-only per-device audit trail.
TABLE_ADMS_DEVICE_ROSTER_VERSION = "dbo.ADMS_DEVICE_ROSTER_VERSION"
TABLE_ADMS_DEVICE_ROSTER = "dbo.ADMS_DEVICE_ROSTER"
#: multi-device-employee-sync delete fan-out. Marks a (Pin, SyncGroup) version snapshot as a
#: deletion rather than a live roster entry -- see sql/adms-schema.sql's own rationale for why
#: this cannot be inferred from NHANVIEN's current state alone.
COL_ROSTER_VERSION_IS_DELETED = "IsDeleted"


def format_enabled(enabled: bool) -> str:
    """
    Render ``NHANVIEN.UserEnable``.

    The column is ``nvarchar(10)``, not a bit. Existing data stores ``"True"``/``"False"``;
    older rows use ``"1"``/``"0"``. New writes use that convention so this service's rows sort
    and filter identically to the desktop app's.
    """
    return "True" if enabled else "False"


def parse_enabled(raw: str | None) -> bool:
    """Read either convention. Blank or NULL counts as disabled."""
    text = (raw or "").strip().lower()
    return text in ("1", "true", "yes", "y")


def resolve_employee_code(employee_code: str, pin: str) -> str:
    """
    The value for ``MaNhanVien`` (NOT NULL) when **inserting** a new employee.

    A device supplies no HR code, so a device-sourced employee falls back to its PIN:
    non-null, unique per employee, and obvious enough that HR replaces it later. Only ever used on
    INSERT — the UPDATE half of the MERGE leaves ``MaNhanVien`` untouched, because a device knows
    nothing about HR codes and overwriting a real one is not recoverable from the device side.
    """
    return (employee_code or "").strip() or pin.strip()
