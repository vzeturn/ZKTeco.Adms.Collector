/* =============================================================================================
   Least-privilege grants for the collector's SQL login.
   Run after adms-schema.sql, as a principal that can GRANT (db_owner or db_securityadmin).

   PREREQUISITE, and the reason this file had never been run: the login must exist first, and
   CREATE LOGIN is a server-level permission the application's own DBA account does
   not hold -- it is db_owner on ATTENDANCEDB and nothing at the server level. Creating the login
   needs a sysadmin-level login (the RDS master user on Amazon RDS).
       -- on the server:  CREATE LOGIN adms_collector WITH PASSWORD = N'...';
       -- in ATTENDANCEDB:   CREATE USER  adms_collector FOR LOGIN adms_collector;

   WHY THE PRINCIPAL IS SPELLED OUT LITERALLY, ONCE PER GRANT (SEVENTEEN TIMES)
   ---------------------------------------------------------------------------
   The previous version declared @Principal SYSNAME and used it as a GRANT target. T-SQL rejects
   that at PARSE time (error 102): GRANT takes an identifier, not an expression. Combined with a
   single GO at the end of the file -- making all of it one batch -- that single parse error
   aborted every grant here. Find-and-replace on the name is the cost of a script that runs.

   WHY GO SEPARATES EACH GROUP
   ---------------------------
   A .sql file without batch separators is one batch, so one failure takes out everything after it.
   With them, a grant on an object this instance happens not to have costs only that group.

   WHY THIS IS WORTH DOING AT ALL, rather than db_datawriter
   --------------------------------------------------------
   The device endpoint is reachable by every device on every site and the ADMS protocol carries no
   credential: a serial number in a query string is the whole of it. The serial allow-list in
   ADMS_DEVICE is the primary control; these grants are the second layer, and they decide what the
   worst case costs when the first one is bypassed by a bug or a spoofed serial.
   ============================================================================================= */

SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

/* ---- Stored procedure: the only way this login writes attendance -------------------------- */
GRANT EXECUTE ON dbo.CheckInOut_add TO adms_collector;
GO

/* ---- Legacy tables, read ------------------------------------------------------------------ */
GRANT SELECT ON MAYCHAMCONG TO adms_collector;   /* resolve MaMCC -> IDMCC / TenMCC   */
GRANT SELECT ON CheckInOut  TO adms_collector;   /* duplicate detection before insert */
GO

/* ---- Legacy tables, write ----------------------------------------------------------------- */
GRANT SELECT, INSERT, UPDATE ON NHANVIEN     TO adms_collector;   /* MERGE from device USER rows */
GRANT SELECT, INSERT, DELETE ON dbo.TEMPLATE TO adms_collector;   /* replace-per-PIN             */
GRANT SELECT, INSERT, DELETE ON dbo.Face     TO adms_collector;   /* replace-per-PIN             */
GO

/* ---- Tables this service owns ------------------------------------------------------------- */
GRANT SELECT, INSERT, UPDATE ON dbo.ADMS_DEVICE     TO adms_collector;
GRANT SELECT, INSERT, UPDATE ON dbo.ADMS_COMMAND    TO adms_collector;
GRANT SELECT, INSERT         ON dbo.ADMS_ATTLOG_RAW TO adms_collector;
GRANT SELECT, INSERT         ON dbo.ADMS_OPERLOG    TO adms_collector;
GRANT SELECT, INSERT         ON dbo.ADMS_PUSH_LOG   TO adms_collector;
GRANT SELECT, INSERT         ON dbo.ADMS_USERPIC    TO adms_collector;
GRANT SELECT, INSERT         ON dbo.ADMS_UNPARSED   TO adms_collector;
GO

/* ---- Tables multi-device-employee-sync owns (Requirement 25.1) --------
   Same UPDATE-not-DELETE posture as ADMS_DEVICE/ADMS_COMMAND above: Roster_Sync bumps a version
   counter and upserts a per-device audit row, it never needs to erase either table's history. */
GRANT SELECT, INSERT, UPDATE ON dbo.ADMS_DEVICE_ROSTER_SEQUENCE TO adms_collector;
GRANT SELECT, INSERT, UPDATE ON dbo.ADMS_DEVICE_ROSTER_VERSION  TO adms_collector;
GRANT SELECT, INSERT, UPDATE ON dbo.ADMS_DEVICE_ROSTER          TO adms_collector;
GO

/* ---- Operator views ----------------------------------------------------------------------- */
GRANT SELECT ON dbo.vw_ADMS_DeviceStatus       TO adms_collector;
GRANT SELECT ON dbo.vw_ADMS_StuckCommands      TO adms_collector;
GRANT SELECT ON dbo.vw_ADMS_UnprojectedPunches TO adms_collector;
GRANT SELECT ON dbo.vw_ADMS_NonNumericPins     TO adms_collector;   /* was missing */
GRANT SELECT ON dbo.vw_ADMS_RosterSyncStatus   TO adms_collector;
GO

/* ---- Deliberately NOT granted, and why ----------------------------------------------------
     DELETE / UPDATE on CheckInOut   this service only ever inserts attendance, so a bug or a
                                     spoofed serial cannot erase or rewrite payroll history.
                                     Corrections stay a separately authorised act.
     DELETE on NHANVIEN              the service upserts employees from devices; it has no
                                     business removing a person. The desktop app owns erasure,
                                     with its own audit trail.
     EXECUTE on dbo.ADMS_PurgeArchives   retention is an operator job under its own login, so a
                                     compromised collector cannot destroy its own archive.
     any DDL                         the legacy schema is not ours to change.

   DELETE on dbo.TEMPLATE and dbo.Face IS granted, and is the sharpest edge here: replacing a
   user's biometrics is delete-then-insert per PIN, because a device uploads a user's templates
   as a complete set and both tables are heaps with no unique index. It is always scoped to one
   PIN and never runs unscoped.
   ------------------------------------------------------------------------------------------ */

/* ---- Verification. Run AS the collector login, not as a DBA -------------------------------
   sys.fn_my_permissions exposes entity_name, subentity_name and permission_name. It has NO
   state_desc column -- a query naming one fails, which is a mistake already made once. */
SELECT  o.name AS ObjectName, p.permission_name
FROM    sys.objects o
CROSS APPLY sys.fn_my_permissions(QUOTENAME(SCHEMA_NAME(o.schema_id)) + N'.' + QUOTENAME(o.name),
                                  N'OBJECT') p
WHERE   o.name IN (N'CheckInOut_add', N'MAYCHAMCONG', N'CheckInOut', N'NHANVIEN', N'TEMPLATE',
                   N'Face', N'ADMS_DEVICE', N'ADMS_COMMAND', N'ADMS_ATTLOG_RAW', N'ADMS_OPERLOG',
                   N'ADMS_PUSH_LOG', N'ADMS_USERPIC', N'ADMS_UNPARSED',
                   N'ADMS_DEVICE_ROSTER_SEQUENCE', N'ADMS_DEVICE_ROSTER_VERSION', N'ADMS_DEVICE_ROSTER',
                   N'vw_ADMS_DeviceStatus', N'vw_ADMS_StuckCommands',
                   N'vw_ADMS_UnprojectedPunches', N'vw_ADMS_NonNumericPins',
                   N'vw_ADMS_RosterSyncStatus')
ORDER BY o.name, p.permission_name;
GO
