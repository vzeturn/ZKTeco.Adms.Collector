/* =============================================================================================
   Least-privilege grants for the admin console's SQL login (adms_console).
   Run after admin-schema.sql AND adms-schema.sql, as a principal that can GRANT (db_owner or
   db_securityadmin). Mirrors grant-least-privilege.sql's own structure and rationale (the
   collector's own grant script) -- read that file's header first if this one is unfamiliar.

   PREREQUISITE: the login must exist first, and CREATE LOGIN is a server-level permission this
   database's own principals do not hold -- it needs a sysadmin-level login (the RDS master user on Amazon RDS), exactly as
   grant-least-privilege.sql's own header explains for adms_collector.
       -- on the server:  CREATE LOGIN adms_console WITH PASSWORD = N'...';
       -- in ATTENDANCEDB:   CREATE USER  adms_console FOR LOGIN adms_console;

   WHY A SEPARATE LOGIN FROM adms_collector, NOT A SHARED ONE
   ------------------------------------------------------------
   By design: adms_collector holds ZERO permissions on any APP_*
   object (sys.database_permissions returns no rows for that principal against APP_USER,
   APP_SESSION, APP_ROLE, APP_USER_ROLE, APP_AUDIT, or vw_APP_DeviceOverview). That is not an
   oversight -- grant-least-privilege.sql never mentions those objects because the collector has
   no business signing anyone in or reading who has console access. Handing the console
   adms_collector's credential would either fail outright (missing grants) or, if someone later
   widened adms_collector's own grants "to make the console work," would silently let a
   compromised device-facing process (which has NO credential of its own -- see the collector's
   own README on why the ADMS endpoint is unauthenticated) read every console user's session and
   audit history. Two logins is what keeps that failure mode from being one grant-script mistake
   away.

   WHY THE CONSOLE NEEDS SOME GRANTS THE COLLECTOR DELIBERATELY DOES NOT HAVE
   ------------------------------------------------------------------------------
   `dbo.ADMS_COMMAND` DELETE: the collector's own script explains DELETE is withheld there so a
   spoofed device serial cannot erase queued commands. The console's DELETE grant on that same
   table is not the same risk -- it is reached only through AdminStore.cancel_command, itself
   reached only through an authenticated, CSRF-protected POST from an operator role, scoped in
   application code to `Status = 'Pending'`. The grant is table-wide (SQL Server has no row-level
   GRANT), so this is the one place this script trusts the application layer's own scoping rather
   than the database's -- worth stating plainly rather than leaving implicit.

   `NHANVIEN` UPDATE (PhanQuyen only, by application code): granting device-admin rights
   (AdminStore.set_employee_admin) rewrites one column on one row. The collector's own grant
   already includes SELECT/INSERT/UPDATE on NHANVIEN for its own purpose (upserting from device
   USER records); this script grants the console the same statement-level permission
   independently, because the two services must be revocable independently even though they
   happen to touch the same table for different reasons.

   WHY GO SEPARATES EACH GROUP, AND WHY EACH PRINCIPAL NAME IS SPELLED OUT LITERALLY
   -----------------------------------------------------------------------------------
   Same two reasons grant-least-privilege.sql already states: a file with no batch separators is
   one failure-cascades-into-everything-after-it batch, and GRANT takes a literal identifier, not
   a variable -- @Principal SYSNAME used as a GRANT target is a T-SQL parse-time error (102).
   ============================================================================================= */

SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

/* ---- Console-owned tables (admin-schema.sql) ----------------------------------------------- */
-- DELETE on APP_USER / APP_USER_ROLE: AdminStore removes a user and its role rows (and revokes a
-- role) with DELETE statements; without it, user removal fails with a permission error.
GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.APP_USER      TO adms_console;
GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.APP_USER_ROLE TO adms_console;
GRANT SELECT                 ON dbo.APP_ROLE             TO adms_console;
GRANT SELECT, INSERT         ON dbo.APP_AUDIT            TO adms_console;
GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.APP_SESSION  TO adms_console;
-- Session housekeeping (admin-schema.sql), so a scheduled job can run as this login.
GRANT EXECUTE ON dbo.APP_PurgeExpiredSessions            TO adms_console;
GO

/* ---- Legacy tables, read -------------------------------------------------------------------
   Same two read-only grants the collector's own script already has, independently re-granted
   here: MAYCHAMCONG for the device-link dropdown (AdminStore.machines), CheckInOut is NOT needed
   by the console (it never reads attendance rows directly -- ADMS_ATTLOG_RAW below is what the
   Activity page reads instead). */
GRANT SELECT ON MAYCHAMCONG TO adms_console;
GO

/* ---- Legacy tables, write -------------------------------------------------------------------
   NHANVIEN: read for AdminStore.get_employee, UPDATE for set_employee_admin's PhanQuyen rewrite
   (grant/revoke device-admin rights). No INSERT -- the console looks up an existing employee by
   PIN, it does not create one; that stays the device-upload path's job (adms.db.employees).
   dbo.TEMPLATE/dbo.Face: read for the same lookup, UPDATE for the device-password write, and
   INSERT on TEMPLATE only for the PWDONLY placeholder row set_employee_admin creates when an
   employee has no biometric row at all (see store.py's _PWD_ONLY_SENTINEL). No DELETE on either
   -- the console never removes a template/face row, only edits enPassword on an existing one. */
GRANT SELECT, UPDATE         ON NHANVIEN     TO adms_console;
GRANT SELECT, INSERT, UPDATE ON dbo.TEMPLATE TO adms_console;
GRANT SELECT, UPDATE         ON dbo.Face     TO adms_console;
GO

/* ---- ADMS_* tables owned by the collector, read/write as the console needs ------------------
   ADMS_DEVICE: read for every device list/detail/summary query, UPDATE for enable/disable
   (Enabled) and link (MaMCC). No INSERT/DELETE -- the console never registers or removes a
   device row; that stays the collector's own register_pending path.
   ADMS_COMMAND: read for command history, INSERT for queuing an operator-issued command, DELETE
   for cancelling one still Pending (see this file's own header note on that grant's scope).
   ADMS_ATTLOG_RAW / ADMS_PUSH_LOG / ADMS_UNPARSED: read-only, for the Activity page's three tabs. */
GRANT SELECT, UPDATE                 ON dbo.ADMS_DEVICE     TO adms_console;
GRANT SELECT, INSERT, DELETE         ON dbo.ADMS_COMMAND    TO adms_console;
GRANT SELECT                         ON dbo.ADMS_ATTLOG_RAW TO adms_console;
GRANT SELECT                         ON dbo.ADMS_PUSH_LOG   TO adms_console;
GRANT SELECT                         ON dbo.ADMS_UNPARSED   TO adms_console;
GO

/* ---- multi-device-employee-sync: Roster_Sync visibility (Requirement 31's own dashboard) ----
   Read-only. The console never writes a Roster_Version or flips IsDeleted itself -- Fan_Out,
   Backfill and delete fan-out are entirely the collector's own responsibility
   (adms.db.roster_sync.SqlServerRosterSync); this login only reads the results to render
   /roster-sync and the dashboard's roster counters. */
GRANT SELECT ON dbo.ADMS_DEVICE_ROSTER_VERSION TO adms_console;
GO

/* ---- Operator views -------------------------------------------------------------------------
   vw_APP_DeviceOverview (admin-schema.sql): the console's own device-health projection.
   vw_ADMS_StuckCommands / vw_ADMS_UnprojectedPunches / vw_ADMS_NonNumericPins: read for the
   dashboard's own diagnostic counters (AdminStore.summary).
   vw_ADMS_RosterSyncStatus (adms-schema.sql, multi-device-employee-sync): read for both the
   dashboard's roster counters and the dedicated /roster-sync page. */
GRANT SELECT ON dbo.vw_APP_DeviceOverview       TO adms_console;
GRANT SELECT ON dbo.vw_ADMS_StuckCommands       TO adms_console;
GRANT SELECT ON dbo.vw_ADMS_UnprojectedPunches  TO adms_console;
GRANT SELECT ON dbo.vw_ADMS_NonNumericPins      TO adms_console;
GRANT SELECT ON dbo.vw_ADMS_RosterSyncStatus    TO adms_console;
GO

/* ---- Deliberately NOT granted, and why -----------------------------------------------------
     ANY permission on APP_SESSION.CsrfSecret's siblings beyond what is listed  the console owns
                                    this table outright (it is the only writer in the schema), so
                                    the grants above are already full CRUD on it -- there is
                                    nothing narrower to withhold here, unlike every locked legacy
                                    table below.
     DELETE on NHANVIEN              the console upserts nothing and deletes nothing about a
                                    person's existence; it only ever flips one privilege column
                                    on an already-existing row. Deleting an employee stays the
                                    desktop app's job, with its own audit trail (see
                                    the desktop pull tool's PII child-table
                                    cascade), never this console's.
     DELETE on dbo.TEMPLATE / dbo.Face   the console never removes enrolment data, only edits or
                                    (for TEMPLATE only) adds a placeholder row for a password with
                                    no biometric to attach to.
     EXECUTE on CheckInOut_add       attendance rows are written only by the collector's own
                                    device-upload path, never by the console.
     INSERT/UPDATE/DELETE on MAYCHAMCONG, CheckInOut, dbo.CheckInOut_add   the console reads the
                                    machine list to populate a dropdown and nothing else; it has
                                    no business writing attendance or machine rows.
     ANY write on ADMS_DEVICE_ROSTER_VERSION, ADMS_DEVICE_ROSTER, ADMS_DEVICE_ROSTER_SEQUENCE
                                    Roster_Sync's own version-bump/fan-out bookkeeping is entirely
                                    the collector's job; the console only ever displays the
                                    result.
     ANY DDL                        neither the legacy schema nor the owned ADMS_ or APP_ schema
                                    is this login's to change.
   ------------------------------------------------------------------------------------------ */

/* ---- Verification. Run AS the console login, not as a DBA ---------------------------------
   Same caveat grant-least-privilege.sql's own footer states: sys.fn_my_permissions has NO
   state_desc column. */
SELECT  o.name AS ObjectName, p.permission_name
FROM    sys.objects o
CROSS APPLY sys.fn_my_permissions(QUOTENAME(SCHEMA_NAME(o.schema_id)) + N'.' + QUOTENAME(o.name),
                                  N'OBJECT') p
WHERE   o.name IN (N'APP_USER', N'APP_USER_ROLE', N'APP_ROLE', N'APP_AUDIT', N'APP_SESSION',
                   N'MAYCHAMCONG', N'NHANVIEN', N'TEMPLATE', N'Face',
                   N'ADMS_DEVICE', N'ADMS_COMMAND', N'ADMS_ATTLOG_RAW', N'ADMS_PUSH_LOG',
                   N'ADMS_UNPARSED', N'ADMS_DEVICE_ROSTER_VERSION',
                   N'vw_APP_DeviceOverview', N'vw_ADMS_StuckCommands',
                   N'vw_ADMS_UnprojectedPunches', N'vw_ADMS_NonNumericPins',
                   N'vw_ADMS_RosterSyncStatus')
ORDER BY o.name, p.permission_name;
GO
