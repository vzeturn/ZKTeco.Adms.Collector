/* =============================================================================================
   Admin console schema -- ADDITIVE layer over the shared ATTENDANCEDB APP_* tables.

   Run once against ATTENDANCEDB, after adms-schema.sql. Idempotent.

   This database already carries an RBAC schema from the desktop pull tool: dbo.APP_USER (a uniqueidentifier PK,
   FullName, KdfIterations, IsActive, ...), dbo.APP_ROLE (RoleId/RoleName = Admin/Operator/Viewer),
   dbo.APP_USER_ROLE (the user-to-role join), and dbo.APP_AUDIT. The console SHARES those tables --
   it does not create or alter them. This script only adds what the console owns and the read view it
   serves device health from.

   WHAT THIS SCRIPT CREATES (nothing here drops, alters or renames an existing object):
     * dbo.APP_SESSION            -- server-side, revocable sessions, keyed to APP_USER by GUID.
     * dbo.APP_PurgeExpiredSessions -- housekeeping for the above.
     * dbo.vw_APP_DeviceOverview  -- console-facing device health (CREATE OR ALTER; a view, not a table).

   WHY THE CONSOLE GETS REAL AUTHENTICATION WHEN THE DEVICE ENDPOINT CANNOT
   The device endpoint is unauthenticated because the ADMS protocol has no way to carry a credential.
   That constraint does not apply here: the users are people with browsers, so this side gets password
   authentication, server-side sessions that can be revoked, CSRF protection, lockout after repeated
   failures, and an audit trail -- reusing APP_USER's PBKDF2-HMAC-SHA256 hashes as they already are.
   ============================================================================================= */

SET NOCOUNT ON;
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

/* ---------------------------------------------------------------------------------------------
   APP_SESSION -- server-side sessions. The one table the console owns outright.

   A signed stateless cookie would need no table, and was rejected for one reason: it cannot be
   revoked. When someone leaves, or a laptop is lost, an administrator has to be able to end that
   session now rather than wait for it to expire. Deleting a row does that.

   TokenHash, not the token. The cookie holds a 32-byte random value; only its SHA-256 lands here, so
   a leaked database backup does not hand over live sessions.

   UserId is a uniqueidentifier, matching APP_USER's PK, with a real FK -- so a session cannot outlive
   the user it belongs to, and a delete of the user cascades in application order.
--------------------------------------------------------------------------------------------- */
IF OBJECT_ID('dbo.APP_SESSION', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.APP_SESSION
    (
        TokenHash     VARBINARY(32)      NOT NULL,
        UserId        UNIQUEIDENTIFIER   NOT NULL,
        CreatedUtc    DATETIME2(0)       NOT NULL CONSTRAINT DF_APP_SESSION_Created DEFAULT (SYSUTCDATETIME()),
        /* Sliding expiry, refreshed on use. Absolute expiry is enforced against CreatedUtc in code so
           a session cannot be kept alive forever by staying active. */
        ExpiresUtc    DATETIME2(0)       NOT NULL,
        LastSeenUtc   DATETIME2(0)       NOT NULL CONSTRAINT DF_APP_SESSION_Seen    DEFAULT (SYSUTCDATETIME()),
        Ip            NVARCHAR(64)       NOT NULL CONSTRAINT DF_APP_SESSION_Ip      DEFAULT (''),
        UserAgent     NVARCHAR(256)      NOT NULL CONSTRAINT DF_APP_SESSION_Ua      DEFAULT (''),
        /* Per-session CSRF secret. Tied to the session rather than global, so one leaked token cannot
           be replayed against another user. */
        CsrfSecret    VARBINARY(32)      NOT NULL,

        CONSTRAINT PK_APP_SESSION PRIMARY KEY CLUSTERED (TokenHash),
        CONSTRAINT FK_APP_SESSION_User FOREIGN KEY (UserId) REFERENCES dbo.APP_USER (UserId)
    );
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_APP_SESSION_User' AND object_id = OBJECT_ID('dbo.APP_SESSION'))
    CREATE INDEX IX_APP_SESSION_User ON dbo.APP_SESSION (UserId) INCLUDE (ExpiresUtc, LastSeenUtc, Ip);
GO

/* ---------------------------------------------------------------------------------------------
   Housekeeping: drop expired sessions.

   Schedule alongside dbo.ADMS_PurgeArchives. Not strictly required for correctness -- expiry is
   enforced on read -- but an unbounded session table is untidy and slows the sign-in path.
--------------------------------------------------------------------------------------------- */
CREATE OR ALTER PROCEDURE dbo.APP_PurgeExpiredSessions
AS
BEGIN
    SET NOCOUNT ON;
    DELETE FROM dbo.APP_SESSION WHERE ExpiresUtc < SYSUTCDATETIME();
    SELECT @@ROWCOUNT AS SessionsRemoved;
END
GO

/* Console-facing view of device health. Wraps the ADMS device row with the upload counts an operator
   actually asks for, which would otherwise be three separate queries per row in the UI. CREATE OR
   ALTER is safe here: a view has no data and this only ever (re)defines a read projection. */
CREATE OR ALTER VIEW dbo.vw_APP_DeviceOverview
AS
SELECT  d.SerialNumber,
        d.DeviceName,
        d.Enabled,
        d.MaMCC,
        m.IDMCC                AS MaSoMay,
        m.TenMCC               AS MachineName,
        m.DiaChiIP             AS MachineIp,
        d.FirmwareVersion,
        d.Platform,
        d.PushVersion,
        d.LastSeenUtc,
        d.ContactCount,
        d.LastIp,
        d.AttLogStamp,
        d.OperLogStamp,
        DATEDIFF(MINUTE, d.LastSeenUtc, SYSUTCDATETIME()) AS MinutesSinceContact,
        CASE
            WHEN d.Enabled = 0                    THEN 'Disabled'
            WHEN m.IDMCC IS NULL                  THEN 'Not linked'
            WHEN d.LastSeenUtc IS NULL            THEN 'Never seen'
            WHEN DATEDIFF(MINUTE, d.LastSeenUtc, SYSUTCDATETIME()) > 15 THEN 'Silent'
            ELSE 'Online'
        END                    AS DeviceState,
        (SELECT COUNT(*) FROM dbo.ADMS_ATTLOG_RAW r
          WHERE r.SerialNumber = d.SerialNumber
            AND r.ReceivedUtc > DATEADD(DAY, -1, SYSUTCDATETIME()))  AS PunchesLast24h,
        (SELECT COUNT(*) FROM dbo.ADMS_COMMAND c
          WHERE c.SerialNumber = d.SerialNumber AND c.Status = 'Pending') AS PendingCommands
FROM    dbo.ADMS_DEVICE d
LEFT JOIN MAYCHAMCONG m ON LTRIM(RTRIM(m.MaMCC)) = LTRIM(RTRIM(d.MaMCC));
GO

PRINT 'Admin console additive schema ready (APP_SESSION + view; shares APP_USER/APP_ROLE/APP_AUDIT).';
PRINT 'The console signs in existing APP_USER accounts; no separate admin bootstrap is required.';
GO
