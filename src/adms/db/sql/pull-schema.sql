/* =============================================================================================
   Pull agent -- tables owned by adms.pull.

   Run once against ATTENDANCEDB, after adms-schema.sql (this script assumes dbo.ADMS_DEVICE
   already exists). Idempotent: every object is guarded, so re-running after an upgrade is safe.

   WHAT THIS ADDS AND WHY
   -----------------------
   The push collector (adms-schema.sql) never dials out to a device -- ADMS is pull-based from the
   device's side only. adms.pull is a second, separate, run-by-hand tool that DOES dial out, over
   the vendor TCP protocol (port 4370), to:
     * pull each device's employee roster into NHANVIEN,
     * pull each device's attendance buffer into CheckInOut / ADMS_ATTLOG_RAW (same tables, same
       dedup key the push path already uses -- a pulled punch is indistinguishable from a pushed
       one), and
     * synchronise employees between devices that share a "pull group" (an operator-defined area,
       e.g. one office), independent of the push side's own Sync_Group/roster-sync feature.

   This reuses dbo.ADMS_DEVICE as the single device list (additive columns only, all nullable or
   defaulted so a schema upgrade opts nothing in) rather than creating a second device table --
   an estate has one set of physical machines, and two independent lists would drift.

   ADMS_PULL_RUN / ADMS_PULL_LOG exist so every invocation is fully auditable: which devices were
   attempted, what stage each one reached, how long it took, and the exact error text if
   something went wrong. That is the whole point of "ghi log day du" (full logging) -- an operator
   running this by hand must be able to see, after the fact, exactly what happened and why.
   ============================================================================================= */

SET NOCOUNT ON;
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

/* ---------------------------------------------------------------------------------------------
   dbo.ADMS_DEVICE -- additive columns for direct-pull connectivity.

   PullEnabled defaults to 0, the same posture Enabled already takes for ADMS pushes: a device
   must be switched on for THIS feature by a person, because dialling into a device is a more
   intrusive operation (it can read and write the roster) than merely accepting its pushes.

   PullIp/PullPort are this feature's own columns rather than a read of MAYCHAMCONG.DiaChiIP/Port:
   those legacy columns exist but nothing in this codebase has ever trusted them for an outbound
   connection, and MAYCHAMCONG is a table this project does not modify (see schema.py's own
   locked-vs-owned split). Keeping the pull address here, on the table this feature already owns,
   means correcting an address is one UPDATE against ADMS_DEVICE, not a change to a legacy table
   another system also writes to.
--------------------------------------------------------------------------------------------- */
IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('dbo.ADMS_DEVICE') AND name = 'PullEnabled')
    ALTER TABLE dbo.ADMS_DEVICE ADD PullEnabled BIT NOT NULL CONSTRAINT DF_ADMS_DEVICE_PullEnabled DEFAULT (0);
GO

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('dbo.ADMS_DEVICE') AND name = 'PullIp')
    ALTER TABLE dbo.ADMS_DEVICE ADD PullIp NVARCHAR(64) NOT NULL CONSTRAINT DF_ADMS_DEVICE_PullIp DEFAULT ('');
GO

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('dbo.ADMS_DEVICE') AND name = 'PullPort')
    ALTER TABLE dbo.ADMS_DEVICE ADD PullPort INT NOT NULL CONSTRAINT DF_ADMS_DEVICE_PullPort DEFAULT (4370);
GO

/* The vendor "communication password" -- a numeric PIN set in the device's own Comm menu, 0 when
   none is set. Not a login credential in the web sense; it is the same weak, device-local secret
   the desktop app already keeps per machine. Stored in plain INT, matching what the protocol
   itself accepts (an unsigned integer), and because it grants nothing beyond "may talk to this one
   device on the local network" -- the real access control is physical/network reachability. */
IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('dbo.ADMS_DEVICE') AND name = 'PullPassword')
    ALTER TABLE dbo.ADMS_DEVICE ADD PullPassword INT NOT NULL CONSTRAINT DF_ADMS_DEVICE_PullPassword DEFAULT (0);
GO

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('dbo.ADMS_DEVICE') AND name = 'PullTimeoutSeconds')
    ALTER TABLE dbo.ADMS_DEVICE ADD PullTimeoutSeconds INT NOT NULL CONSTRAINT DF_ADMS_DEVICE_PullTimeout DEFAULT (10);
GO

/* The employee-sync grouping for the pull agent. Deliberately its own column, independent of
   dbo.ADMS_DEVICE.SyncGroup (multi-device-employee-sync's own push-side feature): the two
   features propagate roster changes through entirely different channels (this one dials out and
   writes directly; that one queues ADMS_COMMAND rows for a device to poll), can be enabled
   independently, and an estate may want different groupings for each -- e.g. pull-syncing four
   readers in one office while never enabling push-side Sync_Group for any of them. NULL/empty
   means "opts out of pull-side employee sync", the same convention SyncGroup already uses. */
IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('dbo.ADMS_DEVICE') AND name = 'PullGroup')
    ALTER TABLE dbo.ADMS_DEVICE ADD PullGroup NVARCHAR(64) NULL;
GO

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('dbo.ADMS_DEVICE') AND name = 'LastPullUtc')
    ALTER TABLE dbo.ADMS_DEVICE ADD LastPullUtc DATETIME2(0) NULL;
GO

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('dbo.ADMS_DEVICE') AND name = 'LastPullStatus')
    ALTER TABLE dbo.ADMS_DEVICE ADD LastPullStatus NVARCHAR(20) NOT NULL CONSTRAINT DF_ADMS_DEVICE_LastPullStatus DEFAULT ('');
GO

/* ---------------------------------------------------------------------------------------------
   dbo.ADMS_PULL_RUN -- one row per invocation of the pull agent.

   Status starts 'Running' and is closed out by the same process that created the row -- see
   adms.pull.runlog.SqlServerPullRunLog. A row stuck at 'Running' with an old StartedUtc means the
   process crashed or was killed mid-run, which is itself a diagnostic an operator can act on
   (vw_ADMS_PullStuckRuns below).
--------------------------------------------------------------------------------------------- */
IF OBJECT_ID('dbo.ADMS_PULL_RUN', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.ADMS_PULL_RUN
    (
        RunId            INT           IDENTITY(1,1) NOT NULL,
        Mode             NVARCHAR(20)  NOT NULL CONSTRAINT DF_ADMS_PULL_RUN_Mode    DEFAULT ('All'),
        Status           NVARCHAR(20)  NOT NULL CONSTRAINT DF_ADMS_PULL_RUN_Status  DEFAULT ('Running'),
        TriggeredBy      NVARCHAR(64)  NOT NULL CONSTRAINT DF_ADMS_PULL_RUN_By      DEFAULT (''),
        DevicesRequested INT           NOT NULL CONSTRAINT DF_ADMS_PULL_RUN_Req     DEFAULT (0),
        DevicesSucceeded INT           NOT NULL CONSTRAINT DF_ADMS_PULL_RUN_Ok      DEFAULT (0),
        DevicesFailed    INT           NOT NULL CONSTRAINT DF_ADMS_PULL_RUN_Bad     DEFAULT (0),
        StartedUtc       DATETIME2(0)  NOT NULL CONSTRAINT DF_ADMS_PULL_RUN_Started DEFAULT (SYSUTCDATETIME()),
        FinishedUtc      DATETIME2(0)  NULL,

        CONSTRAINT PK_ADMS_PULL_RUN PRIMARY KEY CLUSTERED (RunId),
        CONSTRAINT CK_ADMS_PULL_RUN_Status CHECK (Status IN ('Running', 'Success', 'PartialFailure', 'Failed')),
        CONSTRAINT CK_ADMS_PULL_RUN_Mode CHECK (Mode IN ('All', 'Employees', 'Attendance', 'Sync'))
    );
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ADMS_PULL_RUN_Started' AND object_id = OBJECT_ID('dbo.ADMS_PULL_RUN'))
    CREATE INDEX IX_ADMS_PULL_RUN_Started ON dbo.ADMS_PULL_RUN (StartedUtc DESC);
GO

/* ---------------------------------------------------------------------------------------------
   dbo.ADMS_PULL_LOG -- one row per (device, stage) attempted within a run.

   This is the table an operator reads to answer "did the pull have a problem, and with what":
   every stage of every device, in every run, with its own status, record count, timing and exact
   error text. Nothing here is summarised away -- a run that failed for one device out of twelve
   still shows the other eleven succeeded, which a single pass/fail flag on the run itself could
   never say.
--------------------------------------------------------------------------------------------- */
IF OBJECT_ID('dbo.ADMS_PULL_LOG', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.ADMS_PULL_LOG
    (
        Id            BIGINT         IDENTITY(1,1) NOT NULL,
        RunId         INT            NOT NULL,
        SerialNumber  NVARCHAR(64)   NOT NULL,
        DeviceName    NVARCHAR(100)  NOT NULL CONSTRAINT DF_ADMS_PULL_LOG_Name  DEFAULT (''),
        Stage         NVARCHAR(20)   NOT NULL,
        Status        NVARCHAR(20)   NOT NULL,
        RecordCount   INT            NOT NULL CONSTRAINT DF_ADMS_PULL_LOG_Count DEFAULT (0),
        DurationMs    INT            NOT NULL CONSTRAINT DF_ADMS_PULL_LOG_Dur   DEFAULT (0),
        ErrorMessage  NVARCHAR(1024) NOT NULL CONSTRAINT DF_ADMS_PULL_LOG_Err   DEFAULT (''),
        CreatedUtc    DATETIME2(0)   NOT NULL CONSTRAINT DF_ADMS_PULL_LOG_Recv  DEFAULT (SYSUTCDATETIME()),

        CONSTRAINT PK_ADMS_PULL_LOG PRIMARY KEY CLUSTERED (Id),
        CONSTRAINT FK_ADMS_PULL_LOG_Run FOREIGN KEY (RunId) REFERENCES dbo.ADMS_PULL_RUN (RunId),
        CONSTRAINT CK_ADMS_PULL_LOG_Stage CHECK (Stage IN ('Connect', 'PullEmployees', 'PullAttendance', 'SyncEmployees')),
        CONSTRAINT CK_ADMS_PULL_LOG_Status CHECK (Status IN ('Success', 'Failed', 'Skipped'))
    );
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ADMS_PULL_LOG_Run' AND object_id = OBJECT_ID('dbo.ADMS_PULL_LOG'))
    CREATE INDEX IX_ADMS_PULL_LOG_Run ON dbo.ADMS_PULL_LOG (RunId, SerialNumber);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ADMS_PULL_LOG_Device' AND object_id = OBJECT_ID('dbo.ADMS_PULL_LOG'))
    CREATE INDEX IX_ADMS_PULL_LOG_Device ON dbo.ADMS_PULL_LOG (SerialNumber, CreatedUtc DESC);
GO

/* =============================================================================================
   Operator views.
   ============================================================================================= */

/* Every pull-enabled device, its configured address/group, and the outcome of its most recent
   pull attempt (from ADMS_DEVICE's own denormalised LastPullUtc/LastPullStatus, kept current by
   adms.pull.registry.SqlServerPullDeviceRegistry after each run -- cheap to read on its own,
   with no join to the (potentially large) log table needed for the common "is everything OK"
   check). */
CREATE OR ALTER VIEW dbo.vw_ADMS_PullStatus
AS
SELECT  d.SerialNumber,
        d.DeviceName,
        d.PullEnabled,
        d.PullIp,
        d.PullPort,
        d.PullGroup,
        d.MaMCC,
        m.IDMCC              AS MaSoMay,
        d.LastPullUtc,
        d.LastPullStatus,
        DATEDIFF(MINUTE, d.LastPullUtc, SYSUTCDATETIME()) AS MinutesSinceLastPull
FROM    dbo.ADMS_DEVICE d
LEFT JOIN MAYCHAMCONG m ON LTRIM(RTRIM(m.MaMCC)) = LTRIM(RTRIM(d.MaMCC))
WHERE   d.PullEnabled = 1;
GO

/* The full, per-stage detail behind the summary above -- what an operator opens after
   vw_ADMS_PullStatus shows a device with LastPullStatus = 'Failed'. */
CREATE OR ALTER VIEW dbo.vw_ADMS_PullLogRecent
AS
SELECT  l.Id, l.RunId, l.SerialNumber, l.DeviceName, l.Stage, l.Status,
        l.RecordCount, l.DurationMs, l.ErrorMessage, l.CreatedUtc,
        r.Mode AS RunMode, r.TriggeredBy AS RunTriggeredBy
FROM    dbo.ADMS_PULL_LOG l
INNER JOIN dbo.ADMS_PULL_RUN r ON r.RunId = l.RunId;
GO

/* Runs left 'Running' for over two hours -- almost always the process was killed or crashed
   mid-run rather than a pull that is genuinely still going (a full estate pull is a matter of
   seconds to a few minutes per device, not hours). */
CREATE OR ALTER VIEW dbo.vw_ADMS_PullStuckRuns
AS
SELECT  RunId, Mode, TriggeredBy, StartedUtc,
        DATEDIFF(MINUTE, StartedUtc, SYSUTCDATETIME()) AS MinutesRunning
FROM    dbo.ADMS_PULL_RUN
WHERE   Status = 'Running'
  AND   StartedUtc < DATEADD(HOUR, -2, SYSUTCDATETIME());
GO
