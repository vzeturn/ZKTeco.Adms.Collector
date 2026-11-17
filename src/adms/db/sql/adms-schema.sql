/* =============================================================================================
   ADMS attendance collector — tables owned by this service.

   Run once against the ATTENDANCEDB database. Idempotent: every object is guarded, so re-running
   after an upgrade is safe.

   WHAT THIS SCRIPT DOES NOT DO
   ----------------------------
   It does not touch MAYCHAMCONG, NHANVIEN, CheckInOut, dbo.TEMPLATE, dbo.Face or
   dbo.CheckInOut_add. Those belong to the legacy LAYCONG31 system, which is still upgraded on its
   own schedule; adding even an index to them would put this service in the way of that. Every
   piece of state the ADMS model needs and the legacy schema has no room for lives in the ADMS_*
   tables below, and the only coupling is a documented join from ADMS_DEVICE.MaMCC to
   MAYCHAMCONG.MaMCC.

   That join is deliberately NOT a foreign key. MaMCC is NCHAR(8) and space-padded, the legacy
   system occasionally rewrites machine rows, and a constraint here would make an unrelated
   maintenance script fail with an error pointing at us.

   PERMISSIONS
   -----------
   The collector's SQL login needs, and should have nothing beyond:
     - EXECUTE on dbo.CheckInOut_add
     - SELECT on MAYCHAMCONG, CheckInOut
     - SELECT, INSERT, UPDATE on NHANVIEN
     - SELECT, INSERT, DELETE on dbo.TEMPLATE, dbo.Face
     - SELECT, INSERT, UPDATE on the ADMS_* tables
   Notably no DELETE on CheckInOut or NHANVIEN: this service only ever adds attendance and
   upserts employees, so granting more would let a protocol bug or a spoofed device destroy
   payroll history. See grant-least-privilege.sql for a copy-pasteable script.
   ============================================================================================= */

SET NOCOUNT ON;

/* REQUIRED, and not merely conventional. The filtered index on ADMS_COMMAND fails with
   "CREATE INDEX failed because the following SET options have incorrect settings:
   'QUOTED_IDENTIFIER'" unless both of these are ON.

   This bites specifically when the script is run with sqlcmd, which defaults QUOTED_IDENTIFIER to
   OFF, while SSMS defaults it to ON -- so a script that works when a DBA pastes it into SSMS fails
   in an automated deployment. Setting it here makes the file behave the same either way.

   These are session settings and persist across the GO batches below. Stored procedures also capture
   them at creation time, which is a second reason to set them before anything is created. */
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

/* ---------------------------------------------------------------------------------------------
   ADMS_DEVICE — the serial-number allow-list.

   This table IS the authorisation model. ADMS carries no credential of any kind: a device
   announces only its serial number in a query string, over plain HTTP. So "is this serial
   present, and is Enabled = 1" is the entire access decision for every request.

   Enabled defaults to 0 on purpose. A newly discovered device must be switched on by a person,
   because the serial number is the only thing a caller has to claim and it is printed on a label
   on the outside of the unit.

   MaMCC is nullable because the serial-to-machine link cannot be derived: a pushing device
   announces its serial, while CheckInOut.MaSoMay needs MAYCHAMCONG.IDMCC. Someone has to state
   the mapping once. Until they do, the device handshakes (so it appears here, online, with its
   firmware details) but its data pushes are refused with 503 and the device keeps its records.
--------------------------------------------------------------------------------------------- */
IF OBJECT_ID('dbo.ADMS_DEVICE', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.ADMS_DEVICE
    (
        SerialNumber     NVARCHAR(64)   NOT NULL,
        Enabled          BIT            NOT NULL CONSTRAINT DF_ADMS_DEVICE_Enabled     DEFAULT (0),
        MaMCC            NCHAR(8)       NULL,
        DeviceName       NVARCHAR(100)  NOT NULL CONSTRAINT DF_ADMS_DEVICE_DeviceName  DEFAULT (''),
        FirmwareVersion  NVARCHAR(64)   NOT NULL CONSTRAINT DF_ADMS_DEVICE_FirmVer     DEFAULT (''),
        Platform         NVARCHAR(64)   NOT NULL CONSTRAINT DF_ADMS_DEVICE_Platform    DEFAULT (''),
        PushVersion      NVARCHAR(32)   NOT NULL CONSTRAINT DF_ADMS_DEVICE_PushVer     DEFAULT (''),
        OptionsJson      NVARCHAR(MAX)  NULL,
        LastIp           NVARCHAR(64)   NOT NULL CONSTRAINT DF_ADMS_DEVICE_LastIp      DEFAULT (''),

        /* Resumption cursors, one per uploaded table. The device uses the value we echo in the
           handshake to decide what it still owes us, so these are only advanced AFTER the records
           they cover are committed. Echoing a stamp ahead of storage tells the device to discard
           records we never wrote. */
        AttLogStamp      NVARCHAR(32)   NOT NULL CONSTRAINT DF_ADMS_DEVICE_AttStamp    DEFAULT ('0'),
        OperLogStamp     NVARCHAR(32)   NOT NULL CONSTRAINT DF_ADMS_DEVICE_OpStamp     DEFAULT ('0'),
        AttPhotoStamp    NVARCHAR(32)   NOT NULL CONSTRAINT DF_ADMS_DEVICE_PhotoStamp  DEFAULT ('0'),

        /* Site offset from UTC. Per device, not global: an estate can span time zones, and every
           timestamp in this schema is local wall-clock. */
        TimeZoneOffset   INT            NOT NULL CONSTRAINT DF_ADMS_DEVICE_Tz          DEFAULT (7),

        FirstSeenUtc     DATETIME2(0)   NOT NULL CONSTRAINT DF_ADMS_DEVICE_FirstSeen   DEFAULT (SYSUTCDATETIME()),
        LastSeenUtc      DATETIME2(0)   NULL,
        ContactCount     BIGINT         NOT NULL CONSTRAINT DF_ADMS_DEVICE_Contacts    DEFAULT (0),
        Notes            NVARCHAR(400)  NOT NULL CONSTRAINT DF_ADMS_DEVICE_Notes       DEFAULT (''),

        CONSTRAINT PK_ADMS_DEVICE PRIMARY KEY CLUSTERED (SerialNumber)
    );
END
GO

/* Covers the "which devices have gone quiet" query, which is the main operational view: a device
   that stops contacting us is invisible otherwise — there is nothing to poll. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ADMS_DEVICE_LastSeen' AND object_id = OBJECT_ID('dbo.ADMS_DEVICE'))
    CREATE INDEX IX_ADMS_DEVICE_LastSeen ON dbo.ADMS_DEVICE (LastSeenUtc DESC) INCLUDE (Enabled, MaMCC, DeviceName);
GO

/* ---------------------------------------------------------------------------------------------
   ADMS_COMMAND — the server-to-device queue.

   ADMS is strictly pull-based: nothing can be pushed to a device. A row here waits until the
   device's next /iclock/getrequest poll, so the handshake's Delay value is the worst-case latency.

   Status: Pending -> Sent -> Done | Failed. Claimed on read (UPDATE ... OUTPUT), giving at-most-once
   delivery. A row stuck at 'Sent' with an old SentUtc is a command that was dispatched and never
   acknowledged — a real condition worth alerting on, and the reason SentUtc is stored separately
   from CreatedUtc.
--------------------------------------------------------------------------------------------- */
IF OBJECT_ID('dbo.ADMS_COMMAND', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.ADMS_COMMAND
    (
        CommandId     INT            IDENTITY(1,1) NOT NULL,
        SerialNumber  NVARCHAR(64)   NOT NULL,
        CommandText   NVARCHAR(MAX)  NOT NULL,
        Status        NVARCHAR(20)   NOT NULL CONSTRAINT DF_ADMS_COMMAND_Status DEFAULT ('Pending'),
        ReturnCode    INT            NULL,
        ReturnCmd     NVARCHAR(64)   NULL,
        CreatedBy     NVARCHAR(64)   NOT NULL CONSTRAINT DF_ADMS_COMMAND_By     DEFAULT (''),
        CreatedUtc    DATETIME2(0)   NOT NULL CONSTRAINT DF_ADMS_COMMAND_Created DEFAULT (SYSUTCDATETIME()),
        SentUtc       DATETIME2(0)   NULL,
        AckedUtc      DATETIME2(0)   NULL,

        CONSTRAINT PK_ADMS_COMMAND PRIMARY KEY CLUSTERED (CommandId),
        CONSTRAINT CK_ADMS_COMMAND_Status CHECK (Status IN ('Pending', 'Sent', 'Done', 'Failed'))
    );
END
GO

/* The dequeue path's covering index. Filtered to Pending so it stays small no matter how much
   history the table accumulates — the queue is read on every device poll. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ADMS_COMMAND_Pending' AND object_id = OBJECT_ID('dbo.ADMS_COMMAND'))
    CREATE INDEX IX_ADMS_COMMAND_Pending
        ON dbo.ADMS_COMMAND (SerialNumber, CommandId)
        WHERE Status = 'Pending';
GO

/* ---------------------------------------------------------------------------------------------
   ADMS_ATTLOG_RAW — every punch exactly as pushed.

   CheckInOut has no column for Status (in/out), Verify (fingerprint/face/card) or WorkCode; the
   legacy contract fixes KieuCham = '1' and discards the rest. Over ADMS the device sends all of it
   and then deletes it once acknowledged, so without this table the upload would be permanently
   lossy.

   The unique constraint is the natural key and makes replay safe. Status is part of it because a
   legitimate double punch (in then out within the same second) is a real occurrence on a
   fast-reading device.
--------------------------------------------------------------------------------------------- */
IF OBJECT_ID('dbo.ADMS_ATTLOG_RAW', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.ADMS_ATTLOG_RAW
    (
        Id            BIGINT        IDENTITY(1,1) NOT NULL,
        SerialNumber  NVARCHAR(64)  NOT NULL,
        /* NVARCHAR, not int: the archive records what arrived, including the alphanumeric PINs
           that CheckInOut cannot store. Filtering belongs to the projection, not the record. */
        Pin           NVARCHAR(32)  NOT NULL,
        PunchTime     DATETIME      NOT NULL,
        Status        INT           NOT NULL CONSTRAINT DF_ADMS_ATTLOG_Status DEFAULT (0),
        Verify        INT           NOT NULL CONSTRAINT DF_ADMS_ATTLOG_Verify DEFAULT (-1),
        WorkCode      INT           NOT NULL CONSTRAINT DF_ADMS_ATTLOG_Work   DEFAULT (0),
        Reserved1     NVARCHAR(64)  NOT NULL CONSTRAINT DF_ADMS_ATTLOG_R1     DEFAULT (''),
        Reserved2     NVARCHAR(64)  NOT NULL CONSTRAINT DF_ADMS_ATTLOG_R2     DEFAULT (''),
        ReceivedUtc   DATETIME2(0)  NOT NULL CONSTRAINT DF_ADMS_ATTLOG_Recv   DEFAULT (SYSUTCDATETIME()),

        CONSTRAINT PK_ADMS_ATTLOG_RAW PRIMARY KEY CLUSTERED (Id),
        CONSTRAINT UQ_ADMS_ATTLOG_RAW UNIQUE (SerialNumber, Pin, PunchTime, Status)
    );
END
GO

/* ---------------------------------------------------------------------------------------------
   ADMS_OPERLOG — device-side administrative actions (OPLOG records).

   Never touches attendance, and earns its storage the first time someone asks why a user's
   templates disappeared: this is the only record that a delete happened ON THE DEVICE, when, and
   by which admin. OpTime is nullable because a device with a dead clock still produces op logs
   worth keeping, and RawLine preserves the original text either way.
--------------------------------------------------------------------------------------------- */
IF OBJECT_ID('dbo.ADMS_OPERLOG', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.ADMS_OPERLOG
    (
        Id            BIGINT         IDENTITY(1,1) NOT NULL,
        SerialNumber  NVARCHAR(64)   NOT NULL,
        OpCode        INT            NOT NULL CONSTRAINT DF_ADMS_OPERLOG_Op DEFAULT (0),
        OperatorPin   NVARCHAR(32)   NOT NULL CONSTRAINT DF_ADMS_OPERLOG_Pin DEFAULT (''),
        OpTime        DATETIME       NULL,
        Param1        NVARCHAR(64)   NOT NULL CONSTRAINT DF_ADMS_OPERLOG_P1 DEFAULT (''),
        Param2        NVARCHAR(64)   NOT NULL CONSTRAINT DF_ADMS_OPERLOG_P2 DEFAULT (''),
        Param3        NVARCHAR(64)   NOT NULL CONSTRAINT DF_ADMS_OPERLOG_P3 DEFAULT (''),
        RawLine       NVARCHAR(512)  NOT NULL CONSTRAINT DF_ADMS_OPERLOG_Raw DEFAULT (''),
        ReceivedUtc   DATETIME2(0)   NOT NULL CONSTRAINT DF_ADMS_OPERLOG_Recv DEFAULT (SYSUTCDATETIME()),

        CONSTRAINT PK_ADMS_OPERLOG PRIMARY KEY CLUSTERED (Id)
    );
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ADMS_OPERLOG_Device' AND object_id = OBJECT_ID('dbo.ADMS_OPERLOG'))
    CREATE INDEX IX_ADMS_OPERLOG_Device ON dbo.ADMS_OPERLOG (SerialNumber, OpTime DESC);
GO

/* ---------------------------------------------------------------------------------------------
   ADMS_USERPIC — enrollment / attendance photos.

   ATTENDANCEDB has no image column anywhere, and adding one to NHANVIEN is exactly the legacy-schema
   change this project refuses to make. Stored as the device's own base64 text rather than
   VARBINARY: the point of the archive is a byte-exact copy of what arrived, and decoding
   introduces a step that can fail on a payload we would then have nothing of.
--------------------------------------------------------------------------------------------- */
IF OBJECT_ID('dbo.ADMS_USERPIC', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.ADMS_USERPIC
    (
        Id             BIGINT         IDENTITY(1,1) NOT NULL,
        SerialNumber   NVARCHAR(64)   NOT NULL,
        Pin            NVARCHAR(32)   NOT NULL,
        FileName       NVARCHAR(128)  NOT NULL CONSTRAINT DF_ADMS_USERPIC_File DEFAULT (''),
        ContentSize    INT            NOT NULL CONSTRAINT DF_ADMS_USERPIC_Size DEFAULT (0),
        ContentBase64  NVARCHAR(MAX)  NULL,
        ReceivedUtc    DATETIME2(0)   NOT NULL CONSTRAINT DF_ADMS_USERPIC_Recv DEFAULT (SYSUTCDATETIME()),

        CONSTRAINT PK_ADMS_USERPIC PRIMARY KEY CLUSTERED (Id)
    );
END
GO

/* ---------------------------------------------------------------------------------------------
   ADMS_PUSH_LOG — the request envelope and (size-capped) body of every upload.

   This is the replay log. If a mapping bug is found next month, the original bodies are still
   here; without them the only copy was on a device that erased it the moment we answered OK.

   It is also the table with real growth. See the retention job at the end of this script — and note
   that Body can contain personal data (names, and base64 templates that are biometric data), so its
   retention is a privacy decision, not just a storage one.
--------------------------------------------------------------------------------------------- */
IF OBJECT_ID('dbo.ADMS_PUSH_LOG', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.ADMS_PUSH_LOG
    (
        Id            BIGINT          IDENTITY(1,1) NOT NULL,
        SerialNumber  NVARCHAR(64)    NOT NULL CONSTRAINT DF_ADMS_PUSH_LOG_Sn    DEFAULT (''),
        Route         NVARCHAR(200)   NOT NULL CONSTRAINT DF_ADMS_PUSH_LOG_Route DEFAULT (''),
        TableName     NVARCHAR(40)    NOT NULL CONSTRAINT DF_ADMS_PUSH_LOG_Table DEFAULT (''),
        QueryString   NVARCHAR(1024)  NOT NULL CONSTRAINT DF_ADMS_PUSH_LOG_Query DEFAULT (''),
        Body          NVARCHAR(MAX)   NULL,
        RecordCount   INT             NOT NULL CONSTRAINT DF_ADMS_PUSH_LOG_Count DEFAULT (0),
        ReceivedUtc   DATETIME2(0)    NOT NULL CONSTRAINT DF_ADMS_PUSH_LOG_Recv  DEFAULT (SYSUTCDATETIME()),

        CONSTRAINT PK_ADMS_PUSH_LOG PRIMARY KEY CLUSTERED (Id)
    );
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ADMS_PUSH_LOG_Received' AND object_id = OBJECT_ID('dbo.ADMS_PUSH_LOG'))
    CREATE INDEX IX_ADMS_PUSH_LOG_Received ON dbo.ADMS_PUSH_LOG (ReceivedUtc DESC) INCLUDE (SerialNumber, TableName, RecordCount);
GO

/* ---------------------------------------------------------------------------------------------
   ADMS_UNPARSED — record lines the parsers recognised but could not classify.

   Query this first after a firmware upgrade: it answers "what is the device sending that we are
   ignoring" directly, instead of leaving it as a count mismatch nobody can explain.
--------------------------------------------------------------------------------------------- */
IF OBJECT_ID('dbo.ADMS_UNPARSED', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.ADMS_UNPARSED
    (
        Id            BIGINT          IDENTITY(1,1) NOT NULL,
        SerialNumber  NVARCHAR(64)    NOT NULL,
        TableName     NVARCHAR(40)    NOT NULL CONSTRAINT DF_ADMS_UNPARSED_Table DEFAULT (''),
        RawLine       NVARCHAR(1024)  NOT NULL,
        ReceivedUtc   DATETIME2(0)    NOT NULL CONSTRAINT DF_ADMS_UNPARSED_Recv  DEFAULT (SYSUTCDATETIME()),

        CONSTRAINT PK_ADMS_UNPARSED PRIMARY KEY CLUSTERED (Id)
    );
END
GO

/* =============================================================================================
   Operator views. Read-only conveniences — no logic depends on them.
   ============================================================================================= */

/* Device health, including the two states an operator must be able to tell apart:
   'Not linked' (registered but no MAYCHAMCONG row -> data pushes are being refused) and
   'Disabled' (deliberately switched off). */
CREATE OR ALTER VIEW dbo.vw_ADMS_DeviceStatus
AS
SELECT  d.SerialNumber,
        d.DeviceName,
        d.Enabled,
        d.MaMCC,
        m.IDMCC                AS MaSoMay,
        m.TenMCC               AS MachineName,
        d.FirmwareVersion,
        d.LastSeenUtc,
        d.ContactCount,
        DATEDIFF(MINUTE, d.LastSeenUtc, SYSUTCDATETIME()) AS MinutesSinceContact,
        CASE
            WHEN d.Enabled = 0                    THEN 'Disabled'
            WHEN m.IDMCC IS NULL                  THEN 'Not linked'
            WHEN d.LastSeenUtc IS NULL            THEN 'Never seen'
            WHEN DATEDIFF(MINUTE, d.LastSeenUtc, SYSUTCDATETIME()) > 15 THEN 'Silent'
            ELSE 'Online'
        END                    AS DeviceState
FROM    dbo.ADMS_DEVICE d
LEFT JOIN MAYCHAMCONG m ON LTRIM(RTRIM(m.MaMCC)) = LTRIM(RTRIM(d.MaMCC));
GO

/* Punches that arrived over ADMS but never landed in CheckInOut. Should always be empty; a non-empty
   result means a non-numeric PIN, or a projection bug worth replaying from ADMS_PUSH_LOG.

   DELIBERATELY DOES NOT JOIN ON MaSoMay / IDMCC. In the inherited data:
   MAYCHAMCONG.IDMCC can be 1 on most configured machines, and CheckInOut.MaSoMay can be 1 on
   virtually every row, with TenMay carrying the actual machine identity. So a join on IDMCC matches
   many machines at once and this view would report nonsense.

   The correlation is therefore (MaChamCong, GioCham) only, which is exactly the key the deployed
   dbo.CheckInOut_add deduplicates on -- so it answers the real question ("did this punch reach
   CheckInOut at all") rather than a machine-scoped question the data cannot support. */
CREATE OR ALTER VIEW dbo.vw_ADMS_UnprojectedPunches
AS
SELECT  r.Id, r.SerialNumber, r.Pin, r.PunchTime, r.Status, r.Verify, r.ReceivedUtc
FROM    dbo.ADMS_ATTLOG_RAW r
WHERE   TRY_CAST(r.Pin AS INT) IS NOT NULL
  AND   NOT EXISTS (
            SELECT 1
            FROM   CheckInOut c
            WHERE  c.GioCham    = r.PunchTime
              AND  c.MaChamCong = TRY_CAST(r.Pin AS INT)
        );
GO

/* Punches whose PIN is not an integer, so CheckInOut (MaChamCong int) can never hold them. Separated
   from the view above because the two need different actions: this one means a device PIN that will
   never reach payroll and someone has to re-enrol the user, not a bug to replay. */
CREATE OR ALTER VIEW dbo.vw_ADMS_NonNumericPins
AS
SELECT  r.SerialNumber, r.Pin, COUNT(*) AS Punches,
        MIN(r.PunchTime) AS FirstSeen, MAX(r.PunchTime) AS LastSeen
FROM    dbo.ADMS_ATTLOG_RAW r
WHERE   TRY_CAST(r.Pin AS INT) IS NULL
GROUP BY r.SerialNumber, r.Pin;
GO

/* ---------------------------------------------------------------------------------------------
   Seeding ADMS_DEVICE from what MAYCHAMCONG already knows.

   The inherited schema may have a Serial column, populated for most machines. So the serial-to-machine mapping this service needs mostly exists
   already and does not have to be typed in by hand.

   Run this to pre-create the allow-list entries. Note Enabled stays 0: the mapping can be derived,
   but AUTHORISING a device is a decision a person has to make, because the serial number is the
   entire credential the ADMS protocol offers and it is printed on a label on the outside of the unit.

   After running it, review dbo.vw_ADMS_DeviceStatus and switch on the devices you actually expect:
     UPDATE dbo.ADMS_DEVICE SET Enabled = 1 WHERE SerialNumber = N'...';

   IMPORTANT: it is not yet confirmed that MAYCHAMCONG.Serial holds the same value a device sends as
   its SN= query parameter. The stored values are 13-digit numeric (older ZKTeco format) while newer
   models report an alphanumeric serial. Compare against dbo.ADMS_DEVICE rows created by
   ADMS_AUTO_REGISTER_DEVICES, or against the log, before trusting it.
--------------------------------------------------------------------------------------------- */
CREATE OR ALTER PROCEDURE dbo.ADMS_SeedDevicesFromMayChamCong
AS
BEGIN
    SET NOCOUNT ON;

    INSERT INTO dbo.ADMS_DEVICE (SerialNumber, Enabled, MaMCC, DeviceName, Notes)
    SELECT  LTRIM(RTRIM(m.Serial)),
            0,
            m.MaMCC,
            LEFT(ISNULL(m.TenMCC, ''), 100),
            N'Seeded from MAYCHAMCONG.Serial; confirm the serial matches what the device sends.'
    FROM    MAYCHAMCONG m
    WHERE   NULLIF(LTRIM(RTRIM(m.Serial)), '') IS NOT NULL
      AND   NOT EXISTS (
                SELECT 1 FROM dbo.ADMS_DEVICE d
                 WHERE d.SerialNumber = LTRIM(RTRIM(m.Serial))
            );

    SELECT @@ROWCOUNT AS DevicesSeeded;
END
GO

/* Commands dispatched but never acknowledged for over an hour. */
CREATE OR ALTER VIEW dbo.vw_ADMS_StuckCommands
AS
SELECT  CommandId, SerialNumber, CommandText, SentUtc,
        DATEDIFF(MINUTE, SentUtc, SYSUTCDATETIME()) AS MinutesSinceSent
FROM    dbo.ADMS_COMMAND
WHERE   Status = 'Sent'
  AND   SentUtc < DATEADD(HOUR, -1, SYSUTCDATETIME());
GO

/* =============================================================================================
   Retention.

   ADMS_PUSH_LOG and ADMS_USERPIC are the only tables here that grow without bound, and both hold
   personal data — names, and base64 biometric templates. Deleting them on a schedule is a privacy
   obligation as much as a storage one.

   Deliberately a procedure you schedule, not an automatic trigger: how long the replay window
   should be is a policy decision, and 90 days is only a starting suggestion. ADMS_ATTLOG_RAW is
   NOT purged here — it is the lossless attendance record, and attendance retention belongs to
   whoever owns payroll.

   Deletes in bounded batches so the job never holds a long transaction against a table the
   collector is actively inserting into.
   ============================================================================================= */
CREATE OR ALTER PROCEDURE dbo.ADMS_PurgeArchives
    @RetainDays INT = 90,
    @BatchSize  INT = 5000
AS
BEGIN
    SET NOCOUNT ON;

    IF @RetainDays < 1
    BEGIN
        /* Refusing zero mirrors the desktop app's empty-target-set guard: an unbounded purge is
           always a mistake, never an instruction. */
        RAISERROR('@RetainDays must be at least 1. Refusing to purge the entire archive.', 16, 1);
        RETURN;
    END

    DECLARE @cutoff DATETIME2(0) = DATEADD(DAY, -@RetainDays, SYSUTCDATETIME());
    DECLARE @deleted INT = 1;

    WHILE @deleted > 0
    BEGIN
        DELETE TOP (@BatchSize) FROM dbo.ADMS_PUSH_LOG WHERE ReceivedUtc < @cutoff;
        SET @deleted = @@ROWCOUNT;
    END

    SET @deleted = 1;
    WHILE @deleted > 0
    BEGIN
        DELETE TOP (@BatchSize) FROM dbo.ADMS_USERPIC WHERE ReceivedUtc < @cutoff;
        SET @deleted = @@ROWCOUNT;
    END

    SET @deleted = 1;
    WHILE @deleted > 0
    BEGIN
        DELETE TOP (@BatchSize) FROM dbo.ADMS_UNPARSED WHERE ReceivedUtc < @cutoff;
        SET @deleted = @@ROWCOUNT;
    END

    /* Command history: keep only terminal rows past the cutoff, so a Pending command that has been
       waiting for a device on holiday is never silently dropped. */
    SET @deleted = 1;
    WHILE @deleted > 0
    BEGIN
        DELETE TOP (@BatchSize) FROM dbo.ADMS_COMMAND
         WHERE Status IN ('Done', 'Failed') AND CreatedUtc < @cutoff;
        SET @deleted = @@ROWCOUNT;
    END
END
GO

/* =============================================================================================
   Multi-device roster synchronisation (multi-device-employee-sync spec).

   Additive only: nothing above this line changes shape. ADMS_DEVICE gains two nullable/defaulted
   columns; two new owned tables and one new view are created. A device row that never sets
   SyncGroup is untouched by any of it -- see Requirement 25.1's own text: "no device is opted in
   by a schema upgrade alone."
   ============================================================================================= */

/* SyncGroup is the whole of the propagation boundary (Requirement 25): two devices exchange
   nothing through this feature unless both carry the same non-empty, case-sensitive value here.
   NULL on every existing row by construction (ADD ... NULL with no default), so upgrading the
   schema never opts anyone in. */
IF NOT EXISTS (
    SELECT 1 FROM sys.columns
     WHERE object_id = OBJECT_ID('dbo.ADMS_DEVICE') AND name = 'SyncGroup'
)
    ALTER TABLE dbo.ADMS_DEVICE ADD SyncGroup NVARCHAR(64) NULL;
GO

/* The device's own resumption cursor for Roster_Sync's Backfill mechanism -- the highest
   Roster_Version this device is known to have received. Requirement 27.5: advanced only after
   the corresponding commands are durably enqueued, never speculatively -- the same discipline
   AttLogStamp/OperLogStamp already follow for the ATTLOG/OPERLOG resumption cursors above. */
IF NOT EXISTS (
    SELECT 1 FROM sys.columns
     WHERE object_id = OBJECT_ID('dbo.ADMS_DEVICE') AND name = 'RosterSyncStamp'
)
    ALTER TABLE dbo.ADMS_DEVICE ADD RosterSyncStamp BIGINT NOT NULL
        CONSTRAINT DF_ADMS_DEVICE_RosterSyncStamp DEFAULT (0);
GO

/* ---------------------------------------------------------------------------------------------
   ADMS_DEVICE_ROSTER_SEQUENCE -- one row per SyncGroup, the single monotonically increasing
   counter every change in that group draws its Roster_Version from.

   WHY A SEPARATE SEQUENCE TABLE, RATHER THAN LETTING EACH PIN INCREMENT ITS OWN COUNTER
   -----------------------------------------------------------------------------------------
   The first version of this design let (Pin, SyncGroup) increment independently from its own
   starting point (0 -> 1 -> 2 ...). That breaks the cursor model: two DIFFERENT pins can land on
   the SAME version number (both go 0 -> 1 on their first change), so a device's single scalar
   Sync_Cursor cannot tell "I have seen everything up to version 1" apart from "I have seen PIN A's
   version-1 change but not PIN B's version-1 change" -- they are indistinguishable once both PINs
   report the same number. A Backfill that sends one of two version-1-tied PINs and advances the
   cursor to 1 would then report the other as no longer owed, even though it was never sent.

   The fix: every change in a group draws the NEXT value from one shared counter, so no two
   changes in the same group ever produce the same Roster_Version, regardless of which PIN they
   are about. RosterVersion in ADMS_DEVICE_ROSTER_VERSION (below) is a snapshot of "the sequence
   value this PIN was at as of its last change," not a per-PIN increment.
--------------------------------------------------------------------------------------------- */
IF OBJECT_ID('dbo.ADMS_DEVICE_ROSTER_SEQUENCE', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.ADMS_DEVICE_ROSTER_SEQUENCE
    (
        SyncGroup   NVARCHAR(64) NOT NULL,
        NextVersion BIGINT       NOT NULL CONSTRAINT DF_ADMS_ROSTER_SEQ_N DEFAULT (0),

        CONSTRAINT PK_ADMS_DEVICE_ROSTER_SEQUENCE PRIMARY KEY CLUSTERED (SyncGroup)
    );
END
GO

/* ---------------------------------------------------------------------------------------------
   ADMS_DEVICE_ROSTER_VERSION -- one row per (Pin, SyncGroup): the Roster_Version (a value drawn
   from ADMS_DEVICE_ROSTER_SEQUENCE above) this PIN was most recently changed at, which both
   Fan_Out and Backfill compare a device's Sync_Cursor against.

   Keyed on (Pin, SyncGroup) rather than Pin alone (Requirement 25's own design rationale,
   repeated here): NHANVIEN.MaChamCong is a single global PK, but two Sync_Groups never share
   anything (Requirement 25.2), so if the same PIN ever exists in two groups' worth of devices, its
   version must be tracked independently per group.
--------------------------------------------------------------------------------------------- */
IF OBJECT_ID('dbo.ADMS_DEVICE_ROSTER_VERSION', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.ADMS_DEVICE_ROSTER_VERSION
    (
        Pin           INT           NOT NULL,
        SyncGroup     NVARCHAR(64)  NOT NULL,
        RosterVersion BIGINT        NOT NULL CONSTRAINT DF_ADMS_ROSTER_VERSION_V DEFAULT (0),
        UpdatedUtc    DATETIME2(0)  NOT NULL CONSTRAINT DF_ADMS_ROSTER_VERSION_U DEFAULT (SYSUTCDATETIME()),

        CONSTRAINT PK_ADMS_DEVICE_ROSTER_VERSION PRIMARY KEY CLUSTERED (Pin, SyncGroup)
    );
END
GO

/* Covers "what is the current max version for this group", which both the Backfill due-check
   (compare against a device's RosterSyncStamp) and vw_ADMS_RosterSyncStatus run on every
   Enabled_Device contact when Roster_Sync is on. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ADMS_ROSTER_VERSION_Group' AND object_id = OBJECT_ID('dbo.ADMS_DEVICE_ROSTER_VERSION'))
    CREATE INDEX IX_ADMS_ROSTER_VERSION_Group ON dbo.ADMS_DEVICE_ROSTER_VERSION (SyncGroup, RosterVersion DESC);
GO

/* ---------------------------------------------------------------------------------------------
   ADMS_DEVICE_ROSTER -- diagnostic-only per-(device, PIN) audit trail of what Roster_Sync
   believes a given device currently holds, and at what version.

   NOT load-bearing. Backfill's correctness rests entirely on ADMS_DEVICE.RosterSyncStamp (one
   scalar) compared against ADMS_DEVICE_ROSTER_VERSION's group max (in the design's words:
   "deleting every row in it would degrade observability, never correctness"). It exists so
   vw_ADMS_RosterSyncStatus and an operator asking "why doesn't device X have person Y" have a
   per-PIN answer instead of only a per-device version gap.
--------------------------------------------------------------------------------------------- */
IF OBJECT_ID('dbo.ADMS_DEVICE_ROSTER', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.ADMS_DEVICE_ROSTER
    (
        SerialNumber   NVARCHAR(64) NOT NULL,
        Pin            INT          NOT NULL,
        RosterVersion  BIGINT       NOT NULL,
        LastPushedUtc  DATETIME2(0) NOT NULL CONSTRAINT DF_ADMS_DEVICE_ROSTER_L DEFAULT (SYSUTCDATETIME()),

        CONSTRAINT PK_ADMS_DEVICE_ROSTER PRIMARY KEY CLUSTERED (SerialNumber, Pin)
    );
END
GO

/* ---------------------------------------------------------------------------------------------
   vw_ADMS_RosterSyncStatus (Requirement 30.1) -- per Enabled_Device with a Sync_Group, its
   cursor, the group's current max version, and the gap between them.

   PinsOwed is a version-count gap, not a literal PIN count (a design clarification): it
   answers "is this device behind, and by how much version-history", not "which PINs exactly" --
   an operator wanting the literal list runs the two-line join this view does not need to pre-bake.
--------------------------------------------------------------------------------------------- */
CREATE OR ALTER VIEW dbo.vw_ADMS_RosterSyncStatus
AS
SELECT  d.SerialNumber,
        d.DeviceName,
        d.SyncGroup,
        d.RosterSyncStamp,
        ISNULL(g.MaxVersion, 0)                     AS GroupMaxVersion,
        ISNULL(g.MaxVersion, 0) - d.RosterSyncStamp  AS PinsOwed
FROM    dbo.ADMS_DEVICE d
LEFT JOIN (
    SELECT  SyncGroup, MAX(RosterVersion) AS MaxVersion
    FROM    dbo.ADMS_DEVICE_ROSTER_VERSION
    GROUP BY SyncGroup
) g ON g.SyncGroup = d.SyncGroup
WHERE   d.Enabled = 1
  AND   d.SyncGroup IS NOT NULL
  AND   LTRIM(RTRIM(d.SyncGroup)) <> '';
GO

/* =============================================================================================
   Delete fan-out (multi-device-employee-sync, ISO 27001 traceability extension).

   Additive only, same discipline as the block above: one new nullable-then-defaulted column,
   no change to anything's shape. A PIN's ADMS_DEVICE_ROSTER_VERSION row that predates this column
   defaults to IsDeleted = 0 (i.e. "still a live snapshot"), which is the correct reading for
   every row that existed before this feature -- none of them were deletions.

   WHY THIS COLUMN, RATHER THAN INFERRING "DELETED" FROM RosterVersion ALONE
   -----------------------------------------------------------------------------------------
   By the time Backfill (or the reconciler) looks at an owed PIN, its NHANVIEN row may already be
   gone -- that IS the deletion. But Backfill still needs to know, for that owed version, WHICH
   Push_Command to send: DATA UPDATE USER (there is a row, deliver it) or DATA DELETE USERINFO
   (there is no row, remove it from the target too). "NHANVIEN row absent" only tells you the
   CURRENT state of a PIN that might have been re-created since; the flag on the version SNAPSHOT
   is what says "the change at this specific version number was a deletion", independent of
   whatever NHANVIEN holds for that PIN right now.
--------------------------------------------------------------------------------------------- */
IF NOT EXISTS (
    SELECT 1 FROM sys.columns
     WHERE object_id = OBJECT_ID('dbo.ADMS_DEVICE_ROSTER_VERSION') AND name = 'IsDeleted'
)
    ALTER TABLE dbo.ADMS_DEVICE_ROSTER_VERSION ADD IsDeleted BIT NOT NULL
        CONSTRAINT DF_ADMS_ROSTER_VERSION_Deleted DEFAULT (0);
GO

/* Covers the reconciler's "which PINs has this group ever pushed, that are not yet flagged
   deleted" scan -- see SqlServerRosterSync._reconcile_deletions. Filtered to IsDeleted = 0 so the
   index stays proportional to the LIVE roster, not to the group's entire deletion history. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ADMS_ROSTER_VERSION_Live' AND object_id = OBJECT_ID('dbo.ADMS_DEVICE_ROSTER_VERSION'))
    CREATE INDEX IX_ADMS_ROSTER_VERSION_Live ON dbo.ADMS_DEVICE_ROSTER_VERSION (SyncGroup, Pin) WHERE IsDeleted = 0;
GO
