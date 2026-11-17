# ADMS attendance collector

Receives ZKTeco **ADMS/PUSH** uploads from time-attendance devices over plain HTTP and writes them
into the **ATTENDANCEDB** attendance database. Python 3.12 on **IIS**, on-premises.

> **Note on the schema.** The database schema (tables `NHANVIEN`, `MAYCHAMCONG`, `CheckInOut`,
> columns such as `MaChamCong`, `GioCham`, `KieuCham`, `NguonCham`) is an inherited,
> Vietnamese-named attendance schema. The names are kept as they are so this service can share a
> database with existing tools.

## What problem this solves

A desktop pull tool (a WPF app using the 32-bit `zkemkeeper` COM SDK) *pulls* from devices: a
Windows machine opens a TCP session to each device on port 4370 and drags the log buffer across. That
needs a Windows box with a route to every device, and a device only reaches the database when someone
— or a scheduled sweep — asks it to.

This service inverts the direction. In ADMS mode the **device is the client**: it dials out to a
configured server address, uploads punches and user changes as they happen, and polls for commands.
Nothing has to be reachable *at* the device, so devices behind NAT at remote sites work, and punches
land in the database seconds after they occur.

Both can run against the same database. Rows written here go through the same stored procedure with
the same `KieuCham`/`NguonCham` values, and both deduplicate on `(MaChamCong, GioCham)`, so a
migration needs no cutover.

## Why IIS on-premises and not AWS

The project started as a serverless (function-as-a-service) design. It moved, for this reason:

**ZKTeco PUSH firmware speaks plain HTTP.** Most managed cloud front doors (API gateways, CDNs,
function URLs) terminate TLS only and offer no port-80 option. A cloud deployment would therefore
need a load balancer exposing a plaintext endpoint, or firmware that supports HTTPS, which the
vendor documentation does not promise.

IIS resolves that: it listens on port 80 natively, costs nothing on hardware that already exists, and
the devices and the server sit on the same network, so there is no VPN or transit dependency in
the data path.

The protocol parsers, the domain models, the ports, the service orchestration and every SQL adapter
are hosting-independent. Only the thin hosting adapter (`wsgi.py`) and the configuration source
(`config.py`) know about the host. That is what the ports-and-adapters layout is for.

The Dockerfiles in the repository root are a generic container option (see below). The supported and
documented hosting is IIS on-premises.

## Layout

```
src/adms/
  protocol/       pure parsing and formatting; no DB, no network, no clock
                  attlog, operlog (USER/FP/FACE/BIODATA/USERPIC/OPLOG), options,
                  handshake, commands, routes, text
  db/             pyodbc adapters (incl. roster_sync.py) + sql/adms-schema.sql +
                  sql/grant-least-privilege.sql
  ports.py        the boundaries the service depends on (typing.Protocol)
  service.py      orchestration: authorise -> parse -> persist -> acknowledge
  wsgi.py         WSGI adapter; the only hosting-aware module
  hosting/serve.py  the process IIS starts, running waitress
  dbconfig.py     DPAPI-encrypted connection string in the registry
  memory.py       in-memory adapters, for running with no database
  admin/          the admin console: a SECOND WSGI app on its own port (see below)
                  ui.py (HTML only), app.py (the only HTTP-aware module), auth.py
                  (the security arithmetic), store.py (the only DB access), serve.py
  pull/           the pull agent: a run-by-hand CLI, not a hosted app (see below)
                  agent.py (orchestration), zkclient.py (the only module that dials
                  out to a device), registry.py, runlog.py, cli.py
deploy/           collector: install-iis.ps1, web.config; console: install-admin-site.ps1,
                  web.config.admin, create-admin-user.ps1; shared: set-db-connection.ps1,
                  import-rds-ca.ps1, verify.ps1
tools/            local_server.py (real HTTP, no DB needed), smoke_test.py
build.ps1         checks and the local dev server
```

## Install

Run from an elevated PowerShell on the target Windows host, in this order.

```powershell
# 0. Check the code first. Needs nothing but Python: no IIS, no database, no network.
./build.ps1

# 1. IIS site, app pool, virtual environment, firewall rule.
./deploy/install-iis.ps1 -SitePath C:\inetpub\adms-collector -Port 80

# 2. Store the database credential, DPAPI-encrypted in the registry. Prompts for the password.
./deploy/set-db-connection.ps1 `
    -SqlHost sql.example.com `
    -Database ATTENDANCEDB -Username adms_collector

# 3. Optional: if the database server's certificate is signed by an Amazon RDS CA, trust that CA so
#    TLS to the database is validated rather than blindly accepted. Skip for other servers.
./deploy/import-rds-ca.ps1

# 4. Database objects. Run against ATTENDANCEDB as a DBA.
#      src/adms/db/sql/adms-schema.sql            the ADMS_* tables, views and helpers
#      src/adms/db/sql/grant-least-privilege.sql  edit @Principal first

# 5. Register the devices (see below).

# 6. End-to-end check.
./deploy/verify.ps1 -Serial <a registered device serial>
```

### Prerequisites the scripts check for you

| Requirement | Note |
|---|---|
| IIS with **AspNetCoreModuleV2** | Ships with the ASP.NET Core / .NET Hosting Bundle, not with a bare IIS. `install-iis.ps1` fails early with the download link. |
| **ODBC Driver 18 for SQL Server** | 64-bit. `install-iis.ps1` warns if absent. |
| **64-bit Python 3.12+** | A 32-bit Python cannot load the 64-bit ODBC driver. |
| Network path device -> this host, TCP 80 | Same network segment is the intended shape. |
| Network path this host -> SQL Server, TCP 1433 | |

## Registering devices

**A serial that is not registered and enabled is refused with 401**, and the device keeps its punches
and retries. So getting this wrong loses nothing, but nothing is collected until it is right.

The inherited schema may already record each device's serial in `MAYCHAMCONG.Serial`, populated
for most devices. Seed from it rather than typing them in:

```sql
EXEC dbo.ADMS_SeedDevicesFromMayChamCong;   -- creates rows with Enabled = 0
SELECT * FROM dbo.vw_ADMS_DeviceStatus;     -- review
UPDATE dbo.ADMS_DEVICE SET Enabled = 1 WHERE SerialNumber = N'0000000000001';
```

Enabling stays manual on purpose: the serial number is the entire credential the ADMS protocol
offers, and it is printed on a label on the outside of the unit.

If you do not know a device's serial, set `ADMS_AUTO_REGISTER_DEVICES=true` in `web.config`
temporarily. Unknown serials then appear as **disabled** rows you can review and link, which grants
nothing on its own.

## Device configuration

On the device: **Comm → Ethernet / ADMS → Server Address** = this host, **Port** = 80, path
`/iclock` (the default). If `ADMS_PATH_SECRET` is set, use `/<secret>/iclock`.

### Finding out what your firmware actually sends

The protocol is not published in a form anyone can rely on, and builds differ. Point a device at a
laptop and watch every byte:

```powershell
./build.ps1 -Serve      # no database, no ODBC driver; prints every request body
```

A caveat learned the hard way: **do not verify with `Invoke-WebRequest -Body`.** It mangles a
tab-separated body, which looks exactly like a parser bug. Use `curl.exe --data-binary` or Python.

## Auto-enrolment: the roster fills itself

When a punch arrives from a PIN with no `NHANVIEN` row, the service queues a request to that device for
the person's record and fingerprint templates. The device answers on its next poll by POSTing to
`/iclock/querydata`, and the reply lands in `NHANVIEN` and `dbo.TEMPLATE`.

Two things follow from this that are worth knowing:

* **An unknown PIN never blocks a punch.** The punch is stored regardless, as an orphan row, because
  discarding attendance over a lagging roster is the wrong trade. The request simply fixes the roster so
  the next report can attribute it, and `vw_ADMS_UnprojectedPunches` shows anything still outstanding.
* **`dbo.TEMPLATE` is self-healing.** Enrolment data lives on the hardware, so a lost or wiped template
  table refills as people use the readers. Nobody re-enrols a finger.

A cooldown is what keeps this from running away. ADMS has no synchronous request, so asking means
queueing a command and waiting up to `ADMS_POLL_DELAY` seconds — during which the same unknown person
will punch again. A PIN already asked about within `ADMS_ENROLL_QUERY_COOLDOWN_HOURS` (default 6) is
skipped, counting commands in **any** status, so a device that genuinely cannot answer is not asked
forever. Batches are capped at `ADMS_ENROLL_QUERY_MAX_PER_BATCH` (default 25) so a device returning from
a long outage cannot swamp its own command channel.

| Setting | Default | |
|---|---|---|
| `ADMS_ENROLL_QUERY_ENABLED` | `true` | Turn the whole loop off |
| `ADMS_ENROLL_QUERY_FINGERPRINTS` | `true` | Also pull templates, not just the user record |
| `ADMS_ENROLL_QUERY_COOLDOWN_HOURS` | `6` | Before re-asking about the same PIN |
| `ADMS_ENROLL_QUERY_MAX_PER_BATCH` | `25` | Cap per ATTLOG upload |
| `ADMS_QUERY_USERINFO_COMMAND` | empty | Override the user-record wording; empty means `DATA QUERY USERINFO PIN={pin}` |
| `ADMS_QUERY_FINGERTMP_COMMAND` | empty | Override the fingerprint wording; empty means `DATA QUERY FINGERTMP PIN={pin}` |

**Not yet verified against firmware.** The queries are `DATA QUERY USERINFO PIN=<pin>` and
`DATA QUERY FINGERTMP PIN=<pin>`. The vendor guide documents `DATA QUERY` with a table name and filter,
and this is the spelling the reference ADMS server uses, but the accepted table token differs across
builds. After the first real device connects, check `ADMS_COMMAND.ReturnCode`: a negative value means
the firmware rejected the wording, not that the user is absent.

That column is the feedback loop, and the two override settings above are the fix. Correct the wording
by configuration rather than by editing `commands.py`, because we do not know what a given build
accepts — which is also why the setting is free text and not validated against a list of known tokens.
A `{pin}` placeholder is substituted anywhere in the value; a value with no placeholder gets
` PIN=<pin>` appended, so `DATA QUERY USER PIN={pin}` and `DATA QUERY USER` both work. Rendering never
raises, so a stray brace in a pasted value cannot cost an upload.

## Multi-device roster sync: one enrolment, every reader

Off by default in `Settings` (`ADMS_ROSTER_SYNC_ENABLED=false`). When on, a person created, changed or deleted at one device — and their
fingerprint templates — is propagated to every other device in the same **Sync_Group**, so
enrolling someone once at any reader makes them punchable at all of them. A new device, or one
back online after a long outage, is caught up automatically (**Backfill**) instead of needing
every employee re-enrolled by hand.

**Example `SyncGroup` layout** (one group per site): `SITE_A` (the readers at one site), `SITE_B`
(the readers at another site). A device that is not a real endpoint, for example a duplicate row
with a superseded serial, should be left ungrouped.

**Tested against real hardware (firmware `Ver 6.60`).** Pushing a fingerprint template down with
`DATA UPDATE FINGERTMP` was accepted (`ReturnCode=0`); querying the same PIN back immediately
afterwards echoed the identical base64 payload, and it landed in `dbo.TEMPLATE` byte-for-byte
through the existing `OPERLOG`/`querydata` pipeline. `DATA DELETE USER` was rejected
(`ReturnCode=-1004`) by that firmware; `DATA DELETE USERINFO` was accepted and removed the user. If your firmware differs, watch `ADMS_COMMAND.ReturnCode` the same way
the enrolment loop above already tells you to.

### Opting devices in: `SyncGroup`

Two devices exchange nothing through this feature unless both carry the same non-empty,
case-sensitive `ADMS_DEVICE.SyncGroup` value. No device is opted in by turning the feature on or
by the schema upgrade that adds the column — every existing row starts at `NULL`.

```sql
UPDATE dbo.ADMS_DEVICE SET SyncGroup = N'SITE_A' WHERE SerialNumber IN (N'0000000000001', N'0000000000002');
SELECT * FROM dbo.vw_ADMS_RosterSyncStatus;   -- per-device cursor vs. the group's current version
```

A device with no `SyncGroup`, a disabled device, or a device not yet linked to a `MAYCHAMCONG`
row is never a source or a target, regardless of the feature flag — grouping is a second,
independent gate on top of `ADMS_ROSTER_SYNC_ENABLED`, not a substitute for it.

### How a change actually gets from device A to device B

There is no channel for the server to reach out to a device — ADMS is pull-only, exactly like the
command downlink the enrolment loop already uses (see `## Auto-enrolment` above). A change queues
a `DATA UPDATE USER` / `DATA UPDATE FINGERTMP` command in `ADMS_COMMAND` against every eligible
device in the group, and each one picks it up on its next `getrequest` poll — at most `ADMS_POLL_DELAY`
seconds later, which is already short now that this is self-hosted.

**Fan_Out** (real-time, on every `USER`/`FP`/`FACE` upload): propagates that one PIN's change to
every other enabled, linked device sharing the origin's group — never back to the device that sent
the change. Capped at `ADMS_ROSTER_SYNC_MAX_COMMANDS_PER_CYCLE` per target per upload.

**Backfill** (catch-up, checked on every request from a linked device with a group): runs when a
device is owed at least one change *and* either it has never been backfilled before or it has been
silent past `ADMS_ROSTER_SYNC_BACKFILL_SILENCE_HOURS`. An always-online device that Fan_Out already
kept current triggers no Backfill at all — checking costs exactly one query when nothing is owed.

**Trade-off worth knowing:** Fan_Out never advances a device's own Backfill cursor
(`ADMS_DEVICE.RosterSyncStamp`) — only Backfill does. So `vw_ADMS_RosterSyncStatus.PinsOwed` can
read as "behind" for a device that is actually fully current via Fan_Out alone; that number clears
on the device's next Backfill check, not immediately. It is a diagnostic approximation, not a
correctness gap — the device already has the data either way.

| Setting | Default | |
|---|---|---|
| `ADMS_ROSTER_SYNC_ENABLED` | `false` | Turn the whole feature off — no request path calls it at all |
| `ADMS_ROSTER_SYNC_MAX_COMMANDS_PER_CYCLE` | `25` | Cap per target device per Fan_Out upload or Backfill contact |
| `ADMS_ROSTER_SYNC_BACKFILL_SILENCE_HOURS` | `24` | How long a device may go quiet before its next contact triggers a Backfill |
| `ADMS_ROSTER_SYNC_PUSH_FACES` | `false` | Also propagate face templates (`DATA UPDATE BIODATA`) — **not verified against firmware**. Fingerprint-only estates (faces genuinely out of scope) should leave this off, not merely unverified. |
| `ADMS_ROSTER_SYNC_FANOUT_DELETES` | `false` | Master switch for delete fan-out — see below |
| `ADMS_ROSTER_SYNC_RECONCILE_DELETES` | `true` | DB-side delete detection specifically (see below) — separate from the master switch so it can be disabled on its own while diagnosing an unexpected deletion |
| `ADMS_ROSTER_SYNC_DELETE_OPCODES` | *(empty)* | Device-side delete detection specifically — comma-separated `OPLOG` OpCode values. Empty means fully disabled regardless of the master switch. Leave it empty unless you have verified the OpCode — see below. |

### Delete fan-out: removing a person everywhere, not just where they were removed

Added for traceability: a deletion must not be partial across an estate. Two
independent triggers, gated separately because their confidence levels differ:

**DB-side (enabled by `ADMS_ROSTER_SYNC_RECONCILE_DELETES`, default `true`).** On every Backfill-eligible contact, the collector checks
whether any PIN a Sync_Group has ever propagated has since lost its `NHANVIEN` row (the desktop
app, or an operator, deleted it directly) and fans out `DATA DELETE USERINFO` for it — by
polling, never by a trigger on the locked `NHANVIEN` table. This requires no guessing: it only
acts once `NHANVIEN` itself no longer has the row, which is ground truth.

**Device-side (disabled by default — `ADMS_ROSTER_SYNC_DELETE_OPCODES` is empty).** A device's own
`OPLOG` records every administrative action, including a delete performed on its admin menu — in
principle that could be detected and fanned out the same way. In practice, the `OPLOG` `OpCode`
that means "user deleted" is a vendor-internal value with no public documentation. Analysing
logged `ADMS_OPERLOG` rows found no `OpCode` with a pattern conclusively matching a delete event.
Guessing wrong here is not a soft failure: an
incorrect OpCode fans out a real deletion to every device in a group for no real reason, wiping
biometrics that were never meant to be removed, and that is not reversible. Enable this only
after triggering a real deletion on one device, noting the exact timestamp, and reading the
resulting `OpCode` back from `ADMS_OPERLOG` filtered to that serial/PIN/timestamp.

### What is deliberately out of scope

Cross-group propagation (a person moving between groups is a manual, deliberate act — nothing
here infers it), conflict resolution when two devices change the same PIN before either upload
reaches the collector (same "last write to the database wins" behaviour the collector already
has), and a console UI for setting `SyncGroup` (direct SQL for now).

## The pull agent: fetching from a device on demand

Everything above is push-only, deliberately (see "What problem this solves"). `adms.pull` is a
second, separate tool that does the opposite on purpose: run by hand, whenever an operator wants,
it dials out over the vendor TCP protocol (port 4370, via the third-party
`pyzk` library) to a configured list of devices and:

* pulls each device's employee roster into `NHANVIEN`,
* pulls each device's attendance buffer into `CheckInOut` / `ADMS_ATTLOG_RAW` -- through the exact
  same adapters and the same `(MaChamCong, GioCham)` dedup key the push collector uses, so a punch
  pulled here is indistinguishable from one pushed there or entered by the desktop app, and
* synchronises employees between devices that share a `PullGroup` (the same
  area): a person enrolled at one reader in an office is pushed, along with their fingerprint
  templates, to every other device in that office missing them.

It is not a background service. There is no scheduler, no daemon loop, no polling interval to
tune -- an operator runs it, or a Windows Task Scheduler entry runs the exact same command on a
timer, and either way it is one process that starts, does the work, and exits.

```powershell
# 1. Its own dependency, kept out of the collector's own requirements.txt on purpose -- the
#    collector's process must never need pyzk installed.
pip install -r requirements-pull.txt

# 2. Database objects: PullEnabled/PullIp/PullPort/PullGroup on ADMS_DEVICE, plus ADMS_PULL_RUN
#    and ADMS_PULL_LOG for the run history.
#      src/adms/db/sql/pull-schema.sql

# 3. Register which devices to pull, and their pull group if any.
UPDATE dbo.ADMS_DEVICE SET PullEnabled = 1, PullIp = N'10.0.1.20', PullGroup = N'SITE_A'
 WHERE SerialNumber = N'...';

# 4. Verify configuration and connectivity without touching any device.
python -m adms.pull.cli --check

# 5. Run it.
python -m adms.pull.cli                  # every pull-enabled device: employees, attendance, sync
python -m adms.pull.cli --group SITE_A   # just one area
python -m adms.pull.cli --attendance-only
```

### Full logging: every device, every stage, every run

The point of this feature, not an afterthought: every stage of every device in every run --
Connect, PullEmployees, PullAttendance, SyncEmployees -- is logged twice.

* **In real time**, through the same structured JSON logger the collector uses
  (`adms.logging_setup`), so an operator watching the console sees exactly what is happening as it
  happens.
* **Durably**, in `ADMS_PULL_RUN` (one row per invocation) and `ADMS_PULL_LOG` (one row per device
  per stage, with status, record count, timing and the exact error text), so the history survives
  after the console is closed.

```sql
SELECT * FROM dbo.vw_ADMS_PullStatus;      -- every pull-enabled device and its last outcome
SELECT * FROM dbo.vw_ADMS_PullLogRecent;   -- full per-stage detail, across every run
SELECT * FROM dbo.vw_ADMS_PullStuckRuns;   -- a run left 'Running' for hours: the process died
```

One device failing to connect (offline, wrong IP, wrong Comm password) never stops the rest of the
run -- it is recorded as a `Failed` `Connect` stage for that device only, and every other device
still gets pulled. The CLI's exit code is `0` only when every requested device pulled cleanly, so
a wrapping script can tell without parsing the log.

## Security

**The endpoint cannot be authenticated at the transport level, and that is a property of the
protocol, not an omission here.** A device announces a serial number in a query string and cannot
send a header, a bearer token or a client certificate. Adding IIS authentication would break every
device.

What actually protects it, strongest first:

1. **Network placement.** Keep the site's port 80 binding on a segment only the devices reach, and
   scope the firewall rule with `-RemoteAddress`. `install-iis.ps1` creates the rule for the Domain
   and Private profiles only and reminds you to narrow it.
2. **The serial allow-list** in `ADMS_DEVICE`, enforced on every request. The only control that
   survives a network misconfiguration.
3. **Least-privilege SQL grants.** No `DELETE`/`UPDATE` on `CheckInOut`, no `DELETE` on `NHANVIEN`, so
   a bug or a spoofed serial cannot destroy payroll history.
4. **`ADMS_PATH_SECRET`.** Weak by construction: it travels in plaintext and lands in the IIS access
   log. It stops undirected scanning, nothing more.

The connection string is DPAPI-encrypted in `HKLM\SOFTWARE\AdmsCollector\AttendanceDb`, never in
`web.config`, never in an environment variable, and never in a log line — `logging_setup.scrub`
redacts credential-bearing fragments as defence in depth. DPAPI machine scope means the ciphertext is
useless on another host; it also means any process on *this* host that can read the key can decrypt
it, which is why `set-db-connection.ps1` narrows the ACL to the app pool identity and Administrators.

**The pull agent inverts the exposure.** It is the one part of this codebase that opens an
outbound connection *to* a device rather than accepting one *from* it, so it needs network reach to
every device it is configured for — the opposite requirement from the collector, which wants to stay
on a device-only segment. `ADMS_DEVICE.PullPassword` (the vendor's numeric "communication password")
is stored in plain `INT`, not encrypted: it is the same weak, device-local secret the desktop app
already keeps per machine, and it authorises nothing beyond "may talk to this one device on the
local network" — the real control is who can reach that network and that host at all. Run the pull
agent from a host with a route to the devices, never from the same segment the collector's IIS site
listens on for exactly the reason above: one process wants isolation, the other wants reach.

## Operating it

```sql
SELECT * FROM dbo.vw_ADMS_DeviceStatus;         -- Online / Silent / Not linked / Disabled
SELECT * FROM dbo.vw_ADMS_UnprojectedPunches;   -- arrived but never reached CheckInOut; expect empty
SELECT * FROM dbo.vw_ADMS_NonNumericPins;       -- PINs CheckInOut can never hold
SELECT * FROM dbo.vw_ADMS_StuckCommands;        -- dispatched over an hour ago, never acknowledged
```

Logs: `C:\inetpub\adms-collector\logs\adms-yyyyMMdd.log`, one JSON object per line. Start-up failures
land in `stdout*.log` in the same folder (the AspNetCoreModuleV2 stdout capture) — that is the first
place to look for a 502.

Retention is a scheduled job, not automatic, because `ADMS_PUSH_LOG` and `ADMS_USERPIC` hold names and
biometric templates and how long to keep them is a policy decision:

```sql
EXEC dbo.ADMS_PurgeArchives @RetainDays = 90;
```

`ADMS_ATTLOG_RAW` is deliberately not purged by it — that is the lossless attendance record.

## Design notes

Three rules explain most of the code:

**Only return 2xx after a commit.** A 2xx tells the device it may erase those records from its buffer.
Database failures return 503, the device holds its punches and retries after `ErrorDelay`. Nothing
swallows a database error, and `web.config` sets `existingResponse="PassThrough"` so IIS cannot replace
a plain-text 503 with an HTML error page that some firmware reads as success.

**Acknowledge the count the device sent, not the count stored.** Duplicate suppression and skipped
non-numeric PINs make those differ routinely, and firmware reads a short count as partial rejection
and resends.

**Advance the resumption stamp last.** The stamp is what the device uses to decide it may discard
records, so it must never move ahead of durable storage.

## The admin console

The console is a **second, separate web application**. Operators use it to watch the collector, enable
and link devices, queue and cancel device commands, and manage their own logins. It runs as its own IIS
site in its own application pool, on **port 8081**, from `python -m adms.admin.serve`. The collector on
port 80 knows nothing about it.

Two sites rather than one, deliberately:

* **Different audiences on different networks.** The collector sits on a device-only segment and has no
  login — a ZKTeco device cannot send a header, a token or a client certificate, so what protects it is
  network placement and the serial allow-list. The console is the opposite: it sits behind a login and
  belongs on a segment operators reach, never the device network.
* **Different blast radius.** A fault or a compromise in one process cannot reach into the other. The
  console's body cap is 1 MiB against the collector's 32 MiB, because it only ever receives form posts,
  never a photo or template upload.
* **Different database logins.** The collector signs in as `adms_collector` and the console as
  `adms_console`, with disjoint grants: the console can `DELETE` a session or a pending command, which
  the collector never can; the collector can `EXECUTE dbo.CheckInOut_add`, which the console never can.
  The console is granted nothing on `CheckInOut`, so it cannot read or rewrite attendance history. On
  `NHANVIEN`, `TEMPLATE` and `Face` it can read and edit in place (device-admin rights and the device
  password) but never delete. See `src/adms/db/sql/grant-console-privilege.sql`.

### Install

```powershell
# 1. The console's own IIS site, app pool, virtual environment and firewall rule on 8081.
#    Touches nothing of the collector's.
./deploy/install-admin-site.ps1 -SitePath C:\inetpub\adms-console -Port 8081

# 2. Store the console's database credential (its own registry sub-key). Prompts for the password.
./deploy/set-db-connection.ps1 -SqlHost <sql-host> -RegistrySubKey 'SOFTWARE\AdmsConsole\AttendanceDb'

# 3. Database objects. Run against ATTENDANCEDB as a DBA.
#      src/adms/db/sql/admin-schema.sql             APP_ROLE/USER/SESSION/AUDIT, the purge proc, the overview view
#      src/adms/db/sql/grant-console-privilege.sql  the least-privilege grants for adms_console
#    The console's SQL login must be created first (needs a sysadmin-level or RDS master login):
#      CREATE LOGIN adms_console WITH PASSWORD = N'...';   then   CREATE USER adms_console FOR LOGIN adms_console;

# 4. The first administrator. Prompts for a password twice; never puts it on a command line.
#    Refuses a username that already exists. Every further user is created inside the console.
./deploy/create-admin-user.ps1

# 5. Browse to http://<host>:8081 and sign in.
```

The console resolves its connection string from `HKLM\SOFTWARE\AdmsConsole\AttendanceDb` first and the
collector's sub-key otherwise — never from its source folder and never from a page. Run
`python -m adms.admin.serve --check` to confirm configuration, connectivity and that the `APP_*` tables
exist before serving.

### Environment variables

Set in `deploy/web.config.admin`, mirroring the collector's `web.config` but with the console's values.
The connection string is **never** here — it is DPAPI-encrypted in the registry (see step 2).

| Variable | Meaning |
|----------|---------|
| `ADMS_ADMIN_THREADS` | Waitress worker threads (default 4). A handful of operators, so lower than the collector's. Also the cap on concurrent SQL connections. |
| `ADMS_LOG_DIR`, `ADMS_LOG_LEVEL` | Dated JSON log location and level, alongside the AspNetCoreModuleV2 stdout capture. |
| `ADMS_UTC_OFFSET_HOURS` | Site offset from UTC, used for audit timestamps. |
| `ADMS_SQL_TRUST_SERVER_CERT` | Default `false`, so the SQL server certificate is validated. Install the server's CA (for Amazon RDS, `import-rds-ca.ps1`) rather than setting this true. |

### Roles

Three roles, enforced server-side on every request; the UI only hides what a role cannot do, it never
relies on hiding for safety.

* **viewer** — read-only: the dashboard, devices, activity and audit pages.
* **operator** — viewer, plus enable/disable/link a device and queue or cancel a *safe* command. A
  destructive device command is refused with 403.
* **admin** — operator, plus user and session management. The **last enabled admin cannot be demoted,
  disabled or deleted**, so the console can never lock itself out.

### The IIS module, and the standalone fallback

Like the collector, the console is fronted by **AspNetCoreModuleV2** (out-of-process), which ships with
the ASP.NET Core / .NET Hosting Bundle rather than with a bare IIS. Where it is not installed,
`install-admin-site.ps1` stages everything and the site answers `500.19` until the module is present.
Until then — and for any host without IIS — the console runs standalone on the same port:

```powershell
python -m adms.admin.serve --host 0.0.0.0 --port 8081
```

This is the exact WSGI application IIS would serve, so a check over the fallback verifies the real thing.

## Notes on the inherited schema

Three findings about the inherited schema contradicted assumptions made from the desktop tool's
code, and the code and comments were corrected:

* **`dbo.CheckInOut_add` does deduplicate.** The desktop tool's comments say it is a bare INSERT and
  that the caller is the only guard. The deployed body has `IF NOT EXISTS (... MaChamCong AND
  GioCham)`. The application still checks, so the reported insert count stays truthful and so the
  service does not depend on a procedure body for a promise it makes.
* **`IDMCC` is not a unique machine identity.** Most machines can have `IDMCC = 1`, and
  `CheckInOut.MaSoMay` can be 1 on virtually every row, with `TenMay` carrying the real identity.
  Anything joining `MaSoMay` to `IDMCC` is wrong; `vw_ADMS_UnprojectedPunches` was written accordingly.
* **`NHANVIEN.MaThe` is `nvarchar(20)`**, not 50. A longer value would raise a truncation error and
  fail a whole OPERLOG batch for a long card number.

One open decision is documented rather than guessed: `KieuCham` can take several values (for
example 0, 1, 255, 5) and `NguonCham` can carry site names. This service writes `'1'` and `''` to
match the desktop tool exactly, which means the device's in/out status does not reach `CheckInOut`.
Nothing is lost, because it is all in `ADMS_ATTLOG_RAW`, but projecting it differently is a
reporting decision for whoever owns attendance reports.