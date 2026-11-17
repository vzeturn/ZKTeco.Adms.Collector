<#
.SYNOPSIS
    One-shot automatic installer for the ADMS attendance system: collector + admin console.

.DESCRIPTION
    Runs the whole deployment end to end on a fresh Windows host:

      1. install-iis.ps1        collector site (auto-installs IIS, Python, ODBC, Hosting Bundle)
      2. install-admin-site.ps1 admin console site (same prerequisites, idempotent)
      3. set-db-connection.ps1  DPAPI-encrypted DB connection for the collector app pool
      4. set-db-connection.ps1  same, under the console sub-key / pool
      5. import-rds-ca.ps1      trust the Amazon RDS CA so TLS is validated, not just encrypted
      6. verify.ps1             read-only end-to-end check of the collector

    It does NOT run any SQL schema and does NOT create an admin user: the target database and its
    login are assumed already provisioned (schema, ADMS_* / APP_* tables and the admin account all
    exist). This keeps the install additive-only and leaves the live data untouched.

    The database password is never passed on a command line. It is placed into the ADMS_DB_PASSWORD
    environment variable only for the child scripts that need it and cleared immediately afterwards.

.PARAMETER SqlHost
    SQL Server host name / endpoint. Mandatory.

.PARAMETER Password
    SQL password as a SecureString. Prompted securely if omitted.

.EXAMPLE
    ./deploy/install-all.ps1 -SqlHost my-sql.example.com

.EXAMPLE
    # Unattended: supply the password up front.
    $p = Read-Host -AsSecureString 'db pw'
    ./deploy/install-all.ps1 -SqlHost my-sql.example.com -Password $p -TrustServerCertificate
#>
param(
    [Parameter(Mandatory = $true)]
    [string] $SqlHost,

    [string] $Database = 'ATTENDANCEDB',
    [string] $Username = 'adms_collector',

    # SQL password. Prompted securely when omitted so it never lands in history or a transcript.
    [System.Security.SecureString] $Password,

    [int] $CollectorPort = 8080,
    [int] $ConsolePort = 8081,

    # Amazon RDS validates fine after import-rds-ca.ps1, so this is only for a genuinely self-signed
    # server. It leaves the link encrypted but unauthenticated.
    [switch] $TrustServerCertificate,

    # Override the serial verify.ps1 exercises. Omit to auto-pick a registered serial from the DB.
    [string] $VerifySerial,

    [switch] $SkipVerify
)

$ErrorActionPreference = 'Stop'

function Step { param([string] $Text) Write-Host "==> $Text" -ForegroundColor Cyan }
function Info { param([string] $Text) Write-Host "    $Text" -ForegroundColor DarkGray }
function Ok   { param([string] $Text) Write-Host "    $Text" -ForegroundColor Green }
function Warn { param([string] $Text) Write-Warning $Text }

# ---- Preflight: elevation ----------------------------------------------------------------------

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell: it creates IIS sites and writes under C:\inetpub.'
}

$consoleSitePath   = 'C:\inetpub\adms-console'
$consoleSubKey     = 'SOFTWARE\AdmsConsole\AttendanceDb'
$consolePoolName   = 'AdmsConsole'

if (-not $Password) {
    $Password = Read-Host -AsSecureString "SQL password for '$Username'"
}
if ($Password.Length -eq 0) { throw 'A database password is required.' }

# Fail a step loudly. Sub-scripts use $ErrorActionPreference=Stop and throw on error, but native
# exit codes need an explicit check.
function Invoke-Step {
    param([string] $Name, [scriptblock] $Body)
    Step $Name
    $global:LASTEXITCODE = 0
    & $Body
    if ($LASTEXITCODE -ne 0) { throw "$Name failed (exit code $LASTEXITCODE)." }
}

# Pick one registered serial to exercise the handshake with. Prefers an enabled device (the historic
# happy path) but any registered serial works now that the enabled gate is gone. Returns $null and
# never throws when sqlcmd is missing or the query fails -- verification then degrades to health only,
# which must not block an otherwise-good install. The password comes from ADMS_DB_PASSWORD (already
# set by the caller), never from the command line.
function Get-VerifySerial {
    param([string] $SqlHost, [string] $Database, [string] $Username)
    if (-not (Get-Command sqlcmd -ErrorAction SilentlyContinue)) {
        Info 'sqlcmd not found; cannot auto-pick a verify serial.'
        return $null
    }
    $query = @'
SET NOCOUNT ON;
SELECT TOP 1 SerialNumber FROM dbo.ADMS_DEVICE
ORDER BY CASE WHEN Enabled = 1 THEN 0 ELSE 1 END, LastSeen DESC;
'@
    try {
        # -h -1 suppresses the header; -W trims trailing spaces; -b returns a non-zero exit on error.
        $out = & sqlcmd -S $SqlHost -d $Database -U $Username -P $env:ADMS_DB_PASSWORD `
            -C -l 10 -h -1 -W -b -Q $query 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        $serial = ($out | Where-Object { $_ -and $_.Trim() -ne '' } | Select-Object -First 1)
        if ($serial) { return $serial.Trim() }
    }
    catch { Info "verify-serial query failed: $($_.Exception.Message)" }
    return $null
}

$here = $PSScriptRoot

try {
    # The password is needed by set-db-connection (twice) and the verify-serial query. Expose it to
    # child processes only for the duration of this try block; the finally clears it.
    $env:ADMS_DB_PASSWORD = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))

    $trust = @{}
    if ($TrustServerCertificate) { $trust['TrustServerCertificate'] = $true }

    # 1 + 2: the two sites. Each self-installs host prerequisites and is idempotent.
    Invoke-Step 'Collector site (install-iis.ps1)' {
        & (Join-Path $here 'install-iis.ps1') -Port $CollectorPort
    }
    Invoke-Step 'Admin console site (install-admin-site.ps1)' {
        & (Join-Path $here 'install-admin-site.ps1') -Port $ConsolePort
    }

    # 3 + 4: DB connection for each app pool, into its own registry sub-key.
    Invoke-Step 'DB connection - collector' {
        & (Join-Path $here 'set-db-connection.ps1') `
            -SqlHost $SqlHost -Database $Database -Username $Username -UseEnvPassword @trust
    }
    Invoke-Step 'DB connection - console' {
        & (Join-Path $here 'set-db-connection.ps1') `
            -SqlHost $SqlHost -Database $Database -Username $Username -UseEnvPassword `
            -SitePath $consoleSitePath -AppPoolName $consolePoolName -RegistrySubKey $consoleSubKey `
            @trust
    }

    # 5: trust the RDS CA so the TLS handshake is authenticated.
    Invoke-Step 'Import RDS CA bundle (import-rds-ca.ps1)' {
        & (Join-Path $here 'import-rds-ca.ps1')
    }

    # 6: verify. Auto-pick a registered serial unless one was given or verification is skipped.
    if ($SkipVerify) {
        Info 'Verification skipped (-SkipVerify).'
    }
    else {
        $serial = $VerifySerial
        if (-not $serial) { $serial = Get-VerifySerial -SqlHost $SqlHost -Database $Database -Username $Username }
        Invoke-Step 'Verify collector (verify.ps1)' {
            if ($serial) {
                Info "using registered serial '$serial' from dbo.ADMS_DEVICE"
                & (Join-Path $here 'verify.ps1') -Port $CollectorPort -Serial $serial
            }
            else {
                Warn 'No registered device found (or sqlcmd unavailable): verifying health only.'
                & (Join-Path $here 'verify.ps1') -Port $CollectorPort
            }
        }
    }
}
finally {
    # Wipe the password from the environment no matter how we leave.
    Remove-Item Env:\ADMS_DB_PASSWORD -ErrorAction SilentlyContinue
}

# ---- Summary -----------------------------------------------------------------------------------

Write-Host ''
Step 'Done'
Ok  "Collector:  http://localhost:$CollectorPort/iclock/  (device push endpoint)"
Ok  "Console:    http://localhost:$ConsolePort/            (admin UI)"
Info 'Schema and the admin login were assumed already provisioned and were left untouched.'
