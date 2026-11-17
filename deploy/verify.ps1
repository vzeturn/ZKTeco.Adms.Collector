<#
.SYNOPSIS
    End-to-end check of an installed ADMS collector: configuration, database, schema, and the live site.

.DESCRIPTION
    Read-only. Run after install-iis.ps1, set-db-connection.ps1 and the SQL scripts. It answers, in
    order, the questions that actually determine whether a device will work:

      1. Is the site up and does IIS reach the Python process?
      2. Can the process decrypt the stored connection string and reach SQL Server?
      3. Do the ADMS_* tables exist?
      4. Are any devices registered and enabled? (none = every device gets 401)
      5. Does the handshake return the exact literal firmware string-matches?

    Deliberately does NOT push a fake punch. Writing test rows into a production CheckInOut is not
    something a verification script should do behind an operator's back; use tools/local_server.py
    --fake for that, or a real device.

.EXAMPLE
    ./deploy/verify.ps1
    ./deploy/verify.ps1 -Port 8080 -Serial CJXX204960333
#>
[CmdletBinding()]
param(
    [string] $SitePath = 'C:\inetpub\adms-collector',
    [string] $SiteName = 'AdmsCollector',
    [int]    $Port = 80,
    # A serial to exercise the handshake with. Must be registered and enabled, or step 5 reports 401 --
    # which is itself a correct result, just not a useful one.
    [string] $Serial = ''
)

$ErrorActionPreference = 'Continue'
$failures = 0
function Ok   { param([string] $T) Write-Host "  ok   $T" -ForegroundColor Green }
function Bad  { param([string] $T) Write-Host "  FAIL $T" -ForegroundColor Red; $script:failures++ }
function Note { param([string] $T) Write-Host "       $T" -ForegroundColor DarkGray }

Write-Host '1. IIS site and application pool' -ForegroundColor Cyan
Import-Module WebAdministration -ErrorAction SilentlyContinue
if (Test-Path "IIS:\Sites\$SiteName") {
    $state = (Get-Website -Name $SiteName).State
    if ($state -eq 'Started') { Ok "site '$SiteName' is Started" } else { Bad "site '$SiteName' is $state" }
    $poolState = (Get-WebAppPoolState -Name $SiteName -ErrorAction SilentlyContinue).Value
    if ($poolState -eq 'Started') { Ok "app pool '$SiteName' is Started" } else { Bad "app pool is $poolState" }
} else {
    Bad "site '$SiteName' does not exist - run deploy/install-iis.ps1"
}

# The registered IIS global module is the authoritative signal (the DLL lives under
# %ProgramFiles%\IIS\Asp.Net Core Module\V2\, not inetsrv, on modern Hosting Bundles).
$handler = Get-WebGlobalModule -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -in @('AspNetCoreModuleV2', 'AspNetCoreModule') } | Select-Object -First 1
if ($handler) { Ok 'AspNetCoreModuleV2 installed' } else { Bad 'AspNetCoreModuleV2 MISSING' }

Write-Host ''
Write-Host '2. Configuration and database, as the service sees them' -ForegroundColor Cyan
$venvPython = Join-Path $SitePath '.venv\Scripts\python.exe'
if (Test-Path $venvPython) {
    Ok 'virtual environment present'
    $env:PYTHONPATH = Join-Path $SitePath 'src'
    # --check resolves the registry value, lists ODBC drivers and runs SELECT 1. Running it through the
    # site's own venv and PYTHONPATH means this tests the real configuration, not the operator's shell.
    $out = & $venvPython -m adms.hosting.serve --check 2>&1 | Out-String
    $out.Trim() -split "`r?`n" | ForEach-Object { Note $_ }
    if ($LASTEXITCODE -eq 0) { Ok 'configuration + database reachable' } else { Bad 'self-check failed (see above)' }
    Remove-Item env:PYTHONPATH -ErrorAction SilentlyContinue
} else {
    Bad "no virtual environment at $venvPython"
}

Write-Host ''
Write-Host '3. Schema and device registrations' -ForegroundColor Cyan
Note 'Run against ATTENDANCEDB with your own DBA credentials:'
Note "  SELECT name FROM sys.objects WHERE name LIKE 'ADMS[_]%' ORDER BY name;"
Note '  SELECT * FROM dbo.vw_ADMS_DeviceStatus;'
Note 'Expect 7 ADMS_* tables plus 3 views, and at least one device row with Enabled=1 and a MaMCC.'
Note 'A serial with no row is refused with 401 and the device keeps its punches, so this is safe to'
Note 'get wrong at first - but nothing is collected until it is right.'

Write-Host ''
Write-Host '4. Live HTTP through IIS' -ForegroundColor Cyan
$baseUrl = "http://127.0.0.1:$Port"

# /iclock/ping with no SN must be refused with 400. This proves IIS reached the Python process and the
# application is routing, without needing a registered device.
try {
    $r = Invoke-WebRequest -Uri "$baseUrl/iclock/ping" -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
    Bad "GET /iclock/ping without SN returned $($r.StatusCode); expected 400"
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    if ($code -eq 400) {
        Ok 'GET /iclock/ping without SN -> 400 (IIS reached the app and it is routing)'
    } elseif ($code -eq 502 -or $code -eq 503) {
        Bad "got $code - the Python process is not starting. Read logs\stdout*.log"
    } else {
        Bad "unexpected status $code"
    }
}

if ($Serial) {
    Write-Host ''
    Write-Host "5. Handshake for serial '$Serial'" -ForegroundColor Cyan
    try {
        $r = Invoke-WebRequest -Uri "$baseUrl/iclock/cdata?SN=$Serial&options=all&pushver=2.4.1" `
            -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
        $body = $r.Content
        if ($body -match "^GET OPTION FROM: $([regex]::Escape($Serial))") {
            Ok 'first line is the exact literal firmware string-matches'
        } else {
            Bad "first line is wrong: $(($body -split "`r?`n")[0])"
        }
        foreach ($token in @('Realtime=1', 'TransFlag=', 'ATTLOGStamp=', 'Stamp=', 'ErrorDelay=')) {
            if ($body -match [regex]::Escape($token)) { Ok "contains $token" } else { Bad "missing $token" }
        }
        if ($r.Headers['Content-Type'] -eq 'text/plain') {
            Ok 'Content-Type is bare text/plain'
        } else {
            Bad "Content-Type is '$($r.Headers['Content-Type'])'; some firmware rejects a charset"
        }
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -eq 401) {
            Bad "401 - serial '$Serial' is not registered or not enabled in dbo.ADMS_DEVICE"
        } else {
            Bad "handshake failed with $code"
        }
    }
} else {
    Write-Host ''
    Write-Host '5. Handshake - skipped' -ForegroundColor DarkGray
    Note 'Pass -Serial <device serial> to exercise it.'
}

Write-Host ''
if ($failures -eq 0) {
    Write-Host 'All automated checks passed.' -ForegroundColor Green
    Write-Host 'Remaining manual step: point a real device at this host and watch logs\adms-*.log.' -ForegroundColor Yellow
    exit 0
}
Write-Host "$failures check(s) failed." -ForegroundColor Red
exit 1
