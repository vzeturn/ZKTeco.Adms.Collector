<#
.SYNOPSIS
    Install the ADMS admin console as its own IIS site on this host.

.DESCRIPTION
    Idempotent. Creates the console's site folder, a Python virtual environment, an application pool
    and a site on port 8081, deploys web.config.admin, and opens the firewall. Touches nothing that
    belongs to the collector: a different site name, folder, app pool, port and firewall rule, so the
    two can be installed, recycled and removed independently.

    Does NOT store the database credential -- run deploy/set-db-connection.ps1 for that, so the
    credential is never an argument to this script and never lands in PowerShell history. The console
    resolves its connection from HKLM\SOFTWARE\AdmsConsole\AttendanceDb, falling back to the
    collector's sub-key when its own is not configured.

    Order matters and is enforced: the site is created last, so IIS never briefly serves a
    half-deployed folder.

.EXAMPLE
    # From an elevated PowerShell, in the project root:
    ./deploy/install-admin-site.ps1 -SitePath C:\inetpub\adms-console -Port 8081

    # Then, separately:
    ./deploy/set-db-connection.ps1 -SqlHost <rds-endpoint> -RegistrySubKey 'SOFTWARE\AdmsConsole\AttendanceDb'
    ./deploy/create-admin-user.ps1
#>
[CmdletBinding()]
param(
    [string] $SitePath = 'C:\inetpub\adms-console',
    [string] $SiteName = 'AdmsConsole',
    [int]    $Port = 8081,

    # Python to build the virtual environment from. Must be 64-bit 3.12 or newer.
    [string] $PythonExe = 'python',

    # Application pool identity. ApplicationPoolIdentity is the default and least-privilege choice: a
    # virtual account with no network identity and no interactive logon.
    [string] $AppPoolIdentity = 'ApplicationPoolIdentity',

    [switch] $SkipFirewall,

    # Sentry DSN for error reporting (ADMS_SENTRY_DSN in web.config). Optional: when omitted, a DSN
    # already in the site's web.config is kept, so re-running the installer never switches it off.
    # A DSN only lets this host submit events, so it is not a credential worth DPAPI.
    [string] $SentryDsn = '',

    # Stage everything except the working site when AspNetCoreModuleV2 is not installed yet. Files,
    # virtual environment, app pool, ACLs and web.config are put in place; the site returns 500.19
    # until the module is present. Deliberately NOT the default.
    [switch] $SkipHandlerCheck
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot

function Step { param([string] $Text) Write-Host "==> $Text" -ForegroundColor Cyan }
function Info { param([string] $Text) Write-Host "    $Text" -ForegroundColor DarkGray }

# ---- Preflight ---------------------------------------------------------------------------------

Step 'Preflight'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell: it creates an IIS site and writes under C:\inetpub.'
}

# Ensure the whole host environment is present: the IIS Web-Server role, a 64-bit Python 3.12+, the
# ODBC driver and AspNetCoreModuleV2 (ANCM). install-prerequisites.ps1 installs whatever is missing and
# is a no-op when everything is already there, unless -SkipHandlerCheck was given (staging-only mode),
# in which case we merely detect ANCM and warn. ANCM fronts the Python child out-of-process; it does
# not ship with a bare IIS install but with the .NET Hosting Bundle, which the prerequisites script
# installs. The authoritative signal is the registered IIS global module, not a file under
# System32\inetsrv: modern bundles install to %ProgramFiles%\IIS\Asp.Net Core Module\V2\ and register
# by absolute path. Check the global module first, then fall back to a file search across both roots.
function Find-Ancm {
    try {
        Import-Module WebAdministration -ErrorAction Stop
        $gm = Get-WebGlobalModule -ErrorAction Stop |
            Where-Object { $_.Name -in @('AspNetCoreModuleV2', 'AspNetCoreModule') } |
            Select-Object -First 1
        if ($gm) {
            return @([pscustomobject]@{ FullName = [Environment]::ExpandEnvironmentVariables($gm.Image) })
        }
    } catch { }
    foreach ($root in @(
            (Join-Path $env:SystemRoot 'System32\inetsrv'),
            (Join-Path ${env:ProgramFiles} 'IIS\Asp.Net Core Module'))) {
        $hit = Get-ChildItem -Path $root -Filter 'aspnetcorev2.dll' -Recurse -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($hit) { return @($hit) }
    }
    @()
}

$prereqs = Join-Path $PSScriptRoot 'install-prerequisites.ps1'
if ($SkipHandlerCheck) {
    if (-not (Find-Ancm)) {
        Write-Warning 'AspNetCoreModuleV2 is absent and -SkipHandlerCheck was given: staging only.'
        Write-Warning 'The site will return 500.19 until you run deploy/install-prerequisites.ps1.'
    }
    Import-Module WebAdministration -ErrorAction Stop
} else {
    Info 'Ensuring host prerequisites (IIS, Python, ODBC, ANCM) via install-prerequisites.ps1'
    $resolved = & $prereqs -PythonExe $PythonExe
    # install-prerequisites.ps1 prints RESOLVED_PYTHON=<path> as its last line when it installed or
    # relocated Python; adopt that path so the rest of this script uses the interpreter it just set up.
    $line = $resolved | Where-Object { $_ -match '^RESOLVED_PYTHON=' } | Select-Object -Last 1
    if ($line) { $PythonExe = ($line -split '=', 2)[1].Trim() }
    Import-Module WebAdministration -ErrorAction Stop
    $ancm = Find-Ancm
    if (-not $ancm) { throw 'AspNetCoreModuleV2 still absent after install-prerequisites.ps1.' }
    Info "AspNetCoreModuleV2 present ($($ancm[0].FullName))"
}
Info 'WebAdministration module loaded'

# Confirm the interpreter that will build the venv is 64-bit and new enough. install-prerequisites.ps1
# guarantees this when it ran; re-check because -SkipHandlerCheck skips it and -PythonExe may be custom.
# Outer double quotes with inner SINGLE quotes only: PowerShell rewrites embedded double quotes when
# building a native command line, so a snippet containing them reaches python.exe malformed.
$probe = "import sys;print(str(sys.version_info[0])+'.'+str(sys.version_info[1])+' '+('64' if sys.maxsize>2**32 else '32')+'-bit')"
$pythonVersion = (& $PythonExe -c $probe 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0) {
    throw "Could not run '$PythonExe' ($pythonVersion). Pass -PythonExe with a full path."
}
Info "Python: $pythonVersion ($PythonExe)"
if ($pythonVersion -notmatch '64-bit') {
    throw 'A 64-bit Python is required: the 64-bit ODBC driver cannot be loaded by a 32-bit process.'
}
$minor = [int]($pythonVersion -replace '^\d+\.(\d+).*$', '$1')
$major = [int]($pythonVersion -replace '^(\d+)\..*$', '$1')
if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 12)) {
    throw "Python 3.12 or newer is required; found $pythonVersion."
}

# ---- Files ------------------------------------------------------------------------------------

Step "Deploy application files to $SitePath"

foreach ($dir in @($SitePath, (Join-Path $SitePath 'logs'))) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

# Copy src/ wholesale; it is the only thing the runtime needs.
$srcTarget = Join-Path $SitePath 'src'
if (Test-Path $srcTarget) { Remove-Item $srcTarget -Recurse -Force }
Copy-Item (Join-Path $projectRoot 'src') $srcTarget -Recurse -Force
Info "copied src -> $srcTarget"

Copy-Item (Join-Path $projectRoot 'requirements.txt') $SitePath -Force

# The SQL scripts go along so a DBA on this host has them to hand.
$sqlTarget = Join-Path $SitePath 'sql'
if (-not (Test-Path $sqlTarget)) { New-Item -ItemType Directory -Path $sqlTarget -Force | Out-Null }
Copy-Item (Join-Path $projectRoot 'src\adms\db\sql\*.sql') $sqlTarget -Force
Info "copied sql -> $sqlTarget"

# ---- Virtual environment ----------------------------------------------------------------------

Step 'Create the virtual environment and install dependencies'

$venv = Join-Path $SitePath '.venv'
$venvPython = Join-Path $venv 'Scripts\python.exe'
if (-not (Test-Path $venvPython)) {
    & $PythonExe -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw 'venv creation failed.' }
}
& $venvPython -m pip install --upgrade pip --quiet
& $venvPython -m pip install -r (Join-Path $SitePath 'requirements.txt') --quiet
if ($LASTEXITCODE -ne 0) { throw 'pip install failed.' }
Info ((& $venvPython -m pip list --format=freeze 2>$null) -join '  ')

# A venv's python.exe is a thin shim: it re-launches the *base* interpreter named in pyvenv.cfg.
# When that base lives under a user profile (a per-user Python install, common on dev-built boxes),
# the app pool identity cannot read it or even traverse the profile to reach it, and ANCM reports a
# bare 502 with 'Access is denied' in the stdout log. Grant read+execute on the base Python folder and
# traverse (RX, this-folder-only) on each ancestor up to the drive root so the shim can start.
# Detect the base from pyvenv.cfg rather than assuming; a system-wide base under Program Files is
# already readable and the loop below is a no-op there.
$pyvenvCfg = Join-Path $venv 'pyvenv.cfg'
if (Test-Path $pyvenvCfg) {
    $baseHome = (Get-Content $pyvenvCfg | Where-Object { $_ -match '^\s*home\s*=' } |
        ForEach-Object { ($_ -split '=', 2)[1].Trim() } | Select-Object -First 1)
    if ($baseHome -and (Test-Path $baseHome)) {
        $basePoolSid = "IIS AppPool\$SiteName"
        # Read+execute on the whole base Python tree (recursive: it needs the DLLs and stdlib).
        & icacls $baseHome /grant "${basePoolSid}:(OI)(CI)(RX)" /T /C /Q | Out-Null
        # Traverse each ancestor so the pool can walk down to the base without listing siblings.
        $ancestor = Split-Path $baseHome -Parent
        while ($ancestor -and $ancestor -ne (Split-Path $ancestor -Parent)) {
            & icacls $ancestor /grant "${basePoolSid}:(RX)" /C /Q | Out-Null
            $ancestor = Split-Path $ancestor -Parent
        }
        Info "granted $basePoolSid read+execute on base Python at $baseHome (+ ancestor traverse)"
    }
}

# ---- web.config ------------------------------------------------------------------------------

Step 'Write web.config'

# The template carries C:\inetpub\adms-console paths; rewrite them if the site lives elsewhere.
$template = Get-Content (Join-Path $PSScriptRoot 'web.config.admin') -Raw
$template = $template.Replace('C:\inetpub\adms-console', $SitePath)
# UTF-8 with BOM, consistent with the .ps1 rule here.
# Keep the Sentry DSN a previous install (or an operator) put in web.config unless one is given.
$siteConfig = Join-Path $SitePath 'web.config'
$dsnValue = [System.Security.SecurityElement]::Escape($SentryDsn)
if (-not $dsnValue -and (Test-Path $siteConfig)) {
    $found = [regex]::Match((Get-Content $siteConfig -Raw), 'name="ADMS_SENTRY_DSN" value="([^"]*)"')
    if ($found.Success) { $dsnValue = $found.Groups[1].Value }
}
if ($dsnValue) {
    $template = $template.Replace('name="ADMS_SENTRY_DSN" value=""', "name=""ADMS_SENTRY_DSN"" value=""$dsnValue""")
    Info 'Sentry error reporting: DSN set'
}
[System.IO.File]::WriteAllText($siteConfig, $template,
    [System.Text.UTF8Encoding]::new($true))
Info "web.config written, paths pointed at $SitePath"

# ---- Application pool -------------------------------------------------------------------------

Step "Application pool '$SiteName'"

if (-not (Test-Path "IIS:\AppPools\$SiteName")) {
    New-WebAppPool -Name $SiteName | Out-Null
}
# No managed runtime: this pool never executes .NET, it only supervises a Python child process.
Set-ItemProperty "IIS:\AppPools\$SiteName" -Name managedRuntimeVersion -Value ''
Set-ItemProperty "IIS:\AppPools\$SiteName" -Name enable32BitAppOnWin64 -Value $false
Set-ItemProperty "IIS:\AppPools\$SiteName" -Name processModel.identityType -Value $AppPoolIdentity
# Operators sign in during the day and the console is idle overnight; unlike the collector it is fine
# to idle-stop it, but keep AlwaysRunning so the first morning sign-in is not a cold start.
Set-ItemProperty "IIS:\AppPools\$SiteName" -Name processModel.idleTimeout -Value ([TimeSpan]::Zero)
Set-ItemProperty "IIS:\AppPools\$SiteName" -Name recycling.periodicRestart.time -Value ([TimeSpan]::Zero)
Set-ItemProperty "IIS:\AppPools\$SiteName" -Name startMode -Value 'AlwaysRunning'
Info "identity=$AppPoolIdentity, idleTimeout=0, periodicRestart=0, startMode=AlwaysRunning"

# ---- Permissions ------------------------------------------------------------------------------

Step 'Grant the application pool identity access'

$poolSid = "IIS AppPool\$SiteName"

# Read+execute on the site folder, write only on logs. The app pool has no business modifying its own
# code, and denying that removes a whole class of post-exploitation step.
$acl = Get-Acl $SitePath
$acl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    $poolSid, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
Set-Acl $SitePath $acl

$logs = Join-Path $SitePath 'logs'
$logAcl = Get-Acl $logs
$logAcl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    $poolSid, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
Set-Acl $logs $logAcl
Info "read+execute on $SitePath, modify on $logs"

# ---- Site -------------------------------------------------------------------------------------

Step "Site '$SiteName' on port $Port"

if (Test-Path "IIS:\Sites\$SiteName") {
    Set-ItemProperty "IIS:\Sites\$SiteName" -Name physicalPath -Value $SitePath
    Set-ItemProperty "IIS:\Sites\$SiteName" -Name applicationPool -Value $SiteName
    # Reconcile the HTTP binding to the requested port. An idempotent re-run must be able to CHANGE the
    # port: a site left from an earlier install may still bind the old port, and only touching
    # physicalPath/applicationPool would silently ignore -Port and serve on the wrong port.
    $want = "*:${Port}:"
    $current = @(Get-WebBinding -Name $SiteName -Protocol http -ErrorAction SilentlyContinue)
    if ($current.bindingInformation -notcontains $want) {
        foreach ($b in $current) {
            Remove-WebBinding -Name $SiteName -Protocol http `
                -BindingInformation $b.bindingInformation -ErrorAction SilentlyContinue
        }
        New-WebBinding -Name $SiteName -Protocol http -Port $Port -IPAddress '*' | Out-Null
        Info "http binding reconciled to port $Port"
    }
} else {
    New-Website -Name $SiteName -PhysicalPath $SitePath -ApplicationPool $SiteName -Port $Port | Out-Null
}
Info "binding: http://*:$Port"

# Ensure the W3SVC (WWW Publishing) service is running and set to start automatically. After a fresh
# IIS-feature enable on a client OS it is often Stopped and set to Manual, which makes Start-Website
# fail with "RPC server is unavailable (0x800706BA)" -- the site is created but never comes up.
$w3svc = Get-Service W3SVC -ErrorAction SilentlyContinue
if ($w3svc) {
    if ($w3svc.StartType -ne 'Automatic') { Set-Service W3SVC -StartupType Automatic }
    if ($w3svc.Status -ne 'Running') { Start-Service W3SVC; Info 'started W3SVC (was stopped)' }
}

Start-WebAppPool -Name $SiteName -ErrorAction SilentlyContinue
Start-Website -Name $SiteName -ErrorAction Stop

# ---- Firewall ---------------------------------------------------------------------------------

if (-not $SkipFirewall) {
    Step "Firewall rule for TCP $Port"
    $ruleName = "$SiteName (TCP $Port)"
    if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP `
            -LocalPort $Port -Action Allow -Profile Domain, Private | Out-Null
        Info 'created for Domain and Private profiles only'
    } else {
        Info 'already present'
    }
    Write-Host '    NOTE: scope this rule to the operators subnet (-RemoteAddress) once you know it.' -ForegroundColor Yellow
}

# ---- Next steps -------------------------------------------------------------------------------

Write-Host ''
Write-Host 'Console site installed. Remaining steps, in order:' -ForegroundColor Green
Write-Host "  1. ./deploy/set-db-connection.ps1      store the DPAPI connection string (console sub-key)"
Write-Host '  2. Run sql\admin-schema.sql against ATTENDANCEDB, then sql\grant-console-privilege.sql'
Write-Host '  3. ./deploy/create-admin-user.ps1      bootstrap the first admin login'
Write-Host "  4. Browse to http://$($env:COMPUTERNAME):$Port and sign in"
