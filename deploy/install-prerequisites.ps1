<#
.SYNOPSIS
    Install every host prerequisite the ADMS IIS deployment needs, when missing.

.DESCRIPTION
    Idempotent. Each component is detect-then-skip: safe to run repeatedly, and safe to run before
    or after the site installers, which call this at the top of their preflight.

    Order matters and is enforced:
      1. IIS (Web-Server role)      -- must exist before the .NET Hosting Bundle, or ANCM will not
                                        register with it (the bundle's IIS integration step is skipped
                                        when IIS is not yet present).
      2. 64-bit Python >= 3.12      -- the runtime the site's virtual environment is built from.
      3. ODBC Driver 18 for SQL Server -- what the connection string names. Warns, does not throw,
                                        if it cannot be installed: the site can be installed before it.
      4. ANCM (AspNetCoreModuleV2)  -- delegated to install-hosting-bundle.ps1 in this folder, which
                                        already owns the download/install/IIS-restart logic.

.EXAMPLE
    # From an elevated PowerShell:
    ./deploy/install-prerequisites.ps1

.EXAMPLE
    # Skip components already handled elsewhere:
    ./deploy/install-prerequisites.ps1 -SkipOdbc -SkipPython
#>
[CmdletBinding()]
param(
    # Python to probe/build from. Must resolve to 64-bit 3.12 or newer once this script returns.
    [string] $PythonExe = 'python',

    # .NET channel whose Hosting Bundle to install if ANCM is missing. Passed through as -Channel.
    [string] $DotnetChannel = '8.0',

    [switch] $SkipPython,
    [switch] $SkipOdbc,
    [switch] $SkipHostingBundle,
    [switch] $SkipIis
)

$ErrorActionPreference = 'Stop'

function Step { param([string] $Text) Write-Host "==> $Text" -ForegroundColor Cyan }
function Info { param([string] $Text) Write-Host "    $Text" -ForegroundColor DarkGray }

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell: it installs system components.'
}

# Summary lines collected as we go and printed at the end.
$summary = New-Object System.Collections.Generic.List[string]
$resolvedPython = $null
$pythonWasInstalled = $false

# ================================================================================================
# 1. IIS (Web-Server role) + WebAdministration
# ================================================================================================

if ($SkipIis) {
    Info 'IIS: skipped (-SkipIis)'
    $summary.Add('IIS: skipped')
} else {
    Step 'IIS (Web-Server role)'

    $iisEnabled = $false

    # Branch on the ACTUAL OS product type, not on cmdlet availability. Both ServerManager
    # (Get-/Install-WindowsFeature) and DISM (Get-/Enable-WindowsOptionalFeature) cmdlets can be
    # PRESENT on a client SKU, but the ServerManager ones THROW at runtime there ("cannot be a
    # Windows client-based operating system"). Win32_OperatingSystem.ProductType: 1 = client
    # (Windows 10/11), 2 = domain controller, 3 = server. Only 1 must take the DISM path.
    $isClientOs = ((Get-CimInstance Win32_OperatingSystem).ProductType -eq 1)

    if ($isClientOs) {
        try {
            $feature = Get-WindowsOptionalFeature -Online -FeatureName IIS-WebServer -ErrorAction Stop
            $iisEnabled = [bool]($feature -and $feature.State -eq 'Enabled')
        } catch {
            Info "Get-WindowsOptionalFeature probe failed: $($_.Exception.Message)"
        }
    } else {
        try {
            $feature = Get-WindowsFeature -Name Web-Server -ErrorAction Stop
            $iisEnabled = [bool]($feature -and $feature.InstallState -eq 'Installed')
        } catch {
            Info "Get-WindowsFeature probe failed: $($_.Exception.Message)"
        }
    }

    # Fallback detection: if IIS is in fact installed, WebAdministration imports regardless of SKU.
    # This rescues a host where the feature probe errored but IIS is genuinely present.
    if (-not $iisEnabled) {
        try {
            Import-Module WebAdministration -ErrorAction Stop
            $iisEnabled = $true
            Info 'IIS detected via WebAdministration (feature probe was inconclusive)'
        } catch {
            # Genuinely absent; the install branch below handles it.
        }
    }

    if ($iisEnabled) {
        Info 'IIS Web-Server role already enabled'
        $summary.Add('IIS: already present')
    } else {
        Info 'IIS Web-Server role not enabled; installing'
        if ($isClientOs) {
            # DISM path for client OS. IIS-ManagementConsole pulls in the metabase/WMI compat
            # WebAdministration needs; -All enables required parent features.
            Enable-WindowsOptionalFeature -Online -All -NoRestart -FeatureName `
                IIS-WebServerRole, IIS-WebServer, IIS-ManagementConsole | Out-Null
        } else {
            Install-WindowsFeature -Name Web-Server -IncludeManagementTools | Out-Null
        }
        Info 'IIS Web-Server role installed'
        $summary.Add('IIS: installed')
    }

    Import-Module WebAdministration -ErrorAction Stop
    Info 'WebAdministration module imports OK'
}

# ================================================================================================
# 2. 64-bit Python >= 3.12
# ================================================================================================

if ($SkipPython) {
    Info 'Python: skipped (-SkipPython)'
    $summary.Add('Python: skipped')
} else {
    Step '64-bit Python >= 3.12'

    # Outer double quotes with inner SINGLE quotes only. PowerShell rewrites embedded double quotes
    # when building a native command line, so a snippet containing them reaches python.exe malformed.
    $probe = "import sys;print(str(sys.version_info[0])+'.'+str(sys.version_info[1])+' '+('64' if sys.maxsize>2**32 else '32')+'-bit')"

    function Test-PythonCandidate {
        param([string] $Exe)
        try {
            $out = (& $Exe -c $probe 2>&1 | Out-String).Trim()
        } catch {
            return $null
        }
        if ($LASTEXITCODE -ne 0 -or $out -notmatch '^\d+\.\d+ (64|32)-bit$') { return $null }
        if ($out -notmatch '64-bit') { return $null }
        $minor = [int]($out -replace '^\d+\.(\d+).*$', '$1')
        $major = [int]($out -replace '^(\d+)\..*$', '$1')
        if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 12)) { return $null }
        return $out
    }

    $found = Test-PythonCandidate -Exe $PythonExe
    if ($found) {
        Info "Python OK via '$PythonExe': $found"
        $resolvedPython = $PythonExe
        $summary.Add("Python: already present ($found)")
    } else {
        Info "'$PythonExe' is missing, too old, or 32-bit; installing 64-bit Python 3.12"

        $installed = $false
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Info 'installing via winget'
            & winget install --id Python.Python.3.12 --source winget `
                --accept-package-agreements --accept-source-agreements --scope machine
            if ($LASTEXITCODE -eq 0) { $installed = $true }
            else { Info "winget exited with code $LASTEXITCODE; falling back to direct download" }
        }

        if (-not $installed) {
            Info 'downloading the official python.org 3.12 amd64 installer'
            $oldProgress = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'
            try {
                [Net.ServicePointManager]::SecurityProtocol = `
                    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
                $pyInstaller = Join-Path $env:TEMP 'python-3.12.7-amd64.exe'
                Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe' `
                    -OutFile $pyInstaller -UseBasicParsing
            } finally {
                $ProgressPreference = $oldProgress
            }
            Info "downloaded to $pyInstaller"
            $proc = Start-Process -FilePath $pyInstaller `
                -ArgumentList '/quiet', 'InstallAllUsers=1', 'PrependPath=1', 'Include_launcher=1' `
                -Wait -PassThru
            if ($proc.ExitCode -ne 0) { throw "Python installer exited with code $($proc.ExitCode)." }
            Remove-Item $pyInstaller -Force -ErrorAction SilentlyContinue
            $installed = $true
        }

        $pythonWasInstalled = $true

        # The current session's PATH may not yet reflect a fresh install (winget in particular), so
        # re-resolve from known install locations before falling back to re-probing the PATH.
        $candidates = @(
            'C:\Program Files\Python312\python.exe',
            (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python312\python.exe'),
            $PythonExe
        )
        $resolved = $null
        foreach ($candidate in $candidates) {
            if ($resolved) { break }
            $ok = Test-PythonCandidate -Exe $candidate
            if ($ok) { $resolved = $candidate; $found = $ok }
        }
        if (-not $resolved -and (Get-Command py -ErrorAction SilentlyContinue)) {
            $ok = Test-PythonCandidate -Exe 'py -3.12'
            if (-not $ok) {
                # Test-PythonCandidate calls '& $Exe', which does not split 'py -3.12' into args; probe directly.
                try {
                    $out = (& py -3.12 -c $probe 2>&1 | Out-String).Trim()
                    if ($LASTEXITCODE -eq 0 -and $out -match '64-bit') { $ok = $out }
                } catch {}
            }
            if ($ok) { $resolved = (& py -3.12 -c 'import sys;print(sys.executable)' 2>&1 | Out-String).Trim(); $found = $ok }
        }

        if (-not $resolved) {
            throw 'Python 3.12 (64-bit) installer ran but no matching python.exe could be resolved afterwards. Open a new shell and re-run, or pass -PythonExe with the full path.'
        }

        $resolvedPython = $resolved
        Info "resolved python.exe: $resolvedPython ($found)"
        $summary.Add("Python: installed ($resolvedPython, $found)")
    }
}

# ================================================================================================
# 3. ODBC Driver 18 for SQL Server
# ================================================================================================

if ($SkipOdbc) {
    Info 'ODBC Driver 18: skipped (-SkipOdbc)'
    $summary.Add('ODBC Driver 18: skipped')
} else {
    Step 'ODBC Driver 18 for SQL Server'

    $odbc = Get-OdbcDriver -Platform '64-bit' -ErrorAction SilentlyContinue |
        Where-Object Name -match 'ODBC Driver 1[78] for SQL Server'
    if ($odbc) {
        Info "already present: $(($odbc | Select-Object -First 1).Name)"
        $summary.Add("ODBC Driver 18: already present ($(($odbc | Select-Object -First 1).Name))")
    } else {
        Info 'not found; installing'
        $installed = $false
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Info 'installing via winget'
            & winget install --id Microsoft.msodbcsql.18 --source winget `
                --accept-package-agreements --accept-source-agreements --scope machine
            if ($LASTEXITCODE -eq 0) { $installed = $true }
            else { Info "winget exited with code $LASTEXITCODE; falling back to direct MSI download" }
        }

        if (-not $installed) {
            $oldProgress = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'
            try {
                [Net.ServicePointManager]::SecurityProtocol = `
                    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
                $msi = Join-Path $env:TEMP 'msodbcsql.msi'
                Info 'downloading msodbcsql.msi'
                Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/?linkid=2249006' -OutFile $msi -UseBasicParsing
            } finally {
                $ProgressPreference = $oldProgress
            }
            $proc = Start-Process -FilePath 'msiexec.exe' `
                -ArgumentList '/i', "`"$msi`"", '/qn', 'IACCEPTMSODBCSQLLICENSETERMS=YES' `
                -Wait -PassThru
            if ($proc.ExitCode -eq 0) { $installed = $true }
            else { Info "msiexec exited with code $($proc.ExitCode)" }
            Remove-Item $msi -Force -ErrorAction SilentlyContinue
        }

        $odbcNow = Get-OdbcDriver -Platform '64-bit' -ErrorAction SilentlyContinue |
            Where-Object Name -match 'ODBC Driver 1[78] for SQL Server'
        if ($odbcNow) {
            Info "installed: $(($odbcNow | Select-Object -First 1).Name)"
            $summary.Add("ODBC Driver 18: installed ($(($odbcNow | Select-Object -First 1).Name))")
        } else {
            # Matches the existing installers' stance: warn, don't throw. The site can be installed
            # before the driver; it will surface as a connection error at the first device upload.
            Write-Warning "Could not confirm 'ODBC Driver 18 for SQL Server' after install attempt. Install it manually before the service can reach the database: https://learn.microsoft.com/sql/connect/odbc/download-odbc-driver-for-sql-server"
            $summary.Add('ODBC Driver 18: NOT confirmed (see warning above)')
        }
    }
}

# ================================================================================================
# 4. ANCM (AspNetCoreModuleV2)
# ================================================================================================

if ($SkipHostingBundle) {
    Info 'ANCM / Hosting Bundle: skipped (-SkipHostingBundle)'
    $summary.Add('ANCM: skipped')
} else {
    Step 'ANCM (AspNetCoreModuleV2)'

    # Authoritative signal is the registered IIS global module, not a file under System32\inetsrv:
    # modern Hosting Bundles install to %ProgramFiles%\IIS\Asp.Net Core Module\V2\ and register by
    # absolute path. Check the global module first, then fall back to a file search across both roots.
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

    $ancm = Find-Ancm
    if ($ancm) {
        Info "already present: $($ancm[0].FullName)"
        $summary.Add('ANCM: already present')
    } else {
        Info 'not found; delegating to install-hosting-bundle.ps1'
        $bundleScript = Join-Path $PSScriptRoot 'install-hosting-bundle.ps1'
        if (-not (Test-Path $bundleScript)) {
            throw "Cannot install ANCM: sibling script not found at $bundleScript"
        }
        & $bundleScript -Channel $DotnetChannel

        $ancmNow = Find-Ancm
        if (-not $ancmNow) {
            throw 'install-hosting-bundle.ps1 ran but AspNetCoreModuleV2 is still not present. Ensure the Web-Server role is installed, then re-run.'
        }
        Info "installed: $($ancmNow[0].FullName)"
        $summary.Add('ANCM: installed')
    }
}

# ================================================================================================
# Summary
# ================================================================================================

Write-Host ''
Write-Host 'Prerequisite check complete:' -ForegroundColor Green
foreach ($line in $summary) { Write-Host "  - $line" }

if ($pythonWasInstalled -and $resolvedPython) {
    Write-Host ''
    Write-Host "RESOLVED_PYTHON=$resolvedPython"
}
