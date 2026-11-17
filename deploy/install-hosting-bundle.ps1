<#
.SYNOPSIS
    Install the ASP.NET Core Hosting Bundle so IIS gains the AspNetCoreModuleV2 (ANCM) handler.

.DESCRIPTION
    Idempotent. Downloads Microsoft's official dotnet-install channel installer for the Hosting Bundle
    and runs it silently, then restarts IIS so the newly registered native module is picked up.

    Both site installers (install-iis.ps1 and install-admin-site.ps1) call this automatically when ANCM
    is absent, so an operator normally never runs it directly. It is a separate script so the download
    and MSI logic lives in one place and can be run on its own, e.g. behind a proxy or from a cached MSI.

    WHY THIS EXISTS
      ANCM is what lets IIS reverse-proxy to a Python child out-of-process. It does not ship with a bare
      IIS install; it ships with the Hosting Bundle. Without it every request is a 500.19 with nothing to
      explain why, which is the single most common install failure.

    OFFLINE / RESTRICTED HOSTS
      Pass -InstallerPath to run an MSI already staged on the host instead of downloading. That is the
      supported path where the machine cannot reach dotnet.microsoft.com.

.EXAMPLE
    ./deploy/install-hosting-bundle.ps1

.EXAMPLE
    # Use a pre-downloaded MSI (air-gapped / proxied host):
    ./deploy/install-hosting-bundle.ps1 -InstallerPath C:\stage\dotnet-hosting-8.0.11-win.exe
#>
[CmdletBinding()]
param(
    # Major .NET channel whose Hosting Bundle to fetch. Any current LTS works; ANCM is the same module.
    [string] $Channel = '8.0',

    # A pre-staged Hosting Bundle installer to run instead of downloading. When set, no network is used.
    [string] $InstallerPath,

    # Skip the IIS restart. The module is registered by the MSI, but IIS must be recycled to load it;
    # only skip this if you will restart IIS yourself.
    [switch] $SkipIisRestart
)

$ErrorActionPreference = 'Stop'

function Step { param([string] $Text) Write-Host "==> $Text" -ForegroundColor Cyan }
function Info { param([string] $Text) Write-Host "    $Text" -ForegroundColor DarkGray }

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell: it installs a system component and restarts IIS.'
}

# Already installed? Then this is a no-op -- the whole script is safe to call unconditionally.
#
# The authoritative signal is the registered IIS global module, NOT a file under System32\inetsrv:
# modern Hosting Bundles install the DLL to %ProgramFiles%\IIS\Asp.Net Core Module\V2\ and register
# it as a global module by absolute path, so it never appears under inetsrv. We therefore check the
# global-module registration first, then fall back to a file search across both known locations.
function Find-Ancm {
    try {
        Import-Module WebAdministration -ErrorAction Stop
        $gm = Get-WebGlobalModule -ErrorAction Stop |
            Where-Object { $_.Name -in @('AspNetCoreModuleV2', 'AspNetCoreModule') } |
            Select-Object -First 1
        if ($gm) {
            $img = [Environment]::ExpandEnvironmentVariables($gm.Image)
            return @([pscustomobject]@{ FullName = $img })
        }
    } catch {
        # WebAdministration unavailable (IIS not yet imported): fall through to the file search.
    }
    foreach ($root in @(
            (Join-Path $env:SystemRoot 'System32\inetsrv'),
            (Join-Path ${env:ProgramFiles} 'IIS\Asp.Net Core Module'))) {
        $hit = Get-ChildItem -Path $root -Filter 'aspnetcorev2.dll' -Recurse -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($hit) { return @($hit) }
    }
    @()
}

$existing = Find-Ancm
if ($existing) {
    Info "AspNetCoreModuleV2 already present ($($existing[0].FullName)); nothing to do."
    return
}

Step 'Install the ASP.NET Core Hosting Bundle'

$installer = $InstallerPath
$downloaded = $false

if (-not $installer) {
    # Microsoft's dotnet-install script resolves the exact current Hosting Bundle for the channel, so we
    # never pin a URL that later 404s. It downloads the runtime by default; -Runtime aspnetcore plus the
    # Hosting Bundle flag is not offered by the script, so we instead resolve the direct bundle URL from
    # the channel's release metadata.
    $tmp = Join-Path $env:TEMP ("adms-hosting-bundle-{0}" -f ([Guid]::NewGuid().ToString('N')))
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null

    # aka.ms provides a stable redirect to the latest Hosting Bundle installer for a channel.
    $url = "https://aka.ms/dotnet/$Channel/dotnet-hosting-win.exe"
    $installer = Join-Path $tmp 'dotnet-hosting-win.exe'
    Info "downloading Hosting Bundle for channel $Channel"
    Info "  $url"

    $oldProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'  # Invoke-WebRequest is far slower with the progress bar on.
    try {
        # TLS 1.2 is required by the CDN on older Windows PowerShell hosts.
        [Net.ServicePointManager]::SecurityProtocol = `
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $url -OutFile $installer -UseBasicParsing
    } finally {
        $ProgressPreference = $oldProgress
    }
    $downloaded = $true
    Info "downloaded to $installer ($([math]::Round((Get-Item $installer).Length / 1MB, 1)) MB)"
} else {
    if (-not (Test-Path $installer)) { throw "InstallerPath not found: $installer" }
    Info "using staged installer: $installer"
}

Info 'running installer silently (/install /quiet /norestart)'
$proc = Start-Process -FilePath $installer -ArgumentList '/install', '/quiet', '/norestart' `
    -Wait -PassThru
# 0 = success, 3010 = success but a reboot is advised. Neither is a failure for our purpose.
if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
    throw "Hosting Bundle installer exited with code $($proc.ExitCode)."
}
Info "installer exit code $($proc.ExitCode)"

if ($downloaded) {
    Remove-Item (Split-Path $installer -Parent) -Recurse -Force -ErrorAction SilentlyContinue
}

if (-not $SkipIisRestart) {
    Step 'Restart IIS so the native module loads'
    # net stop/start was replaced by iisreset; it recycles WAS and W3SVC and reloads native modules.
    & iisreset /restart | ForEach-Object { Info $_ }
}

$now = Find-Ancm
if (-not $now) {
    throw @'
The Hosting Bundle installer ran but AspNetCoreModuleV2 is still not registered as an IIS global module.
This usually means IIS was not installed BEFORE the bundle, so the bundle skipped the IIS integration.
Ensure the Web-Server role is installed, then re-run this script.
'@
}
Write-Host "AspNetCoreModuleV2 installed: $($now[0].FullName)" -ForegroundColor Green
