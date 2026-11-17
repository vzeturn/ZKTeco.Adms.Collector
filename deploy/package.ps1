<#
.SYNOPSIS
    Build the customer-shippable zip for the ADMS attendance system.

.DESCRIPTION
    Stages the application source and deploy scripts into a clean tree, drops INSTALL.ps1 and a short
    README at the root, scans the staged tree for any leaked secret, and zips it. Never bundles a
    virtual environment, tests, credentials, or the local git history.

    Run this on our side; it is not shipped to the customer.

.PARAMETER Version
    Version tag baked into the zip name. Defaults to the pyproject version, else a date is required
    via -Version.

.PARAMETER OutDir
    Where to write the zip. Defaults to <project>\dist.

.EXAMPLE
    ./deploy/package.ps1 -Version 1.0.0
#>
param(
    [string] $Version,
    [string] $OutDir
)

$ErrorActionPreference = 'Stop'

function Step { param([string] $Text) Write-Host "==> $Text" -ForegroundColor Cyan }
function Info { param([string] $Text) Write-Host "    $Text" -ForegroundColor DarkGray }

$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $OutDir) { $OutDir = Join-Path $projectRoot 'dist' }

if (-not $Version) {
    $pyproject = Get-Content (Join-Path $projectRoot 'pyproject.toml') -Raw
    $m = [regex]::Match($pyproject, '(?m)^\s*version\s*=\s*"([^"]+)"')
    if ($m.Success) { $Version = $m.Groups[1].Value }
    else { throw 'Could not read version from pyproject.toml; pass -Version.' }
}
Info "version $Version"

# Staging dir under the output dir so a failed run is easy to inspect and re-run.
$stageRoot = Join-Path $OutDir "stage-adms-$Version"
if (Test-Path $stageRoot) { Remove-Item $stageRoot -Recurse -Force }
New-Item -ItemType Directory -Path $stageRoot -Force | Out-Null

# ---- Stage the payload -------------------------------------------------------------------------

Step 'Staging payload'

# src\ minus caches; robocopy mirrors and prunes __pycache__ deterministically.
$srcDst = Join-Path $stageRoot 'src'
robocopy (Join-Path $projectRoot 'src') $srcDst /E /XD __pycache__ .pytest_cache /XF *.pyc /NFL /NDL /NJH /NJS /NP | Out-Null
# robocopy exit codes below 8 are success (1 = files copied). Normalise so the non-zero code does not
# linger and make an otherwise-successful run report failure at the end.
if ($LASTEXITCODE -ge 8) { throw "robocopy src failed (code $LASTEXITCODE)." }
$global:LASTEXITCODE = 0

# deploy\ scripts + web.config files (already includes install-all.ps1, set-db-connection.ps1, etc.)
$deployDst = Join-Path $stageRoot 'deploy'
New-Item -ItemType Directory -Path $deployDst -Force | Out-Null
# package.ps1 is our build tool, not something the customer runs; leave it out of the payload.
Get-ChildItem (Join-Path $projectRoot 'deploy\*.ps1') -Exclude 'package.ps1' |
    Copy-Item -Destination $deployDst -Force
Copy-Item (Join-Path $projectRoot 'deploy\web.config') $deployDst -Force
Copy-Item (Join-Path $projectRoot 'deploy\web.config.admin') $deployDst -Force

# Runtime manifests.
Copy-Item (Join-Path $projectRoot 'requirements.txt') $stageRoot -Force
Copy-Item (Join-Path $projectRoot 'pyproject.toml') $stageRoot -Force

# INSTALL.ps1 at the root is the entry point (a copy of the orchestrator).
Copy-Item (Join-Path $projectRoot 'deploy\install-all.ps1') (Join-Path $stageRoot 'INSTALL.ps1') -Force

@"
ADMS Attendance System - Install

1. Extract this folder anywhere on the target Windows server.
2. Open PowerShell as Administrator in this folder.
3. Run:  .\INSTALL.ps1 -SqlHost <sql-server-name>
   You will be prompted for the SQL password. Database/user default to
   ATTENDANCEDB / adms_collector; override with -Database and -Username.
   Add -TrustServerCertificate only for a self-signed SQL certificate.

The installer sets up both sites automatically:
  - Collector (device push)  http://localhost:8080/iclock/
  - Console   (admin UI)     http://localhost:8081/

The database schema and admin login are assumed to already exist and are not modified.
"@ | Set-Content -Path (Join-Path $stageRoot 'README.txt') -Encoding UTF8

# ---- Secret scan -------------------------------------------------------------------------------

Step 'Secret scan'

# Belt-and-braces: refuse to ship if a REAL credential slipped into the staged tree. The patterns
# target actual secrets, not the code that handles them -- an environment-variable name, the public
# RDS truststore URL, or an example endpoint are all legitimate and must not trip the scan.
#   - a private RDS *instance* endpoint (a subdomain before .rds.amazonaws.com), excluding the public
#     truststore.pki host that import-rds-ca.ps1 legitimately references
#   - a plaintext password assigned to a real value (not $env:..., not a variable, not a placeholder)
$patterns = @(
    '(?<!truststore\.pki\.)[a-z0-9-]+\.[a-z0-9]+\.[a-z0-9-]+\.rds\.amazonaws\.com',
    '(?i)(password|pwd)\s*=\s*[''"][^''"$<>{} ]{6,}[''"]'
)
$offenders = @()
Get-ChildItem $stageRoot -Recurse -File | ForEach-Object {
    $text = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
    if ($null -eq $text) { return }
    foreach ($p in $patterns) {
        $mm = [regex]::Match($text, $p)
        if ($mm.Success) { $offenders += "$($_.FullName)  ~=  '$($mm.Value)'" }
    }
}
if ($offenders.Count -gt 0) {
    $offenders | ForEach-Object { Write-Warning $_ }
    throw 'Secret scan found suspicious content in the staged tree; not packaging.'
}
Info 'clean'

# ---- Zip ---------------------------------------------------------------------------------------

Step 'Zipping'

$zipPath = Join-Path $OutDir "adms-package-$Version.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path (Join-Path $stageRoot '*') -DestinationPath $zipPath -Force
Remove-Item $stageRoot -Recurse -Force

$sizeMb = [math]::Round((Get-Item $zipPath).Length / 1MB, 1)
Write-Host ''
Step 'Done'
Write-Host "    $zipPath  ($sizeMb MB)" -ForegroundColor Green
