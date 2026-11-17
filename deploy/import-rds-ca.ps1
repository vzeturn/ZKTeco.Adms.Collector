<#
.SYNOPSIS
    Trust the Amazon RDS certificate authority on this host, so TLS to the database is validated.
    Optional: only needed when the database server is an Amazon RDS SQL Server instance.

.DESCRIPTION
    An RDS SQL Server instance presents a certificate from an Amazon RDS CA. That CA's root is NOT in the Windows certificate store by default, so without
    this the only way to connect is TrustServerCertificate=yes -- encrypted, but unauthenticated, which
    stops passive sniffing and does nothing against an active man-in-the-middle.

    This matters because RDS may be configured with rds.force_ssl = 0, in which case the SERVER accepts
    an unencrypted session. The client is then the only thing that can insist on TLS, and if the
    on-premises host reaches the instance over its public endpoint that traffic crosses the internet.

    Imports the global bundle rather than one regional certificate, so a CA rotation or a region change
    does not require re-running this.

.EXAMPLE
    ./deploy/import-rds-ca.ps1

.EXAMPLE
    # Air-gapped host: download the bundle elsewhere and pass it in.
    ./deploy/import-rds-ca.ps1 -BundlePath .\global-bundle.pem
#>
[CmdletBinding()]
param(
    [string] $BundleUrl = 'https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem',
    [string] $BundlePath
)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell: it writes to the LocalMachine certificate store.'
}

# ---- Obtain the bundle -------------------------------------------------------------------------

if ($BundlePath) {
    if (-not (Test-Path $BundlePath)) { throw "Bundle not found: $BundlePath" }
    $pem = Get-Content $BundlePath -Raw
    Write-Host "Using local bundle: $BundlePath" -ForegroundColor Cyan
} else {
    Write-Host "Downloading $BundleUrl" -ForegroundColor Cyan
    $pem = (Invoke-WebRequest -Uri $BundleUrl -UseBasicParsing).Content
    if ($pem -is [byte[]]) { $pem = [Text.Encoding]::ASCII.GetString($pem) }
}

# ---- Split and import --------------------------------------------------------------------------

# The bundle is a concatenation of PEM blocks, one per CA. Each is imported separately because the
# store takes one certificate at a time.
$blocks = [regex]::Matches($pem, '(?s)-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----')
if ($blocks.Count -eq 0) { throw 'No PEM certificate blocks found in the bundle.' }
Write-Host "Found $($blocks.Count) certificate(s) in the bundle." -ForegroundColor DarkGray

# Root CAs go to Root; intermediates to CertificateAuthority. Deciding by subject/issuer equality is
# how a self-signed root is identified without parsing extensions.
$rootStore = New-Object Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
$caStore = New-Object Security.Cryptography.X509Certificates.X509Store('CA', 'LocalMachine')
$rootStore.Open('ReadWrite')
$caStore.Open('ReadWrite')

$added = 0
$existing = 0
try {
    foreach ($block in $blocks) {
        $der = [Convert]::FromBase64String(
            ($block.Value -replace '-----(BEGIN|END) CERTIFICATE-----', '' -replace '\s', ''))
        $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2(, $der)

        $isRoot = $cert.Subject -eq $cert.Issuer
        $store = if ($isRoot) { $rootStore } else { $caStore }

        if ($store.Certificates.Find('FindByThumbprint', $cert.Thumbprint, $false).Count -gt 0) {
            $existing++
            continue
        }
        $store.Add($cert)
        $added++
        $kind = if ($isRoot) { 'root' } else { 'intermediate' }
        Write-Host ("  + {0,-12} {1}" -f $kind, $cert.Subject) -ForegroundColor DarkGray
    }
} finally {
    $rootStore.Close()
    $caStore.Close()
}

Write-Host ''
Write-Host "Imported $added certificate(s); $existing already present." -ForegroundColor Green
Write-Host ''
Write-Host 'The connection string can now use TrustServerCertificate=no, which is the default in'
Write-Host 'deploy/set-db-connection.ps1. Verify with:  ./deploy/verify.ps1'
