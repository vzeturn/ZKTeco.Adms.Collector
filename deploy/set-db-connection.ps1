<#
.SYNOPSIS
    Store the ATTENDANCEDB connection string, DPAPI-encrypted, in the registry.

.DESCRIPTION
    Writes HKLM\SOFTWARE\AdmsCollector\AttendanceDb\ConnectionString as a REG_BINARY DPAPI blob at
    machine scope, then restricts read access to the application pool identity and Administrators.

    The password is read as a SecureString and prompted for -- never a plain parameter. A plain
    -Password would land in PowerShell history, in the console scrollback and in any transcript, which
    defeats the point of encrypting the value at rest.

    WHY THE REGISTRY AND NOT web.config OR AN ENVIRONMENT VARIABLE
      web.config is plaintext, sits in the site folder, is overwritten by a redeploy and copied by
      every backup. An environment variable is readable from any process running as the same identity
      and shows up in crash dumps. The registry value survives replacing the application folder, and
      DPAPI machine scope makes the ciphertext useless if a backup or a disk leaves the building.

    KNOWN TRADEOFF
      Machine scope means any process on THIS host that can read the key can decrypt it. That is why
      the ACL below is narrowed, and why the SQL login should be the least-privilege one from
      sql\grant-least-privilege.sql -- so what the value unlocks is bounded. ZkManager.App uses
      CurrentUser scope instead, which it can because it is a desktop app run by one operator; a
      service installed by one identity and run by another cannot.

.EXAMPLE
    ./deploy/set-db-connection.ps1 `
        -SqlHost <sql-server-endpoint> `
        -Database ATTENDANCEDB -Username adms_collector

.EXAMPLE
    # Verify what is stored without revealing it
    ./deploy/set-db-connection.ps1 -TestOnly
#>
[CmdletBinding(DefaultParameterSetName = 'Set')]
param(
    [Parameter(ParameterSetName = 'Set', Mandatory = $true)]
    [string] $SqlHost,

    [Parameter(ParameterSetName = 'Set')]
    [string] $Database = 'ATTENDANCEDB',

    [Parameter(ParameterSetName = 'Set')]
    [string] $Username = 'adms_collector',

    [Parameter(ParameterSetName = 'Set')]
    [int] $SqlPort = 1433,

    [Parameter(ParameterSetName = 'Set')]
    [string] $OdbcDriver = 'ODBC Driver 18 for SQL Server',

    # Only for a server with a self-signed certificate. Leaves the connection encrypted but
    # unauthenticated, so it stops passive sniffing and not an active man-in-the-middle.
    [Parameter(ParameterSetName = 'Set')]
    [switch] $TrustServerCertificate,

    [Parameter(ParameterSetName = 'Set')]
    [string] $SitePath = 'C:\inetpub\adms-collector',

    [Parameter(ParameterSetName = 'Set')]
    [string] $AppPoolName = 'AdmsCollector',

    # Registry sub-key under HKLM to store the blob in. The collector uses its own sub-key (the
    # default); the console stores under SOFTWARE\AdmsConsole\AttendanceDb so the two never overwrite
    # each other. The DPAPI entropy is shared (both decrypt with the same _ENTROPY in dbconfig.py), so
    # only the location differs. The -AppPoolName above must name the pool that owns this sub-key, so it
    # gets the read ACE below.
    [Parameter(ParameterSetName = 'Set')]
    [string] $RegistrySubKey = 'SOFTWARE\AdmsCollector\AttendanceDb',

    [Parameter(ParameterSetName = 'Test')]
    [string] $TestSubKey = 'SOFTWARE\AdmsCollector\AttendanceDb',

    # Unattended installs only: read the password from the ADMS_DB_PASSWORD environment variable
    # instead of prompting. There is deliberately no -Password parameter, because a parameter lands in
    # PowerShell history, console scrollback and any transcript. An environment variable set for one
    # process is the least-bad option when a human cannot be at the keyboard.
    [Parameter(ParameterSetName = 'Set')]
    [switch] $UseEnvPassword,

    [Parameter(ParameterSetName = 'Test', Mandatory = $true)]
    [switch] $TestOnly
)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell: it writes under HKLM.'
}

# The Test set uses its own -TestSubKey (default collector); the Set path uses -RegistrySubKey.
$subKey = if ($TestOnly) { $TestSubKey } else { $RegistrySubKey }
$valueName = 'ConnectionString'
# Must match _ENTROPY in src/adms/dbconfig.py, or the service cannot decrypt what this writes.
$entropy = [Text.Encoding]::UTF8.GetBytes('AdmsCollector.AttendanceDb.v1')

Add-Type -AssemblyName System.Security

function Protect-Value {
    param([string] $Plain)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Plain)
    return [Security.Cryptography.ProtectedData]::Protect(
        $bytes, $entropy, [Security.Cryptography.DataProtectionScope]::LocalMachine)
}

function Unprotect-Value {
    param([byte[]] $Cipher)
    $bytes = [Security.Cryptography.ProtectedData]::Unprotect(
        $Cipher, $entropy, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    return [Text.Encoding]::UTF8.GetString($bytes)
}

# ---- Test mode --------------------------------------------------------------------------------

if ($TestOnly) {
    $key = Get-ItemProperty -Path "HKLM:\$subKey" -Name $valueName -ErrorAction SilentlyContinue
    if (-not $key) {
        Write-Host 'Not configured: no value found.' -ForegroundColor Yellow
        exit 1
    }
    $plain = Unprotect-Value -Cipher $key.$valueName
    # Report the SHAPE only. Printing the value would put the password on screen and in scrollback.
    $server   = if ($plain -match 'SERVER=([^;]+)')   { $Matches[1] } else { '(not found)' }
    $database = if ($plain -match 'DATABASE=([^;]+)') { $Matches[1] } else { '(not found)' }
    $uid      = if ($plain -match 'UID=([^;]+)')      { $Matches[1] } else { '(not found)' }
    $encrypt  = if ($plain -match 'Encrypt=([^;]+)')  { $Matches[1] } else { '(not set)' }
    $trust    = if ($plain -match 'TrustServerCertificate=([^;]+)') { $Matches[1] } else { '(not set)' }

    Write-Host 'Configured and decryptable on this host.' -ForegroundColor Green
    Write-Host "  SERVER                 : $server"
    Write-Host "  DATABASE               : $database"
    Write-Host "  UID                    : $uid"
    Write-Host "  Encrypt                : $encrypt"
    Write-Host "  TrustServerCertificate : $trust"
    Write-Host "  PWD                    : (present, $((($plain -split 'PWD=')[1] -split ';')[0].Length) chars, not shown)"
    exit 0
}

# ---- Collect the password ---------------------------------------------------------------------

Write-Host "Storing the connection string for $Username@$SqlHost/$Database" -ForegroundColor Cyan

if ($UseEnvPassword) {
    if (-not $env:ADMS_DB_PASSWORD) {
        throw '-UseEnvPassword was given but ADMS_DB_PASSWORD is not set in the environment.'
    }
    $secure = ConvertTo-SecureString $env:ADMS_DB_PASSWORD -AsPlainText -Force
    Write-Host '  password taken from ADMS_DB_PASSWORD' -ForegroundColor DarkGray
} else {
    $secure = Read-Host -AsSecureString "SQL password for '$Username'"
}
if ($secure.Length -eq 0) { throw 'No password entered.' }

# Marshalled and zeroed immediately: the plaintext exists in this process for as short a window as
# possible, and never in a variable that a transcript or crash dump would capture.
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)

    $trust = if ($TrustServerCertificate) { 'yes' } else { 'no' }
    # Encrypt=yes unconditionally. A server may accept unencrypted sessions (for example RDS with
    # rds.force_ssl = 0) -- the client is the only thing that can insist, and this traffic may cross
    # the internet.
    $connectionString = "DRIVER={$OdbcDriver};SERVER=$SqlHost,$SqlPort;DATABASE=$Database;" +
                        "UID=$Username;PWD=$password;Encrypt=yes;TrustServerCertificate=$trust;" +
                        'Connection Timeout=10;'
    $cipher = Protect-Value -Plain $connectionString
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    $password = $null
    $connectionString = $null
    [GC]::Collect()
}

# ---- Write ------------------------------------------------------------------------------------

if (-not (Test-Path "HKLM:\$subKey")) { New-Item -Path "HKLM:\$subKey" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\$subKey" -Name $valueName -Value $cipher -Type Binary
Write-Host "Written to HKLM\$subKey\$valueName (REG_BINARY, DPAPI machine scope)" -ForegroundColor Green

# ---- Restrict access --------------------------------------------------------------------------

# DPAPI machine scope means anything on this host that can READ the key can decrypt it, so the ACL is
# the control that actually limits exposure. Inheritance is disabled first, otherwise the broad
# Users-read ACE inherited from SOFTWARE would defeat the whole exercise.
$aclPath = "HKLM:\$subKey"
$acl = Get-Acl $aclPath
$acl.SetAccessRuleProtection($true, $false)
$acl.Access | ForEach-Object { [void]$acl.RemoveAccessRule($_) }

foreach ($identity in @('BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM', "IIS AppPool\$AppPoolName")) {
    try {
        $rights = if ($identity -like 'IIS AppPool\*') { 'ReadKey' } else { 'FullControl' }
        $acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule(
            $identity, $rights, 'ContainerInherit', 'None', 'Allow')))
    } catch {
        Write-Warning "Could not add an ACE for '$identity': $($_.Exception.Message)"
    }
}
Set-Acl -Path $aclPath -AclObject $acl
Write-Host 'Access restricted to Administrators, SYSTEM, and the application pool identity (read).' -ForegroundColor Green

# ---- Verify ------------------------------------------------------------------------------------

Write-Host ''
Write-Host 'Verifying it decrypts on this host...' -ForegroundColor Cyan
$check = Get-ItemProperty -Path "HKLM:\$subKey" -Name $valueName
$null = Unprotect-Value -Cipher $check.$valueName
Write-Host 'OK.' -ForegroundColor Green

Write-Host ''
Write-Host 'A DPAPI machine-scope blob is bound to THIS machine. If you move or re-image the host,' -ForegroundColor Yellow
Write-Host 're-run this script there; the copied value will not decrypt.' -ForegroundColor Yellow
Write-Host ''
Write-Host 'Next: ./deploy/import-rds-ca.ps1  then  ./deploy/verify.ps1'
