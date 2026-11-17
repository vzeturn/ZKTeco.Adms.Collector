<#
.SYNOPSIS
    Create the first admin user for the ADMS admin console.

.DESCRIPTION
    Prompts for a username and a password (twice, without echo), derives the password hash with the
    console's own hashing function, and inserts a row into dbo.APP_USER with RoleName 'admin'. This
    is how the console is bootstrapped: once one admin exists, every further user is created through
    the console itself.

    The password is read as a SecureString and never placed on a command line or in an argument
    list. A plain -Password parameter would land in PowerShell history, in the console scrollback and
    in any transcript, and 'python -c "...$password..."' would put it on the child process command
    line where any other process on the host can read it. Instead the program is fed to 'python -' on
    stdin, so PowerShell never rewrites its embedded quotes onto a command line, and the password
    reaches the child only through an environment variable set for that one process and cleared the
    instant it returns.

    The hash is computed by adms.admin.auth.hash_password, not reimplemented in PowerShell: one
    implementation of PBKDF2, iteration count and NFC normalisation means a password created here
    verifies in the console without a second, drifting copy of the scheme.

.EXAMPLE
    ./deploy/create-admin-user.ps1

.EXAMPLE
    ./deploy/create-admin-user.ps1 -Username jane.doe -DisplayName 'Jane Doe'
#>
[CmdletBinding()]
param(
    [string] $Username,

    [string] $DisplayName = '',

    # Path to the console's Python source tree. Defaults to the src/ folder of this checkout so the
    # script works from a clone before an install; on the target host, point it at the site's src.
    [string] $SrcPath,

    # The Python interpreter to use. Defaults to the site's virtual environment when present, else
    # whatever 'python' resolves to on PATH.
    [string] $Python
)

$ErrorActionPreference = 'Stop'

# ---- Locate the source tree and interpreter ---------------------------------------------------

if (-not $SrcPath) {
    $SrcPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'src'
}
if (-not (Test-Path (Join-Path $SrcPath 'adms'))) {
    throw "Cannot find the adms package under '$SrcPath'. Pass -SrcPath pointing at the console's src folder."
}

if (-not $Python) {
    $venv = Join-Path (Split-Path -Parent $PSScriptRoot) '.venv\Scripts\python.exe'
    $Python = if (Test-Path $venv) { $venv } else { 'python' }
}

# ---- Collect the username ---------------------------------------------------------------------

if (-not $Username) {
    $Username = Read-Host 'Username for the new admin'
}
$Username = $Username.Trim()
if (-not $Username) { throw 'No username entered.' }

Write-Host "Creating admin user '$Username'." -ForegroundColor Cyan

# ---- Collect the password twice ---------------------------------------------------------------

$secure1 = Read-Host -AsSecureString 'Password'
$secure2 = Read-Host -AsSecureString 'Confirm password'

$bstr1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure1)
$bstr2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure2)
try {
    $pw1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr1)
    $pw2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr2)
    if ($pw1 -cne $pw2) { throw 'The two passwords do not match.' }
    if ($pw1.Length -eq 0) { throw 'No password entered.' }
    $password = $pw1
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr1)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr2)
    $pw1 = $null
    $pw2 = $null
}

# ---- Hand off to Python -----------------------------------------------------------------------

# The program below runs in the console's own environment. It reads the password from an environment
# variable (never a command-line argument), validates it with the same rules the console enforces,
# refuses a username that already exists, and inserts an enabled admin row whose hash was produced by
# adms.admin.auth.hash_password. The program itself is piped to 'python -' on stdin so PowerShell
# never has to build a command line containing its quotes.
$program = @'
import os
import sys

sys.path.insert(0, os.environ["ADMS_SRC"])

from adms.admin import auth
from adms.admin.serve import _resolve_console_connection
from adms.config import load_settings

username = os.environ["ADMS_NEW_USERNAME"].strip()
display = os.environ.get("ADMS_NEW_DISPLAY", "").strip()
password = os.environ["ADMS_NEW_PASSWORD"]

problems = auth.password_problems(password, username)
if problems:
    sys.stderr.write("Password rejected:\n")
    for p in problems:
        sys.stderr.write("  - " + p + "\n")
    sys.exit(2)

_source, factory = _resolve_console_connection(load_settings())
conn = factory.get()
cursor = conn.cursor()

cursor.execute("SELECT 1 FROM dbo.APP_USER WHERE Username = ?", (username,))
if cursor.fetchone() is not None:
    sys.stderr.write("Username '%s' is already taken; no change made.\n" % username)
    sys.exit(3)

salt = auth.new_salt()
hashed = auth.hash_password(password, salt)
cursor.execute(
    "INSERT INTO dbo.APP_USER "
    "(Username, DisplayName, RoleName, PasswordSalt, PasswordHash, Iterations, "
    " IsEnabled, MustChangePassword, CreatedBy) "
    "VALUES (?, ?, 'admin', ?, ?, ?, 1, 0, 'create-admin-user.ps1')",
    (username, display or username, salt, hashed, auth.PBKDF2_ITERATIONS),
)
conn.commit()
sys.stdout.write("Created admin user '%s'.\n" % username)
'@

$env:ADMS_SRC = $SrcPath
$env:ADMS_NEW_USERNAME = $Username
$env:ADMS_NEW_DISPLAY = $DisplayName
$env:ADMS_NEW_PASSWORD = $password
try {
    $program | & $Python -
    $exit = $LASTEXITCODE
} finally {
    $password = $null
    $env:ADMS_NEW_PASSWORD = $null
    $env:ADMS_NEW_USERNAME = $null
    $env:ADMS_NEW_DISPLAY = $null
    [GC]::Collect()
}

if ($exit -ne 0) {
    throw "Admin user was not created (python exit code $exit). See the message above."
}

Write-Host ''
Write-Host "Admin user '$Username' created." -ForegroundColor Green
Write-Host 'Next: browse to the console on port 8081 and sign in.'
