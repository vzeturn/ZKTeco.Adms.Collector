<#
.SYNOPSIS
    Build-time checks and the local dev server for the ADMS attendance collector.

.DESCRIPTION
    Mirrors the role of ZKTekoManager's build.ps1: one entry point so nobody has to remember the tool
    invocations. With no switches it runs everything that needs nothing but Python -- no IIS, no
    database, no network.

.EXAMPLE
    ./build.ps1                 # compile check + lint + type check + protocol smoke test
    ./build.ps1 -Serve          # local ADMS server with in-memory stores, for pointing a device at
    ./build.ps1 -CheckConfig    # resolve the real connection string and test the database

.NOTES
    Deployment lives in ./deploy/: install-iis.ps1, set-db-connection.ps1, import-rds-ca.ps1,
    verify.ps1. Run them in that order on the target host.
#>
[CmdletBinding()]
param(
    [switch] $Serve,
    [switch] $CheckConfig,
    [switch] $SkipLint,
    [int]    $Port = 8080
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

function Invoke-Step {
    param([string] $Name, [scriptblock] $Body)
    Write-Host "==> $Name" -ForegroundColor Cyan
    & $Body
    if ($LASTEXITCODE -ne 0) { throw "$Name failed with exit code $LASTEXITCODE" }
}

# Blank out /* */ and -- comment text so the .sql gate below reads code only. A .sql file's comments are
# prose, and the corrected grant script's prose has to discuss the very patterns the gate rejects. Line
# and column count are preserved, so a reported line number still matches the file.
function Get-SqlCodeOnly {
    param([string] $Text)
    $out = New-Object System.Text.StringBuilder
    $inBlock = $false
    $i = 0
    while ($i -lt $Text.Length) {
        $c = $Text[$i]
        if ($i + 1 -lt $Text.Length) { $next = $Text[$i + 1] } else { $next = [char]0 }
        if ($inBlock) {
            if ($c -eq '*' -and $next -eq '/') {
                $inBlock = $false
                [void]$out.Append('  ')
                $i += 2
                continue
            }
            if ($c -eq "`n" -or $c -eq "`r") { [void]$out.Append($c) } else { [void]$out.Append(' ') }
            $i++
            continue
        }
        if ($c -eq '/' -and $next -eq '*') {
            $inBlock = $true
            [void]$out.Append('  ')
            $i += 2
            continue
        }
        if ($c -eq '-' -and $next -eq '-') {
            while ($i -lt $Text.Length -and $Text[$i] -ne "`n") {
                [void]$out.Append(' ')
                $i++
            }
            continue
        }
        [void]$out.Append($c)
        $i++
    }
    $out.ToString()
}

# Resolve an interpreter. 'py' is the Windows launcher; fall back to python on PATH.
$python = if (Get-Command py -ErrorAction SilentlyContinue) { 'py' } else { 'python' }

if ($Serve) {
    # --fake: no SQL Server, no ODBC driver. Point a real device at this to find out what its firmware
    # actually sends -- every request body is printed.
    & $python tools/local_server.py --fake --port $Port
    exit $LASTEXITCODE
}

if ($CheckConfig) {
    # Exercises the real configuration path: decrypts the registry value, lists ODBC drivers, runs
    # SELECT 1. Same code deploy/verify.ps1 calls on the server.
    $env:PYTHONPATH = (Resolve-Path 'src').Path
    try {
        & $python -m adms.hosting.serve --check
        exit $LASTEXITCODE
    } finally {
        Remove-Item env:PYTHONPATH -ErrorAction SilentlyContinue
    }
}

# ---- Default: the checks that need nothing but Python ------------------------------------------

# compileall catches syntax errors across every module, including ones no test imports.
Invoke-Step 'compile check' { & $python -m compileall -q src tools }

if (-not $SkipLint) {
    if (Get-Command ruff -ErrorAction SilentlyContinue) {
        Invoke-Step 'ruff' { ruff check src tools }
    } else {
        Write-Host '    ruff not installed; skipping (pip install -r requirements-dev.txt)' -ForegroundColor DarkGray
    }
    if (Get-Command mypy -ErrorAction SilentlyContinue) {
        Invoke-Step 'mypy' { mypy }
    } else {
        Write-Host '    mypy not installed; skipping' -ForegroundColor DarkGray
    }
}

# End-to-end exercise against the in-memory stores. No database, no network -- but it walks a real
# device conversation (handshake, options, ATTLOG, retry, OPERLOG, commands, acks) and asserts the
# responses byte for byte, then drives the same WSGI application object IIS serves.
Invoke-Step 'protocol smoke test' { & $python tools/smoke_test.py }

# web.config is parsed as XML by IIS; a malformed one fails at request time with an unhelpful 500. Both
# sites are checked: the collector's deploy/web.config and the console's deploy/web.config.admin. XML also
# forbids a double hyphen inside a comment, and both files carry prose that once tripped exactly that, so
# each comment is scanned for it with a message that names the file and line.
Invoke-Step 'web.config files are well-formed XML' {
    $bad = 0
    foreach ($file in (Get-ChildItem 'deploy/web.config*' -File)) {
        $raw = Get-Content $file.FullName -Raw
        try {
            [xml]$raw | Out-Null
        } catch {
            $bad++
            Write-Host "    FAIL $($file.Name): $($_.Exception.Message)" -ForegroundColor Red
        }
        foreach ($m in [regex]::Matches($raw, '(?s)<!--(.*?)-->')) {
            if ($m.Groups[1].Value -match '--') {
                $bad++
                $line = ($raw.Substring(0, $m.Index) -split "`n").Count
                Write-Host "    FAIL $($file.Name): double hyphen inside a comment near line $line" -ForegroundColor Red
            }
        }
    }
    $global:LASTEXITCODE = $bad
}

# The deploy scripts are the part an operator runs under pressure; a syntax error there is found at the
# worst possible moment.
Invoke-Step 'deploy scripts parse' {
    $bad = 0
    foreach ($file in (Get-ChildItem 'deploy/*.ps1')) {
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$errors)
        if ($errors.Count) {
            $bad++
            Write-Host "    FAIL $($file.Name)" -ForegroundColor Red
            $errors | ForEach-Object { Write-Host "      line $($_.Extent.StartLineNumber): $($_.Message)" -ForegroundColor Red }
        }
    }
    $global:LASTEXITCODE = $bad
}

# PowerShell 5.1 reads a BOM-less .ps1 as ANSI, so any byte above 0x7F is decoded in the host code page:
# an em dash in a comment came back as a smart closing quote, terminated a string mid-line, and reported a
# parse error pointing somewhere else entirely. Both halves are checked - the BOM has to be there, and
# nothing above 0x7F may follow it. Only scripts this repository owns are scanned: caches, virtual
# environments and build output are skipped, because a vendored script nobody here controls would make the
# gate fail for reasons no commit can fix.
$repoRoot = $PSScriptRoot
Invoke-Step '.ps1 encoding' {
    $bad = 0
    $skip = '\\(\.git|\.venv|venv|__pycache__|\.mypy_cache|\.pytest_cache|\.ruff_cache|node_modules|obj|bin|dist|build)\\'
    $files = Get-ChildItem -Path $repoRoot -Filter '*.ps1' -File -Recurse -Force |
        Where-Object { $_.FullName -notmatch $skip } | Sort-Object FullName
    foreach ($file in $files) {
        $name = $file.FullName.Substring($repoRoot.Length + 1)
        $problems = @()
        $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
            $start = 3
        } else {
            $start = 0
            $problems += 'no UTF-8 byte order mark: PowerShell 5.1 reads this file as ANSI, not UTF-8'
        }
        $line = 1
        $column = 1
        $found = 0
        for ($i = $start; $i -lt $bytes.Length; $i++) {
            $b = $bytes[$i]
            if ($b -gt 0x7F) {
                $found++
                if ($found -le 5) {
                    $problems += ('line {0} byte {1}: 0x{2} is above 0x7F - use plain ASCII hyphens and quotes' -f $line, $column, $b.ToString('X2'))
                }
            }
            if ($b -eq 0x0A) { $line++; $column = 1 } else { $column++ }
        }
        if ($found -gt 5) { $problems += "and $($found - 5) more bytes above 0x7F" }
        if ($problems.Count) {
            $bad++
            Write-Host "    FAIL $name" -ForegroundColor Red
            $problems | ForEach-Object { Write-Host "      $_" -ForegroundColor Red }
        }
    }
    $global:LASTEXITCODE = $bad
}

# Two failures this repository actually had, both in grant-least-privilege.sql, both free to catch here:
#   1. A .sql file without batch separators is one batch, so a single compile error aborts every statement
#      in it. A lone GO at the end of the file separates nothing -- everything before it is still one
#      batch -- so it does not count.
#   2. T-SQL GRANT takes a literal principal identifier. A variable is error 102, raised at parse time,
#      which in a single-batch file takes the whole file down with it.
Invoke-Step '.sql batch separators' {
    $bad = 0
    foreach ($file in (Get-ChildItem 'src/adms/db/sql' -Filter '*.sql' -File -Recurse | Sort-Object Name)) {
        $problems = @()
        $code = Get-SqlCodeOnly ([System.IO.File]::ReadAllText($file.FullName))
        $lines = $code -split "`r?`n"

        $lastContent = -1
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match '\S') { $lastContent = $i }
        }
        $separators = 0
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match '^\s*GO\s*;?\s*$' -and $i -lt $lastContent) { $separators++ }
        }
        if ($separators -eq 0) {
            $problems += 'no batch separator: needs GO on a line of its own, with statements after it'
        }

        foreach ($match in [regex]::Matches($code, '(?is)\bGRANT\b[^;]*?\bTO\s+@\w*')) {
            $line = ($code.Substring(0, $match.Index) -split "`n").Count
            $text = ($match.Value -replace '\s+', ' ')
            $problems += "line ${line}: GRANT to a variable - T-SQL error 102 at parse time: $text"
        }

        if ($problems.Count) {
            $bad++
            Write-Host "    FAIL $($file.Name)" -ForegroundColor Red
            $problems | ForEach-Object { Write-Host "      $_" -ForegroundColor Red }
        }
    }
    $global:LASTEXITCODE = $bad
}

# The property suite (tests/), added alongside the smoke test rather than instead of it: the smoke test
# is the byte-level firmware contract, this is where per-unit red/green signal and the design's
# correctness properties live. Skipped, not failed, when pytest is not installed -- exactly like ruff and
# mypy above -- so the default build still needs nothing but Python. pytest's own suite runs entirely
# against composition.build_fake_service and a recording cursor: no database, no ODBC driver, no network.
# Run through '$python -m pytest' rather than a bare 'pytest' command: the module form puts the repo
# root on sys.path the same way every 'python -m pytest -q' in this project's own task history does,
# and a bare console-script invocation does not, which would otherwise fail an import for a reason that
# has nothing to do with the test itself.
& $python -m pytest --version *> $null
if ($LASTEXITCODE -eq 0) {
    Invoke-Step 'pytest' { & $python -m pytest -q }
} else {
    Write-Host '    pytest not installed; skipping (pip install -r requirements-dev.txt)' -ForegroundColor DarkGray
}

Write-Host ''
Write-Host 'All checks passed.' -ForegroundColor Green
