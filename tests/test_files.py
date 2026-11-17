"""
The file checks the correctness properties do not reach.

The design's coverage note routes a whole column of approved criteria to "build-time file check" or
"build-time source scan". Two of those live in ``build.ps1`` as gates; the rest lived nowhere. They
live here, as tests, for one reason: a failing gate says "the build failed", while a failing test says
which file broke which clause. ``build.ps1`` keeps its two gates -- this file does not replace them,
and the `.ps1`/`.sql` checks below deliberately duplicate them so the suite is a complete statement of
what the shipped files must look like on its own.

**This module implements none of the design's 72 correctness properties.** Every assertion here traces
to a requirement clause instead, named in the test's own docstring. A file check cannot observe
behaviour, so nothing below should be read as evidence that anything runs -- only that what is shipped
says what the requirements say it must.

Two scoping decisions are stated here rather than buried, because a reader who does not know about them
would reasonably think the check is broken:

* **The `vw_ADMS_*` and WSGI scans cover the collector, not the console.** Requirement 23.12 binds the
  Collector, and Requirement 29.1 *requires* the console to be a second WSGI application with its own
  process. ``adms.admin.store`` reads three ``vw_ADMS_*`` views on purpose -- it is the operator UI, and
  those views exist for exactly that. A repo-wide scan would contradict 29.1, so ``adms/admin`` is out
  of scope and named as such.
* **Prose is not code.** ``grant-least-privilege.sql`` contains the string ``state_desc`` inside a
  comment explaining that no such column exists, and discusses ``GRANT ... TO @Principal`` in the same
  breath. A naive scan fails on the design's own words. Every `.sql` scan therefore runs over
  comment-stripped text, the way ``build.ps1``'s ``Get-SqlCodeOnly`` does, and the Python scans run over
  source with comments and docstrings blanked out for the same reason -- a module that *mentions*
  waitress in a docstring is not a module that *uses* it.
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
DEPLOY = REPO / "deploy"
SRC = REPO / "src"
COLLECTOR = SRC / "adms"
SQL_DIR = COLLECTOR / "db" / "sql"
WEB_CONFIG = DEPLOY / "web.config"
WEB_CONFIG_ADMIN = DEPLOY / "web.config.admin"
REQUIREMENTS = REPO / "requirements.txt"
ENV_EXAMPLE = REPO / ".env.example"

#: Caches, virtual environments and build output are skipped for the same reason ``build.ps1`` skips
#: them: a vendored script nobody here controls would make the check fail for reasons no commit can fix.
_SKIP_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "node_modules",
        "obj",
        "bin",
        "dist",
        "build",
    }
)

#: Tables and procedures the legacy LAYCONG31 system owns. Nothing this repository ships may create,
#: alter or drop any of them (Requirement 17.1).
LEGACY_OBJECTS = frozenset(
    {"MAYCHAMCONG", "NHANVIEN", "CheckInOut", "CheckInOut_add", "TEMPLATE", "Face"}
)

#: Package names that would mean an object-relational mapper had arrived (Requirement 17.9).
ORM_PACKAGES = (
    "sqlalchemy",
    "django",
    "peewee",
    "pony",
    "tortoise",
    "sqlmodel",
    "ormar",
    "alembic",
    "sqlobject",
    "dataset",
)


# ---- Collecting the files under test --------------------------------------------------------


def _walk(root: Path, suffix: str) -> list[Path]:
    return sorted(
        path
        for path in root.rglob(f"*{suffix}")
        if not _SKIP_DIRS.intersection(path.relative_to(root).parts[:-1])
    )


def rel(path: Path) -> str:
    """A path as a test id and as an error message reads best relative to the repository root."""
    return path.relative_to(REPO).as_posix()


PS1_FILES = _walk(REPO, ".ps1")
SQL_FILES = _walk(SQL_DIR, ".sql")
#: The collector's own modules. ``adms/admin`` is the console: a separate application by Requirement
#: 29.1, with its own hosting and its own view access. ``adms/pull`` is likewise a separate,
#: run-by-hand tool (see its own package docstring) -- it never sits on the push request path this
#: requirement protects, and its CLI legitimately prints ``vw_ADMS_*`` view names for an operator to
#: query, the same way the console legitimately reads them.
COLLECTOR_MODULES = [
    p
    for p in _walk(COLLECTOR, ".py")
    if "admin" not in p.relative_to(COLLECTOR).parts and "pull" not in p.relative_to(COLLECTOR).parts
]
ALL_PYTHON = _walk(SRC, ".py") + _walk(REPO / "tools", ".py")

PS1_IDS = [rel(p) for p in PS1_FILES]
SQL_IDS = [rel(p) for p in SQL_FILES]
COLLECTOR_IDS = [rel(p) for p in COLLECTOR_MODULES]
PY_IDS = [rel(p) for p in ALL_PYTHON]


def test_the_scan_found_the_files_it_expects() -> None:
    """
    A guard on the guards.

    Most checks below are searches for something that must be absent, and a search over an empty file
    list passes silently. That failure mode is worse than the ones this module exists to catch, so the
    counts are asserted first: five `.ps1` files, three `.sql` files, and a collector package.
    """
    assert len(PS1_FILES) >= 7, f"expected at least seven .ps1 files, found {PS1_IDS}"
    assert len(SQL_FILES) >= 4, f"expected at least four .sql files, found {SQL_IDS}"
    assert len(COLLECTOR_MODULES) >= 10, f"expected the collector package, found {COLLECTOR_IDS}"
    assert WEB_CONFIG.is_file(), f"{rel(WEB_CONFIG)} is missing"
    assert WEB_CONFIG_ADMIN.is_file(), f"{rel(WEB_CONFIG_ADMIN)} is missing"
    for script in ("create-admin-user.ps1", "install-admin-site.ps1"):
        assert (DEPLOY / script).is_file(), f"deploy/{script} is missing"


# ---- Reading files the way the tools that consume them do -----------------------------------


def sql_code_only(text: str) -> str:
    """
    Blank out ``/* */`` and ``--`` comment text, preserving line and column positions.

    A direct port of ``build.ps1``'s ``Get-SqlCodeOnly``, and it has to be: a `.sql` file's comments are
    prose, and the corrected grant script's prose discusses the very patterns these checks reject. Line
    and column are preserved so a reported line number still matches the file.
    """
    out: list[str] = []
    in_block = False
    i = 0
    while i < len(text):
        char = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if in_block:
            if char == "*" and nxt == "/":
                in_block = False
                out.append("  ")
                i += 2
                continue
            out.append(char if char in "\r\n" else " ")
            i += 1
            continue
        if char == "/" and nxt == "*":
            in_block = True
            out.append("  ")
            i += 2
            continue
        if char == "-" and nxt == "-":
            while i < len(text) and text[i] != "\n":
                out.append(" ")
                i += 1
            continue
        out.append(char)
        i += 1
    return "".join(out)


def python_code_only(source: str) -> str:
    """
    Blank out comments and docstrings, preserving line and column positions.

    Needed because the interesting scans are all "does this module *use* X", and the modules that must
    not use waitress or a ``vw_ADMS_*`` view are precisely the ones whose docstrings explain why. String
    literals that are *not* docstrings are left alone: SQL text is code, and a view name inside a
    statement is exactly what Requirement 23.12 forbids.
    """
    rows = [list(line) for line in source.splitlines(keepends=True)]
    docstrings: set[tuple[int, int]] = set()
    for node in ast.walk(ast.parse(source)):
        body = getattr(node, "body", None)
        if not isinstance(body, list):
            continue
        for stmt in body:
            if (
                isinstance(stmt, ast.Expr)
                and isinstance(stmt.value, ast.Constant)
                and isinstance(stmt.value.value, str)
            ):
                docstrings.add((stmt.value.lineno, stmt.value.col_offset))

    def blank(start: tuple[int, int], end: tuple[int, int]) -> None:
        start_line, start_col = start
        end_line, end_col = end
        for line_no in range(start_line, end_line + 1):
            row = rows[line_no - 1]
            first = start_col if line_no == start_line else 0
            last = end_col if line_no == end_line else len(row)
            for index in range(first, min(last, len(row))):
                if row[index] not in "\r\n":
                    row[index] = " "

    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.COMMENT or (
            token.type == tokenize.STRING and token.start in docstrings
        ):
            blank(token.start, token.end)
    return "".join("".join(row) for row in rows)


def ps1_statements(text: str) -> str:
    """
    Join PowerShell backtick line continuations, so one statement is one line.

    ``deploy/verify.ps1``'s handshake request is spread over two lines that way, and a per-line search
    for a parameter on a continued statement finds nothing.
    """
    return re.sub(r"`\r?\n\s*", " ", text)


def ps1_code_only(text: str) -> str:
    """
    Blank ``<# #>`` block comments and ``#`` line comments, preserving line and column positions.

    Same reasoning as ``sql_code_only`` and ``python_code_only``: ``create-admin-user.ps1``'s own
    ``.DESCRIPTION`` explains why it avoids ``python -c`` by writing the forbidden form out, so a scan
    over raw text would reject the script that does the right thing. String literals are left alone --
    a here-string carrying the Python program is code, not prose.
    """
    out: list[str] = []
    in_block = False
    i = 0
    while i < len(text):
        char = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if in_block:
            if char == "#" and nxt == ">":
                in_block = False
                out.append("  ")
                i += 2
                continue
            out.append(char if char in "\r\n" else " ")
            i += 1
            continue
        if char == "<" and nxt == "#":
            in_block = True
            out.append("  ")
            i += 2
            continue
        if char == "#":
            while i < len(text) and text[i] != "\n":
                out.append(" ")
                i += 1
            continue
        out.append(char)
        i += 1
    return "".join(out)


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def read_text(path: Path) -> str:
    """UTF-8 with the BOM discarded, which is how PowerShell and ``sqlcmd`` read these files."""
    return path.read_text(encoding="utf-8-sig")


def ps1_param_block(text: str) -> str:
    """
    The script's top-level ``param(...)`` block, bracket-matched rather than regex-matched.

    A parameter check has to be about the parameter block and nothing else: ``set-db-connection.ps1``
    legitimately holds a ``$password`` local and reads ``ADMS_DB_PASSWORD``, and a whole-file search for
    the word would reject a script that does the right thing.
    """
    match = re.search(r"(?im)^\s*param\s*\(", text)
    assert match, "no param( block found"
    depth = 0
    for index in range(match.end() - 1, len(text)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return text[match.end() : index]
    raise AssertionError("unterminated param( block")


def declared_parameters(param_block: str) -> list[tuple[str, str]]:
    """
    ``(type, name)`` for every parameter declared in a ``param(...)`` block.

    The type is ``""`` for an untyped parameter. Attribute blocks such as
    ``[Parameter(Mandatory = $true)]`` carry parentheses and so never match the type pattern, which is
    what keeps ``$true`` out of the result.
    """
    pattern = r"(?:\[\s*(\w+)\s*\]\s*)?\$(\w+)\s*(?==|,|\)|$)"
    return [
        ((match.group(1) or "").lower(), match.group(2))
        for match in re.finditer(pattern, param_block, re.MULTILINE)
    ]


# ---- .ps1 encoding: Requirement 30.7 --------------------------------------------------------


@pytest.mark.parametrize("path", PS1_FILES, ids=PS1_IDS)
def test_ps1_starts_with_a_utf8_byte_order_mark(path: Path) -> None:
    """
    PowerShell 5.1 reads a BOM-less `.ps1` as ANSI, decoding every byte above 0x7F in the host code
    page. An em dash in a comment came back as a smart closing quote, terminated a string mid-line and
    reported a parse error pointing somewhere else entirely.

    Validates: Requirements 30.7
    """
    head = path.read_bytes()[:3]
    assert head == b"\xef\xbb\xbf", (
        f"{rel(path)} does not begin with a UTF-8 byte order mark (first bytes {head!r}); "
        "PowerShell 5.1 will read it as ANSI"
    )


@pytest.mark.parametrize("path", PS1_FILES, ids=PS1_IDS)
def test_ps1_is_ascii_after_the_byte_order_mark(path: Path) -> None:
    """
    The other half of the same failure: with a BOM present the file decodes, but an ASCII-only body is
    what makes it decode the same way everywhere. Plain hyphens, plain quotes.

    Validates: Requirements 30.7
    """
    data = path.read_bytes()
    body = data[3:] if data[:3] == b"\xef\xbb\xbf" else data
    offenders = [(index, byte) for index, byte in enumerate(body) if byte > 0x7F]
    assert not offenders, (
        f"{rel(path)} has {len(offenders)} byte(s) above 0x7F, first at offset {offenders[0][0]} "
        f"(0x{offenders[0][1]:02X}) - use plain ASCII hyphens and quotes"
    )


# ---- Verification paths: Requirements 30.16, 22.13, 26.13, 26.14, 26.19 ---------------------


@pytest.mark.parametrize("path", PS1_FILES, ids=PS1_IDS)
def test_no_invoke_webrequest_with_a_body(path: Path) -> None:
    """
    ``Invoke-WebRequest -Body`` mangles a tab-separated body. It imitated a parser bug once and cost an
    hour chasing a fault that did not exist. Bodyless GETs through ``Invoke-WebRequest`` are fine, and
    ``deploy/verify.ps1`` uses exactly those; anything carrying a body uses Python or
    ``curl.exe --data-binary``.

    Validates: Requirements 30.16
    """
    statements = ps1_statements(read_text(path))
    offenders = [
        (line_of(statements, match.start()), match.group(0).strip())
        for match in re.finditer(
            r"(?im)^.*\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b.*?-Body\b.*$", statements
        )
    ]
    assert not offenders, (
        f"{rel(path)} sends a body through Invoke-WebRequest, which mangles tab-separated text: "
        f"{offenders}"
    )


def test_set_db_connection_exposes_no_plain_password_parameter() -> None:
    """
    A ``-Password`` parameter lands in PowerShell history, in the console scrollback and in any
    transcript, which defeats encrypting the value at rest. The script prompts for a ``SecureString`` or
    reads one environment variable, and ``-UseEnvPassword`` is a ``[switch]`` -- a flag, not a value.

    Validates: Requirements 22.13
    """
    block = ps1_param_block(read_text(DEPLOY / "set-db-connection.ps1"))
    offenders = [
        (declared_type or "untyped", name)
        for declared_type, name in declared_parameters(block)
        if re.search(r"(?i)pass(word)?|pwd|secret|credential", name) and declared_type != "switch"
    ]
    assert not offenders, (
        "deploy/set-db-connection.ps1 declares a plain credential parameter, which would put the "
        f"password in PowerShell history: {offenders}"
    )


def test_installer_takes_no_database_credential_parameter() -> None:
    """
    Same reasoning, applied to the installer: it takes no database credential at all, so the credential
    never enters PowerShell history. ``deploy/set-db-connection.ps1`` is the only script that handles
    one, and it prompts.

    Requirement 26.13 -- that a second run of the installer changes nothing already correct -- is **not**
    covered here, and cannot be: idempotence is a claim about what running it twice against a real
    elevated host does, which the design's coverage note assigns to integration. This test covers the
    credential-parameter absence and claims nothing further about Requirement 26.

    Validates: Requirements 26.13
    """
    for installer in ("install-iis.ps1", "install-admin-site.ps1"):
        block = ps1_param_block(read_text(DEPLOY / installer))
        offenders = [
            (declared_type or "untyped", name)
            for declared_type, name in declared_parameters(block)
            if re.search(r"(?i)pass(word)?|pwd|sqluser|sqllogin|credential|connectionstring", name)
        ]
        assert not offenders, f"deploy/{installer} takes a credential as a parameter: {offenders}"


def test_verify_script_writes_nothing() -> None:
    """
    The verification script is read-only, and specifically writes no test row into ``CheckInOut``.
    Pushing a fake punch into a production attendance table behind an operator's back is not something a
    check should do; ``tools/local_server.py --fake`` or a real device is how that gets exercised.

    Validates: Requirements 26.14
    """
    statements = ps1_statements(read_text(DEPLOY / "verify.ps1"))
    forbidden = (
        r"\bINSERT\s+INTO\b",
        r"\bUPDATE\s+\w",
        r"\bDELETE\s+FROM\b",
        r"\bMERGE\s+INTO\b",
        r"\bCheckInOut_add\b",
        r"-Method\s+['\"]?(?:POST|PUT|PATCH|DELETE)",
        r"--data(?:-binary)?\b",
    )
    offenders = [
        (line_of(statements, match.start()), match.group(0).strip())
        for pattern in forbidden
        for match in re.finditer(pattern, statements, re.IGNORECASE)
    ]
    assert not offenders, f"deploy/verify.ps1 performs a write: {offenders}"


def test_verify_script_exits_non_zero_when_a_check_fails() -> None:
    """
    An exit code is the only part of a verification script an automated caller reads.

    This is a file check on the shape of that path -- a failure counter, a zero exit only when it is
    zero, and a non-zero exit otherwise. What the script actually reports against an installed site is
    integration, not this.

    Validates: Requirements 26.19
    """
    text = read_text(DEPLOY / "verify.ps1")
    assert re.search(r"\$script:failures\+\+", text), "no failure counter increment"
    assert re.search(r"if\s*\(\s*\$failures\s+-eq\s+0\s*\)", text), "no guard on the failure count"
    assert re.search(r"(?m)^\s*exit\s+0\s*$", text), "no zero exit"
    assert re.search(r"(?m)^\s*exit\s+1\s*$", text), "no non-zero exit"


# ---- .sql structure: Requirements 23.3, 23.4, 24.8, 24.9, 24.10, 30.8, 30.17 ----------------


@pytest.mark.parametrize("path", SQL_FILES, ids=SQL_IDS)
def test_sql_has_batch_separators(path: Path) -> None:
    """
    A `.sql` file without batch separators is one batch, so a single compile error aborts every
    statement in it -- which is exactly how one unparseable ``GRANT`` took out the other twenty. A lone
    ``GO`` at the end of a file separates nothing, so it does not count.

    Validates: Requirements 23.4, 24.9, 30.8
    """
    lines = sql_code_only(read_text(path)).splitlines()
    last_content = max((i for i, line in enumerate(lines) if line.strip()), default=-1)
    separators = [
        i
        for i, line in enumerate(lines)
        if re.fullmatch(r"\s*GO\s*;?\s*", line) and i < last_content
    ]
    assert separators, (
        f"{rel(path)} has no batch separator with statements after it: it is one batch, so one "
        "compile error aborts all of it"
    )


@pytest.mark.parametrize("path", SQL_FILES, ids=SQL_IDS)
def test_sql_sets_ansi_nulls_and_quoted_identifier_before_creating_anything(path: Path) -> None:
    """
    ``sqlcmd`` defaults ``QUOTED_IDENTIFIER`` off where a management studio session defaults it on, and
    the filtered index on ``ADMS_COMMAND`` fails without it. The automated path is the one that has to
    work, so both options are set before the first ``CREATE`` -- and stored procedures capture them at
    creation time, which is the second reason the order matters.

    Validates: Requirements 23.3
    """
    code = sql_code_only(read_text(path))
    ansi = re.search(r"(?i)\bSET\s+ANSI_NULLS\s+ON\b", code)
    quoted = re.search(r"(?i)\bSET\s+QUOTED_IDENTIFIER\s+ON\b", code)
    assert ansi, f"{rel(path)} never sets ANSI_NULLS ON"
    assert quoted, f"{rel(path)} never sets QUOTED_IDENTIFIER ON"

    first_create = re.search(
        r"(?i)\bCREATE\s+(?:OR\s+ALTER\s+)?(?:TABLE|VIEW|PROC|PROCEDURE|INDEX)\b", code
    )
    if first_create is None:
        return
    for name, match in (("ANSI_NULLS", ansi), ("QUOTED_IDENTIFIER", quoted)):
        assert match.start() < first_create.start(), (
            f"{rel(path)} sets {name} on line {line_of(code, match.start())}, after the first CREATE "
            f"on line {line_of(code, first_create.start())}"
        )


@pytest.mark.parametrize("path", SQL_FILES, ids=SQL_IDS)
def test_sql_grants_to_a_literal_principal(path: Path) -> None:
    """
    T-SQL ``GRANT`` takes an identifier and rejects a variable at parse time with error 102. In a
    single-batch file that takes the whole file down, which is Defect 1 in one sentence.

    The scan runs over comment-stripped text on purpose: the corrected script's own header explains the
    mistake using the forbidden syntax, and a naive scan would reject the explanation.

    Validates: Requirements 24.8
    """
    code = sql_code_only(read_text(path))
    offenders = [
        (line_of(code, match.start()), " ".join(match.group(0).split()))
        for match in re.finditer(r"(?is)\bGRANT\b[^;]*?\bTO\s+@\w*", code)
    ]
    assert not offenders, (
        f"{rel(path)} grants to a variable - T-SQL error 102 at parse time: {offenders}"
    )


@pytest.mark.parametrize("path", SQL_FILES, ids=SQL_IDS)
def test_sql_never_queries_state_desc(path: Path) -> None:
    """
    ``sys.fn_my_permissions`` exposes ``entity_name``, ``subentity_name`` and ``permission_name``. It has
    no ``state_desc`` column, and a query naming one fails -- a mistake already made once.

    Comment-stripped again, and here it is load-bearing rather than incidental:
    ``grant-least-privilege.sql`` deliberately carries the string ``state_desc`` inside a comment saying
    the column does not exist. That comment is design-specified, so a scan over raw text would fail on
    the fix.

    Validates: Requirements 24.10, 30.17
    """
    code = sql_code_only(read_text(path))
    offenders = [line_of(code, match.start()) for match in re.finditer(r"(?i)\bstate_desc\b", code)]
    assert not offenders, (
        f"{rel(path)} names state_desc in code on line(s) {offenders}; sys.fn_my_permissions has no "
        "such column"
    )


def test_grant_script_states_what_is_withheld_and_why() -> None:
    """
    A least-privilege script is only reviewable if it says what it deliberately does not grant. Asserted
    against the raw text, not the code: this block *is* a comment, and that is the point.

    Validates: Requirements 24.10
    """
    text = read_text(SQL_DIR / "grant-least-privilege.sql")
    assert re.search(r"(?i)deliberately\s+NOT\s+granted", text), "no withheld-permissions section"
    for clause in (
        r"(?i)DELETE\s*/\s*UPDATE\s+on\s+CheckInOut",
        r"(?i)DELETE\s+on\s+NHANVIEN",
        r"(?i)EXECUTE\s+on\s+dbo\.ADMS_PurgeArchives",
        r"(?i)any\s+DDL",
    ):
        assert re.search(clause, text), f"the withheld-permissions section does not cover {clause!r}"


def test_grant_script_names_one_principal_only() -> None:
    """
    The collector's login and the console's login are two logins with disjoint grants. What a file can
    check is the collector half: every grant in this script targets ``adms_collector`` and no other
    principal, so nothing here can widen a second login by accident.

    The console's own grant script is not in this repository -- it belongs to the admin-console spec --
    so the disjointness of the two permission sets is an integration check against the instance, not
    this test.

    Validates: Requirements 29.3
    """
    code = sql_code_only(read_text(SQL_DIR / "grant-least-privilege.sql"))
    pattern = r"(?is)\bGRANT\b[^;]*?\bTO\s+(\[?[\w\\]+\]?)"
    principals = {match.group(1) for match in re.finditer(pattern, code)}
    assert principals == {"adms_collector"}, (
        f"grant-least-privilege.sql grants to {sorted(principals)}; expected adms_collector alone"
    )


# ---- The console grant script: Requirements 19.3-19.9 ---------------------------------------

CONSOLE_GRANT = SQL_DIR / "grant-console-privilege.sql"

#: The console must never touch these. CheckInOut is the attendance record and CheckInOut_add is the
#: collector's attendance-write path; a grant on either would let the login-facing site read or rewrite
#: attendance history.
CONSOLE_FORBIDDEN = ("CheckInOut_add", "CheckInOut")

#: Identity and biometric tables the console may read and edit in place (device-admin rights and the
#: device password), but must never be able to delete from.
CONSOLE_NO_DELETE = ("NHANVIEN", "TEMPLATE", "Face")


def test_console_grant_names_one_principal_only() -> None:
    """
    Property (task 11.2): every grant in the console script targets ``adms_console`` and no other
    principal, so nothing here can widen the collector's login -- or any other -- by accident.

    Validates: Requirements 19.3
    """
    code = sql_code_only(read_text(CONSOLE_GRANT))
    pattern = r"(?is)\bGRANT\b[^;]*?\bTO\s+(\[?[\w\\]+\]?)"
    principals = {match.group(1) for match in re.finditer(pattern, code)}
    assert principals == {"adms_console"}, (
        f"grant-console-privilege.sql grants to {sorted(principals)}; expected adms_console alone"
    )


@pytest.mark.parametrize("obj", CONSOLE_FORBIDDEN)
def test_console_grant_touches_no_pii_object(obj: str) -> None:
    """
    Property (task 11.2): the console login is granted nothing on any PII or attendance-write object.
    Asserted against comment-stripped code so the withheld-permissions section, which *names* these
    objects to say they are withheld, cannot satisfy or trip the check.

    Validates: Requirements 19.8, 19.9
    """
    code = sql_code_only(read_text(CONSOLE_GRANT))
    # A GRANT ... ON <obj> ... in code -- with or without a dbo. prefix, case-insensitive, word-bounded
    # so CheckInOut does not match CheckInOut_add.
    pattern = rf"(?is)\bGRANT\b[^;]*?\bON\b\s+(?:dbo\.)?\b{re.escape(obj)}\b"
    match = re.search(pattern, code)
    assert match is None, (
        f"grant-console-privilege.sql grants a permission on {obj}, which the console must never touch: "
        f"...{code[match.start():match.start() + 80]!r}..."
    )


@pytest.mark.parametrize("obj", CONSOLE_NO_DELETE)
def test_console_grant_never_deletes_identity_or_biometrics(obj: str) -> None:
    """
    The console edits one privilege column and the device password in place; it never removes a person
    or their enrolment data. Asserted against comment-stripped code, like the PII check above.
    """
    code = sql_code_only(read_text(CONSOLE_GRANT))
    pattern = rf"(?is)\bGRANT\b[^;]*?\bDELETE\b[^;]*?\bON\b\s+(?:dbo\.)?\b{re.escape(obj)}\b"
    match = re.search(pattern, code)
    assert match is None, (
        f"grant-console-privilege.sql grants DELETE on {obj}: "
        f"...{code[match.start():match.start() + 80]!r}..."
    )


def test_console_grant_states_what_is_withheld_and_why() -> None:
    """
    A least-privilege script is only reviewable if it says what it deliberately does not grant. Asserted
    against the raw text, not the code: this block *is* a comment, and that is the point.

    Validates: Requirements 19.9
    """
    text = read_text(CONSOLE_GRANT)
    assert re.search(r"(?i)deliberately\s+NOT\s+granted", text), "no withheld-permissions section"
    for clause in (
        r"(?i)EXECUTE\s+on\s+CheckInOut_add",
        r"(?i)DELETE\s+on\s+NHANVIEN",
        r"(?i)TEMPLATE",
        r"(?i)any\s+DDL",
    ):
        assert re.search(clause, text), f"the withheld-permissions section does not cover {clause!r}"


def test_console_grant_covers_its_own_tables_and_the_purge_proc() -> None:
    """
    The positive half: the console must be able to write its own tables and purge expired sessions,
    or the site cannot function. A withheld-everything script would pass the refusal checks above while
    being useless.

    Validates: Requirements 19.3, 19.4
    """
    code = sql_code_only(read_text(CONSOLE_GRANT))
    assert re.search(r"(?is)\bGRANT\b[^;]*\bDELETE\b[^;]*\bON\b\s+dbo\.APP_USER\b", code), (
        "the console cannot DELETE from APP_USER; last-admin recovery and user removal would fail"
    )
    assert re.search(r"(?is)\bGRANT\b[^;]*\bDELETE\b[^;]*\bON\b\s+dbo\.APP_SESSION\b", code), (
        "the console cannot DELETE from APP_SESSION; session revocation would fail"
    )
    assert re.search(r"(?is)\bGRANT\s+EXECUTE\s+ON\s+dbo\.APP_PurgeExpiredSessions\b", code), (
        "the console cannot EXECUTE APP_PurgeExpiredSessions; expired sessions would never be purged"
    )


# ---- The schema script's DDL text: Requirements 13.8, 13.9, 13.11, 17.2 ---------------------


def _adms_device_ddl() -> str:
    """The ``CREATE TABLE dbo.ADMS_DEVICE`` body, comment-stripped."""
    code = sql_code_only(read_text(SQL_DIR / "adms-schema.sql"))
    match = re.search(r"(?is)CREATE\s+TABLE\s+dbo\.ADMS_DEVICE\s*\((.*?)\n\s*\);", code)
    assert match, "adms-schema.sql does not create dbo.ADMS_DEVICE"
    return match.group(1)


def test_adms_device_enabled_defaults_to_zero() -> None:
    """
    A newly discovered device must be switched on by a person: the serial number is the entire
    credential the ADMS protocol offers, and it is printed on a label on the outside of the unit.

    Validates: Requirements 13.8
    """
    ddl = _adms_device_ddl()
    assert re.search(r"(?is)\bEnabled\b.*?\bDEFAULT\s*\(\s*0\s*\)", ddl), (
        "ADMS_DEVICE.Enabled does not default to 0, so a discovered device would authorise itself"
    )


def test_adms_device_mamcc_is_nullable() -> None:
    """
    The serial-to-machine mapping cannot be derived from anything a device sends, so the column has to
    be able to be empty while a device is registered but not yet linked -- the state that answers 503
    rather than 401.

    Validates: Requirements 13.9
    """
    ddl = _adms_device_ddl()
    match = re.search(r"(?im)^\s*MaMCC\s+NCHAR\(8\)\s+(NOT\s+NULL|NULL)\b", ddl)
    assert match, f"no MaMCC column declaration found in the ADMS_DEVICE DDL: {ddl!r}"
    assert match.group(1).upper() == "NULL", "ADMS_DEVICE.MaMCC is NOT NULL; it must be nullable"


@pytest.mark.parametrize("path", SQL_FILES, ids=SQL_IDS)
def test_no_foreign_key_from_adms_device_to_maychamcong(path: Path) -> None:
    """
    ``MaMCC`` is space-padded ``NCHAR(8)`` and the legacy system rewrites machine rows on its own
    schedule; a constraint here would make an unrelated legacy maintenance script fail with an error
    pointing at this service. The join is documented instead of enforced.

    Validates: Requirements 17.2
    """
    code = sql_code_only(read_text(path))
    offenders = [
        (line_of(code, match.start()), " ".join(match.group(0).split()))
        for match in re.finditer(r"(?is)\bREFERENCES\s+(?:dbo\s*\.\s*)?MAYCHAMCONG\b", code)
    ]
    offenders += [
        (line_of(code, match.start()), " ".join(match.group(0).split()))
        for match in re.finditer(r"(?is)\bFOREIGN\s+KEY\s*\(\s*MaMCC\s*\)", code)
    ]
    assert not offenders, f"{rel(path)} constrains MaMCC against the legacy schema: {offenders}"


def test_schema_script_states_the_serial_equality_is_unconfirmed() -> None:
    """
    ``MAYCHAMCONG.Serial`` holds 13-digit numeric values while newer models report an alphanumeric
    serial, so seeding the allow-list from it is a guess until someone compares the two.

    **This is a check on what the script states, not on the equality.** Whether ``MAYCHAMCONG.Serial``
    equals what a device sends as ``SN`` cannot be established by reading a file: it needs a device on
    the network, which is task 16.1. Nothing here should be read as covering that.

    Validates: Requirements 13.11
    """
    text = read_text(SQL_DIR / "adms-schema.sql")
    assert re.search(r"(?is)not\s+yet\s+confirmed.*?MAYCHAMCONG\.Serial.*?\bSN\b", text), (
        "adms-schema.sql does not state that the MAYCHAMCONG.Serial = SN equality is unconfirmed"
    )


# ---- deploy/web.config: Requirements 25.14 - 25.19 ------------------------------------------


def web_config_root() -> ET.Element:
    """The parsed document. A local file this repository ships, not untrusted input."""
    return ET.parse(WEB_CONFIG).getroot()


def test_web_config_parses_as_xml() -> None:
    """
    IIS parses this file at request time, so a malformed one surfaces as an unhelpful 500 rather than as
    a parse error. ``build.ps1`` checks it too; this repeats the check so a failure names the file and
    the position.

    Validates: Requirements 25.14
    """
    assert web_config_root().tag == "configuration"


def test_web_config_has_no_double_hyphen_inside_a_comment() -> None:
    """
    XML forbids ``--`` inside a comment. This file was invalid for exactly that reason once, and the
    prose in it uses single punctuation deliberately.

    Checked separately from parsing because the message matters: "there is a double hyphen in the
    comment starting at line N" is actionable where "not well-formed" is not.

    Validates: Requirements 25.14
    """
    text = read_text(WEB_CONFIG)
    offenders = [
        (line_of(text, match.start()), match.group(1)[:60])
        for match in re.finditer(r"<!--(.*?)-->", text, re.DOTALL)
        if "--" in match.group(1)
    ]
    assert not offenders, f"deploy/web.config has a double hyphen inside a comment: {offenders}"


def test_web_config_removes_the_inherited_handler_before_adding_ours() -> None:
    """
    The first matching handler wins, and it may not be ours: an inherited Python or CGI handler from a
    parent configuration has to be removed before the add. Order is the whole assertion.

    Validates: Requirements 25.15
    """
    handlers = web_config_root().find("./system.webServer/handlers")
    assert handlers is not None, "no <handlers> section"
    order = [(child.tag, (child.get("name") or "").lower()) for child in handlers]
    assert ("remove", "aspnetcore") in order, "the inherited handler is never removed"
    assert ("add", "aspnetcore") in order, "the handler is never added"
    assert order.index(("remove", "aspnetcore")) < order.index(
        ("add", "aspnetcore")
    ), f"the handler is added before it is removed: {order}"


def test_web_config_starts_the_serve_entry_through_aspnetcore() -> None:
    """
    The child process is ``adms.hosting.serve`` launched by AspNetCoreModuleV2 out-of-process, with
    stdout captured, 60 seconds allowed for a cold start and a one-minute request timeout -- a device
    gives up at around sixty seconds, so IIS waiting longer serves no purpose. ANCM supplies the
    loopback port via the ASPNETCORE_PORT environment variable, not on the command line, so the
    arguments carry only the module name.

    Validates: Requirements 25.15
    """
    ancm = web_config_root().find("./system.webServer/aspNetCore")
    assert ancm is not None, "no <aspNetCore> section"
    arguments = ancm.get("arguments") or ""
    assert "adms.hosting.serve" in arguments, f"the child is not adms.hosting.serve: {arguments!r}"
    assert ancm.get("hostingModel") == "OutOfProcess", (
        "hostingModel is not OutOfProcess; a Python child cannot be hosted in-process"
    )
    assert ancm.get("stdoutLogEnabled") == "true", (
        "stdout capture is off; a failed start is then a bare 502 with nothing to read"
    )
    assert ancm.get("startupTimeLimit") == "60", "start-up allowance is not 60 seconds"
    assert ancm.get("requestTimeout") == "00:01:00", "request timeout is not one minute"


def test_web_config_passes_our_own_error_responses_through() -> None:
    """
    Without this, IIS replaces a plain-text 401 or 503 with an HTML error page, and some firmware reads
    any response as a successful delivery -- then erases the punches it just uploaded.

    Validates: Requirements 25.16
    """
    errors = web_config_root().find("./system.webServer/httpErrors")
    assert errors is not None, "no <httpErrors> section"
    assert errors.get("existingResponse") == "PassThrough", (
        f"existingResponse is {errors.get('existingResponse')!r}; IIS will replace our 401 and 503 "
        "bodies with an HTML error page"
    )


def test_web_config_sets_the_three_request_limits() -> None:
    """
    ADMS puts everything in the query string and some firmware sends long option lists, so the URL and
    query limits matter as much as the content length -- which matches the adapter's own 32 MiB cap.

    Validates: Requirements 25.17
    """
    limits = web_config_root().find(
        "./system.webServer/security/requestFiltering/requestLimits"
    )
    assert limits is not None, "no <requestLimits> element"
    assert limits.get("maxAllowedContentLength") == "33554432", "content length is not 33,554,432"
    assert limits.get("maxQueryString") == "8192", "query string limit is not 8,192 characters"
    assert limits.get("maxUrl") == "4096", "URL limit is not 4,096 characters"


def test_web_config_removes_the_x_powered_by_header() -> None:
    """
    Nothing on an unauthenticated device network needs to know what the platform is.

    Validates: Requirements 25.18
    """
    headers = web_config_root().find("./system.webServer/httpProtocol/customHeaders")
    assert headers is not None, "no <customHeaders> section"
    removed = [(child.get("name") or "").lower() for child in headers if child.tag == "remove"]
    assert "x-powered-by" in removed, f"X-Powered-By is not removed: {removed}"


def web_config_environment() -> dict[str, str]:
    variables = web_config_root().findall(
        "./system.webServer/aspNetCore/environmentVariables/environmentVariable"
    )
    return {(v.get("name") or ""): (v.get("value") or "") for v in variables}


def documented_environment() -> list[str]:
    """
    The variables ``.env.example`` documents, minus the connection string.

    ``.env.example`` is the deployment's own statement of what an operator sets, and its header points
    at ``web.config`` for the IIS host -- so the two are two renderings of one list, and drift between
    them is a real defect in one of them. Deriving the list from ``config.py`` instead would name about
    twenty further settings that exist only as documented defaults; whether Requirement 25.19 means
    those too is a question about its wording, raised in the task's completion note rather than decided
    by weakening or widening this check.
    """
    names = re.findall(r"(?m)^([A-Z][A-Z0-9_]*)\s*=", read_text(ENV_EXAMPLE))
    return [name for name in dict.fromkeys(names) if name != "ADMS_SQL_CONNECTION"]


@pytest.mark.parametrize("name", documented_environment())
def test_web_config_sets_every_documented_non_secret_variable(name: str) -> None:
    """
    Every non-secret variable the collector reads is set here, so an operator changes behaviour by
    editing one file rather than by discovering a variable in the source.

    Validates: Requirements 25.19
    """
    assert name in web_config_environment(), (
        f"{name} is documented in .env.example but is not set in deploy/web.config"
    )


def test_web_config_carries_no_connection_string() -> None:
    """
    ``web.config`` is plaintext, sits in the site folder, is overwritten by a redeploy and is copied by
    every backup. The connection string lives DPAPI-encrypted in the registry instead.

    Validates: Requirements 25.19, 22.16
    """
    assert "ADMS_SQL_CONNECTION" not in web_config_environment(), (
        "deploy/web.config sets the connection string"
    )
    text = read_text(WEB_CONFIG)
    for pattern in (
        r"(?i)\bPWD\s*=",
        r"(?i)\bUID\s*=",
        r"(?i)DRIVER\s*=\s*\{",
        r"(?i)\bDATABASE\s*=\s*\w",
    ):
        match = re.search(pattern, text)
        assert match is None, (
            f"deploy/web.config looks like it carries connection details on line "
            f"{line_of(text, match.start()) if match else 0}: {pattern!r}"
        )


# ---- The console site: web.config.admin and the bootstrap script ----------------------------


def admin_config_root() -> ET.Element:
    """The parsed console web.config. A local file this repository ships, not untrusted input."""
    return ET.parse(WEB_CONFIG_ADMIN).getroot()


def test_admin_web_config_parses_as_xml() -> None:
    """
    IIS parses this file at request time, so a malformed one surfaces as an unhelpful 500 rather than as
    a parse error. ``build.ps1`` checks it too; this repeats the check so a failure names the file.

    Validates: Requirements 25.14 (console site)
    """
    assert admin_config_root().tag == "configuration"


def test_admin_web_config_has_no_double_hyphen_inside_a_comment() -> None:
    """
    XML forbids ``--`` inside a comment. The prose in this file uses single punctuation deliberately;
    a naming message beats a bare "not well-formed".

    Validates: Requirements 25.14 (console site)
    """
    text = read_text(WEB_CONFIG_ADMIN)
    offenders = [
        (line_of(text, match.start()), match.group(1)[:60])
        for match in re.finditer(r"<!--(.*?)-->", text, re.DOTALL)
        if "--" in match.group(1)
    ]
    assert not offenders, f"deploy/web.config.admin has a double hyphen inside a comment: {offenders}"


def test_admin_web_config_starts_the_console_serve_entry() -> None:
    """
    The console's child process is ``adms.admin.serve`` -- NOT the collector's ``adms.hosting.serve`` --
    on the port IIS chooses, with stdout captured. A copy-paste of the collector's arguments is the
    obvious mistake, so the module name is asserted explicitly.

    The site is fronted by AspNetCoreModuleV2 (ANCM) in out-of-process mode: this machine has ANCM but
    not HttpPlatformHandler. ANCM supplies the loopback port via the ASPNETCORE_PORT environment
    variable, not a command-line placeholder, because ``arguments`` are not env-expanded.

    Validates: Requirements 29.1
    """
    platform = admin_config_root().find("./system.webServer/aspNetCore")
    assert platform is not None, "no <aspNetCore> section"
    arguments = platform.get("arguments") or ""
    assert "adms.admin.serve" in arguments, f"the child is not adms.admin.serve: {arguments!r}"
    assert "adms.hosting.serve" not in arguments, "the console points at the collector's entry point"
    assert platform.get("hostingModel") == "OutOfProcess", "ANCM must run the Python child out-of-process"
    assert platform.get("stdoutLogEnabled") == "true", "stdout capture is off"


def test_admin_web_config_caps_the_body_an_order_below_the_collector() -> None:
    """
    The console receives only form posts, never a photo or template upload, so its body cap is 1 MiB --
    an order of magnitude below the collector's 32 MiB. A tighter cap is one fewer lever for an
    authenticated abuser.

    Validates: Requirements 29.1
    """
    limits = admin_config_root().find(
        "./system.webServer/security/requestFiltering/requestLimits"
    )
    assert limits is not None, "no <requestLimits> element"
    assert limits.get("maxAllowedContentLength") == "1048576", (
        f"console content length is {limits.get('maxAllowedContentLength')!r}, not 1,048,576"
    )


def test_admin_web_config_passes_our_own_error_responses_through() -> None:
    """
    The console renders its own styled 403, 404 and 503 pages; an IIS error page in their place would
    leak the platform and lose the intended wording.

    Validates: Requirements 25.16 (console site)
    """
    errors = admin_config_root().find("./system.webServer/httpErrors")
    assert errors is not None, "no <httpErrors> section"
    assert errors.get("existingResponse") == "PassThrough", (
        f"existingResponse is {errors.get('existingResponse')!r}; IIS will replace the console's pages"
    )


def test_admin_web_config_carries_no_connection_string() -> None:
    """
    ``web.config.admin`` is plaintext, sits in the site folder, is overwritten by a redeploy and is
    copied by every backup. The connection string lives DPAPI-encrypted in the registry instead.

    Validates: Requirements 22.16 (console site)
    """
    variables = admin_config_root().findall(
        "./system.webServer/aspNetCore/environmentVariables/environmentVariable"
    )
    assert variables, "no <environmentVariables> under <aspNetCore>"
    names = {(v.get("name") or "") for v in variables}
    assert "ADMS_SQL_CONNECTION" not in names, "deploy/web.config.admin sets the connection string"
    text = read_text(WEB_CONFIG_ADMIN)
    for pattern in (r"(?i)\bPWD\s*=", r"(?i)\bUID\s*=", r"(?i)DRIVER\s*=\s*\{", r"(?i)\bDATABASE\s*=\s*\w"):
        match = re.search(pattern, text)
        assert match is None, (
            f"deploy/web.config.admin looks like it carries connection details on line "
            f"{line_of(text, match.start()) if match else 0}: {pattern!r}"
        )


def test_create_admin_user_never_puts_the_password_on_a_command_line() -> None:
    """
    The bootstrap script prompts twice with ``Read-Host -AsSecureString`` and hands the password to the
    child Python only through an environment variable, never as a ``python -c`` argument or a positional
    argument -- either of which would put the plaintext on a process command line any other process on
    the host can read.

    Validates: Requirements 18 (bootstrap), 22.13
    """
    text = read_text(DEPLOY / "create-admin-user.ps1")
    code = ps1_statements(ps1_code_only(text))
    assert re.search(r"(?i)Read-Host\s+-AsSecureString", code), (
        "the bootstrap script does not read the password as a SecureString"
    )
    # No `python -c "<inline>"` -- the program must reach the interpreter on stdin ('python -'),
    # so a password interpolated into the source can never land on the command line. Scanned over
    # comment-stripped code, because the .DESCRIPTION explains the rule by writing the forbidden form.
    assert not re.search(r"(?i)\bpython(?:\.exe)?\b[^\n|]*\s-c\b", code), (
        "create-admin-user.ps1 uses 'python -c', which would place the program (and any interpolated "
        "secret) on the command line"
    )
    # The password reaches the child through an env var, cleared afterwards.
    assert re.search(r"\$env:ADMS_NEW_PASSWORD\s*=", text), (
        "the password is not handed to the child through the ADMS_NEW_PASSWORD environment variable"
    )
    assert re.search(r"\$env:ADMS_NEW_PASSWORD\s*=\s*\$null", text), (
        "the ADMS_NEW_PASSWORD environment variable is never cleared after use"
    )


# ---- Source scans: Requirements 17.1, 17.4, 17.9, 23.12, 25.1 ------------------------------

_SQL_DDL_TARGET = re.compile(
    r"\b(CREATE|ALTER|DROP)\s+(?:OR\s+ALTER\s+)?"
    r"(TABLE|VIEW|PROCEDURE|PROC|TRIGGER|FUNCTION|INDEX|SCHEMA)\s+"
    r"(?:\[?\w+\]?\s*\.\s*)?\[?(\w+)\]?",
    re.IGNORECASE,
)
_SQL_INDEX_TARGET = re.compile(
    r"\bCREATE\s+(?:UNIQUE\s+)?(?:CLUSTERED\s+|NONCLUSTERED\s+)?INDEX\s+\[?\w+\]?\s+ON\s+"
    r"(?:\[?\w+\]?\s*\.\s*)?\[?(\w+)\]?",
    re.IGNORECASE,
)
_LEGACY_LOWER = {name.lower() for name in LEGACY_OBJECTS}


@pytest.mark.parametrize("path", SQL_FILES, ids=SQL_IDS)
def test_no_ddl_against_the_legacy_schema_in_sql(path: Path) -> None:
    """
    Nothing this service ships may create, alter or drop a legacy object -- not even an index. The point
    is that the next LAYCONG31 upgrade is not blocked by a constraint someone else created.

    The scan reads the DDL *target*, not the whole statement, so a view that selects ``FROM CheckInOut``
    is unaffected: reading the legacy schema is the entire job.

    Validates: Requirements 17.1
    """
    code = sql_code_only(read_text(path))
    offenders: list[tuple[int, str]] = []
    for match in _SQL_DDL_TARGET.finditer(code):
        if match.group(3).lower() in _LEGACY_LOWER:
            offenders.append((line_of(code, match.start()), " ".join(match.group(0).split())))
    for match in _SQL_INDEX_TARGET.finditer(code):
        if match.group(1).lower() in _LEGACY_LOWER:
            offenders.append((line_of(code, match.start()), " ".join(match.group(0).split())))
    assert not offenders, f"{rel(path)} issues DDL against the legacy schema: {offenders}"


@pytest.mark.parametrize("path", ALL_PYTHON, ids=PY_IDS)
def test_no_ddl_in_python(path: Path) -> None:
    """
    The Python side issues no DDL at all -- against the legacy schema or its own. Schema changes are the
    two `.sql` scripts an operator applies deliberately, so an upgrade is never a side effect of a
    request.

    Validates: Requirements 17.1
    """
    code = python_code_only(path.read_text(encoding="utf-8"))
    offenders = [
        (line_of(code, match.start()), " ".join(match.group(0).split()))
        for match in re.finditer(
            r"(?i)\b(?:CREATE\s+(?:OR\s+ALTER\s+)?(?:TABLE|VIEW|INDEX|PROCEDURE|PROC|TRIGGER)"
            r"|ALTER\s+TABLE|DROP\s+(?:TABLE|VIEW|INDEX|PROCEDURE)|TRUNCATE\s+TABLE"
            r"|ADD\s+CONSTRAINT)\b",
            code,
        )
    ]
    assert not offenders, f"{rel(path)} contains DDL: {offenders}"


_JOIN_PATTERNS = (
    r"(?i)\bMaSoMay\b\s*=\s*(?:\w+\s*\.\s*)?\bIDMCC\b",
    r"(?i)\bIDMCC\b\s*=\s*(?:\w+\s*\.\s*)?\bMaSoMay\b",
    r"COL_CC_MASOMAY[^=\n]{0,24}=\s*[^\n]{0,60}COL_IDMCC",
    r"COL_IDMCC[^=\n]{0,24}=\s*[^\n]{0,60}COL_CC_MASOMAY",
)


@pytest.mark.parametrize("path", [*SQL_FILES, *ALL_PYTHON], ids=[*SQL_IDS, *PY_IDS])
def test_nothing_joins_masomay_to_idmcc(path: Path) -> None:
    """
    ``IDMCC`` can be 1 on most configured machines and ``CheckInOut.MaSoMay`` 1 on nearly
    every row, with ``TenMay`` carrying the real machine identity. A join on it
    matches many machines at once, which is how ``vw_ADMS_UnprojectedPunches`` originally reported
    nonsense.

    Equality is what is forbidden, not co-occurrence: ``m.IDMCC AS MaSoMay`` in
    ``vw_ADMS_DeviceStatus`` is a value being copied into the column the legacy contract expects, which
    is the correct use and the one Requirement 17.3 describes.

    Validates: Requirements 17.4
    """
    code = (
        sql_code_only(read_text(path))
        if path.suffix.lower() == ".sql"
        else python_code_only(path.read_text(encoding="utf-8"))
    )
    offenders = [
        (line_of(code, match.start()), " ".join(match.group(0).split()))
        for pattern in _JOIN_PATTERNS
        for match in re.finditer(pattern, code)
    ]
    assert not offenders, f"{rel(path)} joins MaSoMay to IDMCC: {offenders}"


@pytest.mark.parametrize("path", COLLECTOR_MODULES, ids=COLLECTOR_IDS)
def test_no_collector_behaviour_reads_a_vw_adms_view(path: Path) -> None:
    """
    The ``vw_ADMS_*`` views are operator conveniences, so nothing the collector does may depend on one:
    a view can be dropped or rewritten by a DBA reading it as documentation, and no punch should be lost
    over that.

    Scoped to the collector. ``adms.admin.store`` reads three of these views on purpose -- it is the
    console, a separate application under Requirement 29.1, and presenting those views is its job.
    Comments are stripped, so ``db/schema.py``'s warning about why the view is written the way it is
    does not count as a dependency.

    Validates: Requirements 23.12
    """
    code = python_code_only(path.read_text(encoding="utf-8"))
    offenders = [
        (line_of(code, match.start()), match.group(0))
        for match in re.finditer(r"vw_ADMS_\w*", code)
    ]
    assert not offenders, f"{rel(path)} reads an operator view: {offenders}"


_HOSTING_AWARE = frozenset({"adms/wsgi.py", "adms/hosting/serve.py"})


@pytest.mark.parametrize("path", COLLECTOR_MODULES, ids=COLLECTOR_IDS)
def test_only_two_modules_are_aware_of_the_hosting_model(path: Path) -> None:
    """
    ``adms.wsgi`` owns the WSGI surface and ``adms.hosting.serve`` owns the process, and no other module
    knows either exists. That is what lets the smoke test drive the same application object with no IIS
    at all, and what keeps hosting concerns out of the service and the adapters.

    Docstrings are stripped: half these modules explain *why* waitress's thread pool shapes them --
    ``db/connection.py``'s per-thread cache is only sensible if you know that -- and prose is not
    awareness. What would break this claim is an import or a call.

    Validates: Requirements 25.1
    """
    if path.relative_to(SRC).as_posix() in _HOSTING_AWARE:
        return
    code = python_code_only(path.read_text(encoding="utf-8"))
    mentions = [
        (line_of(code, match.start()), match.group(0))
        for match in re.finditer(r"(?i)\bwsgi\w*|\bwaitress\w*", code)
    ]
    assert not mentions, f"{rel(path)} is aware of the hosting model: {mentions}"


def test_the_two_hosting_aware_modules_exist() -> None:
    """
    The other half of the claim above. "Only these two mention it" is satisfied trivially if neither
    file exists, or if one has been renamed and the exemption list has gone stale.

    Validates: Requirements 25.1
    """
    for relative in sorted(_HOSTING_AWARE):
        module = SRC / relative
        assert module.is_file(), f"{relative} is missing, so the hosting exemption list is stale"
        code = python_code_only(module.read_text(encoding="utf-8"))
        assert re.search(r"(?i)wsgi|waitress", code), f"{relative} no longer mentions the hosting model"


# ---- The dependency list: Requirements 30.14, 30.15, 17.9 ----------------------------------


def runtime_pins() -> list[str]:
    lines = read_text(REQUIREMENTS).splitlines()
    return [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]


def test_runtime_dependencies_are_exactly_two_exact_pins() -> None:
    """
    Two packages, pinned exactly. This service is the only path attendance data takes from a device into
    the database and it runs unattended, so a transitive change arriving on its own schedule is not a
    trade worth making. A test-only import in this list is how a two-package deployment stops being one,
    which is why ``pytest`` is in ``requirements-dev.txt`` alone.

    Validates: Requirements 30.14
    """
    pins = runtime_pins()
    assert len(pins) == 2, f"requirements.txt holds {len(pins)} requirement lines: {pins}"
    for pin in pins:
        assert re.fullmatch(r"[A-Za-z0-9_.-]+==[\w.]+", pin), f"{pin!r} is not an exact pin"
    assert {pin.split("==")[0].lower() for pin in pins} == {"pyodbc", "waitress"}, pins


def test_pyodbc_is_pinned_at_the_version_with_a_wheel() -> None:
    """
    5.2.0 ships no wheel for Python 3.14, so pip falls back to building from source and fails on a
    missing ``windows.h`` unless the full MSVC build tools and Windows SDK are installed. 5.3.0 has the
    wheel.

    Validates: Requirements 30.15
    """
    assert "pyodbc==5.3.0" in runtime_pins(), f"pyodbc is not pinned at 5.3.0: {runtime_pins()}"


def test_no_object_relational_mapper_anywhere_in_the_dependency_lists() -> None:
    """
    Raw ODBC, deliberately. Nothing in the stack should want to model or migrate a schema this service
    does not own -- and an ORM's first instinct is to do both.

    Validates: Requirements 17.9
    """
    files = [REQUIREMENTS, REPO / "requirements-dev.txt", REPO / "pyproject.toml"]
    offenders = [
        (rel(path), package)
        for path in files
        if path.is_file()
        for package in ORM_PACKAGES
        if re.search(rf"(?im)^[^#]*\b{package}\b", read_text(path))
    ]
    assert not offenders, f"an object-relational mapper is in the dependency list: {offenders}"
