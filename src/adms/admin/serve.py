"""
Process entry point for the admin console -- the child IIS starts via AspNetCoreModuleV2 (ANCM).

    python -m adms.admin.serve --port 8081

This is deliberately a *separate* process from the collector's ``adms.hosting.serve`` on a *separate*
port. The console sits behind a login and the collector sits on a device-only segment; giving each its
own process means a fault or a compromise in one cannot reach into the other, and the console's much
smaller body cap (1 MiB vs the collector's 32 MiB) reflects that it never receives a photo or template
upload -- only form posts.

Like the collector's entry point this listens on **loopback only** by default: IIS is the public
listener and binding to 0.0.0.0 would expose an unauthenticated bypass of IIS logging and any IP
restriction. ``--host 0.0.0.0`` exists for the standalone fallback smoke test on the target host
(Requirement 18.13).

Also usable standalone:

    python -m adms.admin.serve --port 8081 --host 0.0.0.0
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from adms.config import Settings
    from adms.db.connection import ConnectionFactory

#: The console's own registry sub-key, tried before the collector's. Requirement 18.7: the console
#: resolves its connection string from its own sub-key when one is configured and from the collector's
#: otherwise -- never from its own source folder and never from a page.
CONSOLE_REGISTRY_SUBKEY = r"SOFTWARE\AdmsConsole\AttendanceDb"

#: The tables the console owns. ``--check`` confirms every one exists so a half-applied schema is
#: caught at install time rather than as a 503 on the first sign-in.
APP_TABLES = ("APP_USER", "APP_SESSION", "APP_AUDIT")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Serve the ADMS admin console over WSGI.")
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("ASPNETCORE_PORT") or os.environ.get("HTTP_PLATFORM_PORT") or 8081),
        help="port to listen on; IIS supplies this via %%ASPNETCORE_PORT%% (AspNetCoreModule "
        "out-of-process) or %%HTTP_PLATFORM_PORT%% (HttpPlatformHandler). Default 8081 for the "
        "standalone test.",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="bind address. Defaults to loopback because IIS is the public listener; only override "
        "for the standalone fallback test.",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=int(os.environ.get("ADMS_ADMIN_THREADS") or 4),
        help="waitress worker threads. The console's traffic is a handful of operators, not a device "
        "fleet, so this is lower than the collector's (default: 4).",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify configuration, database connectivity and that the APP_* tables exist, then exit.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    from adms.composition import get_logger
    from adms.config import load_settings

    log = get_logger()

    if args.check:
        return _run_check(log)

    try:
        settings = load_settings()
        store = build_console_store(settings, log)
    except Exception as exc:
        # Fail loudly and exit non-zero: ANCM surfaces a non-starting child as a 502 with
        # the stdout log attached, which is a far better diagnostic than a process that starts and then
        # rejects every request.
        log.error("Could not start: configuration or database unavailable.", exc)
        return 1

    from adms.admin.app import create_app

    app = create_app(store, settings=settings, log=log)

    try:
        from waitress import serve  # type: ignore[import-untyped]
    except ImportError:
        log.error(
            "waitress is not installed. Run 'pip install -r requirements.txt' in the site's virtual "
            "environment.",
            None,
        )
        return 1

    log.info("Listening.", host=args.host, port=args.port, threads=args.threads, pid=os.getpid())

    serve(
        app,
        host=args.host,
        port=args.port,
        threads=args.threads,
        # Neutral identity: the default advertises waitress and its version, free reconnaissance.
        ident="AdmsConsole",
        # The console only ever receives form posts, never a photo or template upload, so cap the body
        # an order of magnitude below the collector. A login page does not need 32 MiB of headroom.
        max_request_body_size=1_048_576,
        channel_timeout=60,
        # IIS sets X-Forwarded-For; adms.admin.app records it but never authorises on it.
        clear_untrusted_proxy_headers=False,
    )
    return 0


def build_console_store(settings: Settings, log: Any):
    """
    Compose the real :class:`~adms.admin.store.AdminStore`.

    Resolves the connection string from the console's own registry sub-key first and the collector's
    otherwise (Requirement 18.7), then opens a shared :class:`ConnectionFactory`.
    """
    _source, factory = _resolve_console_connection(settings)
    from adms.admin.store import AdminStore

    return AdminStore(factory, log=log)


def _resolve_console_connection(settings: Settings) -> tuple[str, ConnectionFactory]:
    """
    Return ``(human-readable source, factory)`` for the console's database.

    Order: ``ADMS_SQL_CONNECTION`` (development only), then the console's own DPAPI-protected sub-key,
    then the collector's. The source string names where the value came from and never any part of the
    value itself, so it is safe to print from ``--check``.
    """
    from adms.db.connection import ConnectionFactory

    if settings.sql_connection:
        source = (
            "taken from ADMS_SQL_CONNECTION (development override; production should use the "
            "DPAPI-protected registry value)"
        )
        conn = settings.sql_connection
    else:
        conn, source = _stored_connection(settings)

    factory = ConnectionFactory(conn, query_timeout=settings.sql_query_timeout, log=None)
    return source, factory


def _stored_connection(settings: Settings) -> tuple[str, str]:
    """Load the DPAPI value from the console sub-key, falling back to the collector's."""
    from adms.dbconfig import DbConnectionStore
    from adms.errors import ConfigError

    console = DbConnectionStore(CONSOLE_REGISTRY_SUBKEY).load()
    if console:
        return console, f"decrypted from HKLM\\{CONSOLE_REGISTRY_SUBKEY}\\ConnectionString"

    collector = DbConnectionStore(settings.registry_subkey).load()
    if collector:
        return collector, (
            f"decrypted from the collector's HKLM\\{settings.registry_subkey}\\ConnectionString "
            "(console sub-key not configured)"
        )

    raise ConfigError(
        "No database configuration. Expected a DPAPI-protected connection string in "
        f"HKLM\\{CONSOLE_REGISTRY_SUBKEY}\\ConnectionString or the collector's "
        f"HKLM\\{settings.registry_subkey}\\ConnectionString -- run deploy/set-db-connection.ps1."
    )


def _console_drivers() -> list[str]:
    import pyodbc

    return list(pyodbc.drivers())


def _app_tables_present(factory: ConnectionFactory) -> list[str]:
    """Return which of ``APP_TABLES`` exist in dbo, via ``sys.tables`` (no PII table is touched)."""
    placeholders = ", ".join("?" for _ in APP_TABLES)
    cursor = factory.get().cursor()
    try:
        cursor.execute(
            f"SELECT name FROM sys.tables WHERE schema_id = SCHEMA_ID('dbo') AND name IN ({placeholders})",
            tuple(APP_TABLES),
        )
        return [row[0] for row in cursor.fetchall()]
    finally:
        cursor.close()


def _run_check(log) -> int:
    """Verify configuration, connectivity and schema without serving."""
    from adms.config import load_settings

    try:
        settings = load_settings()
    except Exception as exc:
        log.error("Configuration is invalid.", exc)
        return 1

    try:
        drivers = _console_drivers()
        print(f"ODBC drivers: {drivers}")
        if not any("ODBC Driver 18" in d for d in drivers):
            print("WARNING: 'ODBC Driver 18 for SQL Server' is not installed on this host.")
    except ImportError:
        print("pyodbc is not installed.")
        return 1

    try:
        source, factory = _resolve_console_connection(settings)
    except Exception as exc:
        print(f"connection string: NOT AVAILABLE - {exc}")
        return 1
    print(f"connection string: {source}")

    try:
        factory.test()
        print("database: reachable, SELECT 1 succeeded")
    except Exception as exc:
        print(f"database: UNREACHABLE - {exc}")
        return 1

    try:
        present = _app_tables_present(factory)
    except Exception as exc:
        print(f"tables: NOT VERIFIABLE - {exc}")
        return 1

    missing = [t for t in APP_TABLES if t not in present]
    print(f"tables present: {present}")
    if missing:
        print(f"tables MISSING: {missing} -- run deploy/apply-console-schema.ps1 (schema not applied).")
        return 1

    print("check: OK")
    return 0


if __name__ == "__main__":
    # Make src/ importable when launched from a checkout without an install step.
    from pathlib import Path

    _src = str(Path(__file__).resolve().parents[2])
    if _src not in sys.path:
        sys.path.insert(0, _src)
    raise SystemExit(main())
