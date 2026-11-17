"""
Process entry point -- the child process IIS starts via AspNetCoreModuleV2 (ANCM, out-of-process).

    python -m adms.hosting.serve --port 8080

IIS chooses a loopback port and passes it to the child in the ``ASPNETCORE_PORT`` environment variable
(ANCM does not env-expand ``arguments``, so the port cannot come on the command line), starts this
process, and proxies inbound requests to it on localhost. So this listens on **loopback only**: the
public listener is IIS's, and binding this to 0.0.0.0 would quietly expose an unauthenticated second
endpoint on the machine that bypasses IIS logging and any IP restriction configured there.

``HTTP_PLATFORM_PORT`` is still honoured for a host that fronts the site with HttpPlatformHandler
instead, so the same build runs under either IIS module.

Also usable standalone for a smoke test on the target host before IIS is configured:

    python -m adms.hosting.serve --port 8080 --host 0.0.0.0
"""

from __future__ import annotations

import argparse
import os
import sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Serve the ADMS collector over WSGI.")
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("ASPNETCORE_PORT") or os.environ.get("HTTP_PLATFORM_PORT") or 8080),
        help="port to listen on; IIS supplies this via %%ASPNETCORE_PORT%% (AspNetCoreModule "
        "out-of-process) or %%HTTP_PLATFORM_PORT%% (HttpPlatformHandler). Default 8080 for the "
        "standalone test.",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="bind address. Defaults to loopback because IIS is the public listener; only override "
        "for a standalone test.",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=int(os.environ.get("ADMS_THREADS") or 8),
        help="waitress worker threads. Each one can hold its own SQL connection, so this is also the "
        "cap on concurrent connections to SQL Server (default: 8).",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify configuration and database connectivity, then exit. Use this after install "
        "instead of discovering a bad connection string from a device's failed upload.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    from adms.composition import get_logger, get_service
    from adms.wsgi import create_app

    log = get_logger()

    if args.check:
        return _run_check(log)

    try:
        service = get_service()
    except Exception as exc:  # noqa: BLE001
        # Fail loudly and exit non-zero: ANCM surfaces a non-starting child as a 502
        # with the stdout log attached, which is a far better diagnostic than a process that starts and
        # then refuses every request.
        log.error("Could not start: configuration or database unavailable.", exc)
        return 1

    app = create_app(service, log=log)

    try:
        from waitress import serve
    except ImportError:
        log.error(
            "waitress is not installed. Run 'pip install -r requirements.txt' in the site's virtual "
            "environment.",
            None,
        )
        return 1

    log.info(
        "Listening.",
        host=args.host,
        port=args.port,
        threads=args.threads,
        pid=os.getpid(),
    )

    serve(
        app,
        host=args.host,
        port=args.port,
        threads=args.threads,
        # Identify as something neutral. The default advertises waitress and its version, which is
        # free reconnaissance for anything scanning the device network.
        ident="AdmsCollector",
        # Devices are unauthenticated, so an oversized Content-Length must not be allowed to buy
        # unbounded memory. Matches MAX_BODY_BYTES in adms.wsgi.
        max_request_body_size=32 * 1024 * 1024,
        # Some firmware is slow to send its body after the headers, especially over a congested site
        # link. The default 30 s has been enough in testing; 60 s leaves margin without letting a dead
        # connection hold a worker thread indefinitely.
        channel_timeout=60,
        # Trust the X-Forwarded-For that IIS sets, but only for logging -- adms.wsgi never uses it for
        # an authorisation decision.
        clear_untrusted_proxy_headers=False,
    )
    return 0


def _run_check(log) -> int:
    """
    Verify configuration and connectivity without serving.

    Reports the ODBC driver list too: 'ODBC Driver 18 for SQL Server' missing on the host is the most
    common install failure, and it otherwise presents as an opaque connection error.
    """
    from adms.composition import build_service
    from adms.config import load_settings, resolve_connection_string

    try:
        settings = load_settings()
    except Exception as exc:  # noqa: BLE001
        log.error("Configuration is invalid.", exc)
        return 1

    try:
        import pyodbc

        drivers = pyodbc.drivers()
        print(f"ODBC drivers: {drivers}")
        if not any("ODBC Driver 18" in d for d in drivers):
            print("WARNING: 'ODBC Driver 18 for SQL Server' is not installed on this host.")
    except ImportError:
        print("pyodbc is not installed.")
        return 1

    try:
        # Resolved separately so a missing registry value is reported as such rather than as a
        # connection failure.
        resolve_connection_string(settings)
    except Exception as exc:  # noqa: BLE001
        print(f"connection string: NOT AVAILABLE - {exc}")
        return 1

    # Report which source won. Saying "registry" when the value actually came from the environment
    # would send someone troubleshooting a permissions problem that does not exist -- and, worse, could
    # let a development override sit unnoticed on a production host.
    if settings.sql_connection:
        print(
            "connection string: taken from ADMS_SQL_CONNECTION (development override; "
            "production should use the DPAPI-protected registry value)"
        )
    else:
        print(
            f"connection string: decrypted from HKLM\\{settings.registry_subkey}\\ConnectionString"
        )

    try:
        build_service(settings, log=log)
        from adms.composition import _factory  # noqa: PLC2701 - deliberate, this is a self-check

        if _factory is not None:
            _factory.test()
        print("database: reachable, SELECT 1 succeeded")
    except Exception as exc:  # noqa: BLE001
        print(f"database: UNREACHABLE - {exc}")
        return 1

    print("check: OK")
    return 0


if __name__ == "__main__":
    # Make src/ importable when launched from a checkout without an install step.
    _here = os.path.dirname(os.path.abspath(__file__))
    _src = os.path.abspath(os.path.join(_here, "..", ".."))
    if _src not in sys.path:
        sys.path.insert(0, _src)
    raise SystemExit(main())
