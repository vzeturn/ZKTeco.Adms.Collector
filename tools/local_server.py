"""
Local ADMS server -- the same WSGI application IIS serves, on a laptop.

Why this exists rather than "just install it"
---------------------------------------------
The ADMS protocol is not published in a form anyone can rely on. What a given firmware build actually
sends differs from the documentation and from other builds, and the only way to find out is to watch a
real device talk. Pointing a device at a laptop running this -- with ``--fake``, so no database is
involved -- turns that from an install-and-redeploy cycle into a five-second loop, and every body the
device sends is printed verbatim.

It is also how you verify a device can reach a host at all before touching IIS: if the device cannot
reach a laptop on the same VLAN, it will not reach the IIS box either.

The application object is exactly the one ``adms.hosting.serve`` gives IIS, so anything that works here
works there. The only difference is who owns the socket.

Usage
-----
    # No database at all. Serial 'TEST123' is pre-registered and linked.
    python tools/local_server.py --fake

    # Against the real database, using the DPAPI-protected registry value.
    python tools/local_server.py --port 8080

    # Against the real database, using an explicit connection string (development only).
    $env:ADMS_SQL_CONNECTION = "DRIVER={ODBC Driver 18 for SQL Server};SERVER=...;..."
    python tools/local_server.py --port 8080

Then configure the device: Comm -> Ethernet/ADMS -> server address = this host, port = 8080, path
``/iclock``.

NOT FOR PRODUCTION. It prints request bodies -- which contain names and biometric templates -- to your
terminal, and it has no authentication beyond the serial allow-list.
"""

from __future__ import annotations

import argparse
import os
import sys

# Make src/ importable when run straight from a checkout, so this needs no install step.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from adms.config import Settings, load_settings  # noqa: E402
from adms.models import DeviceRegistration  # noqa: E402
from adms.wsgi import AdmsWsgiApp  # noqa: E402


def build(args):
    """Return ``(wsgi_app, stores)``; ``stores`` is None when running against a real database."""
    if args.fake:
        from adms.composition import build_fake_service

        settings = Settings(
            # Satisfies nothing in particular -- the fake graph has no database adapter to hand it to.
            sql_connection="fake",
            auto_register_devices=args.auto_register,
            path_secret=args.path_secret,
            archive_raw_bodies=True,
            utc_offset_hours=args.utc_offset,
        )
        devices = [
            DeviceRegistration(
                serial=serial,
                enabled=True,
                machine_code="MCC00001",
                machine_id=1,
                machine_name="Local test machine",
                timezone_offset=args.utc_offset,
            )
            for serial in args.serial
        ]
        service, stores = build_fake_service(settings, devices=devices)
        print(f"[fake] registered serials: {', '.join(args.serial)}")
        return AdmsWsgiApp(service), stores

    from adms.composition import build_service

    service = build_service(load_settings())
    return AdmsWsgiApp(service), None


class VerboseMiddleware:
    """
    Prints each request and response around the real application.

    A middleware rather than logging inside the app, so the app under test is byte-for-byte the one IIS
    runs. The request body has to be buffered and replaced, because reading ``wsgi.input`` to print it
    would consume it before the application saw it.
    """

    def __init__(self, app, stores=None) -> None:
        self._app = app
        self._stores = stores

    def __call__(self, environ, start_response):
        import io

        from adms.protocol import decode_body

        method = environ.get("REQUEST_METHOD", "?")
        path = environ.get("PATH_INFO", "")
        query = environ.get("QUERY_STRING", "")
        print(f"\n--> {method} {path}{'?' + query if query else ''}")

        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        if length > 0 and environ.get("wsgi.input") is not None:
            raw = environ["wsgi.input"].read(length)
            environ["wsgi.input"] = io.BytesIO(raw)
            # Decoded the same way the parsers decode it. This output is the entire reason the tool
            # exists.
            print(decode_body(raw).rstrip())

        captured: dict = {}

        def capture(status, headers, exc_info=None):
            captured["status"] = status
            return start_response(status, headers, exc_info) if exc_info else start_response(status, headers)

        chunks = list(self._app(environ, capture))
        body = b"".join(chunks)
        preview = body.decode("utf-8", errors="replace").rstrip()
        print(f"<-- {captured.get('status', '?')} {preview[:400]}")

        if self._stores is not None:
            attendance = self._stores["attendance"]
            templates = self._stores["templates"]
            print(
                f"    [state] punches={len(attendance.rows)} "
                f"employees={len(self._stores['employees'].employees)} "
                f"fingers={sum(len(v) for v in templates.fingers.values())} "
                f"faces={sum(len(v) for v in templates.faces.values())}"
            )
        return [body]


def main() -> int:
    parser = argparse.ArgumentParser(description="Local ADMS/PUSH server for device testing.")
    parser.add_argument("--host", default="0.0.0.0", help="bind address (default: all interfaces)")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument(
        "--fake",
        action="store_true",
        help="use in-memory stores instead of SQL Server (no database or ODBC driver needed)",
    )
    parser.add_argument(
        "--serial",
        action="append",
        default=None,
        help="serial to pre-register in --fake mode; repeatable (default: TEST123)",
    )
    parser.add_argument("--path-secret", default="", help="require this URL path segment")
    parser.add_argument("--auto-register", action="store_true", help="record unknown serials as pending")
    parser.add_argument("--utc-offset", type=int, default=7, help="site offset from UTC (default: 7)")
    parser.add_argument("--quiet", action="store_true", help="do not print request/response bodies")
    parser.add_argument("--threads", type=int, default=4)
    args = parser.parse_args()

    if not args.serial:
        args.serial = ["TEST123"]

    app, stores = build(args)
    if not args.quiet:
        app = VerboseMiddleware(app, stores)

    print(f"ADMS local server on http://{args.host}:{args.port}/iclock/  (Ctrl+C to stop)")
    print(f"Device setting: Comm -> Ethernet/ADMS -> server address = this host, port = {args.port}")

    try:
        from waitress import serve
    except ImportError:
        # Fall back to the stdlib so the tool works before `pip install`. Single-threaded, which is
        # fine for one device but will serialise a fleet.
        from wsgiref.simple_server import make_server

        print("[note] waitress is not installed; using the single-threaded wsgiref server")
        with make_server(args.host, args.port, app) as httpd:
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("\nstopping")
        return 0

    try:
        serve(app, host=args.host, port=args.port, threads=args.threads, ident="AdmsCollector")
    except KeyboardInterrupt:
        print("\nstopping")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
