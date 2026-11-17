"""
Command-line entry point for the pull agent.

    python -m adms.pull.cli                          # employees -> sync -> attendance, every device
    python -m adms.pull.cli --since 2026-01-01        # attendance limited to punches from that date
    python -m adms.pull.cli --group SITE_A            # only devices in one pull group
    python -m adms.pull.cli --attendance-only         # skip the employee pull and the sync pass
    python -m adms.pull.cli --employees-only          # skip attendance
    python -m adms.pull.cli --no-sync                 # pull each device, but never sync between them
    python -m adms.pull.cli --check                   # verify configuration and database connectivity

Run by hand, whenever an operator wants a pull -- there is no scheduler or
daemon mode here on purpose, mirroring ``adms.hosting.serve``'s own ``--check`` convention for a
pre-flight test. If a site wants this to run unattended on a timer, wrap this exact command in
Windows Task Scheduler; the tool itself stays a plain, one-shot process either way, which is what
keeps "run it right now" and "run it every night at 2am" the same code path.

**Ordering and safety, not configurable from here on purpose.** Employees are always pulled (and
synced between devices in the same ``PullGroup``) before attendance, and every write in every
phase is insert-only: a PIN or a punch already stored is left exactly as it was, never
overwritten. See :mod:`adms.pull.agent`'s own module docstring for why.

Exit code is 0 only when every requested device pulled cleanly; 1 if any device failed, so a
wrapping script (or a human's own habit of checking ``$LASTEXITCODE``) can tell without parsing
the log.
"""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import os
import sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Pull employees and attendance from a list of ADMS devices, on demand."
    )
    parser.add_argument(
        "--group",
        default="",
        help="only pull devices whose ADMS_DEVICE.PullGroup matches this value. Default: every "
        "pull-enabled device regardless of group.",
    )
    parser.add_argument(
        "--employees-only",
        action="store_true",
        help="pull employee rosters only; skip attendance and the cross-device sync pass.",
    )
    parser.add_argument(
        "--attendance-only",
        action="store_true",
        help="pull attendance only; skip the employee roster pull and the cross-device sync pass.",
    )
    parser.add_argument(
        "--no-sync",
        action="store_true",
        help="pull each device as configured, but never push employees between devices in the "
        "same PullGroup.",
    )
    parser.add_argument(
        "--since",
        default="",
        metavar="YYYY-MM-DD",
        help="only pull attendance punches at or after this date (device-local wall-clock, same "
        "as every other timestamp in this schema). Default: every punch currently on the device. "
        "Has no effect on the employee pull or sync phases -- those always run in full.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify configuration and database connectivity, then exit. Does not contact any "
        "device.",
    )
    return parser


def _parse_since(raw: str) -> dt.datetime | None:
    if not raw:
        return None
    try:
        return dt.datetime.strptime(raw, "%Y-%m-%d")
    except ValueError as exc:
        raise SystemExit(f"--since must be YYYY-MM-DD, got {raw!r}") from exc


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.employees_only and args.attendance_only:
        print("--employees-only and --attendance-only are mutually exclusive.", file=sys.stderr)
        return 2

    since = _parse_since(args.since)

    from adms.pull.composition import build_agent, get_logger

    log = get_logger()

    if args.check:
        return _run_check(log)

    try:
        agent = build_agent(log=log)
    except Exception as exc:
        log.error("Could not start the pull agent: configuration or database unavailable.", exc)
        return 1

    mode = "Employees" if args.employees_only else "Attendance" if args.attendance_only else "All"
    triggered_by = _current_user()

    try:
        result = agent.run(
            mode=mode,
            group=args.group,
            triggered_by=triggered_by,
            pull_employees=not args.attendance_only,
            pull_attendance=not args.employees_only,
            sync_employees=not args.no_sync and not args.employees_only and not args.attendance_only,
            since=since,
        )
    except Exception as exc:
        # device list could not be read); every individual device's own failure is already
        # handled inside PullAgent.run and never raises here.
        log.error("The pull run could not complete.", exc)
        return 1

    summary = result.summary()
    since_note = f", attendance since {since.date()}" if since else ""
    print(
        f"Pull run {result.run_id}: {summary['succeeded']}/{summary['devices']} devices OK, "
        f"{summary['failed']} failed{since_note}."
    )
    if result.devices_failed:
        print(f"Failed: {', '.join(sorted(result.devices_failed))}")
        print("See ADMS_PULL_LOG (or dbo.vw_ADMS_PullLogRecent) for the exact error per device/stage.")

    return 0 if result.succeeded else 1


def _current_user() -> str:
    try:
        return os.environ.get("USERNAME") or os.environ.get("USER") or getpass.getuser()
    except Exception:
        return ""


def _run_check(log) -> int:
    from adms.config import load_settings, resolve_connection_string

    try:
        settings = load_settings()
    except Exception as exc:
        log.error("Configuration is invalid.", exc)
        return 1

    try:
        import zk  # noqa: F401

        print("pyzk: installed")
    except ImportError:
        print("pyzk: NOT INSTALLED - run 'pip install -r requirements-pull.txt'")
        return 1

    try:
        resolve_connection_string(settings)
    except Exception as exc:
        print(f"connection string: NOT AVAILABLE - {exc}")
        return 1

    try:
        from adms.db import ConnectionFactory

        factory = ConnectionFactory(
            resolve_connection_string(settings), query_timeout=settings.sql_query_timeout, log=log
        )
        factory.test()
        print("database: reachable, SELECT 1 succeeded")

        from adms.pull.registry import SqlServerPullDeviceRegistry

        devices = SqlServerPullDeviceRegistry(factory, log=log).list_pull_enabled()
        print(f"pull-enabled devices: {len(devices)}")
        for device in devices:
            print(f"  {device.serial}  {device.address}  group={device.pull_group or '(none)'}")
    except Exception as exc:
        print(f"database: UNREACHABLE - {exc}")
        return 1

    print("check: OK")
    return 0


if __name__ == "__main__":
    from pathlib import Path

    _src = str(Path(__file__).resolve().parents[2])
    if _src not in sys.path:
        sys.path.insert(0, _src)
    raise SystemExit(main())
