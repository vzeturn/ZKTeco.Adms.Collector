"""
The console's process entry point (task 10.1): ``python -m adms.admin.serve``.

IIS starts this child through AspNetCoreModuleV2 (out-of-process) and proxies to it on loopback, so the
defaults must match ``web.config.admin``: port 8081 (overridable by ``ASPNETCORE_PORT`` -- the variable
ANCM sets -- or ``HTTP_PLATFORM_PORT`` as a fallback), host 127.0.0.1, four worker threads (overridable
by ``ADMS_ADMIN_THREADS``). The identity string, body cap and channel timeout are the console's own,
not the collector's -- an oversized body must not buy unbounded memory on a site that, unlike the
collector, sits behind a login rather than on a device-only segment.

``waitress.serve`` is patched to capture the keyword arguments rather than actually bind a socket, so
these run with no network and no database.
"""

from __future__ import annotations

import sys

import pytest

from adms.admin import serve as serve_mod


@pytest.fixture(autouse=True)
def _clear_serve_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("ASPNETCORE_PORT", "HTTP_PLATFORM_PORT", "ADMS_ADMIN_THREADS"):
        monkeypatch.delenv(name, raising=False)


# ── parser defaults ─────────────────────────────────────────────────────────────────────────────


def test_defaults_match_the_console_site_contract() -> None:
    args = serve_mod.build_parser().parse_args([])
    assert args.port == 8081  # distinct from the collector's 8080
    assert args.host == "127.0.0.1"  # loopback: IIS is the public listener
    assert args.threads == 4
    assert args.check is False


def test_aspnetcore_port_overrides_the_default_port(monkeypatch: pytest.MonkeyPatch) -> None:
    # ANCM (the module fronting this site) supplies the loopback port as ASPNETCORE_PORT.
    monkeypatch.setenv("ASPNETCORE_PORT", "9091")
    assert serve_mod.build_parser().parse_args([]).port == 9091


def test_http_platform_port_overrides_the_default_port(monkeypatch: pytest.MonkeyPatch) -> None:
    # Still honoured for a host fronted by HttpPlatformHandler instead, so one build runs under either.
    monkeypatch.setenv("HTTP_PLATFORM_PORT", "9099")
    assert serve_mod.build_parser().parse_args([]).port == 9099


def test_aspnetcore_port_wins_over_http_platform_port(monkeypatch: pytest.MonkeyPatch) -> None:
    # If both are set, the ANCM variable takes precedence: this site is fronted by ANCM.
    monkeypatch.setenv("ASPNETCORE_PORT", "9091")
    monkeypatch.setenv("HTTP_PLATFORM_PORT", "9099")
    assert serve_mod.build_parser().parse_args([]).port == 9091


def test_admin_threads_env_overrides_the_default_thread_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ADMS_ADMIN_THREADS", "12")
    assert serve_mod.build_parser().parse_args([]).threads == 12


def test_explicit_flags_beat_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTP_PLATFORM_PORT", "9099")
    args = serve_mod.build_parser().parse_args(["--port", "7000", "--host", "0.0.0.0", "--threads", "2"])
    assert (args.port, args.host, args.threads) == (7000, "0.0.0.0", 2)


# ── the hand-off to waitress ────────────────────────────────────────────────────────────────────


class _FakeStore:
    pass


def _patch_composition(monkeypatch: pytest.MonkeyPatch, captured: dict) -> None:
    """Replace the real store composition and waitress.serve so main() runs offline."""
    monkeypatch.setattr(serve_mod, "build_console_store", lambda _settings, _log: _FakeStore())

    fake_waitress = type(sys)("waitress")

    def _serve(app: object, **kwargs: object) -> None:
        captured["app"] = app
        captured["kwargs"] = kwargs

    fake_waitress.serve = _serve
    monkeypatch.setitem(sys.modules, "waitress", fake_waitress)


def test_main_hands_the_console_settings_to_waitress(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}
    _patch_composition(monkeypatch, captured)

    rc = serve_mod.main(["--port", "8081", "--threads", "4"])

    assert rc == 0
    kw = captured["kwargs"]
    assert kw["host"] == "127.0.0.1"
    assert kw["port"] == 8081
    assert kw["threads"] == 4
    assert kw["ident"] == "AdmsConsole"  # not "AdmsCollector"
    assert kw["max_request_body_size"] == 1_048_576  # 1 MiB, an order of magnitude below the collector
    assert kw["channel_timeout"] == 60


def test_main_binds_the_host_it_is_given(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}
    _patch_composition(monkeypatch, captured)
    serve_mod.main(["--host", "0.0.0.0"])
    assert captured["kwargs"]["host"] == "0.0.0.0"


def test_main_returns_nonzero_when_composition_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(_settings: object, _log: object) -> None:
        raise RuntimeError("no database")

    monkeypatch.setattr(serve_mod, "build_console_store", _boom)
    # waitress must never be reached, so leave it unpatched: if main() got that far it would try to
    # import the real thing, and either way the store failure has to short-circuit to a non-zero exit.
    assert serve_mod.main([]) == 1


# ── --check ────────────────────────────────────────────────────────────────────────────────────


def test_check_reports_drivers_source_select1_and_tables_then_ok(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(serve_mod, "_console_drivers", lambda: ["ODBC Driver 18 for SQL Server"])

    class _Factory:
        def test(self) -> None:
            pass

    monkeypatch.setattr(
        serve_mod,
        "_resolve_console_connection",
        lambda _settings: ("connection string: from HKLM\\SOFTWARE\\AdmsConsole", _Factory()),
    )
    monkeypatch.setattr(serve_mod, "_app_tables_present", lambda _factory: list(serve_mod.APP_TABLES))

    rc = serve_mod.main(["--check"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "ODBC Driver 18 for SQL Server" in out
    assert "connection string:" in out
    assert "SELECT 1" in out
    assert "APP_USER" in out and "APP_SESSION" in out
    assert "check: OK" in out


def test_check_exits_nonzero_when_a_table_is_missing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(serve_mod, "_console_drivers", lambda: ["ODBC Driver 18 for SQL Server"])

    class _Factory:
        def test(self) -> None:
            pass

    monkeypatch.setattr(
        serve_mod,
        "_resolve_console_connection",
        lambda _settings: ("connection string: from the collector's sub-key", _Factory()),
    )
    monkeypatch.setattr(serve_mod, "_app_tables_present", lambda _factory: ["APP_USER"])  # rest missing

    rc = serve_mod.main(["--check"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "MISSING" in out
    assert "check: OK" not in out


def test_check_exits_nonzero_when_the_database_is_unreachable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from adms.errors import AttendanceDbError

    monkeypatch.setattr(serve_mod, "_console_drivers", lambda: ["ODBC Driver 18 for SQL Server"])

    class _Factory:
        def test(self) -> None:
            raise AttendanceDbError("nope")

    monkeypatch.setattr(
        serve_mod,
        "_resolve_console_connection",
        lambda _settings: ("connection string: somewhere", _Factory()),
    )

    rc = serve_mod.main(["--check"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "UNREACHABLE" in out
    assert "check: OK" not in out
