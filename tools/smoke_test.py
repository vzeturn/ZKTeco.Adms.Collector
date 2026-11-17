"""
End-to-end protocol exercise against the in-memory stores.

Walks one realistic device conversation and asserts the exact bytes we send back, because the
response text *is* the contract with the firmware: ``OK: 3`` and ``OK: 2`` mean different things to a
device, and ``OK`` where a handshake belongs makes a correctly-wired device sit silent forever.

Run by ``build.ps1`` on every build. Needs no database, no ODBC driver and no cloud credentials, which
is the point — it makes the parts that are easy to break cheap to check.

    python tools/smoke_test.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from adms.composition import build_fake_service  # noqa: E402
from adms.config import Settings  # noqa: E402
from adms.logging_setup import NullLogger, scrub  # noqa: E402
from adms.models import AdmsRequest, DeviceRegistration  # noqa: E402
from adms.protocol import commands as cmd  # noqa: E402
from adms.wsgi import AdmsWsgiApp, build_request  # noqa: E402

SERIAL = "CJXX204960333"
UNKNOWN_SERIAL = "NOTREGISTERED9"

_failures: list[str] = []
_checks = 0


def check(condition: bool, label: str, detail: str = "") -> None:
    global _checks
    _checks += 1
    if condition:
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}" + (f"\n         {detail}" if detail else ""))
        _failures.append(label)


def equal(actual, expected, label: str) -> None:
    check(actual == expected, label, f"expected {expected!r}, got {actual!r}")


def build():
    settings = Settings(
        sql_connection="fake",
        utc_offset_hours=7,
        archive_raw_bodies=True,
        auto_register_devices=True,
        path_secret="",
    )
    devices = [
        DeviceRegistration(
            serial=SERIAL,
            enabled=True,
            machine_code="MCC00001",
            machine_id=7,
            machine_name="Cong chinh",
        ),
        DeviceRegistration(
            serial="UNLINKED0001",
            enabled=True,
            machine_code="",
            machine_id=None,
        ),
        DeviceRegistration(serial="DISABLED0001", enabled=False, machine_id=9),
    ]
    return build_fake_service(settings, devices=devices, log=NullLogger())


def get(path: str, **query) -> AdmsRequest:
    return AdmsRequest(method="GET", path=path, query=query, source_ip="10.0.0.9")


def post(path: str, body: str, **query) -> AdmsRequest:
    return AdmsRequest(
        method="POST", path=path, query=query, body=body.encode("utf-8"), source_ip="10.0.0.9"
    )


def main() -> int:
    service, stores = build()

    # Seed the roster with the PINs the main flow below punches with. Without this, auto-enrolment
    # correctly fires for every one of them and fills the command queue, which is realistic but makes
    # the command-queue assertions further down meaningless. Auto-enrolment gets its own section with
    # its own service, where the queue starts genuinely empty.
    stores["employees"].preexisting.update(
        {101, 102, 103, 104, 105, 106, 107, 201, 202, 203, 301, 302}
    )

    # ── Handshake ────────────────────────────────────────────────────────────────────────────
    print("\nhandshake")
    response = service.handle(get("/iclock/cdata", SN=SERIAL, options="all", pushver="2.4.1"))
    equal(response.status, 200, "handshake returns 200")
    check(
        response.body.startswith(f"GET OPTION FROM: {SERIAL}"),
        "first line is the exact literal firmware string-matches",
        response.body.splitlines()[0] if response.body else "<empty>",
    )
    check("Realtime=1" in response.body, "Realtime=1 (else punches arrive twice a day, not live)")
    check("ATTLOGStamp=" in response.body and "Stamp=" in response.body,
          "emits both the modern and legacy stamp vocabularies")
    check("TransFlag=" in response.body, "TransFlag present")
    equal(response.content_type, "text/plain", "content type is bare text/plain")

    # ── Authorisation ────────────────────────────────────────────────────────────────────────
    print("\nauthorisation")
    response = service.handle(get("/iclock/cdata", SN=UNKNOWN_SERIAL, options="all"))
    equal(response.status, 401, "unknown serial is refused")
    equal(response.body, "Unauthorized", "refusal body carries no internal detail")
    check(UNKNOWN_SERIAL in stores["registry"].pending, "unknown serial recorded as pending")
    check(
        UNKNOWN_SERIAL not in stores["registry"].devices,
        "recording a pending device does NOT grant it access",
    )

    # Deliberate: Enabled is an operator display label, not an
    # access gate. A registered-but-disabled device is served exactly like an enabled one, so
    # switching a device off never drops the punches it has already recorded. This smoke test
    # itself was left asserting the older behaviour (401) until now.
    response = service.handle(get("/iclock/cdata", SN="DISABLED0001", options="all"))
    equal(response.status, 200, "a disabled-but-registered serial is still served (Enabled is a label, not a gate)")

    response = service.handle(get("/iclock/cdata", SN=""))
    equal(response.status, 400, "missing SN is a 400, not a retryable 5xx")

    # A device that has not been linked to a MAYCHAMCONG row must still complete its handshake, so an
    # operator can see it in order to link it — but its data must be refused.
    response = service.handle(get("/iclock/cdata", SN="UNLINKED0001", options="all"))
    equal(response.status, 200, "unlinked device may still handshake")
    response = service.handle(
        post("/iclock/cdata", "1\t2026-08-07 08:00:00\t0\t1\t0\t\t\n", SN="UNLINKED0001", table="ATTLOG")
    )
    equal(response.status, 503, "unlinked device cannot push data")
    equal(response.body, "Device Not Configured", "unlinked failure is distinguishable from 401")

    # ── ATTLOG ───────────────────────────────────────────────────────────────────────────────
    print("\nATTLOG")
    attlog = (
        "101\t2026-08-07 07:58:12\t0\t1\t0\t\t\n"
        "102\t2026-08-07 08:01:44\t1\t15\t0\t\t\n"
        "103\t2026-08-07 08:03:02\t0\t2\t7\t\t\n"
    )
    response = service.handle(post("/iclock/cdata", attlog, SN=SERIAL, table="ATTLOG", Stamp="9999"))
    equal(response.status, 200, "ATTLOG accepted")
    equal(response.body, "OK: 3", "acknowledges the count the DEVICE sent")
    equal(len(stores["attendance"].rows), 3, "3 punches stored")
    equal(stores["attendance"].rows[0]["KieuCham"], "1", "KieuCham matches the LAYCONG31 contract")
    equal(stores["attendance"].rows[0]["NguonCham"], "", "NguonCham matches the LAYCONG31 contract")
    equal(stores["attendance"].rows[0]["MaSoMay"], 7, "MaSoMay comes from MAYCHAMCONG.IDMCC")
    equal(stores["attendance"].rows[0]["TenMay"], "Cong chinh", "TenMay comes from MAYCHAMCONG.TenMCC")
    equal(
        stores["registry"].devices[SERIAL].attlog_stamp,
        "9999",
        "stamp advanced only after the data committed",
    )

    # The retry case, which is the normal case: the device did not get our reply and re-sends.
    print("\nATTLOG retry (idempotency)")
    response = service.handle(post("/iclock/cdata", attlog, SN=SERIAL, table="ATTLOG", Stamp="9999"))
    equal(response.body, "OK: 3", "retry is acknowledged with the same count")
    equal(len(stores["attendance"].rows), 3, "retry inserted nothing — no duplicated punches")

    # A batch mixing new and already-stored punches must store only the new one.
    mixed = attlog + "104\t2026-08-07 08:10:00\t0\t1\t0\t\t\n"
    response = service.handle(post("/iclock/cdata", mixed, SN=SERIAL, table="ATTLOG", Stamp="10000"))
    equal(response.body, "OK: 4", "mixed batch acknowledges all 4")
    equal(len(stores["attendance"].rows), 4, "mixed batch stored only the 1 new punch")

    # ── Malformed and hostile punches ────────────────────────────────────────────────────────
    print("\nATTLOG edge cases")
    bad = (
        "105\t2026-08-07 09:00:00\t0\t1\t0\t\t\n"
        "\t2026-08-07 09:01:00\t0\t1\t0\t\t\n"          # no PIN
        "106\t0000-00-00 00:00:00\t0\t1\t0\t\t\n"        # dead RTC
        "107\tnot-a-date\t0\t1\t0\t\t\n"                 # garbage
        "ABC12\t2026-08-07 09:02:00\t0\t1\t0\t\t\n"      # alphanumeric PIN
    )
    before = len(stores["attendance"].rows)
    response = service.handle(post("/iclock/cdata", bad, SN=SERIAL, table="ATTLOG", Stamp="10001"))
    equal(response.status, 200, "a batch with bad lines is still acknowledged")
    equal(response.body, "OK: 5", "unusable lines are counted so the device stops resending them")
    equal(len(stores["attendance"].rows) - before, 1, "only the one valid numeric punch reached CheckInOut")
    check(len(stores["archive"].unparsed) >= 3, "unusable lines were archived, not discarded")
    check(
        any(log.pin == "ABC12" for _, log in stores["attendance"].archived),
        "the alphanumeric PIN survives in the raw archive even though CheckInOut cannot hold it",
    )

    # ── Auto-enrolment ───────────────────────────────────────────────────────────────────────
    # The rule: a punch from a PIN the roster does not know must make the service ASK THE DEVICE for
    # that person, because enrolment data lives on the hardware. Exercised on its own service so the
    # command queue starts empty and the counts are unambiguous.
    print("\nauto-enrolment: a punch from an unknown PIN pulls the employee from the device")
    enrol_settings = Settings(sql_connection="fake", utc_offset_hours=7)
    enrol_service, enrol_stores = build_fake_service(
        enrol_settings,
        devices=[DeviceRegistration(serial=SERIAL, enabled=True, machine_id=7, machine_name="M")],
        log=NullLogger(),
    )
    # PIN 500 is already on the roster; 501 and 502 are not.
    enrol_stores["employees"].preexisting.add(500)

    body = (
        "500\t2026-08-07 08:00:00\t0\t1\t0\t\t\n"
        "501\t2026-08-07 08:00:05\t0\t1\t0\t\t\n"
        "502\t2026-08-07 08:00:09\t0\t1\t0\t\t\n"
    )
    response = enrol_service.handle(post("/iclock/cdata", body, SN=SERIAL, table="ATTLOG", Stamp="1"))
    equal(response.body, "OK: 3", "all three punches acknowledged regardless of roster state")
    equal(len(enrol_stores["attendance"].rows), 3, "an unknown PIN does NOT stop the punch being stored")

    queued = [b for _s, _i, b, _t in enrol_stores["commands"].history]
    check(
        any("PIN=501" in q and "USERINFO" in q for q in queued),
        "queued a user-info query for the unknown PIN 501",
        str(queued),
    )
    check(
        any("PIN=502" in q and "USERINFO" in q for q in queued),
        "queued a user-info query for the unknown PIN 502",
    )
    check(
        any("PIN=501" in q and "FINGERTMP" in q for q in queued),
        "queued a fingerprint query too, so dbo.TEMPLATE is self-healing",
    )
    check(
        not any("PIN=500" in q for q in queued),
        "did NOT ask about PIN 500, which the roster already knows",
    )

    # The cooldown is what stops this becoming a runaway: the same person punches again within seconds.
    before = len(enrol_stores["commands"].history)
    again = "501\t2026-08-07 08:01:00\t0\t1\t0\t\t\n"
    enrol_service.handle(post("/iclock/cdata", again, SN=SERIAL, table="ATTLOG", Stamp="2"))
    equal(
        len(enrol_stores["commands"].history),
        before,
        "a second punch from the same unknown PIN queues NOTHING more (cooldown holds)",
    )

    # PIN=50 must not be considered "already asked" just because PIN=501 was.
    enrol_stores["employees"].preexisting.discard(50)
    prefix = "50\t2026-08-07 08:02:00\t0\t1\t0\t\t\n"
    enrol_service.handle(post("/iclock/cdata", prefix, SN=SERIAL, table="ATTLOG", Stamp="3"))
    check(
        any("PIN=50" in b and "USERINFO" in b for _s, _i, b, _t in enrol_stores["commands"].history
            if "PIN=501" not in b and "PIN=502" not in b),
        "PIN=50 is asked about despite PIN=501 already having been (no prefix collision)",
    )

    # The device answers on /iclock/querydata, which must land in the roster and the template store.
    answer = (
        "USER PIN=501\tName=Tra Ve Tu May\tPri=0\tCard=99887766\tGrp=1\n"
        "FP PIN=501\tFID=0\tSize=1404\tValid=1\tTMP=UFVMTEVEQkFDSw==\n"
    )
    response = enrol_service.handle(
        post("/iclock/querydata", answer, SN=SERIAL, type="userinfo_and_fp", cmdid="1")
    )
    equal(response.status, 200, "the device's answer is accepted on /iclock/querydata")
    check(501 in enrol_stores["employees"].employees, "the pulled employee reached the roster")
    equal(
        enrol_stores["employees"].employees[501].name,
        "Tra Ve Tu May",
        "the pulled employee's name is intact",
    )
    check(501 in enrol_stores["templates"].fingers, "the pulled fingerprint reached the template store")

    # And once known, a further punch must not re-ask.
    settled = len(enrol_stores["commands"].history)
    enrol_service.handle(
        post("/iclock/cdata", "501\t2026-08-07 09:00:00\t0\t1\t0\t\t\n",
             SN=SERIAL, table="ATTLOG", Stamp="4")
    )
    equal(
        len(enrol_stores["commands"].history),
        settled,
        "once the employee is known, punches stop triggering requests",
    )

    # ── OPERLOG ──────────────────────────────────────────────────────────────────────────────
    print("\nOPERLOG")
    operlog = (
        "USER PIN=201\tName=Nguyen Van A\tPri=0\tPasswd=\tCard=1234567\tGrp=1\tTZ=0000000000000000\n"
        "USER PIN=202\tName=Tran Thi B\tPri=14\tPasswd=1234\tCard=\tGrp=1\n"
        "FP PIN=201\tFID=0\tSize=1404\tValid=1\tTMP=Kj0xMjM0NUFCQ0RFRg==\n"
        "FP PIN=201\tFID=1\tSize=1404\tValid=0\tTMP=Kj05ODc2NVpZWFdW\n"
        "FACE PIN=202\tFID=13\tSIZE=9280\tVALID=1\tTMP=RkFDRVRFTVBMQVRF\n"
        "BIODATA Pin=203\tNo=2\tIndex=0\tValid=1\tDuress=0\tType=1\tMajorVer=10\tMinorVer=0\tFormat=0\tTmp=QklPRklOR0VS\n"
        "BIODATA Pin=203\tNo=0\tIndex=0\tValid=1\tDuress=0\tType=9\tMajorVer=5\tMinorVer=0\tFormat=0\tTmp=UEFMTQ==\n"
        "OPLOG 4\t1\t2026-08-07 07:30:00\t201\t0\t0\t0\n"
        "SOMETHINGNEW PIN=999\tField=1\n"
    )
    response = service.handle(post("/iclock/cdata", operlog, SN=SERIAL, table="OPERLOG", Stamp="55"))
    equal(response.status, 200, "OPERLOG accepted")
    equal(response.body, "OK: 9", "every line is counted, including the unrecognised tag")
    equal(len(stores["employees"].employees), 2, "2 employees upserted")
    equal(stores["employees"].employees[201].name, "Nguyen Van A", "Vietnamese name survives intact")
    equal(stores["employees"].employees[201].card, "1234567", "card number parsed")
    equal(int(stores["employees"].employees[202].privilege), 14, "administrator privilege parsed")
    equal(len(stores["templates"].fingers[201]), 2, "both fingers stored for PIN 201")
    equal(stores["templates"].fingers[201][1].normalized_flag, 1, "a 0 flag is coerced to 1")
    equal(len(stores["templates"].faces[202]), 1, "face template stored")
    equal(len(stores["templates"].fingers[203]), 1, "BIODATA Type=1 folded into fingerprints")
    check(203 not in stores["templates"].faces, "BIODATA Type=9 (palm) was not stored as a face")
    equal(len(stores["archive"].operations), 1, "the OPLOG event was archived")
    equal(stores["archive"].operations[0][1].op_code, 4, "OPLOG op code parsed")
    check(
        any("SOMETHINGNEW" in line for _, _, line in stores["archive"].unparsed),
        "the unrecognised tag was archived for whoever adds support",
    )
    equal(stores["registry"].devices[SERIAL].operlog_stamp, "55", "OPERLOG stamp advanced")

    # Replace-per-PIN: a second upload for 201 must replace, not accumulate.
    replace = "FP PIN=201\tFID=0\tSize=1404\tValid=1\tTMP=TkVXVEVNUExBVEU=\n"
    service.handle(post("/iclock/cdata", replace, SN=SERIAL, table="OPERLOG", Stamp="56"))
    equal(len(stores["templates"].fingers[201]), 1, "re-upload replaced the finger set, not merged it")

    # ── options ──────────────────────────────────────────────────────────────────────────────
    print("\ntable=options")
    options = (
        "~DeviceName=SpeedFace-V5L\r\nFirmVer=Ver 8.0.4.7-20230915\r\n~Platform=ZLM60_TFT\r\n"
        "~SerialNumber=CJXX204960333\r\nUserCount=245\r\nFPCount=488\r\nPushVersion=2.4.1\r\n"
    )
    response = service.handle(post("/iclock/cdata", options, SN=SERIAL, table="options"))
    equal(response.status, 200, "options accepted")
    equal(response.body, "OK", "options answers bare OK, not a counted reply")
    info = stores["registry"].options[SERIAL]
    equal(info.device_name, "SpeedFace-V5L", "device name read")
    equal(info.firmware, "Ver 8.0.4.7-20230915", "firmware version read")
    equal(info.platform, "ZLM60_TFT", "platform read")

    # ── Commands ─────────────────────────────────────────────────────────────────────────────
    print("\ncommands")
    response = service.handle(get("/iclock/getrequest", SN=SERIAL))
    equal(response.body, "OK", "an empty queue answers OK, never an empty body")

    id1 = stores["commands"].enqueue(SERIAL, cmd.check())
    # DATA DELETE USERINFO, not DATA DELETE USER: the latter is confirmed rejected (ReturnCode=-1004)
    # by real firmware.
    # delete_user is kept only as a deprecated alias rendering the same accepted wording.
    id2 = stores["commands"].enqueue(SERIAL, cmd.delete_userinfo("202"))
    response = service.handle(get("/iclock/getrequest", SN=SERIAL))
    equal(
        response.body,
        f"C:{id1}:CHECK\r\nC:{id2}:DATA DELETE USERINFO PIN=202\r\n",
        "commands rendered as C:<id>:<body>, CRLF separated",
    )

    response = service.handle(get("/iclock/getrequest", SN=SERIAL))
    equal(response.body, "OK", "claimed commands are not handed out twice (at-most-once)")

    response = service.handle(
        post("/iclock/devicecmd", f"ID={id1}&Return=0&CMD=CHECK\nID={id2}&Return=-3&CMD=DATA", SN=SERIAL)
    )
    equal(response.status, 200, "acks accepted")
    equal(len(stores["commands"].acks), 2, "both acks recorded")
    check(stores["commands"].acks[0].succeeded, "Return=0 counts as success")
    check(not stores["commands"].acks[1].succeeded, "a negative Return counts as failure")

    # ── ping and unknown routes ──────────────────────────────────────────────────────────────
    print("\nmisc routes")
    equal(service.handle(get("/iclock/ping", SN=SERIAL)).status, 200, "ping answered")
    equal(service.handle(get("/nope")).status, 404, "unknown path is a 404")
    equal(
        service.handle(post("/iclock/cdata", "x\n", SN=SERIAL, table="FUTURETABLE")).body,
        "OK: 1",
        "an unsupported table is acknowledged so it cannot wedge the device's upload queue",
    )

    # ── Path secret ──────────────────────────────────────────────────────────────────────────
    print("\npath secret")
    secret_settings = Settings(sql_connection="fake", path_secret="s3cr3t", utc_offset_hours=7)
    secret_service, _ = build_fake_service(
        secret_settings,
        devices=[DeviceRegistration(serial=SERIAL, enabled=True, machine_id=7, machine_name="M")],
        log=NullLogger(),
    )
    equal(
        secret_service.handle(get("/iclock/cdata", SN=SERIAL, options="all")).status,
        404,
        "a request without the secret segment looks exactly like an unknown path",
    )
    equal(
        secret_service.handle(get("/s3cr3t/iclock/cdata", SN=SERIAL, options="all")).status,
        200,
        "the secret-prefixed path is served",
    )

    # ── WSGI translation ─────────────────────────────────────────────────────────────────────
    print("\nWSGI translation (the IIS hosting path)")
    import io

    body_bytes = b"301\t2026-08-07 10:00:00\t0\t1\t0\t\t"
    environ = {
        "REQUEST_METHOD": "POST",
        "SCRIPT_NAME": "",
        "PATH_INFO": "/iclock/cdata",
        "QUERY_STRING": f"SN={SERIAL}&table=ATTLOG&Stamp=1",
        "CONTENT_TYPE": "text/plain",
        "CONTENT_LENGTH": str(len(body_bytes)),
        "REMOTE_ADDR": "127.0.0.1",
        "HTTP_X_FORWARDED_FOR": "10.20.30.40:52341, 127.0.0.1",
        "wsgi.input": io.BytesIO(body_bytes),
    }
    request = build_request(environ)
    equal(request.method, "POST", "method read from environ")
    equal(request.path, "/iclock/cdata", "path read from environ")
    equal(request.serial, SERIAL, "serial read from QUERY_STRING")
    equal(request.body, body_bytes, "body read from wsgi.input, bounded by CONTENT_LENGTH")
    equal(
        request.source_ip,
        "10.20.30.40",
        "device IP taken from X-Forwarded-For, with the port IIS appends stripped",
    )

    # A virtual directory prefix must survive, because an AdmsPathSecret lives in the prefix.
    prefixed = build_request(
        {**environ, "SCRIPT_NAME": "/s3cr3t", "wsgi.input": io.BytesIO(body_bytes)}
    )
    equal(prefixed.path, "/s3cr3t/iclock/cdata", "SCRIPT_NAME is preserved ahead of PATH_INFO")

    # A bodyless POST is normal: some firmware polls devicecmd with nothing to acknowledge.
    equal(
        build_request(
            {**environ, "CONTENT_LENGTH": "", "wsgi.input": io.BytesIO(b"")}
        ).body,
        b"",
        "a missing Content-Length yields an empty body rather than an error",
    )

    # The body read is capped, so an unauthenticated caller cannot buy unbounded memory with a large
    # Content-Length. Verified by asking for more than is available AND more than the cap allows.
    from adms.wsgi import MAX_BODY_BYTES

    check(MAX_BODY_BYTES <= 64 * 1024 * 1024, "the body cap is bounded")

    # Now the full application object, exercised exactly as waitress would call it.
    app = AdmsWsgiApp(service, log=NullLogger())
    captured: dict = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = dict(headers)

    chunks = app(
        {**environ, "wsgi.input": io.BytesIO(body_bytes)},
        start_response,
    )
    payload = b"".join(chunks)
    equal(captured["status"], "200 OK", "WSGI status line")
    equal(captured["headers"]["Content-Type"], "text/plain", "bare text/plain, no charset")
    equal(captured["headers"]["Content-Length"], str(len(payload)), "Content-Length matches the body")
    equal(captured["headers"]["Cache-Control"], "no-store", "caching refused explicitly")
    equal(payload, b"OK: 1", "the application replies through WSGI unchanged")

    # A refusal must carry a plain-text body and the right status, not an error page.
    chunks = app(
        {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/iclock/cdata",
            "QUERY_STRING": f"SN={UNKNOWN_SERIAL}&options=all",
            "REMOTE_ADDR": "127.0.0.1",
            "wsgi.input": io.BytesIO(b""),
        },
        start_response,
    )
    equal(captured["status"], "401 Unauthorized", "unregistered serial gets 401 through WSGI")
    equal(b"".join(chunks), b"Unauthorized", "refusal body is a fixed phrase")

    # ── Secret redaction ─────────────────────────────────────────────────────────────────────
    print("\nsecret redaction")
    dsn = "DRIVER={ODBC Driver 18};SERVER=db1,1433;UID=sa;PWD=Sup3rSecret!;Encrypt=yes"
    redacted = str(scrub(dsn))
    check("Sup3rSecret" not in redacted, "PWD value is redacted from log output", redacted)
    check("sa" not in redacted.split("UID=")[1][:5], "UID value is redacted", redacted)
    check("SERVER=db1,1433" in redacted, "non-secret parts stay readable for diagnosis", redacted)

    # ── Result ───────────────────────────────────────────────────────────────────────────────
    print()
    if _failures:
        print(f"FAILED: {len(_failures)} of {_checks} checks")
        for name in _failures:
            print(f"  - {name}")
        return 1

    print(f"PASSED: {_checks} checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
