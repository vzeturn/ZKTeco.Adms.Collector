"""
Example tests for ``adms.protocol.options.parse_options`` and the Requirement 6 behaviours around it.

**This module is example-based: it implements none of the numbered correctness properties.**
Requirement 6.1-6.7 (device self-description / options parsing) is covered here by example tests
("separators, alias lookup, serial preference, the 8000-char bound"). Every assertion below traces to
a requirement clause, named in the test's own docstring.

What is covered, each by example rather than by generation, and each naming the clause it stands in for:

* Every pair separator firmware uses between ``Key=Value`` options -- newline, carriage return, tab and
  comma (Requirement 6.2), and that the mapping stays flat text rather than a fixed column set, so a key
  none of the four named properties recognise still survives (Requirement 6.3).
* Case-insensitive alias lookup that ignores a leading ``~`` on either side, across the spellings
  firmware uses for device name, firmware version, platform and push version (Requirement 6.4).
* That the caller's serial wins over one repeated in the body, and the body is consulted only when the
  caller supplied none (Requirement 6.5).
* The 8,000-character ``OptionsJson`` bound ``adms.db.registry._options_json`` applies after
  ``json.dumps(sort_keys=True)`` (Requirement 6.6).
* The two service-level behaviours that make an ``options`` upload different from every other table: no
  link is required (Requirement 6.1), and the reply is the bare body ``OK``, never an ``Ok_Count``
  (Requirement 6.7).
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from conftest import SERIAL_UNLINKED, unlinked_device

from adms.db.registry import _options_json
from adms.models import DeviceInfo
from adms.protocol.options import parse_options

# ---- Separators between option pairs: Requirement 6.2 --------------------------------------

_SEPARATOR_NAMES = {"\n": "newline", "\r": "carriage-return", "\t": "tab", ",": "comma"}


@pytest.mark.parametrize("separator", sorted(_SEPARATOR_NAMES), ids=lambda s: _SEPARATOR_NAMES[s])
def test_each_accepted_separator_divides_option_pairs(separator: str) -> None:
    """
    Firmware is inconsistent about which character divides one ``Key=Value`` pair from the next, and
    none of the four accepted separators may be treated as part of a value.

    Requirement 6.2
    """
    body = separator.join(["Zone=1", "DeviceName=Reader1", "FirmVer=6.60"])
    info = parse_options(body)
    assert info.values == {"Zone": "1", "DeviceName": "Reader1", "FirmVer": "6.60"}


def test_separators_can_be_mixed_within_one_body() -> None:
    """
    A real body is not consistent even within one upload, so the separator is a property of the pair
    boundary rather than of the whole body -- a parser that requires one consistent separator fails on
    the very inconsistency this requirement exists to tolerate.

    Requirement 6.2
    """
    body = "Zone=1\r\nDeviceName=Reader1\tFirmVer=6.60,Platform=MIFARE"
    info = parse_options(body)
    assert info.values == {
        "Zone": "1",
        "DeviceName": "Reader1",
        "FirmVer": "6.60",
        "Platform": "MIFARE",
    }


# ---- The mapping is flat text, not promoted columns: Requirement 6.3 -----------------------


def test_an_unrecognised_key_survives_as_text_rather_than_being_dropped() -> None:
    """
    The key set differs per model and grows with every firmware release, and none of it drives logic --
    so a key none of the four named lookups recognise must still be readable afterwards, verbatim, as
    text in the flat mapping.

    Requirement 6.3
    """
    body = "DeviceName=Reader1\r\nNewFirmwareFieldNobodyHasSeenYet=42"
    info = parse_options(body)
    assert info.values["NewFirmwareFieldNobodyHasSeenYet"] == "42"
    assert info.values["DeviceName"] == "Reader1"


# ---- Case-insensitive lookup ignoring a leading '~': Requirement 6.4 ------------------------


@pytest.mark.parametrize(
    ("stored_key", "lookup_name"),
    [
        ("~DeviceName", "DeviceName"),
        ("DeviceName", "~DeviceName"),
        ("~SerialNumber", "SerialNumber"),
    ],
    ids=["tilde-stored-plain-lookup", "plain-stored-tilde-lookup", "tilde-both"],
)
def test_lookup_ignores_a_leading_tilde_on_either_side(stored_key: str, lookup_name: str) -> None:
    """
    Vendor keys are prefixed with ``~`` on some firmware and not on others for the same logical field, so
    the tilde must be ignored whichever side of the lookup carries it.

    Requirement 6.4
    """
    info = DeviceInfo(serial="", values={stored_key: "value-under-test"})
    assert info.get(lookup_name) == "value-under-test"


@pytest.mark.parametrize(
    "body",
    ["~DeviceName=Reader-A", "DeviceName=Reader-A", "devicename=Reader-A", "DEVICENAME=Reader-A"],
    ids=["tilde", "plain", "lower", "upper"],
)
def test_device_name_resolves_case_insensitively_across_spellings(body: str) -> None:
    """Requirement 6.4"""
    assert parse_options(body).device_name == "Reader-A"


@pytest.mark.parametrize(
    "body",
    ["FirmVer=6.60", "~FirmVer=6.60", "FirmwareVersion=6.60", "firmver=6.60"],
    ids=["FirmVer", "tilde-FirmVer", "FirmwareVersion", "lower"],
)
def test_firmware_resolves_case_insensitively_across_spellings(body: str) -> None:
    """Requirement 6.4"""
    assert parse_options(body).firmware == "6.60"


@pytest.mark.parametrize(
    "body",
    ["~Platform=MIFARE", "Platform=MIFARE", "PLATFORM=MIFARE"],
    ids=["tilde", "plain", "upper"],
)
def test_platform_resolves_case_insensitively_across_spellings(body: str) -> None:
    """Requirement 6.4"""
    assert parse_options(body).platform == "MIFARE"


@pytest.mark.parametrize(
    "body",
    ["PushVersion=2.4.1", "~PushVersion=2.4.1", "pushver=2.4.1", "PUSHVER=2.4.1"],
    ids=["PushVersion", "tilde-PushVersion", "pushver", "upper"],
)
def test_push_version_resolves_case_insensitively_across_spellings(body: str) -> None:
    """Requirement 6.4"""
    assert parse_options(body).push_version == "2.4.1"


# ---- The caller's serial wins over the body's: Requirement 6.5 -----------------------------


def test_the_callers_serial_wins_over_one_repeated_in_the_body() -> None:
    """
    The caller has already validated its serial against the allow-list; a body claiming a different one
    must not override it.

    Requirement 6.5
    """
    body = "~SerialNumber=BODY0001\r\nDeviceName=Reader1"
    info = parse_options(body, serial="CALLER0002")
    assert info.serial == "CALLER0002"


@pytest.mark.parametrize("body_key", ["~SerialNumber", "SerialNumber"], ids=["tilde", "plain"])
def test_the_body_serial_is_used_only_when_the_caller_supplied_none(body_key: str) -> None:
    """Requirement 6.5"""
    body = f"{body_key}=BODY0001\r\nDeviceName=Reader1"
    info = parse_options(body, serial="")
    assert info.serial == "BODY0001"


def test_with_no_serial_supplied_anywhere_the_result_is_empty() -> None:
    """Requirement 6.5"""
    info = parse_options("DeviceName=Reader1", serial="")
    assert info.serial == ""


# ---- The OptionsJson bound after json.dumps(sort_keys=True): Requirement 6.6 ----------------


def test_options_json_is_bounded_at_8000_characters() -> None:
    """
    ``ADMS_DEVICE.OptionsJson`` is one ``NVARCHAR(MAX)`` column holding the whole option mapping, and a
    firmware build that reports an unusually large option set must not fail the write -- the value is
    clipped rather than rejected.

    Requirement 6.6
    """
    huge_values = {f"Key{i:04d}": "x" * 40 for i in range(400)}
    info = DeviceInfo(serial="X", values=huge_values)
    stored = _options_json(info)
    assert len(stored) == 8000
    assert stored == json.dumps(huge_values, ensure_ascii=False, sort_keys=True)[:8000]


def test_options_json_is_sorted_and_untruncated_when_under_the_bound() -> None:
    """
    A stable key order is what makes two readings of the same device diffable, which is why the
    serialisation is ``sort_keys=True`` rather than insertion order.

    Requirement 6.6
    """
    values = {"Zone": "1", "DeviceName": "Reader1", "FirmVer": "6.60"}
    info = DeviceInfo(serial="X", values=values)
    stored = _options_json(info)
    assert json.loads(stored) == values
    assert stored == json.dumps(values, ensure_ascii=False, sort_keys=True)


# ---- Service-level behaviour: Requirements 6.1 and 6.7 --------------------------------------


def test_an_unlinked_but_enabled_device_may_upload_options(fake: Any, wire: Any) -> None:
    """
    Options is metadata about the device itself -- exactly what an operator reads while deciding which
    machine row a serial belongs to -- so it must not require the very link that metadata would help
    someone create. Every other data-carrying route (ATTLOG, OPERLOG, a query result) answers 503 for the
    same registration; this one must not.

    Requirement 6.1
    """
    service, _stores = fake(devices=[unlinked_device()])
    response = service.handle(wire.options(SERIAL_UNLINKED, {"~DeviceName": "Reader1"}))
    assert response.status == 200


def test_options_is_acknowledged_with_the_bare_body_ok(fake: Any, wire: Any) -> None:
    """
    Some firmware reads a counted reply to a non-record upload as a protocol error, so an ``options``
    upload must answer the bare body ``OK`` and never ``OK: <n>``, however many option pairs arrived.

    Requirement 6.7
    """
    service, _stores = fake(devices=[unlinked_device()])
    response = service.handle(
        wire.options(
            SERIAL_UNLINKED, {"~DeviceName": "Reader1", "FirmVer": "6.60", "Platform": "MIFARE"}
        )
    )
    assert response.body == "OK"
