"""
Property tests for ``adms.protocol.text`` -- the wire-text primitives every parser in this service is
built on. Every one of Requirement 4's clauses is either "decode this without raising" or "split /
coerce this leniently and default explicitly", so the whole module is exercised here and nowhere else.

Properties 14, 19 and 20 are the three the design marks as generated: seeded, at least
:data:`generators.ITERATIONS` iterations, drawn from ``tests/generators.py``'s hand-rolled corpora over
``random.Random``. Everything else below is table-driven parametrisation over adversarial fixed inputs,
per the design's Testing Strategy -- no ``hypothesis``.

One property, one test, so a failure names the claim that broke. Each generated test carries
``# Feature: adms-attendance-system, Property N: <claim>``; the table-driven tests carry
``Validates: Requirements ...`` in their own docstring, matching ``tests/test_files.py``.
"""

from __future__ import annotations

import datetime as dt

import pytest

import generators as gen
from adms.protocol import text

# ── Property 14: Body decoding is total ─────────────────────────────────────────────────────


def test_decode_body_is_total_over_hostile_bytes() -> None:
    # Feature: adms-attendance-system, Property 14: For all byte sequences, decode_body returns a
    # string and raises nothing.
    #
    # generators.byte_sequence already mixes in GBK_ONLY_FRAGMENTS (valid GBK, invalid UTF-8),
    # UNDECODABLE_FRAGMENTS (a lone surrogate, a truncated multi-byte sequence, an over-long form) and
    # hostile_text encoded with surrogatepass, so drawing from it alone covers every shape Requirement
    # 4.1 names.
    #
    # Validates: Requirements 4.1
    rng = gen.rng()
    for _ in range(gen.ITERATIONS):
        raw = gen.byte_sequence(rng)
        result = text.decode_body(raw)
        assert isinstance(result, str), f"seed={gen.SEED} raw={raw!r}"


# ── Property 15: Line splitting preserves order and discards only blanks ────────────────────

_LINE_SPLIT_CASES: tuple[tuple[str, list[str]], ...] = (
    ("a\r\nb\nc\rd", ["a", "b", "c", "d"]),
    ("a\r\n\r\nb", ["a", "b"]),
    ("  a  \r\n b \n", ["a", "b"]),
    ("\r\n\r\n\n\r", []),
    ("a\rb\r\nc\n\nd\r\n", ["a", "b", "c", "d"]),
    ("   \r\nsecond\r\n   \nthird", ["second", "third"]),
    ("only-one-line", ["only-one-line"]),
    ("", []),
)
_LINE_SPLIT_IDS = [f"case-{i}" for i in range(len(_LINE_SPLIT_CASES))]


@pytest.mark.parametrize(("raw", "expected"), _LINE_SPLIT_CASES, ids=_LINE_SPLIT_IDS)
def test_split_lines_preserves_order_and_discards_only_blanks(raw: str, expected: list[str]) -> None:
    """
    For all texts mixing ``\\r\\n``, ``\\n`` and a bare ``\\r``, the result is the sequence of
    non-blank lines in arrival order, each trimmed, with its length equal to the number of non-blank
    lines in the input.

    Validates: Requirements 4.2
    """
    result = text.split_lines(raw)
    assert result == expected, f"raw={raw!r}"
    # The accounting half of the property, stated independently of the exact case above: the result's
    # length is exactly the count of non-blank lines once every line ending is normalised.
    normalised = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    assert len(result) == sum(1 for line in normalised if line.strip())


# ── Property 16: Field splitting prefers tabs, and a single space never splits a value ──────

_FIELD_SPLIT_CASES: tuple[tuple[str, list[str]], ...] = (
    ("A\tB\tC", ["A", "B", "C"]),
    ("A\tB  C\tD", ["A", "B  C", "D"]),  # tab wins; the double space inside a field survives
    ("A  B   C", ["A", "B", "C"]),  # no tab: runs of 2+ spaces split
    ("Name=Nguyen Van A", ["Name=Nguyen Van A"]),  # single spaces never split a value
    ("PIN=1  Name=Nguyen Van A", ["PIN=1", "Name=Nguyen Van A"]),  # mixed: only the run of 2 splits
    ("\tPIN=1\t", ["", "PIN=1", ""]),  # tabs at the edges yield empty fields, not a shifted list
    ("no-separator-at-all", ["no-separator-at-all"]),
)
_FIELD_SPLIT_IDS = [f"case-{i}" for i in range(len(_FIELD_SPLIT_CASES))]


@pytest.mark.parametrize(("line", "expected"), _FIELD_SPLIT_CASES, ids=_FIELD_SPLIT_IDS)
def test_split_fields_prefers_tabs_and_a_single_space_never_splits(line: str, expected: list[str]) -> None:
    """
    For all lines containing a tab, splitting is on tabs alone; for all tab-free lines, splitting is
    on runs of two or more spaces; and for all values containing single spaces
    (``Name=Nguyen Van A``), the value survives intact.

    Validates: Requirements 4.3, 4.4
    """
    assert text.split_fields(line) == expected, f"line={line!r}"


# ── Property 17: Key=Value parsing splits once and lower-cases the key ──────────────────────

_KV_CASES: tuple[tuple[list[str] | str, dict[str, str]], ...] = (
    (["PIN=101"], {"pin": "101"}),
    # =-padded base64 must survive whole: split on the FIRST = only.
    (["TMP=QklPRklOR0VS=="], {"tmp": "QklPRklOR0VS=="}),
    (["Name=A=B=C"], {"name": "A=B=C"}),
    (["PIN"], {"_0": "PIN"}),  # no '=' at all -> positional key
    (["PIN=101", "Name"], {"pin": "101", "_0": "Name"}),
    (["OPLOG", "5", "Enroll=1"], {"_0": "OPLOG", "_1": "5", "enroll": "1"}),
    ("PIN=101\tName=Nguyen Van A", {"pin": "101", "name": "Nguyen Van A"}),  # str input
    (["Size=10", "SIZE=20"], {"size": "20"}),  # case-insensitive key collision, last wins
    (["", "PIN=1"], {"pin": "1"}),  # a blank field contributes nothing, not a positional slot
    (["=novalue"], {"_0": "=novalue"}),  # an empty key falls through to positional, raw text kept
)
_KV_IDS = [f"case-{i}" for i in range(len(_KV_CASES))]


@pytest.mark.parametrize(("fields_in", "expected"), _KV_CASES, ids=_KV_IDS)
def test_parse_kv_splits_once_and_lowercases_the_key(
    fields_in: list[str] | str, expected: dict[str, str]
) -> None:
    """
    The split is on the first ``=`` only, so a ``=``-padded base64 payload is returned whole; every
    key is lower-cased; and any field carrying no ``=`` is reachable under a positional key.

    Validates: Requirements 4.5, 4.6
    """
    assert text.parse_kv(fields_in) == expected, f"fields_in={fields_in!r}"


# ── Property 18: Integer and boolean parsing are lenient and default explicitly ──────────────


def test_to_int_and_to_bool_are_lenient_and_default_explicitly() -> None:
    """
    to_int returns the integer value, the truncation of a decimal form such as ``"1.0"``, or the
    supplied default; to_bool maps the seven true spellings and seven false spellings
    case-insensitively and returns the supplied default for everything else, including blank.

    Validates: Requirements 4.7, 4.8
    """
    int_cases: tuple[tuple[object, int, int], ...] = (
        ("101", 0, 101),
        ("1.0", 0, 1),
        ("-3.9", 0, -3),  # truncation, not rounding
        ("", 5, 5),
        ("   ", 3, 3),
        (None, 7, 7),
        ("abc", 9, 9),
        (" 42 ", 0, 42),
        (42, 0, 42),  # a non-string input is stringified first
        ("3.0", -1, 3),
    )
    for raw, default, expected in int_cases:
        result = text.to_int(raw, default)
        assert isinstance(result, int)
        assert result == expected, f"raw={raw!r} default={default!r}"

    true_spellings = ("1", "true", "yes", "y", "on", "enable", "enabled")
    false_spellings = ("0", "false", "no", "n", "off", "disable", "disabled")

    for spelling in true_spellings:
        assert text.to_bool(spelling, False) is True, f"spelling={spelling!r}"
        assert text.to_bool(spelling.upper(), False) is True, f"spelling={spelling.upper()!r}"

    for spelling in false_spellings:
        assert text.to_bool(spelling, True) is False, f"spelling={spelling!r}"
        assert text.to_bool(spelling.upper(), True) is False, f"spelling={spelling.upper()!r}"

    # Blank and unrecognised text both fall through to the supplied default, explicitly.
    assert text.to_bool("", True) is True
    assert text.to_bool("", False) is False
    assert text.to_bool("   ", True) is True
    assert text.to_bool(None, True) is True
    assert text.to_bool(None, False) is False
    assert text.to_bool("maybe", True) is True
    assert text.to_bool("maybe", False) is False


# ── Property 19: Timestamp parsing round-trips, and an unusable timestamp yields no punch ───


def test_timestamp_parsing_round_trips_and_dead_clocks_yield_no_punch() -> None:
    # Feature: adms-attendance-system, Property 19: For any whole-second datetime and any accepted
    # layout, formatting then parsing returns that datetime, with any fractional-second suffix
    # discarded without affecting the result; for all strings matching no accepted layout -- including
    # "0000-00-00 00:00:00" -- the result is None; and for all inputs the result is naive.
    #
    # Validates: Requirements 4.9, 4.10, 4.11
    rng = gen.rng()
    for _ in range(gen.ITERATIONS):
        moment = gen.whole_second_datetime(rng)
        layout = rng.choice(gen.ROUND_TRIP_LAYOUTS)
        formatted = moment.strftime(layout)

        result = text.parse_timestamp(formatted)
        assert result == moment, f"seed={gen.SEED} layout={layout!r} formatted={formatted!r}"
        assert result is not None
        assert result.tzinfo is None, f"seed={gen.SEED} formatted={formatted!r}"

        # A fractional-second suffix is discarded without affecting the result.
        fractional = f"{formatted}.{rng.randint(0, 999_999):06d}"
        with_fraction = text.parse_timestamp(fractional)
        assert with_fraction == moment, f"seed={gen.SEED} fractional={fractional!r}"

    for stamp in gen.DEAD_CLOCK_STAMPS:
        assert text.parse_timestamp(stamp) is None, f"stamp={stamp!r}"

    # The two cases the task names explicitly, spelled out so a reader does not have to open
    # generators.py to see that Requirement 4.10's example is actually covered.
    assert text.parse_timestamp("0000-00-00 00:00:00") is None
    assert text.parse_timestamp("2026-02-30 10:00:00") is None


def test_round_trip_layouts_are_a_subset_of_the_module_under_test() -> None:
    """
    generators.ROUND_TRIP_LAYOUTS is a deliberate *copy* of text._TIMESTAMP_FORMATS, not an import --
    a property that reads its expectation from the code under test cannot fail when that code changes.
    This is the drift guard: the copy must stay a subset of the real layout tuple, or the round-trip
    property above would silently stop meaning anything the day a layout was renamed or removed.

    Not one of the design's 72 correctness properties -- a guard on the test fixture itself.
    """
    assert set(gen.ROUND_TRIP_LAYOUTS) <= set(text._TIMESTAMP_FORMATS), (
        f"ROUND_TRIP_LAYOUTS={gen.ROUND_TRIP_LAYOUTS!r} is not a subset of "
        f"text._TIMESTAMP_FORMATS={text._TIMESTAMP_FORMATS!r}"
    )


# ── Property 20: Every wire-text primitive is total and type-correct ────────────────────────


def test_every_text_primitive_is_total_and_type_correct() -> None:
    # Feature: adms-attendance-system, Property 20: For all inputs, each function in protocol.text
    # returns a value of its declared type and raises no exception.
    #
    # Validates: Requirement 4.12
    rng = gen.rng()
    misc_objects: tuple[object, ...] = (None, True, False, 0, -7, 3.14, "", "   ")

    for _ in range(gen.ITERATIONS):
        raw_bytes = gen.byte_sequence(rng)
        decoded = text.decode_body(raw_bytes)
        assert isinstance(decoded, str), f"seed={gen.SEED} raw_bytes={raw_bytes!r}"

        hostile = gen.hostile_text(rng)
        decoded_str = text.decode_body(hostile)
        assert isinstance(decoded_str, str), f"seed={gen.SEED} hostile={hostile!r}"

        for candidate in (decoded, hostile):
            lines = text.split_lines(candidate)
            assert isinstance(lines, list), f"seed={gen.SEED} candidate={candidate!r}"
            assert all(isinstance(line, str) for line in lines), f"seed={gen.SEED} lines={lines!r}"

            # split_fields and parse_kv are exercised on the whole candidate directly, so coverage
            # does not depend on split_lines having produced anything for this draw.
            fields = text.split_fields(candidate)
            assert isinstance(fields, list), f"seed={gen.SEED} candidate={candidate!r}"
            assert all(isinstance(f, str) for f in fields), f"seed={gen.SEED} fields={fields!r}"

            kv_from_list = text.parse_kv(fields)
            assert isinstance(kv_from_list, dict), f"seed={gen.SEED} fields={fields!r}"
            assert all(
                isinstance(k, str) and isinstance(v, str) for k, v in kv_from_list.items()
            ), f"seed={gen.SEED} kv_from_list={kv_from_list!r}"

            kv_from_str = text.parse_kv(candidate)
            assert isinstance(kv_from_str, dict), f"seed={gen.SEED} candidate={candidate!r}"

            stamp = text.parse_timestamp(candidate)
            assert stamp is None or isinstance(stamp, dt.datetime), f"seed={gen.SEED} candidate={candidate!r}"

        misc = rng.choice((*misc_objects, hostile))
        default_int = rng.randint(-1000, 1000)
        int_result = text.to_int(misc, default_int)
        assert isinstance(int_result, int), f"seed={gen.SEED} misc={misc!r}"

        default_bool = rng.choice((True, False))
        bool_result = text.to_bool(misc, default_bool)
        assert isinstance(bool_result, bool), f"seed={gen.SEED} misc={misc!r}"
