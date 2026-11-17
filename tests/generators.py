"""
Hand-rolled, seeded generation for the three properties the design marks as generated: 14 (body
decoding is total), 19 (timestamp parsing round-trips) and 20 (every wire-text primitive is total).

``hypothesis`` is deliberately not adopted. The runtime is two packages and the dev list is
deliberately lean, and what these three claims need is volume over a small, well-understood input
space -- bytes, whole-second datetimes, hostile text -- not shrinking, a strategy language and an
on-disk example database. So generation is :class:`random.Random` with a fixed seed, and a failing run
is reproducible from the seed the assertion message carries. Everything else in the suite is
parametrised over adversarial fixed inputs, which is a better instrument when the interesting cases
are already known by name.

Imported as a plain module -- ``import generators`` -- because ``tests/`` has no ``__init__.py``,
matching the flat layout the design names, and pytest puts the directory holding ``conftest.py`` on
``sys.path``.

The convention, so a failure names the input rather than the run:

    import generators as gen

    def test_decoding_is_total() -> None:
        rng = gen.rng()
        for _ in range(gen.ITERATIONS):
            raw = gen.byte_sequence(rng)
            assert isinstance(decode_body(raw), str), f"seed={gen.SEED} raw={raw!r}"

Each generator yields one value per call rather than a batch, so the loop above reads the same way in
every property and the failing value is in scope when the assertion breaks.
"""

from __future__ import annotations

import datetime as dt
import random

__all__ = [
    "DEAD_CLOCK_STAMPS",
    "GBK_ONLY_FRAGMENTS",
    "ITERATIONS",
    "LOSSY_LAYOUTS",
    "ROUND_TRIP_LAYOUTS",
    "SEED",
    "UNDECODABLE_FRAGMENTS",
    "byte_sequence",
    "hostile_text",
    "rng",
    "whole_second_datetime",
]

#: Fixed, so a failure is reproducible. Printed by every property that uses it. The value is a date,
#: which is only a convention -- it just has to never change silently.
SEED = 20_260_807

#: Minimum iterations per generated property, per the design's test configuration.
ITERATIONS = 100


def rng(seed: int = SEED) -> random.Random:
    """
    A generator seeded independently of the global one.

    Its own instance rather than ``random.seed()``: the module-level generator is shared with anything
    else in the process, so seeding it would make one property's reproducibility depend on whether
    another ran first.
    """
    return random.Random(seed)


# ── Bytes ────────────────────────────────────────────────────────────────────────────────────

#: Valid GBK, invalid UTF-8. The whole reason ``decode_body`` tries three encodings in order: this is
#: what Chinese-market firmware sends for a name, and a strict UTF-8 decode would reject the batch.
GBK_ONLY_FRAGMENTS = (
    b"\xd6\xd0\xce\xc4",          # 中文
    b"\xc4\xe3\xba\xc3",          # 你好
    b"\xd0\xd5\xc3\xfb",          # 姓名
)

#: Byte sequences no strict decoder accepts: a lone surrogate encoded through surrogatepass, a
#: truncated multi-byte sequence, an over-long form, and bare high bytes. Latin-1 terminates the chain,
#: so the required outcome is a string -- possibly mojibake -- and never an exception.
UNDECODABLE_FRAGMENTS = (
    b"\xed\xa0\x80",              # lone surrogate D800
    b"\xe4\xb8",                  # truncated three-byte sequence
    b"\xc0\x80",                  # over-long encoding of NUL
    b"\xff\xfe",                  # a BOM that is not one here
    b"\x80\x81\x82",
)

#: The separators and terminators that decide where records begin and end.
_STRUCTURAL = (b"\t", b"\n", b"\r\n", b"\r", b"=", b"\x00", b"  ", b"&")

_ASCII_WORDS = (b"PIN", b"101", b"2026-08-07 08:00:00", b"TMP=QklPRklOR0VS", b"Valid", b"0")


def byte_sequence(source: random.Random, *, max_parts: int = 8) -> bytes:
    """
    One request body's worth of bytes, biased towards the shapes that have broken decoders.

    Not uniform random bytes. Uniform noise almost never contains a valid GBK pair, a lone surrogate or
    a truncated multi-byte sequence, which are precisely the three cases the encoding chain exists for,
    so the corpus is mixed in deliberately.
    """
    pool = (
        *GBK_ONLY_FRAGMENTS,
        *UNDECODABLE_FRAGMENTS,
        *_STRUCTURAL,
        *_ASCII_WORDS,
    )
    parts: list[bytes] = []
    for _ in range(source.randint(0, max_parts)):
        choice = source.random()
        if choice < 0.55:
            parts.append(source.choice(pool))
        elif choice < 0.8:
            parts.append(bytes(source.randint(0, 255) for _ in range(source.randint(1, 12))))
        else:
            parts.append(hostile_text(source).encode("utf-8", errors="surrogatepass"))
    return b"".join(parts)


# ── Timestamps ───────────────────────────────────────────────────────────────────────────────

#: Layouts that carry whole seconds, so formatting a datetime and parsing it back must return the same
#: value. Copied from ``adms.protocol.text._TIMESTAMP_FORMATS`` rather than imported: a property that
#: reads its expectation from the code under test cannot fail when that code changes. Property 19's
#: test also asserts this tuple is a subset of the module's own, so the copy cannot drift unnoticed.
ROUND_TRIP_LAYOUTS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%Y%m%d%H%M%S",
)

#: Accepted layouts that discard information. A round trip through these is expected to lose the
#: seconds or the whole time, so they are asserted against a truncated expectation, not equality.
LOSSY_LAYOUTS = (
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d",
)

#: Timestamps that must yield no punch at all. A device with a dead real-time clock emits these, and a
#: punch that cannot be filed against a day is worse than a punch that was rejected and re-sent.
DEAD_CLOCK_STAMPS = (
    "0000-00-00 00:00:00",
    "2000-00-00 00:00:00",
    "2026-02-30 10:00:00",
    "2026-13-01 10:00:00",
    "2026-08-07 25:00:00",
    "not-a-date",
    "",
    "   ",
)

#: Bounds wide enough to cover a device shipped with a factory clock and one set a decade ahead, and
#: narrow enough that every value is representable in ATTENDANCEDB's DATETIME.
_EPOCH = dt.datetime(2000, 1, 1, 0, 0, 0)
_HORIZON = dt.datetime(2035, 12, 31, 23, 59, 59)


def whole_second_datetime(source: random.Random) -> dt.datetime:
    """
    A naive datetime on a whole second.

    Whole seconds because every accepted wire layout has second resolution and ATTENDANCEDB's ``DATETIME``
    is compared to the second for duplicate detection -- a generated microsecond could never round-trip
    and would test the generator's imagination rather than the parser.
    """
    span = int((_HORIZON - _EPOCH).total_seconds())
    return _EPOCH + dt.timedelta(seconds=source.randint(0, span))


# ── Text ─────────────────────────────────────────────────────────────────────────────────────

#: Each entry is here because it has broken something: Vietnamese diacritics (the names in this
#: database), a double space where a tab belongs, ``=`` padding on base64 templates, the ``~`` prefix
#: firmware puts on option names, and control characters that arrive from a wiring fault.
_TEXT_ATOMS = (
    "Nguyen Van A",
    "Tran Thi B",
    "Nguyễn Văn Ánh",
    "  ",
    "\t",
    "=",
    "==",
    "~DeviceName",
    "PIN",
    "0",
    "中文",
    "\x00",
    "\x1b",
    "\u200b",
    "🙂",
    "'; DROP TABLE CheckInOut --",
    "\ud800",
)


def hostile_text(source: random.Random, *, max_parts: int = 6) -> str:
    """
    A string assembled from the fragments that have caused real trouble.

    May contain a lone surrogate, which is why callers encode with ``surrogatepass`` -- a body that
    cannot be encoded by the usual route is exactly the kind the wire delivers, and the primitives must
    still be total over it.
    """
    return "".join(source.choice(_TEXT_ATOMS) for _ in range(source.randint(0, max_parts)))
