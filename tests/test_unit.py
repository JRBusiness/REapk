"""Fixture-free unit tests for the low-level codecs."""
import io
import struct
import zipfile

import pytest

from reapk.dex._leb import (
    _mutf8, _sleb128, _uleb128, enc_mutf8, enc_sleb, enc_uleb,
)
from reapk.dex.pool import _u16key
from reapk.zipalign import read_zip_entries, stored_entry, write_aligned_zip

DEX_MAGIC = b"dex\n035" + bytes([0])
EMOJI = chr(0x1F600)        # supplementary char -> UTF-16 surrogate pair (0xD83D ..)
HIGH_BMP = chr(0xE000)      # BMP char that sorts AFTER the surrogate in UTF-16 order


@pytest.mark.parametrize("n", [0, 1, 127, 128, 255, 16384, 0x7FFFFFFF, 0xFFFFFFFF])
def test_uleb_roundtrip(n):
    v, off = _uleb128(enc_uleb(n), 0)
    assert v == n and off == len(enc_uleb(n))


@pytest.mark.parametrize("n", [0, 1, -1, 63, -64, 127, -128, 300, -300, 1 << 20, -(1 << 20)])
def test_sleb_roundtrip(n):
    v, _ = _sleb128(enc_sleb(n), 0)
    assert v == n


@pytest.mark.parametrize("s", ["", "hello", "café", chr(0) + "embedded",
                               "emoji " + EMOJI + " x", "mix é " + HIGH_BMP + " end"])
def test_mutf8_roundtrip(s):
    blob = enc_mutf8(s)
    _, off = _uleb128(blob, 0)          # skip the uleb length prefix
    end = blob.index(0, off)            # find the terminator
    assert _mutf8(blob[off:end]) == s


def test_u16key_supplementary_order():
    # DEX sorts by UTF-16 code unit, so a supplementary char (surrogate, 0xD83D)
    # sorts BEFORE a BMP char at 0xE000 -- the opposite of Python's code-point
    # order, where the supplementary char (0x1F600) sorts last.
    items = [EMOJI, HIGH_BMP, "A"]
    assert sorted(items, key=_u16key) == ["A", EMOJI, HIGH_BMP]
    assert sorted(items) == ["A", HIGH_BMP, EMOJI]
    assert sorted(items, key=_u16key) != sorted(items)


def _make_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", bytes([0, 1, 2]) + b"stored", zipfile.ZIP_STORED)
        z.writestr("lib/x86_64/libfoo.so", b"NATIVE" * 100, zipfile.ZIP_STORED)
        z.writestr("classes.dex", DEX_MAGIC + b"x" * 500, zipfile.ZIP_DEFLATED)
    return buf.getvalue()


def test_zip_roundtrip_and_alignment():
    entries = read_zip_entries(_make_zip())
    out = write_aligned_zip(entries)
    z = zipfile.ZipFile(io.BytesIO(out))
    assert z.read("AndroidManifest.xml") == bytes([0, 1, 2]) + b"stored"
    assert z.read("classes.dex").startswith(DEX_MAGIC)
    # native .so data must be 4096-aligned; other stored entries 4-aligned
    for info in z.infolist():
        if info.compress_type != zipfile.ZIP_STORED:
            continue
        off = info.header_offset
        nlen, elen = struct.unpack_from("<HH", out, off + 26)
        data_off = off + 30 + nlen + elen
        want = 4096 if info.filename.endswith(".so") else 4
        assert data_off % want == 0, (info.filename, data_off, want)


def test_stored_entry_crc():
    e = stored_entry(b"x.txt", b"payload")
    assert e["method"] == 0 and e["usize"] == 7 and e["raw"] == b"payload"
