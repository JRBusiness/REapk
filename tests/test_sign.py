"""Structural tests for the native v2/v3 signer (no apksigner needed)."""
import io
import struct
import zipfile

import pytest

pytest.importorskip("cryptography")

from reapk import Signer  # noqa: E402

_DEX = b"dex\n035" + bytes([0]) + b"payload"


def _zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", bytes([0]) + b"manifest")
        z.writestr("classes.dex", _DEX)
    return buf.getvalue()


def test_signing_block_inserted():
    raw = _zip()
    signed = Signer().sign(raw)
    assert signed != raw
    assert b"APK Sig Block 42" in signed
    # the v2 and v3 block IDs are present in the signing block
    assert struct.pack("<I", 0x7109871A) in signed   # v2
    assert struct.pack("<I", 0xF05368C0) in signed   # v3
    # EOCD central-directory offset advanced past the inserted block
    e0, e1 = raw.rfind(b"PK\x05\x06"), signed.rfind(b"PK\x05\x06")
    assert struct.unpack_from("<I", signed, e1 + 16)[0] > \
        struct.unpack_from("<I", raw, e0 + 16)[0]
    # the zip still reads back
    assert zipfile.ZipFile(io.BytesIO(signed)).read("classes.dex") == _DEX
