"""High-level, object-oriented API.

This is the ergonomic entry point most callers want::

    from reapk import Apk

    apk = Apk.open("app.apk")
    print(apk.manifest.package, len(apk.manifest.exported_components))

    apk.manifest.set_debuggable().set_cleartext()
    apk.manifest.add_permission("android.permission.INTERNET")
    apk.save("patched.apk")              # repackage (zipalign) + v2/v3 sign

The classes here are thin, well-typed facades over the package's verified
procedural core (``axml``, ``dex``, ``zipalign``, ``sign`` ...).
"""
from __future__ import annotations

import io
import zipfile
from typing import List, Optional

from .axml import (
    Arsc, encode_axml, parse_axml, parse_axml_ir, patch_add_permission,
    patch_cleartext, patch_debuggable,
)
from .bundle import load_base_apk
from .dex import DexFile, disassemble
from .errors import BundleError
from .manifest import analyze_manifest
from .secrets import scan_secrets
from .sign import apk_sign_v2
from .zipalign import read_zip_entries, stored_entry, write_aligned_zip

_MANIFEST = "AndroidManifest.xml"


class Signer:
    """Native APK Signature Scheme **v2 + v3** signer (RSA-2048 / SHA-256).

    Requires no JDK or ``apksigner``. The signing key/cert are generated once
    and cached under ``~/.reapk/``.
    """

    def sign(self, apk_bytes: bytes) -> bytes:
        """Return ``apk_bytes`` with a v2+v3 APK Signing Block inserted."""
        return apk_sign_v2(apk_bytes)


class Manifest:
    """The ``AndroidManifest.xml`` of an APK: read its attack surface, or edit it.

    Reads are lazy and cached. Edits build a binary-XML IR and mark the manifest
    dirty; :meth:`to_bytes` re-encodes it with the native AXML writer.
    """

    def __init__(self, raw: bytes, arsc: Optional[Arsc] = None) -> None:
        self._raw = raw
        self._arsc = arsc
        self._info: Optional[dict] = None
        self._ir: Optional[dict] = None
        self._dirty = False

    # -- analysis ---------------------------------------------------------
    @property
    def info(self) -> dict:
        """Parsed manifest facts (package, components, flags, permissions)."""
        if self._info is None:
            self._info = analyze_manifest(parse_axml(self._raw, self._arsc))
        return self._info

    @property
    def package(self) -> str:
        return self.info["package"]

    @property
    def permissions(self) -> List[str]:
        return self.info["permissions"]

    @property
    def exported_components(self) -> List[dict]:
        return self.info["exported"]

    @property
    def debuggable(self) -> bool:
        return self.info["debuggable"] == "true"

    # -- editing ----------------------------------------------------------
    @property
    def dirty(self) -> bool:
        return self._dirty

    def _edit(self):
        if self._ir is None:
            self._ir = parse_axml_ir(self._raw)
        self._dirty = True
        self._info = None
        return self._ir

    def set_debuggable(self, value: bool = True) -> "Manifest":
        """Set ``android:debuggable="true"`` on ``<application>``."""
        patch_debuggable(self._edit())
        return self

    def set_cleartext(self, value: bool = True) -> "Manifest":
        """Set ``android:usesCleartextTraffic="true"`` (enables HTTP / MITM)."""
        patch_cleartext(self._edit())
        return self

    def add_permission(self, name: str) -> "Manifest":
        """Add a ``<uses-permission>`` for ``name``."""
        patch_add_permission(self._edit(), name)
        return self

    def to_bytes(self) -> bytes:
        """Re-encode the (possibly edited) manifest to binary XML."""
        return encode_axml(self._ir) if self._ir is not None else self._raw


class Apk:
    """An Android package -- the high-level facade tying everything together."""

    def __init__(self, data: bytes, label: str = "<bytes>") -> None:
        self._data = data
        self.label = label
        self._zf = zipfile.ZipFile(io.BytesIO(data))
        self._manifest: Optional[Manifest] = None
        self._dex: Optional[List[DexFile]] = None

    # -- construction -----------------------------------------------------
    @classmethod
    def open(cls, path: str) -> "Apk":
        """Open an ``.apk`` or the base split of an ``.xapk`` / ``.apks`` bundle."""
        if path.lower().endswith(".apk"):
            with open(path, "rb") as f:
                return cls(f.read(), path)
        _zf, label = load_base_apk(path)        # picks + validates the base split
        if "!" not in label:
            with open(path, "rb") as f:
                return cls(f.read(), label)
        outer, member = label.split("!", 1)
        return cls(zipfile.ZipFile(outer).read(member), label)

    @classmethod
    def from_bytes(cls, data: bytes, label: str = "<bytes>") -> "Apk":
        return cls(data, label)

    # -- views ------------------------------------------------------------
    @property
    def manifest(self) -> Manifest:
        if self._manifest is None:
            try:
                arsc = Arsc(self._zf.read("resources.arsc"))
            except Exception:
                arsc = None
            self._manifest = Manifest(self._zf.read(_MANIFEST), arsc)
        return self._manifest

    @property
    def dex(self) -> List[DexFile]:
        """Every ``classesN.dex`` parsed into a :class:`DexFile`."""
        if self._dex is None:
            import re
            names = sorted(n for n in self._zf.namelist()
                           if re.fullmatch(r"classes\d*\.dex", n))
            self._dex = [DexFile(self._zf.read(n)) for n in names]
        return self._dex

    def analyze(self, secrets: bool = False) -> dict:
        """Attack-surface report: manifest facts (+ optional secret/URL scan)."""
        out = dict(self.manifest.info)
        if secrets:
            secs, urls = scan_secrets(self._zf)
            out["secrets"], out["endpoints"] = secs, urls
        return out

    def disassemble(self, method_sig: str) -> List[str]:
        """Disassemble ``Lpkg/Cls;->name()Ret`` to smali across all dex files."""
        import re
        m = re.match(r"(L[^;]+;)->([^(]+)\(", method_sig)
        if not m:
            raise ValueError("bad method signature: %s" % method_sig)
        for dex in self.dex:
            meth = dex.find_method(m.group(1), m.group(2))
            if meth:
                return disassemble(dex, meth["code_off"])[1]
        raise BundleError("method not found: %s" % method_sig)

    # -- output -----------------------------------------------------------
    def to_bytes(self, sign: bool = True) -> bytes:
        """Serialize the APK (repackaging if the manifest was edited), optionally signed."""
        if self._manifest is not None and self._manifest.dirty:
            entries = [e for e in read_zip_entries(self._data)
                       if e["name"] != _MANIFEST.encode()]
            entries.insert(0, stored_entry(_MANIFEST, self._manifest.to_bytes()))
            data = write_aligned_zip(entries)
        else:
            data = self._data
        return Signer().sign(data) if sign else data

    def save(self, path: str, sign: bool = True) -> None:
        """Write the APK to ``path`` (zipaligned; v2/v3 signed unless ``sign=False``)."""
        with open(path, "wb") as f:
            f.write(self.to_bytes(sign=sign))


__all__ = ["Apk", "Manifest", "Signer"]
