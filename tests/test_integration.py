"""Integration tests against a real APK (skipped unless one is provided).

These encode the engine's correctness invariants — the same round-trip oracles
used during development.
"""

import reapk
from reapk import Apk
from reapk.dex import DexFile, build_dex, disassemble


def test_open_and_analyze(apk_path):
    apk = Apk.open(apk_path)
    info = apk.analyze()
    assert info["package"]
    assert isinstance(info["exported"], list)
    assert apk.dex, "expected at least one classes.dex"


def test_dex_rewrite_is_identity(apk_path):
    """build_dex must reproduce every method byte-for-byte (disasm identical)."""
    dex = Apk.open(apk_path).dex[0]
    rebuilt = DexFile(build_dex(dex))
    checked = 0
    for c in dex.classes():
        nc = next((x for x in rebuilt.classes() if x["name"] == c["name"]), None)
        new = {m["name"] + m["proto"]: m
               for m in (rebuilt.class_methods(nc["cdata"]) if nc else [])}
        for m in dex.class_methods(c["cdata"]):
            if not m["code_off"]:
                continue
            _, a = disassemble(dex, m["code_off"])
            m2 = new.get(m["name"] + m["proto"])
            _, b = disassemble(rebuilt, m2["code_off"]) if m2 and m2["code_off"] else (None, [])
            assert a == b, "%s->%s changed under rewrite" % (c["name"], m["name"])
            checked += 1
            if checked >= 2000:
                return
    assert checked > 0


def test_manifest_patch_roundtrip(apk_path):
    """Editing the manifest and re-encoding must survive a parse round-trip."""
    apk = Apk.open(apk_path)
    assert apk.manifest.package
    apk.manifest.set_debuggable().set_cleartext()
    apk.manifest.add_permission("android.permission.INTERNET")
    new_bytes = apk.manifest.to_bytes()
    reparsed = reapk.analyze_manifest(reapk.parse_axml(new_bytes))
    assert reparsed["debuggable"] == "true"
    assert reparsed["usesCleartextTraffic"] == "true"
    assert "android.permission.INTERNET" in reparsed["permissions"]


def test_add_string_remap_keeps_methods_identical(apk_path):
    """Interning a new string renumbers indices but must preserve every method."""
    dex = Apk.open(apk_path).dex[0]
    rebuilt = DexFile(build_dex(dex, add_strings=["reapk_unit_test_marker"]))
    assert "reapk_unit_test_marker" in {rebuilt.string(i) for i in range(rebuilt.n_str)}
    checked = 0
    for c in dex.classes():
        nc = next((x for x in rebuilt.classes() if x["name"] == c["name"]), None)
        new = {m["name"] + m["proto"]: m
               for m in (rebuilt.class_methods(nc["cdata"]) if nc else [])}
        for m in dex.class_methods(c["cdata"]):
            if not m["code_off"]:
                continue
            _, a = disassemble(dex, m["code_off"])
            m2 = new.get(m["name"] + m["proto"])
            _, b = disassemble(rebuilt, m2["code_off"]) if m2 and m2["code_off"] else (None, [])
            assert a == b
            checked += 1
            if checked >= 1000:
                return
