# Guide

Task-oriented recipes for the DEX engine. They assume `apk = Apk.open("app.apk")` and `dex = apk.dex[0]`, and that you are working on an app you are authorized to test.

## Round-trip a method

Disassemble then assemble to confirm the toolchain reproduces a method exactly.

```python
import struct
from reapk.dex import disassemble, assemble, Assembler

m = dex.find_method("Lp/C;", "m")
ci, lines = disassemble(dex, m["code_off"])
original = [struct.unpack_from("<H", dex.d, ci["insns_off"] + 2 * i)[0]
           for i in range(ci["insns_size"])]
words = assemble(Assembler(dex), lines)
assert words == original
```

`Assembler(dex)` resolves operand references against the dex's pools.

## Force a method to return a fixed value

`build_dex(dex, replacements={code_off: new_code_item})` re-emits a whole, valid DEX with method bodies swapped. Build the replacement body with `build_return_insns` and `build_code_item`.

```python
from reapk.dex import build_return_insns, build_code_item, build_dex, DexFile

m = dex.find_method("Lp/C;", "isRooted")        # ()Z
ci = dex.code_insns(m["code_off"])
words = build_return_insns("Z", "false", ci["regs"])
new_code = build_code_item(ci["regs"], ci["ins"], 0, words)

out = build_dex(dex, replacements={m["code_off"]: new_code})
DexFile(out)                                     # re-parses, so it is valid
```

`build_return_insns(ret_desc, value, regs)` accepts `value` in `{"true", "false", "null", "void"}`.

## Bypass SSL pinning, then repackage and sign

Pinning and hostname verification done in code block an intercepting proxy. Neutralize the usual sinks across every dex, then rebuild and re-sign the APK.

```python
import re
import zipfile
from reapk import Signer
from reapk.dex import build_return_insns, build_code_item, build_dex
from reapk.zipalign import read_zip_entries, stored_entry, write_aligned_zip

def find_pin_sinks(dex):
    repl = {}
    for c in dex.classes():
        cname = c["name"]
        for m in dex.class_methods(c["cdata"]):
            if not m["code_off"]:
                continue
            nm, proto = m["name"], m["proto"]
            ci = dex.code_insns(m["code_off"])
            words = None
            if nm == "check" and "CertificatePinner" in cname and proto.endswith(")V"):
                words = build_return_insns("V", "void", ci["regs"])
            elif nm in ("checkServerTrusted", "checkClientTrusted") and proto.endswith(")V"):
                words = build_return_insns("V", "void", ci["regs"])
            elif (nm == "verify" and proto.endswith(")Z") and ci["regs"] >= 1
                  and ("HostnameVerifier" in cname or "Ljavax/net/ssl/SSLSession;" in proto)):
                words = build_return_insns("Z", "true", ci["regs"])
            if words is not None:
                repl[m["code_off"]] = build_code_item(ci["regs"], ci["ins"], 0, words)
    return repl

names = sorted(n for n in zipfile.ZipFile("app.apk").namelist()
               if re.fullmatch(r"classes\d*\.dex", n))
patched = {}
for name, d in zip(names, apk.dex):
    repl = find_pin_sinks(d)
    if repl:
        patched[name] = build_dex(d, replacements=repl)

entries = read_zip_entries(open("app.apk", "rb").read())
rebuilt = [stored_entry(e["name"], patched[e["name"].decode()])
           if e["name"].decode() in patched else e
           for e in entries]
out = Signer().sign(write_aligned_zip(rebuilt))
open("patched.apk", "wb").write(out)
```

The `verify` rule is kept narrow (hostname verifiers, or methods that take an `SSLSession`) so unrelated signature checks are left alone.

## Intern a new string

Adding a pool entry shifts indices, so `build_dex` remaps every reference.

```python
from reapk.dex import Interner, build_dex, DexFile

it = Interner(dex)
it.add_string("patched-by-reapk")
it.finalize()
dex2 = DexFile(build_dex(dex, interner=it))
assert "patched-by-reapk" in [dex2.string(i) for i in range(dex2.n_str)]
```

`Interner` also has `add_type`, `add_field`, and `add_method`, each of which interns its dependencies. After `finalize`, the remaps are on `sr`, `tr`, `fr`, `mr`, and `pr`.

## Make an app debuggable

Manifest edits go through the `Manifest` view and `save` repackages and signs.

```python
apk.manifest.set_debuggable().set_cleartext()
apk.manifest.add_permission("android.permission.INTERNET")
apk.save("debuggable.apk")
```

## Print a full smali listing

```python
from reapk.playground import dump_dex
print(dump_dex(apk.dex[0], max_classes=3, max_methods_per_class=5))
```

The caps keep the output readable on a real app, where a single dex can hold thousands of classes.
