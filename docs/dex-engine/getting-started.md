# Getting started

## Install

```bash
pip install reapk
```

From a checkout, install in editable mode:

```bash
pip install -e .
```

REapk needs Python 3.8 or newer. Its one runtime dependency, `cryptography`, is used for v2/v3 signing and installs automatically.

## Open an APK and read its surface

The high-level `Apk` facade ties everything together.

```python
from reapk import Apk

apk = Apk.open("app.apk")
print(apk.manifest.package)
print(len(apk.manifest.exported_components), "exported components")
print(len(apk.dex), "dex files")
```

`Apk.open` also accepts the base split of an `.xapk` or `.apks` bundle.

## Disassemble a method

`apk.dex` is a list of parsed `DexFile` objects. Find a method and disassemble it across every dex with the facade, or work with a single `DexFile` directly.

```python
from reapk.dex import disassemble

dex = apk.dex[0]
m = dex.find_method("Lokhttp3/CertificatePinner;", "check")
if m:
    ci, lines = disassemble(dex, m["code_off"])
    print("\n".join(lines))
```

`find_method` returns a dict with `name`, `proto`, `access`, and `code_off`, or `None`. `disassemble` returns the parsed `code_item` and the smali lines.

## Next

Read the [guide](guide.md) for patching, SSL-pinning bypass, interning, and re-signing, or the [API reference](api.md) for the full surface.
