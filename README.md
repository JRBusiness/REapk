# REapk

A **native, zero-Java APK toolkit**. REapk parses and rewrites Android's binary formats *directly* in Python, with no third-party tools and no JVM. It handles recon, manifest and DEX edits, repackaging, zipalign, and v2/v3 signing.

```bash
pip install reapk
```

Documentation: [jrbusiness.github.io/REapk](https://jrbusiness.github.io/REapk/)

## Pipeline

<p align="center">
  <img src="https://raw.githubusercontent.com/JRBusiness/REapk/main/docs/pipeline.gif" alt="REapk pipeline: ingest an APK/XAPK, branch on the requested operation into a read-only recon lane or a rewrite lane, then zipalign and v2/v3 sign." width="100%">
</p>

## The DEX engine

REapk includes a complete **`smali ↔ DEX` assembler**: a disassembler, a single-method assembler, a constant-pool rebuilder, and a whole-DEX writer.

The writer preserves `debug_info` and annotations, relocates oversized method bodies, and interns brand-new strings / types / fields / methods with full index remapping. It is round-trip verified against tens of thousands of real production methods and cross-checked against Android's own `dexdump`.

`classes*.dex` is editable and recompilable: disassemble it, edit or replace method bodies, inject new methods, reassemble to valid DEX, repackage, and sign.

For resources, REapk reads `resources.arsc` to resolve references (turning `@string/…` / `@xml/…` in the manifest into real values and resolving deeplink schemes) and edits the binary `AndroidManifest.xml` directly: debuggable, permissions, cleartext, and so on. A full `res/` source tree and arbitrary `resources.arsc` re-encoding are out of scope for the native engine; the optional `decode` / `build` commands hand that off to an external tool when one is installed.

## Playground

Learn the DEX engine hands-on with a runnable Jupyter notebook. Point it at your own APK with the `REAPK_TEST_APK` environment variable:

```bash
pip install -e .[playground]
REAPK_TEST_APK=/path/to/app.apk jupyter lab examples/notebooks/playground.ipynb
```

It loads an APK, reads its manifest, disassembles a method to smali, hex-dumps raw DEX bytes, and renders a full smali listing with `dump_dex`. See [`examples/notebooks/`](examples/notebooks/README.md) for details.

## Library use

```python
import reapk

# High-level facade
apk = reapk.Apk.open("app.apk")
print(apk.manifest.package, len(apk.manifest.exported_components))

apk.manifest.set_debuggable().set_cleartext()
apk.manifest.add_permission("android.permission.INTERNET")
apk.save("patched.apk")            # repackage (zipalign) + v2/v3 sign

# Disassemble a method across every dex
smali = apk.disassemble("Lp/C;->m()V")
```

Lower-level procedural functions (`parse_axml`, `DexFile`, `disassemble`, `assemble`, `build_dex`, `apk_sign_v2`, `scan_secrets`, …) are exported from the top-level package for direct use.

## CLI

```
reapk analyze | js | dex | dexdis | dexasm | dexpool | dexwrite |
       dexpatch | dexreplace | patch | sign | decode | build
```

A bare path with no subcommand defaults to `analyze`. Every command is fully native except `decode` / `build`, which call an external tool when one is present.

## Development

```bash
git clone https://github.com/JRBusiness/reapk && cd reapk
pip install -e .[test]
pytest -q                 # unit + signer tests (integration skipped w/o an APK)
ruff check .              # lint

# run the full integration round-trip oracles against a real APK:
REAPK_TEST_APK=/path/to/app.apk pytest -q

# benchmark against external tooling:
python scripts/bench_apk.py /path/to/app.apk --runs 1
```

## License

MIT. See [LICENSE](LICENSE).
