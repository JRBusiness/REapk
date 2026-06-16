First release of REapk, a native, zero-Java APK toolkit. It parses and rewrites Android's binary formats directly in Python, with no third-party tools and no JVM.

## Highlights

- A full smali-to-DEX toolchain: a disassembler, a single-method assembler, a constant-pool rebuilder with full index remapping, and a whole-DEX writer that keeps `debug_info` and annotations and relocates oversized method bodies. It is round-trip verified against tens of thousands of real production methods.
- Patch a method to return a fixed value, replace a method body of any size, or inject calls to brand-new interned methods.
- Native zipalign and APK Signature Scheme v2 and v3 signing, with no JDK and no external signing tools.
- Decode, edit, and re-encode the binary `AndroidManifest.xml`, resolve `resources.arsc` references, and extract hybrid JavaScript from Cordova, Capacitor, and React-Native apps.
- A documentation site and a runnable notebook that walks the engine against a real app, including an SSL-pinning bypass for apps you are authorized to test.

## Install

```bash
pip install reapk
```

Requires Python 3.8 or newer.

See the [CHANGELOG](https://github.com/JRBusiness/REapk/blob/main/CHANGELOG.md) for the full list and the [docs](https://jrbusiness.github.io/REapk/) to get started.
