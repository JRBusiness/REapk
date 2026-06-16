# Changelog

All notable changes to this project are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.1] - 2026-06-16

Initial release. A native, zero-Java APK toolkit that parses and rewrites Android's binary formats directly in Python, with no third-party tools and no JVM.

### Added

- **Binary manifest (AXML):** native decode, encode, and patch (`--debuggable`, `--cleartext`, add `<uses-permission>`), plus `resources.arsc` reference resolution (for example, resolving `@string/…` values and deeplink schemes).
- **Native DEX engine:** a disassembler, a single-method assembler, a constant-pool rebuilder with full index remapping, and a whole-DEX writer that preserves `debug_info` and annotations and relocates oversized method bodies.
- **Code patching:** surgical in-place bytecode patches (`dexpatch`, force-return), method-body replacement of any size, and injection of calls to brand-new interned methods (`dexreplace --intern`).
- **Native zipalign and APK Signature Scheme v2 + v3 signing:** no JDK and no external signing tools required.
- **Hybrid-JS extraction** for Cordova, Capacitor, and React-Native, including Hermes detection.
- **CLI:** `analyze`, `js`, `dex`, `dexdis`, `dexasm`, `dexpool`, `dexwrite`, `dexpatch`, `dexreplace`, `patch`, and `sign`, plus `decode` and `build`, which delegate to an external tool when one is installed.
- **High-level API:** the `Apk`, `Manifest`, and `Signer` classes.
- **Display helpers** in `reapk.playground` (`dump_dex`, `hexdump`, `show_smali`) and an example notebook that walks the engine against a real APK.
- A typed package (`py.typed`), an exception hierarchy (`REapkError` and friends), and a test suite covering unit tests, signer structure, and integration round-trip oracles.

[0.1.1]: https://github.com/JRBusiness/reapk/releases/tag/v0.1.1
