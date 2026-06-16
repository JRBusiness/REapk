# DEX engine overview

The DEX engine is the core of REapk. It reads `classes*.dex` straight from an APK and gives you a full `smali ↔ DEX` toolchain in pure Python: a disassembler, a single-method assembler, a constant-pool rebuilder with full index remapping, and a whole-DEX writer that preserves `debug_info` and annotations and relocates oversized method bodies. It is round-trip verified against tens of thousands of real production methods and cross-checked against Android's own `dexdump`.

## The mental model

Working with the engine flows one direction and back:

1. Read. `DexFile` parses the header, the id tables (strings, types, protos, fields, methods), the class definitions, and the code, and its accessors resolve indices into real values.
2. Disassemble. `disassemble` turns a method's bytecode into smali.
3. Assemble. `assemble` turns smali back into bytecode words; disassembling then assembling is a byte-identical round trip.
4. Patch. `build_dex` re-emits a whole, valid DEX with method bodies swapped or new pool entries interned, remapping every index so existing references keep their meaning.
5. Repackage and sign. The zipalign helpers rebuild the APK zip and `Signer` applies a v2/v3 signature, with no JDK and no external signing tools.

## What it is not

The engine disassembles to smali. It does not decompile to Java source. On the resource side it reads `resources.arsc` to resolve references and edits the binary `AndroidManifest.xml`, but a full `res/` source tree and arbitrary `resources.arsc` re-encoding are out of scope for the native engine; the optional `decode` and `build` commands hand that off to an external tool when one is installed.
