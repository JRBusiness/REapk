# API reference

Everything below is importable from the top-level `reapk` package, except the display helpers, which live in `reapk.playground`. Signatures reflect the current source.

## High-level facade

### `Apk`

```python
Apk.open(path) -> Apk
Apk.from_bytes(data, label="<bytes>") -> Apk
```

| member | description |
| --- | --- |
| `apk.manifest` | a `Manifest` view (lazy, cached) |
| `apk.dex` | list of `DexFile`, one per `classesN.dex` |
| `apk.analyze(secrets=False)` | manifest facts, optionally with a secret and URL scan |
| `apk.disassemble(method_sig)` | disassemble `Lpkg/Cls;->name()Ret` across every dex |
| `apk.to_bytes(sign=True)` | serialize, repackaging if the manifest changed |
| `apk.save(path, sign=True)` | write the APK (zipaligned, v2/v3 signed unless `sign=False`) |

### `Manifest`

`info`, `package`, `permissions`, `exported_components`, and `debuggable` are read accessors. `set_debuggable(value=True)`, `set_cleartext(value=True)`, and `add_permission(name)` edit the binary manifest and return `self` for chaining. `to_bytes()` re-encodes it.

### `Signer`

```python
Signer().sign(apk_bytes) -> bytes
```

Inserts an APK Signature Scheme v2 + v3 block (RSA-2048, SHA-256). The key and cert are generated once and cached under `~/.reapk/`. No JDK required.

## Reading a DEX

### `DexFile(data: bytes)`

Raises `ValueError` if the magic is not `dex\n`. Attributes include `d` (raw bytes) and the pool counts and offsets (`n_str`/`off_str`, `n_type`/`off_type`, and so on).

| method | returns |
| --- | --- |
| `string(i)` / `type(i)` | a pool string / a type descriptor |
| `method_full(i)` | `(class, name, return_type, params)` |
| `field_ref(i)` / `method_ref(i)` | the referenced field / method |
| `classes()` | iterator of `{"name", "access", "cdata"}` |
| `class_methods(cdata_off)` | list of `{"name", "proto", "access", "code_off"}` |
| `find_method(class_desc, name)` | a method dict with a code body, or `None` |
| `code_insns(code_off)` | `{"regs", "ins", "insns_size", "insns_off"}` |
| `patch_return(code_off, ret_desc, value)` | in-place forced return (nop-padded) |
| `finalize()` | recompute the SHA-1 signature and Adler-32 checksum |

## Disassemble and assemble

```python
disassemble(dex, code_off) -> (code_item_info, smali_lines)
assemble(asm, lines) -> list[int]            # 16-bit words
assemble_interned(dex, lines) -> (Interner, words)
Assembler(dex, interner=None, collecting=False)
compute_outs(words) -> int
build_code_item(regs, ins, outs, words) -> bytes
build_return_insns(ret_desc, value, regs) -> list[int]
```

`assemble` raises `AsmSkip` for a mnemonic it does not handle. `build_return_insns` takes `value` in `{"true", "false", "null", "void"}`. `OPCODES` maps each opcode byte to `(mnemonic, format, ref_kind)`.

## Rewrite a whole DEX

```python
build_dex(dex, replacements=None, add_strings=None, interner=None) -> bytes
```

- `replacements`: `{code_off: new_code_item_bytes}` to swap method bodies of any size.
- `add_strings`: a list of strings to intern.
- `interner`: a finalized `Interner` for interning types, fields, and methods as well.

### `Interner(dex)`

`add_string(s)`, `add_type(t)`, `add_field(cls, name, typ)`, and `add_method(cls, name, ret, params)` queue new entries (each interns its dependencies). Call `finalize()`, then read the new positions on `spos`/`tpos`/`fpos`/`mpos`/`ppos` and the old-to-new remaps on `sr`/`tr`/`fr`/`mr`/`pr`. `PoolModel(dex)` is a read-only view of the same pools with canonical sort checks.

## Repackaging

```python
read_zip_entries(data) -> list[entry]
stored_entry(name, data) -> entry
write_aligned_zip(entries) -> bytes
apk_sign_v2(apk_bytes) -> bytes
```

## Other helpers

`parse_axml`, `analyze_manifest`, and `scan_secrets` cover manifest parsing and recon. In `reapk.playground`: `dump_dex(dex, max_classes=None, max_methods_per_class=None)`, `hexdump(data, start=0, length=None, width=16)`, and `show_smali(lines)`.

## Errors

All exceptions derive from `REapkError`: `AxmlError`, `BundleError`, `ZipError`, `DexError`, `AssembleError`, `SignError`, and `EngineError`.
