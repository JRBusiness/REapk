# Concepts

## The DEX file format

A `.dex` (Dalvik Executable) holds all the compiled code in an APK. Its layout is fixed: a 0x70-byte header, then five id tables (strings, types, protos, fields, methods), then the class definitions, then a data section holding the actual blobs (string bytes, code, class data), and finally a `map_list` that indexes every section.

The header at offset `0x38` carries the count and file offset of each id table. `DexFile` reads these into `n_str`, `n_type`, `n_proto`, `n_field`, `n_method`, and `n_class`, plus the matching offsets.

## The constant pools

Every type, field, and method is stored once and referenced by index. The id tables are pure indices into the string pool, so almost everything in a DEX bottoms out as a string. A method id, for example, points at a class type, a name string, and a proto (return type plus parameter types), and each of those points at more strings.

This deduplication is the reason patching is non-trivial. If you add a new string, type, field, or method, its index lands in the middle of a sorted pool and shifts everything after it. Every reference in the file then has to be remapped to the new indices.

## Code items and smali

A method's body is a `code_item`: register count, incoming-argument count, outgoing-argument count, then a stream of 16-bit instruction words. Each Dalvik instruction is one or more words, with the opcode in the low byte of the first word. The disassembler decodes those words into smali, the human-readable assembly. For example the word `0x1012` decodes as `const/4 v0, #1` (opcode `0x12`, register `v0`, literal `1` in the high nibble).

## Interning and remapping

`Interner` adds new entries to every pool and computes the five old-to-new index maps (strings, types, protos, fields, methods). Adding one entry transitively pulls in its dependencies: a method pulls in its class type, name string, and proto, and a proto pulls in its types and shorty. `build_dex` then applies those maps across the id tables, code, debug info, annotations, and encoded arrays, so the rebuilt DEX stays internally consistent.
