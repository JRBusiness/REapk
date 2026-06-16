"""reapk -- a native, zero-Java APK toolkit.

Parses and rewrites Android's binary formats directly: AndroidManifest (AXML),
resources.arsc, the DEX bytecode (disassemble / assemble / whole-DEX rewrite),
plus native zipalign and v2/v3 APK signing. No apktool, no apksigner, no Java.
"""
from .errors import (
    REapkError, AssembleError, AxmlError, BundleError, DexError, EngineError,
    SignError, ZipError,
)
from .api import Apk, Manifest, Signer
from .axml import Arsc, encode_axml, parse_axml, parse_axml_ir
from .manifest import analyze_manifest, print_report
from .bundle import detect_framework, load_base_apk, read_manifest_bytes
from .zipalign import read_zip_entries, stored_entry, write_aligned_zip
from .sign import apk_sign_v2
from .secrets import scan_secrets
from .dex import (
    Assembler, DexFile, Interner, PoolModel, OPCODES, assemble,
    assemble_interned, build_code_item, build_dex, compute_outs, decode_insn,
    disassemble, encode_insn, insn_length,
)

__version__ = "0.1.0"

__all__ = [
    "Apk", "Manifest", "Signer",
    "REapkError", "AxmlError", "BundleError", "ZipError", "DexError",
    "AssembleError", "SignError", "EngineError",
    "Arsc", "encode_axml", "parse_axml", "parse_axml_ir",
    "analyze_manifest", "print_report",
    "detect_framework", "load_base_apk", "read_manifest_bytes",
    "read_zip_entries", "stored_entry", "write_aligned_zip",
    "apk_sign_v2", "scan_secrets",
    "DexFile", "disassemble", "decode_insn", "insn_length", "OPCODES",
    "Assembler", "assemble", "assemble_interned", "encode_insn",
    "build_code_item", "compute_outs", "PoolModel", "Interner", "build_dex",
]
