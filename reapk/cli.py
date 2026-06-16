import argparse
import sys

from .commands import (
    cmd_analyze, cmd_build, cmd_decode, cmd_dex, cmd_dexasm, cmd_dexdis,
    cmd_dexpatch, cmd_dexpool, cmd_dexreplace, cmd_dexwrite, cmd_js, cmd_patch,
    cmd_sign,
)
from .errors import REapkError


def main(argv=None):
    """reapk command-line entry point. Returns a process exit code."""
    # Legacy Windows consoles default to cp1252 and raise UnicodeEncodeError when
    # we print non-ASCII (e.g. strings/deeplinks/class names pulled from the APK).
    # Re-encode our streams as UTF-8 so CLI output can never crash the process.
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, ValueError):
            pass

    ap = argparse.ArgumentParser(
        prog="reapk",
        description="reapk -- native APK/XAPK recon, DEX engine, patch & sign")
    sub = ap.add_subparsers(dest="cmd")

    a = sub.add_parser("analyze", help="manifest attack-surface recon (self-contained)")
    a.add_argument("input")
    a.add_argument("--secrets", action="store_true")
    a.add_argument("--json", action="store_true")
    a.set_defaults(func=cmd_analyze)

    j = sub.add_parser("js", help="extract/decompile hybrid JavaScript")
    j.add_argument("input")
    j.add_argument("-o", "--out")
    j.set_defaults(func=cmd_js)

    d = sub.add_parser("decode", help="full smali+resource decode (drives apktool/APKEditor)")
    d.add_argument("input")
    d.add_argument("-o", "--out")
    d.add_argument("--engine", choices=["apktool", "apkeditor"], default="apktool")
    d.set_defaults(func=cmd_decode)

    b = sub.add_parser("build", help="rebuild + zipalign + sign in one step")
    b.add_argument("input", help="decoded directory")
    b.add_argument("-o", "--out", required=True, help="output .apk")
    b.add_argument("--engine", choices=["apktool", "apkeditor"], default="apktool")
    b.add_argument("--no-sign", action="store_true")
    b.add_argument("--keystore")
    b.add_argument("--ks-pass", default="android")
    b.add_argument("--ks-alias", default="androiddebugkey")
    b.set_defaults(func=cmd_build)

    p = sub.add_parser("patch", help="edit the manifest + repackage natively (no apktool)")
    p.add_argument("input")
    p.add_argument("-o", "--out", required=True, help="output .apk (unsigned)")
    p.add_argument("--debuggable", action="store_true", help="set android:debuggable=true")
    p.add_argument("--cleartext", action="store_true", help="set usesCleartextTraffic=true (MITM)")
    p.add_argument("--add-perm", action="append", metavar="PERM", help="add a uses-permission")
    p.add_argument("--no-sign", action="store_true", help="leave the apk unsigned")
    p.set_defaults(func=cmd_patch)

    s = sub.add_parser("sign", help="native APK v2 signer (no apksigner / no Java)")
    s.add_argument("input")
    s.add_argument("-o", "--out", required=True)
    s.set_defaults(func=cmd_sign)

    x = sub.add_parser("dex", help="native DEX reader: classes/methods/strings (no apktool)")
    x.add_argument("input")
    x.add_argument("--cls", metavar="SUBSTR", help="list classes matching substring + their methods")
    x.add_argument("--strings", metavar="SUBSTR", help="grep DEX string pool")
    x.add_argument("--limit", type=int, default=20)
    x.set_defaults(func=cmd_dex)

    dp = sub.add_parser("dexpatch", help="surgical in-place DEX method patch (force-return)")
    dp.add_argument("input")
    dp.add_argument("--method", required=True, metavar="Lpkg/Cls;->name()Ret",
                    help="target method (smali signature)")
    dp.add_argument("--force-return", default="true",
                    choices=["true", "false", "null", "void"])
    dp.add_argument("-o", "--out", required=True)
    dp.add_argument("--no-sign", action="store_true")
    dp.set_defaults(func=cmd_dexpatch)

    dd = sub.add_parser("dexdis", help="disassemble a method's bytecode to smali (no apktool)")
    dd.add_argument("input")
    dd.add_argument("--method", required=True, metavar="Lpkg/Cls;->name()Ret")
    dd.set_defaults(func=cmd_dexdis)

    da = sub.add_parser("dexasm", help="assemble smali->bytecode; round-trip self-test vs disassembler")
    da.add_argument("input")
    da.add_argument("-n", type=int, default=4000, help="methods to round-trip test")
    da.set_defaults(func=cmd_dexasm)

    pl = sub.add_parser("dexpool", help="verify canonical pool sort + interning/remap (Phase 3)")
    pl.add_argument("input")
    pl.set_defaults(func=cmd_dexpool)

    pw = sub.add_parser("dexwrite", help="whole-DEX writer: re-emit + verify round-trip (Phase 4)")
    pw.add_argument("input")
    pw.add_argument("--dex", help="which classesN.dex (default: first)")
    pw.add_argument("--add-string", action="append", metavar="STR",
                    help="intern a new string (tests Boundary 2 remap)")
    pw.add_argument("-o", "--out", help="write rebuilt dex to file")
    pw.set_defaults(func=cmd_dexwrite)

    pr = sub.add_parser("dexreplace", help="replace a method body (any size) via whole-DEX relocate")
    pr.add_argument("input")
    pr.add_argument("--method", required=True, metavar="Lpkg/Cls;->name()Ret")
    pr.add_argument("--smali", help="file with replacement smali")
    pr.add_argument("--body", help="inline smali, ';'-separated")
    pr.add_argument("--registers", type=int, default=0, help="register count (default: original)")
    pr.add_argument("--intern", action="store_true",
                    help="auto-intern smali refs (methods/fields/types) not in the dex")
    pr.add_argument("-o", "--out", required=True)
    pr.add_argument("--no-sign", action="store_true")
    pr.set_defaults(func=cmd_dexreplace)

    # Back-compat: a bare path (not a subcommand) means 'analyze'.
    argv = list(sys.argv[1:] if argv is None else argv)
    known = {"analyze", "js", "decode", "build", "patch", "dex", "dexpatch",
             "dexdis", "dexasm", "dexpool", "dexwrite", "dexreplace",
             "sign", "-h", "--help"}
    if argv and argv[0] not in known:
        argv = ["analyze"] + argv

    args = ap.parse_args(argv)
    if not getattr(args, "func", None):
        ap.print_help()
        return 1
    try:
        return args.func(args)
    except REapkError as e:
        print("reapk: error: %s" % e, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
