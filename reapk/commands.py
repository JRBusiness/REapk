import struct
from .errors import REapkError
import re
import zlib
import os
import shutil
import zipfile
import json

from .axml import Arsc, encode_axml, parse_axml, parse_axml_ir, patch_add_permission, patch_cleartext, patch_debuggable
from .bundle import HERMES_MAGIC, detect_framework, load_base_apk, read_manifest_bytes
from .dex.asm import AsmSkip, Assembler, assemble, assemble_interned, build_code_item, compute_outs
from .dex.disasm import disassemble
from .dex.file import DexFile, _acc_str, _desc_to_java
from .dex.pool import PoolModel
from .dex.writer import build_dex
from .engines import _find_tool, _resolve_engine, run
from .manifest import analyze_manifest, print_report
from .secrets import scan_secrets
from .sign import apk_sign_v2
from .zipalign import read_zip_entries, stored_entry, write_aligned_zip


def cmd_dexpatch(args):
    with open(args.input, "rb") as f:
        apk = f.read()
    # parse "Lcom/foo/Bar;->method()Z"  ->  class, name, return-descriptor
    m = re.match(r"(L[^;]+;)->([^(]+)\([^)]*\)(.+)", args.method)
    if not m:
        raise REapkError("bad --method (want: Lpkg/Cls;->name()RetDesc )")
    class_desc, mname, ret_desc = m.group(1), m.group(2), m.group(3)

    entries = read_zip_entries(apk)
    target = None
    for e in entries:
        if not re.fullmatch(rb"classes\d*\.dex", e["name"]):
            continue
        raw = e["raw"] if e["method"] == 0 else zlib.decompress(e["raw"], -15)
        dex = DexFile(raw)
        meth = dex.find_method(class_desc, mname)
        if meth:
            dex.patch_return(meth["code_off"], ret_desc, args.force_return)
            e["raw"] = dex.finalize()
            e["crc"] = zlib.crc32(e["raw"]) & 0xFFFFFFFF
            e["csize"] = e["usize"] = len(e["raw"])
            e["method"] = 0  # store the patched dex (so our raw bytes are used verbatim)
            target = (e["name"].decode(), meth)
            break
    if not target:
        raise REapkError("method not found: %s" % args.method)
    name, meth = target
    print("patched %s->%s ... force-return %s  (in %s)"
          % (class_desc, mname, args.force_return, name))

    apk_out = write_aligned_zip(entries)
    if not args.no_sign:
        try:
            apk_out = apk_sign_v2(apk_out)
        except ImportError:
            print("!! cryptography missing -- output UNSIGNED")
    with open(args.out, "wb") as f:
        f.write(apk_out)
    print(">> %s (native DEX patch + repackage%s)"
          % (args.out, "" if args.no_sign else " + sign"))
    return 0

def cmd_dexdis(args):
    with open(args.input, "rb") as f:
        apk = f.read()
    mm = re.match(r"(L[^;]+;)->([^(]+)\(", args.method)
    if not mm:
        raise REapkError("bad --method (want: Lpkg/Cls;->name()Ret )")
    class_desc, mname = mm.group(1), mm.group(2)
    for e in read_zip_entries(apk):
        if not re.fullmatch(rb"classes\d*\.dex", e["name"]):
            continue
        raw = e["raw"] if e["method"] == 0 else zlib.decompress(e["raw"], -15)
        dex = DexFile(raw)
        meth = dex.find_method(class_desc, mname)
        if not meth:
            continue
        ci, lines = disassemble(dex, meth["code_off"])
        print(".method %s%s   (%s, registers=%d)"
              % (mname, meth["proto"], e["name"].decode(), ci["regs"]))
        print("\n".join(lines))
        print(".end method")
        return 0
    raise REapkError("method not found: %s" % args.method)

def cmd_dexasm(args):
    with open(args.input, "rb") as f:
        apk = f.read()
    total = ok = skip = fail = 0
    fails = []
    for e in read_zip_entries(apk):
        if not re.fullmatch(rb"classes\d*\.dex", e["name"]):
            continue
        raw = e["raw"] if e["method"] == 0 else zlib.decompress(e["raw"], -15)
        dex = DexFile(raw)
        asm = Assembler(dex)
        for c in dex.classes():
            for m in dex.class_methods(c["cdata"]):
                if not m["code_off"] or total >= args.n:
                    continue
                total += 1
                ci, lines = disassemble(dex, m["code_off"])
                if any(("payload" in ln or "unknown" in ln) for ln in lines):
                    skip += 1
                    continue
                try:
                    words = assemble(asm, lines)
                except AsmSkip:
                    skip += 1
                    continue
                except Exception as ex:  # noqa: BLE001
                    fail += 1
                    fails.append("%s->%s: %s" % (c["name"], m["name"], ex))
                    continue
                orig = [struct.unpack_from("<H", dex.d, ci["insns_off"] + 2 * i)[0]
                        for i in range(ci["insns_size"])]
                if words == orig:
                    ok += 1
                else:
                    fail += 1
                    fails.append("%s->%s: byte mismatch" % (c["name"], m["name"]))
            if total >= args.n:
                break
        break  # one dex is enough to validate the assembler
    print("round-trip self-test (%s): %d methods  ok=%d  skip=%d  fail=%d"
          % (e["name"].decode(), total, ok, skip, fail))
    if ok + fail:
        print("match rate (of assembled): %.2f%%" % (100.0 * ok / max(ok + fail, 1)))
    for f in fails[:12]:
        print("  FAIL", f)
    return 0

def cmd_dexreplace(args):
    with open(args.input, "rb") as f:
        apk = f.read()
    mm = re.match(r"(L[^;]+;)->([^(]+)\([^)]*\)", args.method)
    if not mm:
        raise REapkError("bad --method")
    class_desc, mname = mm.group(1), mm.group(2)
    smali = open(args.smali).read() if args.smali else args.body
    if not smali:
        raise REapkError("provide --smali FILE or --body 'line | line | ...'")
    # '|' separates inline instructions (smali descriptors contain ';', so not that)
    lines = re.split(r"[|\n]", smali) if args.body else smali.splitlines()

    entries = read_zip_entries(apk)
    done = None
    for e in entries:
        if not re.fullmatch(rb"classes\d*\.dex", e["name"]):
            continue
        raw = e["raw"] if e["method"] == 0 else zlib.decompress(e["raw"], -15)
        dex = DexFile(raw)
        meth = dex.find_method(class_desc, mname)
        if not meth:
            continue
        co = meth["code_off"]
        regs0, ins0, outs0, _t, _dbg, sz0 = struct.unpack_from("<HHHHII", dex.d, co)
        if args.intern:
            it, words = assemble_interned(dex, lines)
        else:
            it, words = None, assemble(Assembler(dex), lines)
        regs = max(args.registers, regs0) if args.registers else regs0
        ci = build_code_item(regs, ins0, max(outs0, compute_outs(words)), words)
        new = build_dex(dex, replacements={co: ci}, interner=it)
        nd = DexFile(new)
        nm = nd.find_method(class_desc, mname)
        _, dis = disassemble(nd, nm["code_off"])
        print("replaced %s->%s: %d->%d insn words (relocated)" % (class_desc, mname, sz0, len(words)))
        print("new body disassembles as:")
        for ln in dis[:12]:
            print(ln)
        e["raw"] = new
        e["method"] = 0
        e["crc"] = zlib.crc32(new) & 0xFFFFFFFF
        e["csize"] = e["usize"] = len(new)
        done = e["name"].decode()
        break
    if not done:
        raise REapkError("method not found")
    out = write_aligned_zip(entries)
    if not args.no_sign:
        out = apk_sign_v2(out)
    with open(args.out, "wb") as f:
        f.write(out)
    print(">> %s (whole-DEX relocate + repackage%s)" % (args.out, "" if args.no_sign else " + sign"))
    return 0

def cmd_dexwrite(args):
    with open(args.input, "rb") as f:
        apk = f.read()
    want = args.dex.encode() if args.dex else None
    for e in read_zip_entries(apk):
        if not re.fullmatch(rb"classes\d*\.dex", e["name"]):
            continue
        if want and e["name"] != want:
            continue
        raw = e["raw"] if e["method"] == 0 else zlib.decompress(e["raw"], -15)
        dex = DexFile(raw)
        new = build_dex(dex, add_strings=args.add_string or None)
        ndex = DexFile(new)
        if args.add_string:
            present = set(ndex.string(i) for i in range(ndex.n_str))
            for s in args.add_string:
                print("  add-string %r -> %s (pool %d -> %d)"
                      % (s, "PRESENT" if s in present else "MISSING", dex.n_str, ndex.n_str))
        # verify: every method disassembles identically
        total = same = diff = 0
        for c in dex.classes():
            nm = None
            for cc in ndex.classes():
                if cc["name"] == c["name"]:
                    nm = cc
                    break
            old_ms = dex.class_methods(c["cdata"])
            new_ms = ndex.class_methods(nm["cdata"]) if nm else []
            nbyname = {m["name"] + m["proto"]: m for m in new_ms}
            for m in old_ms:
                if not m["code_off"]:
                    continue
                total += 1
                _, o = disassemble(dex, m["code_off"])
                nm2 = nbyname.get(m["name"] + m["proto"])
                _, n2 = disassemble(ndex, nm2["code_off"]) if nm2 and nm2["code_off"] else (None, [])
                if o == n2:
                    same += 1
                else:
                    diff += 1
        print("%s: rebuilt %d bytes (orig %d). methods: total=%d identical=%d diff=%d"
              % (e["name"].decode(), len(new), len(raw), total, same, diff))
        if args.out:
            with open(args.out, "wb") as f:
                f.write(new)
            print("  wrote", args.out)
        return 0 if diff == 0 else 1
    raise REapkError("dex not found")

def cmd_dexpool(args):
    with open(args.input, "rb") as f:
        apk = f.read()
    agg = {"strings": 0, "types": 0, "protos": 0, "fields": 0, "methods": 0}
    ndex = 0
    last = None
    for e in read_zip_entries(apk):
        if not re.fullmatch(rb"classes\d*\.dex", e["name"]):
            continue
        raw = e["raw"] if e["method"] == 0 else zlib.decompress(e["raw"], -15)
        pm = PoolModel(DexFile(raw))
        res = pm.check_canonical()
        ndex += 1
        last = (e["name"].decode(), pm, res)
        for k, v in res.items():
            agg[k] += 1 if v else 0
        print("%-14s strings=%d types=%d protos=%d fields=%d methods=%d  canonical=%s"
              % (e["name"].decode(), len(pm.strings), len(pm.types), len(pm.protos),
                 len(pm.fields), len(pm.methods),
                 "ALL-PASS" if all(res.values()) else
                 ",".join(k for k, v in res.items() if not v) + " FAIL"))
    print("\ncanonical-sort comparators reproduce DEX order in %d/%d dexes (per pool: %s)"
          % (min(agg.values()), ndex, agg))

    # interning demo: add a brand-new string and show where it lands + churn
    name, pm, _ = last
    merged, remap, newpos = pm.intern_strings(["reapk_injected_marker_zzz"])
    moved = sum(1 for o, n in remap.items() if o != n)
    print("\nintern demo (%s): added 'reapk_injected_marker_zzz' -> new string index %d; "
          "%d/%d existing string indices shift (remap table built)"
          % (name, newpos["reapk_injected_marker_zzz"], moved, len(pm.strings)))
    return 0

def load_dex_files(apk_zip):
    dexes = []
    for n in sorted(apk_zip.namelist()):
        if re.fullmatch(r"classes\d*\.dex", n):
            try:
                dexes.append((n, DexFile(apk_zip.read(n))))
            except Exception as e:
                print("!! %s: %s" % (n, e))
    return dexes

def cmd_dex(args):
    apk_zip, label = load_base_apk(args.input)
    dexes = load_dex_files(apk_zip)
    if not dexes:
        raise REapkError("no classes*.dex in %s" % label)
    print("source:", label)
    total_c = total_m = total_s = 0
    cls_hits, str_hits = [], []
    for name, dex in dexes:
        nc = nm = 0
        for c in dex.classes():
            nc += 1
            ms = dex.class_methods(c["cdata"])
            nm += len(ms)
            jname = _desc_to_java(c["name"])
            if args.cls and args.cls.lower() in jname.lower():
                cls_hits.append((jname, c["access"], ms))
        total_c += nc
        total_m += nm
        ns = dex.n_str
        total_s += ns
        if args.strings:
            for s in dex.all_strings():
                if args.strings.lower() in s.lower():
                    str_hits.append(s)
        print("  %-14s classes=%-6d methods=%-7d strings=%d" % (name, nc, nm, ns))
    print("TOTAL: classes=%d methods=%d strings=%d  (our own DEX engine, no apktool)"
          % (total_c, total_m, total_s))

    for jname, acc, ms in cls_hits[:args.limit]:
        print("\n[class] %s %s  (%d methods)" % (_acc_str(acc), jname, len(ms)))
        for m in ms[:60]:
            print("    %s %s%s" % (_acc_str(m["access"]), m["name"], m["proto"]))
    if args.strings:
        uniq = sorted(set(str_hits))
        print("\n[strings ~ %r] %d match(es)" % (args.strings, len(uniq)))
        for s in uniq[:args.limit]:
            print("   ", s[:200])
    return 0

def cmd_patch(args):
    apk_zip, label = load_base_apk(args.input)
    raw = read_manifest_bytes(apk_zip)
    if not raw:
        raise REapkError("no AndroidManifest.xml in %s" % label)
    ir = parse_axml_ir(raw)
    did = []
    if args.debuggable:
        patch_debuggable(ir); did.append("debuggable=true")
    if args.cleartext:
        patch_cleartext(ir); did.append("usesCleartextTraffic=true")
    for p in (args.add_perm or []):
        patch_add_permission(ir, p); did.append("uses-permission " + p)
    if not did:
        raise REapkError("nothing to patch (use --debuggable / --add-perm NAME)")

    new_manifest = encode_axml(ir)
    # self-check: our writer's output must parse back cleanly
    check = analyze_manifest(parse_axml(new_manifest))
    print("patched:", ", ".join(did))
    print("verify : package=%s debuggable=%s perms=%d (re-parsed our own output)"
          % (check["package"], check["debuggable"], len(check["permissions"])))

    src = args.input if args.input.lower().endswith(".apk") else label.split("!", 1)[0]
    if "!" in label:  # base apk lives inside a bundle -- extract its bytes
        outer = zipfile.ZipFile(src)
        src_bytes = outer.read(label.split("!", 1)[1])
    else:
        with open(src, "rb") as f:
            src_bytes = f.read()

    # repackage with our own aligned zip writer (native zipalign)
    entries = [e for e in read_zip_entries(src_bytes)
               if e["name"] != b"AndroidManifest.xml"]
    entries.insert(0, stored_entry(b"AndroidManifest.xml", new_manifest))
    apk_bytes = write_aligned_zip(entries)

    if args.no_sign:
        with open(args.out, "wb") as f:
            f.write(apk_bytes)
        print(">> repackaged (no apktool, UNSIGNED):", args.out)
        return 0
    try:
        signed = apk_sign_v2(apk_bytes)
    except ImportError:
        with open(args.out, "wb") as f:
            f.write(apk_bytes)
        print(">> repackaged UNSIGNED (install `cryptography` for native signing):", args.out)
        return 0
    with open(args.out, "wb") as f:
        f.write(signed)
    print(">> repackaged + signed (native, no apktool/apksigner):", args.out)
    return 0

def cmd_sign(args):
    with open(args.input, "rb") as f:
        signed = apk_sign_v2(f.read())
    with open(args.out, "wb") as f:
        f.write(signed)
    print(">> signed (native v2, no apksigner):", args.out)
    return 0

def cmd_js(args):
    apk_zip, label = load_base_apk(args.input)
    out = args.out or (re.sub(r"\.[^.]+$", "", os.path.basename(args.input)) + "_js")
    framework, assets = detect_framework(apk_zip)
    print("source   :", label)
    print("framework:", framework)

    if framework == "native":
        print("\n[native app -- no JavaScript]")
        print("  This is Java/Kotlin. There is no JS to recover.")
        print("  -> Java source : reapk decode %s   (drives apktool)" % args.input)
        print("  -> or use jadx -d out/ %s" % args.input)
        return 0
    if framework == "flutter":
        print("\n[Flutter -- Dart, not JS]")
        print("  Logic is compiled Dart in libapp.so. Use 'blutter' to reverse it.")
        return 0

    os.makedirs(out, exist_ok=True)
    saved, hermes = [], []
    for a in assets:
        try:
            blob = apk_zip.read(a)
        except Exception:
            continue
        dst = os.path.join(out, os.path.basename(a))
        with open(dst, "wb") as f:
            f.write(blob)
        saved.append(dst)
        if blob[:4] == HERMES_MAGIC:
            hermes.append(dst)

    # Cordova/Capacitor: pull the whole web root, it's plain source
    if framework == "cordova/capacitor":
        web = [n for n in apk_zip.namelist()
               if n.lower().startswith(("assets/www/", "assets/public/"))]
        for n in web:
            dst = os.path.join(out, n.replace("assets/", ""))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as f:
                f.write(apk_zip.read(n))
            saved.append(dst)

    print("\n[saved %d file(s)] -> %s/" % (len(saved), out))
    for s in saved[:20]:
        print("  ", s)

    if hermes:
        print("\n[!] Hermes bytecode detected (%d bundle) -- NOT plain JS" % len(hermes))
        hd = _find_tool("hermes-dec") or _find_tool("hbctool")
        if hd:
            for h in hermes:
                run([hd, h])
        else:
            print("  Install a Hermes decompiler to recover source:")
            print("    pip install hermes-dec   ->  hermes-dec %s" % hermes[0])
            print("    or hbctool disasm %s out_asm/" % hermes[0])
    else:
        print("\n[plain JS] minified -- beautify with:  npx prettier --write %s/" % out)
    return 0

def cmd_decode(args):
    engine, tool = _resolve_engine(args.engine)
    if not engine:
        raise REapkError(
            "error: need apktool or APKEditor.jar.\n"
            "  apktool : https://apktool.org   (or set APKTOOL_JAR=apktool.jar)\n"
            "  APKEditor: set APKEDITOR_JAR=APKEditor.jar")
    out = args.out or (re.sub(r"\.[^.]+$", "", os.path.basename(args.input)) + "_decoded")
    if engine == "apktool":
        cmd = ([tool] if shutil.which(str(tool)) else ["java", "-jar", tool])
        return run(cmd + ["d", "-f", args.input, "-o", out])
    return run(["java", "-jar", tool, "d", "-i", args.input, "-o", out])

def cmd_build(args):
    engine, tool = _resolve_engine(args.engine)
    if not engine:
        raise REapkError("error: need apktool or APKEditor.jar to rebuild (see 'decode').")
    unsigned = args.out + ".unsigned"
    if engine == "apktool":
        cmd = ([tool] if shutil.which(str(tool)) else ["java", "-jar", tool])
        rc = run(cmd + ["b", "-f", args.input, "-o", unsigned])
    else:
        rc = run(["java", "-jar", tool, "b", "-i", args.input, "-o", unsigned])
    # apktool can exit 0 with aapt warnings yet leave no/empty apk -- verify the
    # artifact before signing so we never emit a 0-byte "apk".
    if rc != 0 or not os.path.isfile(unsigned) or os.path.getsize(unsigned) == 0:
        if os.path.isfile(unsigned):
            os.remove(unsigned)
        raise REapkError(
            "rebuild failed (rc=%d) -- no valid apk produced.\n"
            "  If you see 'attribute android:* not found', apktool needs the target\n"
            "  framework: apktool if <path-to-framework-res.apk>, then retry." % rc)

    # zipalign (optional but recommended) then sign -- the step apktool omits
    zipalign = _find_tool("zipalign")
    aligned = args.out + ".aligned"
    target = unsigned
    if zipalign:
        if run([zipalign, "-f", "-p", "4", unsigned, aligned]) == 0:
            target = aligned

    apksigner = _find_tool("apksigner")
    if args.no_sign or not apksigner:
        shutil.move(target, args.out)
        if not apksigner and not args.no_sign:
            print("!! apksigner not found -- emitted UNSIGNED apk (won't install). "
                  "Install Android build-tools.")
        print(">> built:", args.out, "(unsigned)")
        return 0

    ks = args.keystore or os.path.expanduser("~/.android/debug.keystore")
    if not os.path.isfile(ks):
        print("!! keystore %s missing. Create one:" % ks)
        print('   keytool -genkey -v -keystore %s -storepass android \\' % ks)
        print('     -alias androiddebugkey -keypass android -keyalg RSA -keysize 2048 \\')
        print('     -validity 10000 -dname "CN=Android Debug,O=Android,C=US"')
        raise REapkError(1)
    rc = run([apksigner, "sign", "--ks", ks, "--ks-pass", "pass:" + args.ks_pass,
              "--ks-key-alias", args.ks_alias, "--out", args.out, target])
    if rc == 0:
        run([apksigner, "verify", args.out])
        print(">> built + signed:", args.out)
    for tmp in (unsigned, aligned):
        if os.path.isfile(tmp):
            os.remove(tmp)
    return rc

def cmd_analyze(args):
    apk_zip, label = load_base_apk(args.input)
    mb = read_manifest_bytes(apk_zip)
    if not mb:
        raise REapkError("error: no AndroidManifest.xml in %s" % label)
    arsc = None
    try:
        arsc = Arsc(apk_zip.read("resources.arsc"))
    except Exception:
        arsc = None
    info = analyze_manifest(parse_axml(mb, arsc))
    secrets, urls = (scan_secrets(apk_zip) if args.secrets else ({}, []))
    if args.json:
        print(json.dumps({"source": label, "manifest": info,
                          "secrets": secrets, "endpoints": urls}, indent=2))
    else:
        print("\nsource:", label)
        print_report(info, secrets, urls)
    return 0
