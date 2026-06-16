#!/usr/bin/env python3
"""
bench_apk.py — benchmark reapk vs apktool vs APKEditor on real-world goals.

Times the *whole task* a user actually wants done, best-of-N. Where the tools
do different amounts of work it is labelled honestly (apktool/APKEditor fully
decode+recompile; reapk works on the binary formats directly).

  python bench_apk.py app.apk [--runs 3]

Tool discovery (env overrides): APKTOOL_JAR, APKEDITOR_JAR. apksigner/zipalign
come from the Android SDK build-tools on PATH.
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
# Run reapk via the SAME interpreter that launched the benchmark — robust across
# venvs (avoids matching a stale `reapk.exe` from another environment).
# Requires reapk importable here: `pip install -e .` in the active environment.
REAPK = [sys.executable, "-m", "reapk"]


def _which_jar(name, env):
    if os.environ.get(env):
        return os.environ[env]
    for c in (name, os.path.join(HERE, name)):
        if os.path.isfile(c):
            return c
    return None


def apktool_cmd(args):
    p = shutil.which("apktool") or _which_jar("apktool.jar", "APKTOOL_JAR")
    if not p:
        return None
    return (["java", "-jar", p] if str(p).endswith(".jar") else [p]) + args


def apkeditor_cmd(args):
    p = _which_jar("APKEditor.jar", "APKEDITOR_JAR")
    return (["java", "-jar", p] + args) if p else None


APKSIGNER = shutil.which("apksigner")
ZIPALIGN = shutil.which("zipalign")
KEYSTORE = os.path.expanduser("~/.android/debug.keystore")


def dirsize(p):
    if not p or not os.path.exists(p):
        return None
    if os.path.isfile(p):
        return os.path.getsize(p)
    return sum(os.path.getsize(os.path.join(r, f))
               for r, _, fs in os.walk(p) for f in fs)


def run_seq(cmds):
    """Run a sequence of commands; return total wall-time, or None on failure.

    A missing executable or a non-zero exit is a graceful failure (the tool
    just shows ``FAIL``) rather than crashing the whole benchmark.
    """
    t = time.perf_counter()
    for cmd in cmds:
        try:
            r = subprocess.run(cmd, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            return None
        if r.returncode != 0:
            return None
    return time.perf_counter() - t


def bench(label, build, runs):
    """build(tmpdir) -> (list_of_cmds, size_path|None). Returns (best_time, size)."""
    if build is None:
        return ("n/a", None)
    best, size = None, None
    for _ in range(runs):
        with tempfile.TemporaryDirectory() as td:
            cmds, sp = build(td)
            if cmds is None:
                return ("n/a", None)
            dt = run_seq(cmds)
            if dt is None:
                return ("FAIL", None)
            best = dt if best is None else min(best, dt)
            size = dirsize(sp) if sp else size
    return (best, size)


def fmt(v):
    return "%7.2fs" % v if isinstance(v, float) else "%8s" % v


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("apk", nargs="?", default="sinet.startup.inDriver.apk")
    ap.add_argument("--runs", type=int, default=3)
    args = ap.parse_args()
    apk = os.path.abspath(args.apk)
    if not os.path.isfile(apk):
        sys.exit("apk not found: " + apk)

    # Preflight: run the FIRST real reapk op and surface its error if it fails
    # (the benchmark otherwise discards reapk's stderr, hiding the cause).
    print("preflight: %s analyze ..." % " ".join(REAPK))
    chk = subprocess.run(REAPK + ["analyze", apk], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if chk.returncode != 0:
        print("\n*** reapk is FAILING (rc=%d). Its real stderr: ***" % chk.returncode)
        print((chk.stderr or "(no stderr captured)").rstrip())
        print("\nMost common fix -- install reapk into THIS interpreter:")
        print("  %s -m pip install -e ." % sys.executable)
        print("  (uv venv?  uv pip install -e .)\n")
    else:
        print("preflight OK: reapk runs.\n")

    can_sign = bool(APKSIGNER and os.path.isfile(KEYSTORE))

    def sign_cmd(src, out):
        return [APKSIGNER, "sign", "--ks", KEYSTORE, "--ks-pass", "pass:android",
                "--ks-key-alias", "androiddebugkey", "--out", out, src]

    # --- goal definitions: each maps tool -> build(tmpdir) -> (cmds, size_path) ---
    goals = []

    # GOAL 1: read manifest / attack surface
    goals.append(("read manifest + recon", {
        "reapk": lambda td: ([REAPK + ["analyze", apk]], None),
        "apktool": lambda td: (apktool_cmd(["d", "-f", "-o", td + "/o", apk])
                               and [apktool_cmd(["d", "-f", "-o", td + "/o", apk])], td + "/o"),
        "APKEditor": lambda td: (apkeditor_cmd(["d", "-i", apk, "-o", td + "/o"])
                                 and [apkeditor_cmd(["d", "-i", apk, "-o", td + "/o"])], td + "/o"),
    }, "apktool/APKEditor fully decode; reapk reads the binary manifest only"))

    # GOAL 2: parse ALL bytecode (read every class/method)
    goals.append(("parse all DEX code", {
        "reapk": lambda td: ([REAPK + ["dex", apk]], None),
        "apktool": lambda td: (apktool_cmd(["d", "-f", "-o", td + "/o", apk])
                               and [apktool_cmd(["d", "-f", "-o", td + "/o", apk])], td + "/o"),
        "APKEditor": lambda td: (apkeditor_cmd(["d", "-i", apk, "-o", td + "/o"])
                                 and [apkeditor_cmd(["d", "-i", apk, "-o", td + "/o"])], td + "/o"),
    }, "reapk parses in-memory; others write smali to disk"))

    # GOAL 3: produce a SIGNED, modified apk (make debuggable) — the real task
    def reapk_patch(td):
        return ([REAPK + ["patch", apk, "--debuggable", "-o", td + "/out.apk"]], td + "/out.apk")

    def apktool_patch(td):
        d, b = apktool_cmd(["d", "-f", "-o", td + "/d", apk]), None
        if not d:
            return (None, None)
        b = apktool_cmd(["b", "-f", td + "/d", "-o", td + "/u.apk"])
        seq = [d, b]
        if ZIPALIGN:
            seq.append([ZIPALIGN, "-f", "4", td + "/u.apk", td + "/a.apk"])
            src = td + "/a.apk"
        else:
            src = td + "/u.apk"
        if can_sign:
            seq.append(sign_cmd(src, td + "/out.apk"))
        return (seq, td + "/out.apk" if can_sign else src)

    def apkeditor_patch(td):
        d = apkeditor_cmd(["d", "-i", apk, "-o", td + "/d"])
        if not d:
            return (None, None)
        b = apkeditor_cmd(["b", "-i", td + "/d", "-o", td + "/u.apk"])
        seq = [d, b]
        out = td + "/u.apk"
        if can_sign:
            seq.append(sign_cmd(td + "/u.apk", td + "/out.apk"))
            out = td + "/out.apk"
        return (seq, out)

    goals.append(("patch->signed apk (debuggable)", {
        "reapk": reapk_patch, "apktool": apktool_patch, "APKEditor": apkeditor_patch,
    }, "reapk: 1 native step. others: decode+recompile+align+sign pipeline"))

    # GOAL 4: sign an apk
    goals.append(("sign apk (v2/v3)", {
        "reapk": lambda td: ([REAPK + ["sign", apk, "-o", td + "/s.apk"]], td + "/s.apk"),
        "apktool": None,
        "APKEditor": None,
    }, "reapk native v2/v3 signer; apksigner shown separately below"))

    size_mb = os.path.getsize(apk) / 1e6
    print("APK: %s (%.1f MB)   runs=%d (best shown)\n" % (os.path.basename(apk), size_mb, args.runs))
    print("%-30s %9s %9s %9s   %s" % ("GOAL", "reapk", "apktool", "APKEditor", "notes"))
    print("-" * 100)
    for name, tools, note in goals:
        row = {}
        for t in ("reapk", "apktool", "APKEditor"):
            best, _sz = bench(t, tools.get(t), args.runs)
            row[t] = best
        print("%-30s %9s %9s %9s   %s"
              % (name, fmt(row["reapk"]), fmt(row["apktool"]), fmt(row["APKEditor"]), note))

    # apksigner reference for the sign goal
    if can_sign:
        with tempfile.TemporaryDirectory() as td:
            best = None
            for _ in range(args.runs):
                dt = run_seq([sign_cmd(apk, td + "/s.apk")])
                if dt:
                    best = dt if best is None else min(best, dt)
            print("\napksigner sign (reference): %s" % (fmt(best) if best else "FAIL"))
    print("\nlower is better. 'n/a' = tool does not perform that task.")


if __name__ == "__main__":
    main()
