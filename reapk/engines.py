"""Discovery + invocation of optional external engines (apktool / APKEditor).

Only the ``decode`` / ``build`` commands use these; every other reapk command is
fully native.
"""
import logging
import os
import shutil
import subprocess

log = logging.getLogger("reapk.engines")


def _find_tool(name, env=None):
    if env and os.environ.get(env):
        return os.environ[env]
    return shutil.which(name)


def _find_jar(env, *candidates):
    if os.environ.get(env):
        return os.environ[env]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def run(cmd):
    """Run an external command, logging it. Returns its exit code."""
    log.info("run: %s", " ".join(str(c) for c in cmd))
    # stdin=DEVNULL so a .bat "Press any key to continue" pause can't hang us.
    return subprocess.call(cmd, stdin=subprocess.DEVNULL)


def _resolve_engine(prefer):
    apktool = _find_tool("apktool") or _find_jar("APKTOOL_JAR", "apktool.jar", "./apktool.jar")
    apkeditor = _find_jar("APKEDITOR_JAR", "APKEditor.jar", "./APKEditor.jar")
    if prefer == "apkeditor" and apkeditor:
        return "apkeditor", apkeditor
    if prefer == "apktool" and apktool:
        return "apktool", apktool
    if apktool:
        return "apktool", apktool
    if apkeditor:
        return "apkeditor", apkeditor
    return None, None
