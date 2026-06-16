import zipfile
from .errors import BundleError

from .axml import parse_axml
from .manifest import _find


def read_manifest_bytes(apk_zip):
    try:
        return apk_zip.read("AndroidManifest.xml")
    except KeyError:
        return None

def load_base_apk(path):
    """Return (apk_zip, label). Picks the base split from a bundle."""
    if path.lower().endswith(".apk"):
        return zipfile.ZipFile(path), path
    outer = zipfile.ZipFile(path)
    apks = [n for n in outer.namelist() if n.lower().endswith(".apk")]
    if not apks:
        raise BundleError("error: no .apk inside bundle %s" % path)
    # base = the apk whose manifest is NOT a config split (no 'split' attr / has <application>)
    best = None
    for n in apks:
        z = zipfile.ZipFile(__import__("io").BytesIO(outer.read(n)))
        mb = read_manifest_bytes(z)
        if not mb:
            continue
        root = parse_axml(mb)
        if root and "split" not in root.get("attrs", {}) and _find(root, "application"):
            return z, "%s!%s" % (path, n)
        best = best or (z, "%s!%s" % (path, n))
    if best:
        return best
    raise BundleError("error: no base apk found in %s" % path)

HERMES_MAGIC = b"\xc6\x1f\xbc\x03"

def detect_framework(apk_zip):
    names = apk_zip.namelist()
    nl = [n.lower() for n in names]
    js_assets = [n for n in names if n.lower().startswith("assets/")
                 and n.lower().endswith((".js", ".jsbundle", ".bundle", ".html"))]
    if any(n.startswith("assets/www/") for n in nl) or any(n.startswith("assets/public/") for n in nl):
        return "cordova/capacitor", js_assets
    if any(n.endswith("index.android.bundle") for n in nl) or "libhermes.so" in " ".join(nl):
        bundles = [n for n in names if n.lower().endswith(("index.android.bundle", ".jsbundle"))]
        return "react-native", bundles or js_assets
    if any(n.endswith("libflutter.so") for n in nl) or any("flutter_assets/" in n for n in nl):
        return "flutter", []
    if js_assets:
        return "hybrid-js", js_assets
    return "native", []