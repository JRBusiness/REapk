import re


SECRET_PATTERNS = {
    "google_api_key": re.compile(rb"AIza[0-9A-Za-z_\-]{35}"),
    "aws_access_key": re.compile(rb"(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}"),
    "google_oauth": re.compile(rb"[0-9]+-[0-9a-z_]{20,}\.apps\.googleusercontent\.com"),
    "firebase_db": re.compile(rb"[a-z0-9.\-]+\.firebaseio\.com"),
    "gcp_bucket": re.compile(rb"[a-z0-9.\-]+\.appspot\.com"),
    "private_key": re.compile(rb"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "jwt": re.compile(rb"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
}

URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#@!$&'()*+,;=%\-]{6,}")

SCAN_EXT = (".dex", ".json", ".js", ".xml", ".properties", ".txt", ".cfg", ".html")

def scan_secrets(apk_zip):
    secrets, urls = {}, set()
    for name in apk_zip.namelist():
        low = name.lower()
        if not (low.endswith(SCAN_EXT) or low.startswith("assets/") or low.startswith("res/raw/")):
            continue
        try:
            blob = apk_zip.read(name)
        except Exception:
            continue
        for label, rx in SECRET_PATTERNS.items():
            for m in rx.findall(blob):
                secrets.setdefault(label, set()).add(m.decode("latin-1")[:120])
        for m in URL_RE.findall(blob):
            u = m.decode("latin-1")
            if not any(u.endswith(x) for x in (".png", ".jpg", ".css", ".gif", ".svg")):
                urls.add(u[:160])
    return ({k: sorted(v) for k, v in secrets.items()}, sorted(urls))
