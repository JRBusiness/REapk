COMPONENTS = ("activity", "activity-alias", "service", "receiver", "provider")

def _find(node, tag):
    return [c for c in node.get("children", []) if c["tag"] == tag]

def _has_intent_filter(comp):
    return bool(_find(comp, "intent-filter"))

def is_exported(comp):
    e = comp["attrs"].get("exported")
    if e is not None:
        return e == "true"
    return _has_intent_filter(comp)

def collect_deeplinks(comp):
    links = []
    for f in _find(comp, "intent-filter"):
        cats = {c["attrs"].get("name", "") for c in _find(f, "category")}
        browsable = "android.intent.category.BROWSABLE" in cats
        for d in _find(f, "data"):
            scheme = d["attrs"].get("scheme")
            host = d["attrs"].get("host", "")
            path = (d["attrs"].get("path") or d["attrs"].get("pathPrefix")
                    or d["attrs"].get("pathPattern") or "")
            if scheme:
                links.append({
                    "uri": "%s://%s%s" % (scheme, host, path),
                    "browsable": browsable,
                })
    return links

def analyze_manifest(root):
    app = (_find(root, "application") or [None])[0] or {"attrs": {}, "children": []}
    a = app["attrs"]
    info = {
        "package": root["attrs"].get("package", ""),
        "versionName": root["attrs"].get("versionName", ""),
        "versionCode": root["attrs"].get("versionCode", ""),
        "minSdk": (_find(root, "uses-sdk") or [{"attrs": {}}])[0]["attrs"].get("minSdkVersion", ""),
        "targetSdk": (_find(root, "uses-sdk") or [{"attrs": {}}])[0]["attrs"].get("targetSdkVersion", ""),
        "debuggable": a.get("debuggable", "false"),
        "allowBackup": a.get("allowBackup", "true (default)"),
        "usesCleartextTraffic": a.get("usesCleartextTraffic", ""),
        "networkSecurityConfig": a.get("networkSecurityConfig", ""),
        "permissions": sorted(p["attrs"].get("name", "") for p in _find(root, "uses-permission")),
        "custom_permissions": sorted(p["attrs"].get("name", "") for p in _find(root, "permission")),
        "exported": [],
    }
    for comp in app["children"]:
        if comp["tag"] not in COMPONENTS or not is_exported(comp):
            continue
        info["exported"].append({
            "type": comp["tag"],
            "name": comp["attrs"].get("name", ""),
            "permission": comp["attrs"].get("permission", ""),
            "authorities": comp["attrs"].get("authorities", ""),
            "deeplinks": collect_deeplinks(comp),
        })
    return info

def print_report(info, secrets=None, urls=None):
    risk = []
    if info["debuggable"] == "true":
        risk.append("android:debuggable=TRUE -- app is debuggable")
    if str(info["allowBackup"]).startswith("true"):
        risk.append("android:allowBackup=TRUE -- adb backup data exfil")
    if info["usesCleartextTraffic"] == "true":
        risk.append("usesCleartextTraffic=TRUE -- HTTP allowed")
    if not info["networkSecurityConfig"] and info["usesCleartextTraffic"] != "false":
        risk.append("no networkSecurityConfig -- default cleartext policy applies")

    print("=" * 64)
    print("package      :", info["package"])
    print("version      : %s (%s)" % (info["versionName"], info["versionCode"]))
    print("sdk          : min=%s target=%s" % (info["minSdk"], info["targetSdk"]))
    print("debuggable   :", info["debuggable"])
    print("allowBackup  :", info["allowBackup"])
    print("cleartext    :", info["usesCleartextTraffic"] or "(unset)")
    print("netSecConfig :", info["networkSecurityConfig"] or "(none)")
    print("=" * 64)

    if risk:
        print("\n[!] RISK FLAGS")
        for r in risk:
            print("  -", r)

    print("\n[exported components] (%d)" % len(info["exported"]))
    for c in info["exported"]:
        perm = (" perm=%s" % c["permission"]) if c["permission"] else " (NO permission)"
        print("  %-15s %s%s" % (c["type"], c["name"], perm))
        if c["authorities"]:
            print("        authorities:", c["authorities"])
        for dl in c["deeplinks"]:
            tag = "BROWSABLE" if dl["browsable"] else "internal"
            print("        deeplink [%s]: %s" % (tag, dl["uri"]))

    dangerous = [p for p in info["permissions"]
                 if any(k in p for k in ("SMS", "CONTACTS", "LOCATION", "CAMERA",
                                         "RECORD_AUDIO", "STORAGE", "ACCESSIBILITY",
                                         "SYSTEM_ALERT", "READ_PHONE"))]
    if dangerous:
        print("\n[notable permissions]")
        for p in dangerous:
            print("  -", p)

    if secrets:
        print("\n[secrets]")
        for label, vals in secrets.items():
            for v in vals[:8]:
                print("  %-16s %s" % (label, v))
    if urls:
        print("\n[endpoints] (%d unique, first 25)" % len(urls))
        for u in urls[:25]:
            print("  -", u)
    print()
