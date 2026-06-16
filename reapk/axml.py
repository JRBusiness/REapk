import struct
from .errors import AxmlError



RES_STRING_POOL = 0x0001

RES_XML_RESOURCE_MAP = 0x0180

RES_XML_START_ELEMENT = 0x0102

RES_XML_END_ELEMENT = 0x0103

T_REFERENCE = 0x01

T_STRING = 0x03

T_FLOAT = 0x04

T_INT_DEC = 0x10

T_INT_HEX = 0x11

T_INT_BOOL = 0x12

ATTR_IDS = {
    0x01010003: "name",
    0x01010006: "permission",
    0x0101000F: "debuggable",
    0x01010010: "exported",
    0x01010011: "process",
    0x01010018: "authorities",
    0x0101001A: "grantUriPermissions",
    0x0101001B: "host",
    0x0101001C: "port",
    0x0101001D: "path",
    0x0101001E: "pathPrefix",
    0x0101001F: "pathPattern",
    0x01010026: "mimeType",
    0x01010027: "scheme",
    0x0101020C: "minSdkVersion",
    0x01010270: "targetSdkVersion",
    0x01010280: "allowBackup",
    0x0101021B: "versionCode",
    0x0101021C: "versionName",
    0x01010527: "networkSecurityConfig",
    0x01010604: "usesCleartextTraffic",
}

def _u8len(data, off):
    val = data[off]
    off += 1
    if val & 0x80:
        val = ((val & 0x7F) << 8) | data[off]
        off += 1
    return val, off

def _u16len(data, off):
    val = struct.unpack_from("<H", data, off)[0]
    off += 2
    if val & 0x8000:
        low = struct.unpack_from("<H", data, off)[0]
        off += 2
        val = ((val & 0x7FFF) << 16) | low
    return val, off

def parse_string_pool(data, base):
    string_count = struct.unpack_from("<I", data, base + 8)[0]
    flags = struct.unpack_from("<I", data, base + 16)[0]
    strings_start = struct.unpack_from("<I", data, base + 20)[0]
    is_utf8 = bool(flags & 0x100)
    offsets = struct.unpack_from("<%dI" % string_count, data, base + 28)
    sd = base + strings_start
    out = []
    for o in offsets:
        p = sd + o
        try:
            if is_utf8:
                _, p = _u8len(data, p)       # char count (unused)
                blen, p = _u8len(data, p)    # byte count
                out.append(data[p:p + blen].decode("utf-8", "replace"))
            else:
                n, p = _u16len(data, p)
                out.append(data[p:p + n * 2].decode("utf-16-le", "replace"))
        except Exception:
            out.append("")
    return out

def _fmt_value(vtype, vdata, strings, arsc=None):
    if vtype == T_STRING:
        return strings[vdata] if 0 <= vdata < len(strings) else ""
    if vtype == T_INT_BOOL:
        return "true" if vdata != 0 else "false"
    if vtype == T_REFERENCE:
        if arsc is not None:
            r = arsc.resolve(vdata)
            if r:
                return r
        return "@0x%08x" % vdata
    if vtype == T_INT_HEX:
        return "0x%x" % vdata
    if vtype == T_INT_DEC:
        return str(vdata if vdata < 0x80000000 else vdata - 0x100000000)
    if vtype == T_FLOAT:
        return str(struct.unpack("<f", struct.pack("<I", vdata))[0])
    return str(vdata)

class Arsc:
    """Minimal native resources.arsc reader -- resolves resource IDs to values."""

    def __init__(self, data):
        self.global_strings = []
        self.values = {}
        hs = struct.unpack_from("<H", data, 2)[0]
        off, n = hs, len(data)
        while off + 8 <= n:
            ctype, _chs, csize = struct.unpack_from("<HHI", data, off)
            if csize < 8:
                break
            if ctype == RES_STRING_POOL and not self.global_strings:
                self.global_strings = parse_string_pool(data, off)
            elif ctype == 0x0200:  # RES_TABLE_PACKAGE_TYPE
                self._pkg(data, off, csize)
            off += csize

    def _pkg(self, data, base, csize):
        pkg_id = struct.unpack_from("<I", data, base + 8)[0]
        hs = struct.unpack_from("<H", data, base + 2)[0]
        off, end = base + hs, base + csize
        while off + 8 <= end:
            ctype, _chs, sz = struct.unpack_from("<HHI", data, off)
            if sz < 8:
                break
            if ctype == 0x0201:  # RES_TABLE_TYPE_TYPE
                self._type(data, off, pkg_id)
            off += sz

    def _type(self, data, base, pkg_id):
        type_id = data[base + 8]
        flags = data[base + 9]
        entry_count = struct.unpack_from("<I", data, base + 12)[0]
        entries_start = struct.unpack_from("<I", data, base + 16)[0]
        hs = struct.unpack_from("<H", data, base + 2)[0]
        ostart = base + hs
        offsets = {}
        if flags & 0x01:            # sparse
            for i in range(entry_count):
                idx, o = struct.unpack_from("<HH", data, ostart + 4 * i)
                offsets[idx] = o * 4
        elif flags & 0x02:          # offset16
            for i in range(entry_count):
                o = struct.unpack_from("<H", data, ostart + 2 * i)[0]
                if o != 0xFFFF:
                    offsets[i] = o * 4
        else:                       # dense u32
            for i in range(entry_count):
                o = struct.unpack_from("<I", data, ostart + 4 * i)[0]
                if o != 0xFFFFFFFF:
                    offsets[i] = o
        for idx, o in offsets.items():
            ep = base + entries_start + o
            if ep + 8 > len(data):
                continue
            esize, eflags = struct.unpack_from("<HH", data, ep)
            if eflags & 0x0001 or eflags & 0x0008:   # complex map / compact -- skip
                continue
            vp = ep + (esize if esize >= 8 else 8)
            vtype = data[vp + 3]
            vdata = struct.unpack_from("<I", data, vp + 4)[0]
            rid = (pkg_id << 24) | (type_id << 16) | idx
            self.values.setdefault(rid, (vtype, vdata))

    def resolve(self, rid, depth=0):
        v = self.values.get(rid)
        if not v or depth > 4:
            return None
        vtype, vdata = v
        if vtype == T_STRING:
            return self.global_strings[vdata] if vdata < len(self.global_strings) else None
        if vtype == T_REFERENCE:
            return self.resolve(vdata, depth + 1)
        return None

def parse_axml(data, arsc=None):
    """Return the manifest as a nested {tag, attrs, children} tree."""
    strings, resmap = [], []
    off = struct.unpack_from("<H", data, 2)[0]  # headerSize
    stack, root = [], None

    while off + 8 <= len(data):
        ctype, _hs, csize = struct.unpack_from("<HHI", data, off)
        if csize < 8:
            break
        if ctype == RES_STRING_POOL:
            strings = parse_string_pool(data, off)
        elif ctype == RES_XML_RESOURCE_MAP:
            n = (csize - 8) // 4
            resmap = list(struct.unpack_from("<%dI" % n, data, off + 8))
        elif ctype == RES_XML_START_ELEMENT:
            name_i = struct.unpack_from("<I", data, off + 20)[0]
            attr_start, attr_size, attr_count = struct.unpack_from("<HHH", data, off + 24)
            tag = strings[name_i] if 0 <= name_i < len(strings) else "?"
            attrs = {}
            abase = off + 16 + attr_start
            for i in range(attr_count):
                a = abase + i * attr_size
                a_name = struct.unpack_from("<I", data, a + 4)[0]
                vtype = data[a + 15]
                vdata = struct.unpack_from("<I", data, a + 16)[0]
                name = strings[a_name] if 0 <= a_name < len(strings) else ""
                if not name and 0 <= a_name < len(resmap):
                    name = ATTR_IDS.get(resmap[a_name], "attr_%08x" % resmap[a_name])
                attrs[name or "?"] = _fmt_value(vtype, vdata, strings, arsc)
            node = {"tag": tag, "attrs": attrs, "children": []}
            if stack:
                stack[-1]["children"].append(node)
            else:
                root = node
            stack.append(node)
        elif ctype == RES_XML_END_ELEMENT:
            if stack:
                stack.pop()
        off += csize

    return root

ANDROID_NS = "http://schemas.android.com/apk/res/android"

RES_XML_TYPE = 0x0003

RES_XML_START_NS = 0x0100

RES_XML_END_NS = 0x0101

RES_XML_CDATA = 0x0104

RID_NAME = 0x01010003

RID_DEBUGGABLE = 0x0101000F

RID_EXPORTED = 0x01010010

def _none_if_max(i):
    return None if i == 0xFFFFFFFF else i

def parse_axml_ir(data):
    """Parse the binary manifest into an editable, re-encodable IR."""
    strings, resmap, events = [], [], []
    off = struct.unpack_from("<H", data, 2)[0]
    while off + 8 <= len(data):
        ctype, _hs, csize = struct.unpack_from("<HHI", data, off)
        if csize < 8:
            break
        if ctype == RES_STRING_POOL:
            strings = parse_string_pool(data, off)
        elif ctype == RES_XML_RESOURCE_MAP:
            n = (csize - 8) // 4
            resmap = list(struct.unpack_from("<%dI" % n, data, off + 8))
        elif ctype in (RES_XML_START_NS, RES_XML_END_NS):
            line = struct.unpack_from("<I", data, off + 8)[0]
            pi, ui = struct.unpack_from("<II", data, off + 16)
            kind = "ns_start" if ctype == RES_XML_START_NS else "ns_end"
            events.append((kind, line,
                           strings[pi] if pi < len(strings) else None,
                           strings[ui] if ui < len(strings) else None))
        elif ctype == RES_XML_START_ELEMENT:
            line = struct.unpack_from("<I", data, off + 8)[0]
            ns_i, name_i = struct.unpack_from("<II", data, off + 16)
            attr_start, attr_size, attr_count = struct.unpack_from("<HHH", data, off + 24)
            id_idx, class_idx, style_idx = struct.unpack_from("<HHH", data, off + 30)
            tag = strings[name_i] if name_i < len(strings) else "?"
            ns_uri = strings[ns_i] if ns_i < len(strings) else None
            attrs = []
            abase = off + 16 + attr_start
            for i in range(attr_count):
                a = abase + i * attr_size
                a_ns, a_name = struct.unpack_from("<II", data, a)
                vtype = data[a + 15]
                vdata = struct.unpack_from("<I", data, a + 16)[0]
                resid = resmap[a_name] if a_name < len(resmap) else None
                name_s = strings[a_name] if a_name < len(strings) else ""
                attrs.append({
                    "ns": strings[a_ns] if a_ns < len(strings) else None,
                    "name": name_s, "resid": resid, "vtype": vtype,
                    "vstr": strings[vdata] if (vtype == T_STRING and vdata < len(strings)) else None,
                    "vdata": vdata,
                })
            events.append(("start", line, ns_uri, tag, attrs, id_idx, class_idx, style_idx))
        elif ctype == RES_XML_END_ELEMENT:
            line = struct.unpack_from("<I", data, off + 8)[0]
            ns_i, name_i = struct.unpack_from("<II", data, off + 16)
            events.append(("end", line,
                           strings[ns_i] if ns_i < len(strings) else None,
                           strings[name_i] if name_i < len(strings) else "?"))
        off += csize
    resid_pairs = [(strings[i], resmap[i]) for i in range(len(resmap)) if i < len(strings)]
    return {"resid": resid_pairs, "events": events}

def _enc_len8(n):
    return bytes([((n >> 8) & 0x7F) | 0x80, n & 0xFF]) if n > 0x7F else bytes([n & 0x7F])

def _enc_string_pool(strings):
    offsets, blob = [], bytearray()
    for s in strings:
        offsets.append(len(blob))
        b = s.encode("utf-8")
        blob += _enc_len8(len(s)) + _enc_len8(len(b)) + b + b"\x00"
    while len(blob) % 4:
        blob.append(0)
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    out = bytearray(struct.pack("<HHI", RES_STRING_POOL, header_size, strings_start + len(blob)))
    out += struct.pack("<IIIII", len(strings), 0, 0x00000100, strings_start, 0)
    for o in offsets:
        out += struct.pack("<I", o)
    return bytes(out + blob)

def encode_axml(ir):
    """Serialize the IR back to a binary manifest (our own writer)."""
    resid_pairs = ir["resid"]
    pool = [s for s, _ in resid_pairs]
    resids = [r for _, r in resid_pairs]
    residx = {r: i for i, (_, r) in enumerate(resid_pairs)}
    sidx = {}
    for i, s in enumerate(pool):
        sidx.setdefault(s, i)

    def intern(s):
        if s is not None and s not in sidx:
            sidx[s] = len(pool)
            pool.append(s)

    for ev in ir["events"]:
        if ev[0] in ("ns_start", "ns_end"):
            intern(ev[2]); intern(ev[3])
        elif ev[0] == "start":
            intern(ev[2]); intern(ev[3])
            for a in ev[4]:
                intern(a["ns"])
                if a["resid"] is None:
                    intern(a["name"])
                if a["vtype"] == T_STRING:
                    intern(a["vstr"])
        elif ev[0] == "end":
            intern(ev[2]); intern(ev[3])

    def ref(s):
        return sidx[s] if s is not None else 0xFFFFFFFF

    nodes = bytearray()
    for ev in ir["events"]:
        if ev[0] in ("ns_start", "ns_end"):
            ctype = RES_XML_START_NS if ev[0] == "ns_start" else RES_XML_END_NS
            nodes += struct.pack("<HHI", ctype, 16, 24)
            nodes += struct.pack("<IIII", ev[1], 0xFFFFFFFF, ref(ev[2]), ref(ev[3]))
        elif ev[0] == "start":
            _, line, ns_uri, tag, attrs, id_idx, class_idx, style_idx = ev
            body = bytearray(struct.pack("<II", ref(ns_uri), ref(tag)))
            body += struct.pack("<HHH", 20, 20, len(attrs))
            body += struct.pack("<HHH", id_idx, class_idx, style_idx)
            for a in attrs:
                a_name = residx[a["resid"]] if a["resid"] is not None else sidx[a["name"]]
                if a["vtype"] == T_STRING:
                    vdata = sidx[a["vstr"]]; raw = vdata
                else:
                    vdata = a["vdata"]; raw = 0xFFFFFFFF
                body += struct.pack("<III", ref(a["ns"]), a_name, raw)
                body += struct.pack("<HBBI", 8, 0, a["vtype"], vdata)
            nodes += struct.pack("<HHI", RES_XML_START_ELEMENT, 16, 16 + len(body))
            nodes += struct.pack("<II", line, 0xFFFFFFFF) + body
        elif ev[0] == "end":
            nodes += struct.pack("<HHI", RES_XML_END_ELEMENT, 16, 24)
            nodes += struct.pack("<IIII", ev[1], 0xFFFFFFFF, ref(ev[2]), ref(ev[3]))

    strpool = _enc_string_pool(pool)
    resmap = struct.pack("<HHI", RES_XML_RESOURCE_MAP, 8, 8 + 4 * len(resids))
    resmap += b"".join(struct.pack("<I", r) for r in resids)
    body = strpool + resmap + bytes(nodes)
    return struct.pack("<HHI", RES_XML_TYPE, 8, 8 + len(body)) + body

def _ensure_resid(ir, name, rid):
    if rid not in {r for _, r in ir["resid"]}:
        ir["resid"].append((name, rid))

def _app_start(ir):
    for ev in ir["events"]:
        if ev[0] == "start" and ev[3] == "application":
            return ev
    return None

def _set_attr(start_ev, name, resid, vtype, vdata=0, vstr=None):
    for a in start_ev[4]:
        if a["resid"] == resid or a["name"] == name:
            a.update(vtype=vtype, vdata=vdata, vstr=vstr, resid=resid)
            return
    start_ev[4].append({"ns": ANDROID_NS, "name": name, "resid": resid,
                        "vtype": vtype, "vstr": vstr, "vdata": vdata})

def patch_debuggable(ir):
    app = _app_start(ir)
    if not app:
        raise AxmlError("no <application> element")
    _ensure_resid(ir, "debuggable", RID_DEBUGGABLE)
    _set_attr(app, "debuggable", RID_DEBUGGABLE, T_INT_BOOL, 0xFFFFFFFF)

RID_CLEARTEXT = 0x01010604

def patch_cleartext(ir):
    app = _app_start(ir)
    if not app:
        raise AxmlError("no <application> element")
    _ensure_resid(ir, "usesCleartextTraffic", RID_CLEARTEXT)
    _set_attr(app, "usesCleartextTraffic", RID_CLEARTEXT, T_INT_BOOL, 0xFFFFFFFF)

def patch_add_permission(ir, perm):
    _ensure_resid(ir, "name", RID_NAME)
    # insert <uses-permission android:name=perm/> just before <application>
    idx = next(i for i, e in enumerate(ir["events"]) if e[0] == "start" and e[3] == "application")
    attr = {"ns": ANDROID_NS, "name": "name", "resid": RID_NAME,
            "vtype": T_STRING, "vstr": perm, "vdata": 0}
    start = ("start", 0, None, "uses-permission", [attr], 0, 0, 0)
    end = ("end", 0, None, "uses-permission")
    ir["events"][idx:idx] = [start, end]