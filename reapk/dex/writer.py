import struct
from ..errors import DexError
import zlib

from ._leb import _sleb128, _uleb128, enc_mutf8, enc_sleb, enc_uleb
from .disasm import OPCODES, insn_length
from .pool import Interner


def skip_encoded_value(d, p):
    at = d[p]
    p += 1
    vt, va = at & 0x1F, (at >> 5) & 0x7
    if vt == 0x1C:                       # array
        return skip_encoded_array(d, p)
    if vt == 0x1D:                       # annotation
        _, p = _uleb128(d, p)
        size, p = _uleb128(d, p)
        for _ in range(size):
            _, p = _uleb128(d, p)
            p = skip_encoded_value(d, p)
        return p
    if vt in (0x1E, 0x1F):               # null, boolean
        return p
    return p + va + 1

def skip_encoded_array(d, p):
    size, p = _uleb128(d, p)
    for _ in range(size):
        p = skip_encoded_value(d, p)
    return p

def parse_class_data(dex, off):
    d, p = dex.d, off
    sf, p = _uleb128(d, p)
    inf, p = _uleb128(d, p)
    dm, p = _uleb128(d, p)
    vm, p = _uleb128(d, p)

    def rd_fields(n):
        nonlocal p
        res, idx = [], 0
        for _ in range(n):
            diff, p = _uleb128(d, p)
            acc, p = _uleb128(d, p)
            idx += diff
            res.append([idx, acc])
        return res

    def rd_methods(n):
        nonlocal p
        res, idx = [], 0
        for _ in range(n):
            diff, p = _uleb128(d, p)
            acc, p = _uleb128(d, p)
            co, p = _uleb128(d, p)
            idx += diff
            res.append([idx, acc, co])
        return res

    return rd_fields(sf), rd_fields(inf), rd_methods(dm), rd_methods(vm)

def emit_class_data(cd, code_remap, R=None):
    sfl, ifl, dml, vml = cd
    if R is not None:                       # remap field/method indices, then re-sort
        sfl = sorted([R.fr[i], a] for i, a in sfl)
        ifl = sorted([R.fr[i], a] for i, a in ifl)
        dml = sorted([R.mr[i], a, co] for i, a, co in dml)
        vml = sorted([R.mr[i], a, co] for i, a, co in vml)
    out = bytearray(enc_uleb(len(sfl)) + enc_uleb(len(ifl))
                    + enc_uleb(len(dml)) + enc_uleb(len(vml)))
    for lst in (sfl, ifl):
        prev = 0
        for idx, acc in lst:
            out += enc_uleb(idx - prev) + enc_uleb(acc)
            prev = idx
    for lst in (dml, vml):
        prev = 0
        for idx, acc, co in lst:
            out += enc_uleb(idx - prev) + enc_uleb(acc)
            out += enc_uleb(code_remap[co] if co else 0)
            prev = idx
    return bytes(out)

def code_item_length(dex, co):
    d = dex.d
    _r, _i, _o, tries, _dbg, insz = struct.unpack_from("<HHHHII", d, co)
    p = co + 16 + insz * 2
    if tries:
        if insz & 1:
            p += 2
        p += tries * 8
        hsize, p = _uleb128(d, p)
        for _ in range(hsize):
            sz, p = _sleb128(d, p)
            for _ in range(abs(sz)):
                _, p = _uleb128(d, p)
                _, p = _uleb128(d, p)
            if sz <= 0:
                _, p = _uleb128(d, p)
    return p - co

def _align(buf, n):
    while len(buf) % n:
        buf.append(0)

def debug_info_length(d, off):
    p = off
    _, p = _uleb128(d, p)            # line_start
    psize, p = _uleb128(d, p)        # parameters_size
    for _ in range(psize):
        _, p = _uleb128(d, p)        # parameter name (uleb128p1)
    while True:
        op = d[p]
        p += 1
        if op == 0x00:               # DBG_END_SEQUENCE
            break
        if op == 0x01:               # ADVANCE_PC
            _, p = _uleb128(d, p)
        elif op == 0x02:             # ADVANCE_LINE
            _, p = _sleb128(d, p)
        elif op == 0x03:             # START_LOCAL
            for _ in range(3):
                _, p = _uleb128(d, p)
        elif op == 0x04:             # START_LOCAL_EXTENDED
            for _ in range(4):
                _, p = _uleb128(d, p)
        elif op in (0x05, 0x06, 0x09):  # END/RESTART_LOCAL, SET_FILE
            _, p = _uleb128(d, p)
        # 0x07,0x08 and special opcodes 0x0a-0xff: no operands
    return p - off

def skip_encoded_annotation(d, p):
    _, p = _uleb128(d, p)            # type_idx
    size, p = _uleb128(d, p)
    for _ in range(size):
        _, p = _uleb128(d, p)        # name_idx
        p = skip_encoded_value(d, p)
    return p

def annotation_item_length(d, off):
    return skip_encoded_annotation(d, off + 1) - off

def remap_code(buf, R):
    """Remap all pool references (string/type/field/method/proto) in a code_item."""
    rmap = {"string": R.sr, "type": R.tr, "field": R.fr, "method": R.mr, "proto": R.pr}
    insz = struct.unpack_from("<I", buf, 12)[0]
    words = [struct.unpack_from("<H", buf, 16 + 2 * i)[0] for i in range(insz)]
    pos = 0
    while pos < insz:
        op = words[pos] & 0xFF
        ent = OPCODES.get(op)
        if ent and ent[2] in rmap:
            rm, fmt = rmap[ent[2]], ent[1]
            if fmt in ("21c", "22c", "35c", "3rc"):
                new = rm[words[pos + 1]]
                if new > 0xFFFF:
                    raise DexError("ref index overflow (needs instruction widening)")
                struct.pack_into("<H", buf, 16 + 2 * (pos + 1), new)
            elif fmt == "31c":
                new = rm[words[pos + 1] | (words[pos + 2] << 16)]
                struct.pack_into("<H", buf, 16 + 2 * (pos + 1), new & 0xFFFF)
                struct.pack_into("<H", buf, 16 + 2 * (pos + 2), (new >> 16) & 0xFFFF)
            elif fmt in ("45cc", "4rcc"):
                struct.pack_into("<H", buf, 16 + 2 * (pos + 1), rm[words[pos + 1]])
                struct.pack_into("<H", buf, 16 + 2 * (pos + 3), R.pr[words[pos + 3]])
        pos += max(insn_length(words, pos), 1)

def _p1(v, rm):
    return 0 if v == 0 else rm[v - 1] + 1

def emit_debug_remap(d, off, R):
    p = off
    out = bytearray()
    v, p = _uleb128(d, p); out += enc_uleb(v)            # line_start
    ps, p = _uleb128(d, p); out += enc_uleb(ps)
    for _ in range(ps):
        v, p = _uleb128(d, p); out += enc_uleb(_p1(v, R.sr))  # param name (string)
    while True:
        op = d[p]; p += 1; out.append(op)
        if op == 0x00:
            break
        if op == 0x01:
            v, p = _uleb128(d, p); out += enc_uleb(v)
        elif op == 0x02:
            v, p = _sleb128(d, p); out += enc_sleb(v)
        elif op == 0x03:                                  # START_LOCAL (name str, type)
            r, p = _uleb128(d, p); out += enc_uleb(r)
            nm, p = _uleb128(d, p); out += enc_uleb(_p1(nm, R.sr))
            ty, p = _uleb128(d, p); out += enc_uleb(_p1(ty, R.tr))
        elif op == 0x04:                                  # START_LOCAL_EXTENDED (+sig)
            r, p = _uleb128(d, p); out += enc_uleb(r)
            nm, p = _uleb128(d, p); out += enc_uleb(_p1(nm, R.sr))
            ty, p = _uleb128(d, p); out += enc_uleb(_p1(ty, R.tr))
            sg, p = _uleb128(d, p); out += enc_uleb(_p1(sg, R.sr))
        elif op in (0x05, 0x06):
            v, p = _uleb128(d, p); out += enc_uleb(v)
        elif op == 0x09:                                  # SET_FILE (string)
            v, p = _uleb128(d, p); out += enc_uleb(_p1(v, R.sr))
    return bytes(out)

def _remap_idx_value(at, d, p, rm):
    va = (at >> 5) & 0x7
    old = int.from_bytes(d[p:p + va + 1], "little")
    new = rm[old]
    w = max(1, (new.bit_length() + 7) // 8)
    return bytes([(at & 0x1F) | ((w - 1) << 5)]) + new.to_bytes(w, "little"), p + va + 1

def emit_encoded_value_remap(d, p, R):
    at = d[p]; p += 1
    vt = at & 0x1F
    if vt == 0x1C:                                        # array
        body, p = emit_encoded_array_remap(d, p, R)
        return bytes([at]) + body, p
    if vt == 0x1D:                                        # annotation
        body, p = emit_encoded_annotation_remap(d, p, R)
        return bytes([at]) + body, p
    if vt in (0x1E, 0x1F):                                # null, boolean
        return bytes([at]), p
    idx_rm = {0x15: R.pr, 0x17: R.sr, 0x18: R.tr,         # method-type/string/type
              0x19: R.fr, 0x1A: R.mr, 0x1B: R.fr}.get(vt)  # field/method/enum
    if idx_rm is not None:
        return _remap_idx_value(at, d, p, idx_rm)
    va = (at >> 5) & 0x7                                  # numeric/handle: copy
    return bytes([at]) + d[p:p + va + 1], p + va + 1

def emit_encoded_array_remap(d, p, R):
    size, p = _uleb128(d, p)
    out = bytearray(enc_uleb(size))
    for _ in range(size):
        ev, p = emit_encoded_value_remap(d, p, R)
        out += ev
    return bytes(out), p

def emit_encoded_annotation_remap(d, p, R):
    tidx, p = _uleb128(d, p)
    size, p = _uleb128(d, p)
    out = bytearray(enc_uleb(R.tr[tidx]) + enc_uleb(size))  # annotation type -> remap
    for _ in range(size):
        nm, p = _uleb128(d, p); out += enc_uleb(R.sr[nm])   # element name (string)
        ev, p = emit_encoded_value_remap(d, p, R)
        out += ev
    return bytes(out), p

def build_dex(dex, replacements=None, add_strings=None, interner=None):
    """Re-emit a full, valid DEX preserving debug_info + annotations.

    replacements: {code_off: new_code_item_bytes} to swap method bodies (any size).
    add_strings / interner: intern new pool entries (strings, and via an Interner,
        types/protos/fields/methods); every index is remapped through every section
        (id tables, code refs, debug_info, annotations, encoded arrays, class_data)
        so all existing references keep their meaning.
    """
    replacements = replacements or {}
    d = dex.d
    if interner is None and add_strings:
        interner = Interner(dex)
        for s in add_strings:
            interner.add_string(s)
        interner.finalize()
    R = interner
    n_class = dex.n_class
    if R:
        n_str, n_type, n_proto = len(R.S), len(R.T), len(R.P)
        n_field, n_method = len(R.F), len(R.M)
    else:
        n_str, n_type, n_proto = dex.n_str, dex.n_type, dex.n_proto
        n_field, n_method = dex.n_field, dex.n_method

    off_str = 0x70
    off_type = off_str + n_str * 4
    off_proto = off_type + n_type * 4
    off_field = off_proto + n_proto * 12
    off_method = off_field + n_field * 8
    off_class = off_method + n_method * 8
    data_start = off_class + n_class * 32
    data_start += (-data_start) % 4

    data = bytearray()
    sections = {}  # map_type -> [offsets]

    def place(tc, blob, align=1):
        if align > 1:
            _align(data, align)
        pos = data_start + len(data)
        data.extend(blob)
        sections.setdefault(tc, []).append(pos)
        return pos

    cls = dex.off_class

    # 1. type_lists
    tl_map, tl_by_desc, iface_desc = {}, {}, {}

    def make_tl(descs):
        descs = tuple(descs)
        if not descs:
            return 0
        if descs not in tl_by_desc:
            buf = bytearray(struct.pack("<I", len(descs)))
            for de in descs:
                buf += struct.pack("<H", R.tpos[de])
            tl_by_desc[descs] = place(0x1001, bytes(buf), 4)
        return tl_by_desc[descs]

    if R:
        needed = {tuple(params) for _ret, params in R.P if params}
        for i in range(n_class):
            io = struct.unpack_from("<I", d, cls + 32 * i + 12)[0]
            if io:
                sz = struct.unpack_from("<I", d, io)[0]
                descs = tuple(dex.type(struct.unpack_from("<H", d, io + 4 + 2 * k)[0])
                              for k in range(sz))
                iface_desc[i] = descs
                needed.add(descs)
        for descs in sorted(needed):
            make_tl(descs)
    else:
        tl_offs = set()
        for i in range(dex.n_proto):
            po = struct.unpack_from("<I", d, dex.off_proto + 12 * i + 8)[0]
            if po:
                tl_offs.add(po)
        for i in range(n_class):
            io = struct.unpack_from("<I", d, cls + 32 * i + 12)[0]
            if io:
                tl_offs.add(io)
        for old in sorted(tl_offs):
            size = struct.unpack_from("<I", d, old)[0]
            tl_map[old] = place(0x1001, d[old:old + 4 + size * 2], 4)

    # 2. debug_info items
    cdata_offs = [struct.unpack_from("<I", d, cls + 32 * i + 24)[0] for i in range(n_class)]
    parsed_cd = {co: parse_class_data(dex, co) for co in set(cdata_offs) if co}
    code_offs = sorted({m[2] for cd in parsed_cd.values()
                        for lst in (cd[2], cd[3]) for m in lst if m[2]})
    dbg_map = {}
    for co in code_offs:
        do = struct.unpack_from("<I", d, co + 8)[0]
        if do and do not in dbg_map:
            blob = emit_debug_remap(d, do, R) if R else d[do:do + debug_info_length(d, do)]
            dbg_map[do] = place(0x2003, blob)

    # 3. annotations tree
    ai_map, set_map, rl_map, dir_map = _emit_annotations(dex, place, R)

    # 4. code_items (debug_info_off fixed up; or replaced; refs remapped)
    code_map = {}
    for old in code_offs:
        if old in replacements:
            buf = bytearray(replacements[old])
        else:
            buf = bytearray(d[old:old + code_item_length(dex, old)])
            struct.pack_into("<I", buf, 8, dbg_map.get(struct.unpack_from("<I", buf, 8)[0], 0))
            if R:
                remap_code(buf, R)
        code_map[old] = place(0x2001, buf, 4)

    # 5. string_data (new sorted order; new strings MUTF-8 encoded)
    str_map = {}
    if R:
        orig_bytes = {}
        for i in range(dex.n_str):
            so = struct.unpack_from("<I", d, dex.off_str + 4 * i)[0]
            _, p = _uleb128(d, so)
            orig_bytes[dex.string(i)] = d[so:d.index(0, p) + 1]
        for i, s in enumerate(R.S):
            str_map[i] = place(0x2002, orig_bytes.get(s) or enc_mutf8(s))
    else:
        for i in range(n_str):
            so = struct.unpack_from("<I", d, dex.off_str + 4 * i)[0]
            _, p = _uleb128(d, so)
            str_map[i] = place(0x2002, d[so:d.index(0, p) + 1])

    # 6. static values (encoded_array; remapped if interning)
    sv_map = {}
    for i in range(n_class):
        so = struct.unpack_from("<I", d, cls + 32 * i + 28)[0]
        if so and so not in sv_map:
            blob = emit_encoded_array_remap(d, so, R)[0] if R else d[so:skip_encoded_array(d, so)]
            sv_map[so] = place(0x2005, blob)

    # 7. class_data (remapped field/method indices + new code offsets)
    cd_map = {}
    for old in sorted(parsed_cd):
        cd_map[old] = place(0x2000, emit_class_data(parsed_cd[old], code_map, R))

    # ---- leading index tables ----
    string_ids = b"".join(struct.pack("<I", str_map[i]) for i in range(n_str))
    if R:
        type_ids = b"".join(struct.pack("<I", R.spos[R.T[i]]) for i in range(n_type))
        proto_ids = bytearray()
        for ret, params in R.P:
            proto_ids += struct.pack("<III", R.spos[R._shorty(ret, params)],
                                     R.tpos[ret], make_tl(params))
        field_ids = bytearray()
        for c, name, t in R.F:
            field_ids += struct.pack("<HHI", R.tpos[c], R.tpos[t], R.spos[name])
        method_ids = bytearray()
        for c, name, ret, params in R.M:
            method_ids += struct.pack("<HHI", R.tpos[c], R.ppos[(ret, params)], R.spos[name])
    else:
        type_ids = d[dex.off_type:dex.off_type + n_type * 4]
        proto_ids = bytearray(d[dex.off_proto:dex.off_proto + n_proto * 12])
        for i in range(n_proto):
            po = struct.unpack_from("<I", proto_ids, 12 * i + 8)[0]
            if po:
                struct.pack_into("<I", proto_ids, 12 * i + 8, tl_map[po])
        field_ids = d[dex.off_field:dex.off_field + n_field * 8]
        method_ids = d[dex.off_method:dex.off_method + n_method * 8]
    class_defs = bytearray(d[cls:cls + n_class * 32])
    for i in range(n_class):
        b = 32 * i
        if R:
            struct.pack_into("<I", class_defs, b,
                             R.tr[struct.unpack_from("<I", class_defs, b)[0]])  # class
            su = struct.unpack_from("<I", class_defs, b + 8)[0]
            if su != 0xFFFFFFFF:
                struct.pack_into("<I", class_defs, b + 8, R.tr[su])             # superclass
            io = struct.unpack_from("<I", class_defs, b + 12)[0]
            struct.pack_into("<I", class_defs, b + 12, make_tl(iface_desc[i]) if io else 0)
            sf = struct.unpack_from("<I", class_defs, b + 16)[0]
            if sf != 0xFFFFFFFF:
                struct.pack_into("<I", class_defs, b + 16, R.sr[sf])            # source_file
        else:
            io = struct.unpack_from("<I", class_defs, b + 12)[0]
            struct.pack_into("<I", class_defs, b + 12, tl_map[io] if io else 0)
        ao = struct.unpack_from("<I", class_defs, b + 20)[0]
        struct.pack_into("<I", class_defs, b + 20, dir_map[ao] if ao else 0)
        co = struct.unpack_from("<I", class_defs, b + 24)[0]
        struct.pack_into("<I", class_defs, b + 24, cd_map[co] if co else 0)
        so = struct.unpack_from("<I", class_defs, b + 28)[0]
        struct.pack_into("<I", class_defs, b + 28, sv_map[so] if so else 0)

    # ---- map_list ----
    _align(data, 4)
    map_off = data_start + len(data)
    entries = [(0x0000, 1, 0), (0x0001, n_str, off_str), (0x0002, n_type, off_type),
               (0x0003, n_proto, off_proto), (0x0004, n_field, off_field),
               (0x0005, n_method, off_method), (0x0006, n_class, off_class)]
    for tc, offs in sections.items():
        entries.append((tc, len(offs), min(offs)))
    entries.append((0x1000, 1, map_off))
    entries.sort(key=lambda e: e[2])
    mp = bytearray(struct.pack("<I", len(entries)))
    for t, c, o in entries:
        mp += struct.pack("<HHII", t, 0, c, o)
    data.extend(mp)

    # ---- assemble ----
    out = bytearray(0x70)
    out += string_ids + type_ids + bytes(proto_ids) + field_ids + method_ids + bytes(class_defs)
    _align(out, 4)
    out += data
    total = len(out)

    struct.pack_into("<8s", out, 0, d[0:8])             # magic (copy version)
    struct.pack_into("<I", out, 0x20, total)            # file_size
    struct.pack_into("<I", out, 0x24, 0x70)             # header_size
    struct.pack_into("<I", out, 0x28, 0x12345678)       # endian
    struct.pack_into("<IIIIIIIIIIII", out, 0x38,
                     n_str, off_str, n_type, off_type, n_proto, off_proto,
                     n_field, off_field, n_method, off_method, n_class, off_class)
    struct.pack_into("<II", out, 0x68, total - data_start, data_start)
    struct.pack_into("<I", out, 0x34, map_off)
    import hashlib
    out[12:32] = hashlib.sha1(bytes(out[32:])).digest()
    struct.pack_into("<I", out, 8, zlib.adler32(bytes(out[12:])) & 0xFFFFFFFF)
    return bytes(out)

def _emit_annotations(dex, place, R=None):
    """Copy the annotation offset-tree with offset fixups. Returns 4 remaps."""
    d = dex.d
    dir_offs = {struct.unpack_from("<I", d, dex.off_class + 32 * i + 20)[0]
                for i in range(dex.n_class)}
    dir_offs.discard(0)
    dirs, set_offs, rl_offs = {}, set(), set()
    for do in dir_offs:
        ca, fs, ms, ps = struct.unpack_from("<IIII", d, do)
        p = do + 16
        fields, methods, params = [], [], []
        for _ in range(fs):
            fi, ao = struct.unpack_from("<II", d, p); p += 8
            fields.append((fi, ao)); set_offs.add(ao)
        for _ in range(ms):
            mi, ao = struct.unpack_from("<II", d, p); p += 8
            methods.append((mi, ao)); set_offs.add(ao)
        for _ in range(ps):
            mi, ao = struct.unpack_from("<II", d, p); p += 8
            params.append((mi, ao)); rl_offs.add(ao)
        if ca:
            set_offs.add(ca)
        dirs[do] = (ca, fields, methods, params)
    rls = {}
    for ro in rl_offs:
        size = struct.unpack_from("<I", d, ro)[0]
        items = [struct.unpack_from("<I", d, ro + 4 + 4 * k)[0] for k in range(size)]
        set_offs.update(s for s in items if s)
        rls[ro] = items
    set_offs.discard(0)
    sets, ai_offs = {}, set()
    for so in set_offs:
        size = struct.unpack_from("<I", d, so)[0]
        items = [struct.unpack_from("<I", d, so + 4 + 4 * k)[0] for k in range(size)]
        ai_offs.update(items)
        sets[so] = items
    ai_map = {}
    for ao in sorted(ai_offs):
        if R:
            body, _ = emit_encoded_annotation_remap(d, ao + 1, R)
            blob = bytes([d[ao]]) + body          # visibility byte + remapped annotation
        else:
            blob = d[ao:ao + annotation_item_length(d, ao)]
        ai_map[ao] = place(0x2004, blob)
    set_map = {}
    for so in sorted(sets):
        buf = bytearray(struct.pack("<I", len(sets[so])))
        for a in sets[so]:
            buf += struct.pack("<I", ai_map[a])
        set_map[so] = place(0x1003, buf, 4)
    rl_map = {}
    for ro in sorted(rls):
        buf = bytearray(struct.pack("<I", len(rls[ro])))
        for s in rls[ro]:
            buf += struct.pack("<I", set_map[s] if s else 0)
        rl_map[ro] = place(0x1002, buf, 4)
    dir_map = {}
    for do in sorted(dirs):
        ca, fields, methods, params = dirs[do]
        buf = bytearray(struct.pack("<IIII", set_map[ca] if ca else 0,
                                    len(fields), len(methods), len(params)))
        # directory entries must stay sorted by index; remap then re-sort
        fld = sorted((R.fr[fi] if R else fi, ao) for fi, ao in fields)
        mth = sorted((R.mr[mi] if R else mi, ao) for mi, ao in methods)
        par = sorted((R.mr[mi] if R else mi, ao) for mi, ao in params)
        for fi, ao in fld:
            buf += struct.pack("<II", fi, set_map[ao] if ao else 0)
        for mi, ao in mth:
            buf += struct.pack("<II", mi, set_map[ao] if ao else 0)
        for mi, ao in par:
            buf += struct.pack("<II", mi, rl_map[ao] if ao else 0)
        dir_map[do] = place(0x2006, buf, 4)
    return ai_map, set_map, rl_map, dir_map