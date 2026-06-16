import struct
from ..errors import AssembleError
import re

from .disasm import FMT_LEN, OPCODES, _unescape_str, insn_length
from .pool import Interner


MNEMONIC = {mn: (op, fmt, ref) for op, (mn, fmt, ref) in OPCODES.items()}

class AsmSkip(AssembleError):
    pass

def _parse_types(s):
    out, i = [], 0
    while i < len(s):
        st = i
        while s[i] == "[":
            i += 1
        i = s.index(";", i) + 1 if s[i] == "L" else i + 1
        out.append(s[st:i])
    return out

def _parse_proto(s):
    j = s.index(")")
    return s[j + 1:], _parse_types(s[s.index("(") + 1:j])

class Assembler:
    def __init__(self, dex, interner=None, collecting=False):
        self.dex = dex
        self.interner = interner       # resolve refs against final interned indices
        self.collecting = collecting   # first pass: add unknown refs to the interner
        self._s = self._t = self._f = self._m = self._p = None

    def str_idx(self, s):
        if self._s is None:
            self._s = {self.dex.string(i): i for i in range(self.dex.n_str)}
        return self._s.get(s)

    def type_idx(self, d):
        if self._t is None:
            self._t = {self.dex.type(i): i for i in range(self.dex.n_type)}
        return self._t.get(d)

    def field_idx(self, c, n, t):
        if self._f is None:
            self._f = {self.dex.field_ref(i): i for i in range(self.dex.n_field)}
        return self._f.get((c, n, t))

    def method_idx(self, c, n, p):
        if self._m is None:
            self._m = {self.dex.method_ref(i): i for i in range(self.dex.n_method)}
        return self._m.get((c, n, p))

    def proto_idx(self, d):
        if self._p is None:
            self._p = {self.dex.proto_desc(i): i for i in range(self.dex.n_proto)}
        return self._p.get(d)

def _refidx(asm, kind, s):
    s = s.strip()
    it = asm.interner
    if it is not None:
        if kind == "string":
            v = _unescape_str(s[1:-1])
            return (it.add_string(v) and 0) or 0 if asm.collecting else it.spos[v]
        if kind == "type":
            return (it.add_type(s) and 0) or 0 if asm.collecting else it.tpos[s]
        if kind == "field":
            m = re.match(r"(L[^;]+;)->([^:]+):(.+)", s)
            c, n, t = m.group(1), m.group(2), m.group(3)
            return (it.add_field(c, n, t) and 0) or 0 if asm.collecting else it.fpos[(c, n, t)]
        if kind == "method":
            m = re.match(r"(L[^;]+;)->([^(]+)(\(.*)", s)
            c, n, ret_p = m.group(1), m.group(2), m.group(3)
            ret, params = _parse_proto(ret_p)
            if asm.collecting:
                it.add_method(c, n, ret, params)
                return 0
            return it.mpos[(c, n, ret, tuple(params))]
        if kind == "proto":
            ret, params = _parse_proto(s)
            if asm.collecting:
                it.add_proto(ret, params)
                return 0
            return it.ppos[(ret, tuple(params))]
    idx = None
    if kind == "string":
        idx = asm.str_idx(_unescape_str(s[1:-1]))
    elif kind == "type":
        idx = asm.type_idx(s)
    elif kind == "field":
        m = re.match(r"(L[^;]+;)->([^:]+):(.+)", s)
        if m:
            idx = asm.field_idx(m.group(1), m.group(2), m.group(3))
    elif kind == "method":
        m = re.match(r"(L[^;]+;)->([^(]+)(\(.*)", s)
        if m:
            idx = asm.method_idx(m.group(1), m.group(2), m.group(3))
    elif kind == "proto":
        idx = asm.proto_idx(s)
    if idx is None:
        raise AsmSkip("ref not in pool: %s" % s)
    return idx

def assemble_interned(dex, lines):
    """Assemble smali, auto-interning any refs not already in the dex pools."""
    it = Interner(dex)
    assemble(Assembler(dex, interner=it, collecting=True), lines)  # collect new refs
    it.finalize()
    return it, assemble(Assembler(dex, interner=it), lines)

def encode_insn(asm, mn, ops, off, labels):
    op, fmt, ref = MNEMONIC[mn]

    def br(t):
        t = t.strip()
        return (labels[t] - off) if t.startswith(":") else int(t, 0)

    def regs(s):
        return [int(x) for x in re.findall(r"v(\d+)", s)]

    w = [op] + [0] * (FMT_LEN[fmt] - 1)
    if fmt == "10x":
        pass
    elif fmt == "12x":
        a, b = regs(ops)
        w[0] |= (a << 8) | (b << 12)
    elif fmt == "11n":
        m = re.match(r"v(\d+),\s*#(-?\w+)", ops)
        w[0] |= (int(m.group(1)) << 8) | ((int(m.group(2), 0) & 0xF) << 12)
    elif fmt == "11x":
        w[0] |= regs(ops)[0] << 8
    elif fmt == "10t":
        w[0] |= (br(ops) & 0xFF) << 8
    elif fmt == "20t":
        w[1] = br(ops) & 0xFFFF
    elif fmt == "22x":
        a, b = regs(ops)
        w[0] |= a << 8
        w[1] = b
    elif fmt == "21t":
        m = re.match(r"v(\d+),\s*(.+)", ops)
        w[0] |= int(m.group(1)) << 8
        w[1] = br(m.group(2)) & 0xFFFF
    elif fmt == "21s":
        m = re.match(r"v(\d+),\s*#(-?\w+)", ops)
        w[0] |= int(m.group(1)) << 8
        w[1] = int(m.group(2), 0) & 0xFFFF
    elif fmt == "21h":
        m = re.match(r"v(\d+),\s*#(-?\w+)", ops)
        sh = 16 if op == 0x15 else 48
        w[0] |= int(m.group(1)) << 8
        w[1] = (int(m.group(2), 0) >> sh) & 0xFFFF
    elif fmt == "21c":
        m = re.match(r"v(\d+),\s*(.+)", ops)
        w[0] |= int(m.group(1)) << 8
        w[1] = _refidx(asm, ref, m.group(2))
    elif fmt == "23x":
        a, b, c = regs(ops)
        w[0] |= a << 8
        w[1] = b | (c << 8)
    elif fmt == "22b":
        m = re.match(r"v(\d+),\s*v(\d+),\s*#(-?\w+)", ops)
        w[0] |= int(m.group(1)) << 8
        w[1] = (int(m.group(2)) & 0xFF) | ((int(m.group(3), 0) & 0xFF) << 8)
    elif fmt == "22t":
        m = re.match(r"v(\d+),\s*v(\d+),\s*(.+)", ops)
        w[0] |= (int(m.group(1)) << 8) | (int(m.group(2)) << 12)
        w[1] = br(m.group(3)) & 0xFFFF
    elif fmt == "22s":
        m = re.match(r"v(\d+),\s*v(\d+),\s*#(-?\w+)", ops)
        w[0] |= (int(m.group(1)) << 8) | (int(m.group(2)) << 12)
        w[1] = int(m.group(3), 0) & 0xFFFF
    elif fmt == "22c":
        m = re.match(r"v(\d+),\s*v(\d+),\s*(.+)", ops)
        w[0] |= (int(m.group(1)) << 8) | (int(m.group(2)) << 12)
        w[1] = _refidx(asm, ref, m.group(3))
    elif fmt == "30t":
        t = br(ops) & 0xFFFFFFFF
        w[1], w[2] = t & 0xFFFF, (t >> 16) & 0xFFFF
    elif fmt == "32x":
        a, b = regs(ops)
        w[1], w[2] = a, b
    elif fmt in ("31i", "31t"):
        m = re.match(r"v(\d+),\s*(.+)", ops)
        w[0] |= int(m.group(1)) << 8
        val = (br(m.group(2)) if fmt == "31t"
               else int(m.group(2).lstrip("#"), 0)) & 0xFFFFFFFF
        w[1], w[2] = val & 0xFFFF, (val >> 16) & 0xFFFF
    elif fmt == "31c":
        m = re.match(r"v(\d+),\s*(.+)", ops)
        w[0] |= int(m.group(1)) << 8
        idx = _refidx(asm, ref, m.group(2))
        w[1], w[2] = idx & 0xFFFF, (idx >> 16) & 0xFFFF
    elif fmt == "35c":
        m = re.match(r"\{([^}]*)\},\s*(.+)", ops)
        rg = regs(m.group(1))
        idx = _refidx(asm, ref, m.group(2))
        cnt = len(rg)
        g = rg[4] if cnt == 5 else 0
        w[0] |= (g << 8) | (cnt << 12)
        w[1] = idx
        cr = (rg + [0, 0, 0, 0])[:4]
        w[2] = cr[0] | (cr[1] << 4) | (cr[2] << 8) | (cr[3] << 12)
    elif fmt == "3rc":
        m = re.match(r"\{v(\d+)\.\.v(\d+)\},\s*(.+)", ops)
        start, end = int(m.group(1)), int(m.group(2))
        w[0] |= (end - start + 1) << 8
        w[1] = _refidx(asm, ref, m.group(3))
        w[2] = start
    elif fmt == "51l":
        m = re.match(r"v(\d+),\s*#(-?\w+)", ops)
        w[0] |= int(m.group(1)) << 8
        val = int(m.group(2), 0) & 0xFFFFFFFFFFFFFFFF
        w[1], w[2] = val & 0xFFFF, (val >> 16) & 0xFFFF
        w[3], w[4] = (val >> 32) & 0xFFFF, (val >> 48) & 0xFFFF
    else:
        raise AsmSkip("format %s unsupported" % fmt)
    return [x & 0xFFFF for x in w]

def assemble(asm, lines):
    body, labels, off = [], {}, 0
    for ln in lines:
        s = ln.strip()
        mm = re.match(r"^[0-9a-fA-F]{4}:\s*(.*)", s)
        if mm:
            s = mm.group(1)
        if not s or s[0] in ".#":
            continue
        if s.startswith(":"):
            labels[s] = off
            continue
        sp = s.split(None, 1)
        mn = sp[0]
        if mn not in MNEMONIC:
            raise AsmSkip("unknown mnemonic %s" % mn)
        body.append((off, mn, sp[1] if len(sp) > 1 else ""))
        off += FMT_LEN[MNEMONIC[mn][1]]
    words = []
    for o, mn, ops in body:
        words += encode_insn(asm, mn, ops, o, labels)
    return words

def compute_outs(words):
    outs, pos = 0, 0
    while pos < len(words):
        op = words[pos] & 0xFF
        ent = OPCODES.get(op)
        if ent and ent[1] in ("35c", "45cc"):
            outs = max(outs, (words[pos] >> 12) & 0xF)
        elif ent and ent[1] in ("3rc", "4rcc"):
            outs = max(outs, (words[pos] >> 8) & 0xFF)
        pos += max(insn_length(words, pos), 1)
    return outs

def build_code_item(regs, ins, outs, words):
    body = b"".join(struct.pack("<H", w) for w in words)
    return struct.pack("<HHHHII", regs, ins, outs, 0, 0, len(words)) + body
