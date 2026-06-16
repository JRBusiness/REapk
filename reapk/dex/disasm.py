import struct



_OPC_TABLE = """
00 nop 10x
01 move 12x
02 move/from16 22x
03 move/16 32x
04 move-wide 12x
05 move-wide/from16 22x
06 move-wide/16 32x
07 move-object 12x
08 move-object/from16 22x
09 move-object/16 32x
0a move-result 11x
0b move-result-wide 11x
0c move-result-object 11x
0d move-exception 11x
0e return-void 10x
0f return 11x
10 return-wide 11x
11 return-object 11x
12 const/4 11n
13 const/16 21s
14 const 31i
15 const/high16 21h
16 const-wide/16 21s
17 const-wide/32 31i
18 const-wide 51l
19 const-wide/high16 21h
1a const-string 21c string
1b const-string/jumbo 31c string
1c const-class 21c type
1d monitor-enter 11x
1e monitor-exit 11x
1f check-cast 21c type
20 instance-of 22c type
21 array-length 12x
22 new-instance 21c type
23 new-array 22c type
24 filled-new-array 35c type
25 filled-new-array/range 3rc type
26 fill-array-data 31t
27 throw 11x
28 goto 10t
29 goto/16 20t
2a goto/32 30t
2b packed-switch 31t
2c sparse-switch 31t
2d cmpl-float 23x
2e cmpg-float 23x
2f cmpl-double 23x
30 cmpg-double 23x
31 cmp-long 23x
32 if-eq 22t
33 if-ne 22t
34 if-lt 22t
35 if-ge 22t
36 if-gt 22t
37 if-le 22t
38 if-eqz 21t
39 if-nez 21t
3a if-ltz 21t
3b if-gez 21t
3c if-gtz 21t
3d if-lez 21t
44 aget 23x
45 aget-wide 23x
46 aget-object 23x
47 aget-boolean 23x
48 aget-byte 23x
49 aget-char 23x
4a aget-short 23x
4b aput 23x
4c aput-wide 23x
4d aput-object 23x
4e aput-boolean 23x
4f aput-byte 23x
50 aput-char 23x
51 aput-short 23x
52 iget 22c field
53 iget-wide 22c field
54 iget-object 22c field
55 iget-boolean 22c field
56 iget-byte 22c field
57 iget-char 22c field
58 iget-short 22c field
59 iput 22c field
5a iput-wide 22c field
5b iput-object 22c field
5c iput-boolean 22c field
5d iput-byte 22c field
5e iput-char 22c field
5f iput-short 22c field
60 sget 21c field
61 sget-wide 21c field
62 sget-object 21c field
63 sget-boolean 21c field
64 sget-byte 21c field
65 sget-char 21c field
66 sget-short 21c field
67 sput 21c field
68 sput-wide 21c field
69 sput-object 21c field
6a sput-boolean 21c field
6b sput-byte 21c field
6c sput-char 21c field
6d sput-short 21c field
6e invoke-virtual 35c method
6f invoke-super 35c method
70 invoke-direct 35c method
71 invoke-static 35c method
72 invoke-interface 35c method
74 invoke-virtual/range 3rc method
75 invoke-super/range 3rc method
76 invoke-direct/range 3rc method
77 invoke-static/range 3rc method
78 invoke-interface/range 3rc method
7b neg-int 12x
7c not-int 12x
7d neg-long 12x
7e not-long 12x
7f neg-float 12x
80 neg-double 12x
81 int-to-long 12x
82 int-to-float 12x
83 int-to-double 12x
84 long-to-int 12x
85 long-to-float 12x
86 long-to-double 12x
87 float-to-int 12x
88 float-to-long 12x
89 float-to-double 12x
8a double-to-int 12x
8b double-to-long 12x
8c double-to-float 12x
8d int-to-byte 12x
8e int-to-char 12x
8f int-to-short 12x
90 add-int 23x
91 sub-int 23x
92 mul-int 23x
93 div-int 23x
94 rem-int 23x
95 and-int 23x
96 or-int 23x
97 xor-int 23x
98 shl-int 23x
99 shr-int 23x
9a ushr-int 23x
9b add-long 23x
9c sub-long 23x
9d mul-long 23x
9e div-long 23x
9f rem-long 23x
a0 and-long 23x
a1 or-long 23x
a2 xor-long 23x
a3 shl-long 23x
a4 shr-long 23x
a5 ushr-long 23x
a6 add-float 23x
a7 sub-float 23x
a8 mul-float 23x
a9 div-float 23x
aa rem-float 23x
ab add-double 23x
ac sub-double 23x
ad mul-double 23x
ae div-double 23x
af rem-double 23x
b0 add-int/2addr 12x
b1 sub-int/2addr 12x
b2 mul-int/2addr 12x
b3 div-int/2addr 12x
b4 rem-int/2addr 12x
b5 and-int/2addr 12x
b6 or-int/2addr 12x
b7 xor-int/2addr 12x
b8 shl-int/2addr 12x
b9 shr-int/2addr 12x
ba ushr-int/2addr 12x
bb add-long/2addr 12x
bc sub-long/2addr 12x
bd mul-long/2addr 12x
be div-long/2addr 12x
bf rem-long/2addr 12x
c0 and-long/2addr 12x
c1 or-long/2addr 12x
c2 xor-long/2addr 12x
c3 shl-long/2addr 12x
c4 shr-long/2addr 12x
c5 ushr-long/2addr 12x
c6 add-float/2addr 12x
c7 sub-float/2addr 12x
c8 mul-float/2addr 12x
c9 div-float/2addr 12x
ca rem-float/2addr 12x
cb add-double/2addr 12x
cc sub-double/2addr 12x
cd mul-double/2addr 12x
ce div-double/2addr 12x
cf rem-double/2addr 12x
d0 add-int/lit16 22s
d1 rsub-int 22s
d2 mul-int/lit16 22s
d3 div-int/lit16 22s
d4 rem-int/lit16 22s
d5 and-int/lit16 22s
d6 or-int/lit16 22s
d7 xor-int/lit16 22s
d8 add-int/lit8 22b
d9 rsub-int/lit8 22b
da mul-int/lit8 22b
db div-int/lit8 22b
dc rem-int/lit8 22b
dd and-int/lit8 22b
de or-int/lit8 22b
df xor-int/lit8 22b
e0 shl-int/lit8 22b
e1 shr-int/lit8 22b
e2 ushr-int/lit8 22b
fa invoke-polymorphic 45cc method
fb invoke-polymorphic/range 4rcc method
fc invoke-custom 35c callsite
fd invoke-custom/range 3rc callsite
fe const-method-handle 21c mhandle
ff const-method-type 21c proto
"""

FMT_LEN = {"10x": 1, "12x": 1, "11n": 1, "11x": 1, "10t": 1, "20t": 2, "22x": 2,
           "21t": 2, "21s": 2, "21h": 2, "21c": 2, "23x": 2, "22b": 2, "22t": 2,
           "22s": 2, "22c": 2, "30t": 3, "32x": 3, "31i": 3, "31t": 3, "31c": 3,
           "35c": 3, "3rc": 3, "45cc": 4, "4rcc": 4, "51l": 5}

OPCODES = {}

for _l in _OPC_TABLE.strip().splitlines():
    _p = _l.split()
    OPCODES[int(_p[0], 16)] = (_p[1], _p[2], _p[3] if len(_p) > 3 else None)

def _sN(x, bits):
    return x - (1 << bits) if x >= (1 << (bits - 1)) else x

def _smali_str(s):
    out = ['"']
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)

def _unescape_str(s):
    out, i = [], 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n == "u":
                out.append(chr(int(s[i + 2:i + 6], 16)))
                i += 6
                continue
            out.append({"n": "\n", "t": "\t", "r": "\r"}.get(n, n))
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)

def _ref(dex, kind, idx):
    if kind == "string":
        return _smali_str(dex.string(idx))
    if kind == "type":
        return dex.type(idx)
    if kind == "field":
        c, n, t = dex.field_ref(idx)
        return "%s->%s:%s" % (c, n, t)
    if kind == "method":
        c, n, p = dex.method_ref(idx)
        return "%s->%s%s" % (c, n, p)
    if kind == "proto":
        return dex.proto_desc(idx)
    return "@%d" % idx

def decode_insn(dex, w, pos):
    """Return (length_in_code_units, smali_text) for the instruction at pos."""
    w0 = w[pos]
    op = w0 & 0xFF
    if op == 0x00 and (w0 >> 8):  # payload pseudo-op
        ident = w0 >> 8
        if ident == 0x01:
            size = w[pos + 1]
            return (size * 2 + 4, ".packed-switch-payload (%d targets)" % size)
        if ident == 0x02:
            size = w[pos + 1]
            return (size * 4 + 2, ".sparse-switch-payload (%d targets)" % size)
        if ident == 0x03:
            ew = w[pos + 1]
            sz = w[pos + 2] | (w[pos + 3] << 16)
            return (((sz * ew + 1) // 2) + 4, ".fill-array-data-payload")
        return (1, ".nop-data")

    ent = OPCODES.get(op)
    if not ent:
        return (1, "<unknown op 0x%02x>" % op)
    mn, fmt, ref = ent
    n = FMT_LEN[fmt]
    A, B = (w0 >> 8) & 0xF, (w0 >> 12) & 0xF
    AA = (w0 >> 8) & 0xFF
    w1 = w[pos + 1] if n > 1 else 0
    o = ""
    if fmt == "10x":
        o = ""
    elif fmt == "12x":
        o = "v%d, v%d" % (A, B)
    elif fmt == "11n":
        o = "v%d, #%d" % (A, _sN(B, 4))
    elif fmt == "11x":
        o = "v%d" % AA
    elif fmt == "10t":
        o = "%+d" % _sN(AA, 8)
    elif fmt == "20t":
        o = "%+d" % _sN(w1, 16)
    elif fmt == "22x":
        o = "v%d, v%d" % (AA, w1)
    elif fmt == "21t":
        o = "v%d, %+d" % (AA, _sN(w1, 16))
    elif fmt == "21s":
        o = "v%d, #%d" % (AA, _sN(w1, 16))
    elif fmt == "21h":
        sh = 16 if op == 0x15 else 48
        o = "v%d, #%d" % (AA, _sN(w1, 16) << sh)
    elif fmt == "21c":
        o = "v%d, %s" % (AA, _ref(dex, ref, w1))
    elif fmt == "23x":
        o = "v%d, v%d, v%d" % (AA, w1 & 0xFF, (w1 >> 8) & 0xFF)
    elif fmt == "22b":
        o = "v%d, v%d, #%d" % (AA, w1 & 0xFF, _sN((w1 >> 8) & 0xFF, 8))
    elif fmt == "22t":
        o = "v%d, v%d, %+d" % (A, B, _sN(w1, 16))
    elif fmt == "22s":
        o = "v%d, v%d, #%d" % (A, B, _sN(w1, 16))
    elif fmt == "22c":
        o = "v%d, v%d, %s" % (A, B, _ref(dex, ref, w1))
    elif fmt == "30t":
        o = "%+d" % _sN(w1 | (w[pos + 2] << 16), 32)
    elif fmt == "32x":
        o = "v%d, v%d" % (w1, w[pos + 2])
    elif fmt == "31i":
        o = "v%d, #%d" % (AA, _sN(w1 | (w[pos + 2] << 16), 32))
    elif fmt == "31t":
        o = "v%d, %+d" % (AA, _sN(w1 | (w[pos + 2] << 16), 32))
    elif fmt == "31c":
        o = "v%d, %s" % (AA, _ref(dex, ref, w1 | (w[pos + 2] << 16)))
    elif fmt in ("35c", "45cc"):
        cnt = (w0 >> 12) & 0xF
        g = (w0 >> 8) & 0xF
        w2 = w[pos + 2]
        regs = [w2 & 0xF, (w2 >> 4) & 0xF, (w2 >> 8) & 0xF, (w2 >> 12) & 0xF, g][:cnt]
        o = "{%s}, %s" % (", ".join("v%d" % r for r in regs), _ref(dex, ref, w1))
        if fmt == "45cc":
            o += ", %s" % dex.proto_desc(w[pos + 3])
    elif fmt in ("3rc", "4rcc"):
        start = w[pos + 2]
        o = "{v%d..v%d}, %s" % (start, start + AA - 1, _ref(dex, ref, w1))
        if fmt == "4rcc":
            o += ", %s" % dex.proto_desc(w[pos + 3])
    elif fmt == "51l":
        lo = w1 | (w[pos + 2] << 16)
        hi = w[pos + 3] | (w[pos + 4] << 16)
        o = "v%d, #%d" % (AA, _sN(lo | (hi << 32), 64))
    return (n, ("%s %s" % (mn, o)).strip())

def disassemble(dex, code_off):
    ci = dex.code_insns(code_off)
    words = [struct.unpack_from("<H", dex.d, ci["insns_off"] + 2 * i)[0]
             for i in range(ci["insns_size"])]
    out, pos = [], 0
    while pos < len(words):
        n, text = decode_insn(dex, words, pos)
        out.append("    %04x: %s" % (pos, text))
        pos += max(n, 1)
    return ci, out

def insn_length(words, pos):
    w0 = words[pos]
    op = w0 & 0xFF
    if op == 0x00 and (w0 >> 8):
        ident = w0 >> 8
        if ident == 0x01:
            return words[pos + 1] * 2 + 4
        if ident == 0x02:
            return words[pos + 1] * 4 + 2
        if ident == 0x03:
            return ((words[pos + 1] * (words[pos + 2] | (words[pos + 3] << 16)) + 1) // 2) + 4
        return 1
    ent = OPCODES.get(op)
    return FMT_LEN[ent[1]] if ent else 1
