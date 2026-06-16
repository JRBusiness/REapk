import struct
from ..errors import DexError
import zlib

from ._leb import _mutf8, _uleb128


ACC = [(0x1, "public"), (0x2, "private"), (0x4, "protected"), (0x8, "static"),
       (0x10, "final"), (0x100, "native"), (0x200, "interface"),
       (0x400, "abstract"), (0x1000, "synthetic")]

def _acc_str(flags):
    return " ".join(n for bit, n in ACC if flags & bit)

def _desc_to_java(d):
    """Lst;-style descriptor -> dotted Java name."""
    arr = ""
    while d.startswith("["):
        arr += "[]"
        d = d[1:]
    prim = {"V": "void", "Z": "boolean", "B": "byte", "S": "short", "C": "char",
            "I": "int", "J": "long", "F": "float", "D": "double"}
    if d in prim:
        return prim[d] + arr
    if d.startswith("L") and d.endswith(";"):
        return d[1:-1].replace("/", ".") + arr
    return d + arr

class DexFile:
    def __init__(self, data):
        if data[:4] != b"dex\n":
            raise ValueError("not a DEX file")
        self.d = data
        h = struct.unpack_from("<14I", data, 0x38)
        (self.n_str, self.off_str, self.n_type, self.off_type,
         self.n_proto, self.off_proto, self.n_field, self.off_field,
         self.n_method, self.off_method, self.n_class, self.off_class,
         _ds, _do) = h
        self._scache = {}

    def string(self, i):
        if i in self._scache:
            return self._scache[i]
        off = struct.unpack_from("<I", self.d, self.off_str + 4 * i)[0]
        _, off = _uleb128(self.d, off)           # utf16 length (unused)
        end = self.d.index(0, off)
        s = _mutf8(self.d[off:end])
        self._scache[i] = s
        return s

    def type(self, i):
        return self.string(struct.unpack_from("<I", self.d, self.off_type + 4 * i)[0])

    def proto_desc(self, i):
        base = self.off_proto + 12 * i
        ret_idx, params_off = struct.unpack_from("<II", self.d, base + 4)
        params = ""
        if params_off:
            n = struct.unpack_from("<I", self.d, params_off)[0]
            for k in range(n):
                t = struct.unpack_from("<H", self.d, params_off + 4 + 2 * k)[0]
                params += self.type(t)
        return "(%s)%s" % (params, self.type(ret_idx))

    def method_ref(self, i):
        base = self.off_method + 8 * i
        class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", self.d, base)
        return self.type(class_idx), self.string(name_idx), self.proto_desc(proto_idx)

    def field_ref(self, i):
        base = self.off_field + 8 * i
        class_idx, type_idx, name_idx = struct.unpack_from("<HHI", self.d, base)
        return self.type(class_idx), self.string(name_idx), self.type(type_idx)

    def proto_parts(self, i):
        base = self.off_proto + 12 * i
        ret_idx, params_off = struct.unpack_from("<II", self.d, base + 4)
        params = []
        if params_off:
            n = struct.unpack_from("<I", self.d, params_off)[0]
            for k in range(n):
                t = struct.unpack_from("<H", self.d, params_off + 4 + 2 * k)[0]
                params.append(self.type(t))
        return self.type(ret_idx), tuple(params)

    def method_full(self, i):
        base = self.off_method + 8 * i
        class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", self.d, base)
        ret, params = self.proto_parts(proto_idx)
        return self.type(class_idx), self.string(name_idx), ret, params

    def classes(self):
        for i in range(self.n_class):
            base = self.off_class + 32 * i
            class_idx, access, _super, _ifc, _src, _anno, cdata_off, _sv = \
                struct.unpack_from("<8I", self.d, base)
            yield {"name": self.type(class_idx), "access": access, "cdata": cdata_off}

    def class_methods(self, cdata_off):
        if not cdata_off:
            return []
        off = cdata_off
        sf, off = _uleb128(self.d, off)
        inf, off = _uleb128(self.d, off)
        dm, off = _uleb128(self.d, off)
        vm, off = _uleb128(self.d, off)
        # skip encoded_fields (static + instance)
        for _ in range(sf + inf):
            _, off = _uleb128(self.d, off)       # field_idx_diff
            _, off = _uleb128(self.d, off)       # access_flags
        methods = []
        for count in (dm, vm):
            midx = 0
            for _ in range(count):
                diff, off = _uleb128(self.d, off)
                acc, off = _uleb128(self.d, off)
                code_off, off = _uleb128(self.d, off)
                midx += diff
                _, name, proto = self.method_ref(midx)
                methods.append({"name": name, "proto": proto,
                                "access": acc, "code_off": code_off})
        return methods

    def all_strings(self):
        return (self.string(i) for i in range(self.n_str))

    def find_method(self, class_desc, mname):
        for c in self.classes():
            if c["name"] != class_desc:
                continue
            for m in self.class_methods(c["cdata"]):
                if m["name"] == mname and m["code_off"]:
                    return m
        return None

    def code_insns(self, code_off):
        regs, ins, outs, tries, _dbg, insz = struct.unpack_from("<HHHHII", self.d, code_off)
        return {"regs": regs, "ins": ins, "insns_size": insz, "insns_off": code_off + 16}

    def patch_return(self, code_off, ret_desc, value):
        """Overwrite a method body with a forced return (in place, nop-padded)."""
        ci = self.code_insns(code_off)
        words = build_return_insns(ret_desc, value, ci["regs"])
        if len(words) > ci["insns_size"]:
            raise DexError("method body too small to patch (%d > %d words)"
                             % (len(words), ci["insns_size"]))
        b = bytearray(self.d)
        for i in range(ci["insns_size"]):
            w = words[i] if i < len(words) else 0x0000  # pad with nop
            struct.pack_into("<H", b, ci["insns_off"] + 2 * i, w)
        self.d = bytes(b)

    def finalize(self):
        """Recompute DEX signature (SHA-1) + checksum (Adler-32) after edits."""
        import hashlib
        b = bytearray(self.d)
        b[12:32] = hashlib.sha1(bytes(b[32:])).digest()
        struct.pack_into("<I", b, 8, zlib.adler32(bytes(b[12:])) & 0xFFFFFFFF)
        self.d = bytes(b)
        return self.d

def build_return_insns(ret_desc, value, regs):
    """Dalvik bytecode for a forced return. value in {true,false,null,void}."""
    if ret_desc == "V" or value == "void":
        return [0x000E]                                   # return-void
    is_obj = ret_desc.startswith("L") or ret_desc.startswith("[")
    if regs < 1:
        raise DexError("method has no registers; cannot synthesize a value return")
    if is_obj or value == "null":
        return [0x0012, 0x0011]                           # const/4 v0,#0 ; return-object v0
    lit = 1 if value == "true" else 0
    return [(lit << 12) | 0x12, 0x000F]