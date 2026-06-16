def _u16key(s):
    # UTF-16-BE bytes compared lexicographically == UTF-16 code-unit order.
    return s.encode("utf-16-be", "surrogatepass")

class PoolModel:
    def __init__(self, dex):
        self.strings = [dex.string(i) for i in range(dex.n_str)]
        self.types = [dex.type(i) for i in range(dex.n_type)]
        self.protos = [dex.proto_parts(i) for i in range(dex.n_proto)]   # (ret, params)
        self.fields = [dex.field_ref(i) for i in range(dex.n_field)]     # (cls, name, type)
        self.methods = [dex.method_full(i) for i in range(dex.n_method)]  # (cls, name, ret, params)

    # canonical sort keys (all reduce to UTF-16 code-unit comparison)
    def k_str(self, s):
        return _u16key(s)

    def k_type(self, t):
        return _u16key(t)

    def k_proto(self, p):
        return (_u16key(p[0]), tuple(_u16key(x) for x in p[1]))

    def k_field(self, f):
        return (_u16key(f[0]), _u16key(f[1]), _u16key(f[2]))

    def k_method(self, m):
        return (_u16key(m[0]), _u16key(m[1]), _u16key(m[2]), tuple(_u16key(x) for x in m[3]))

    def check_canonical(self):
        """True per pool iff our sort reproduces the DEX's original order."""
        return {
            "strings": self.strings == sorted(self.strings, key=self.k_str),
            "types": self.types == sorted(self.types, key=self.k_type),
            "protos": self.protos == sorted(self.protos, key=self.k_proto),
            "fields": self.fields == sorted(self.fields, key=self.k_field),
            "methods": self.methods == sorted(self.methods, key=self.k_method),
        }

    def intern_strings(self, new):
        """Add new strings, re-sort, return (sorted_list, old_index->new_index)."""
        old = list(self.strings)
        merged = sorted(set(old) | set(new), key=self.k_str)
        pos = {s: i for i, s in enumerate(merged)}
        remap = {i: pos[s] for i, s in enumerate(old)}
        return merged, remap, {s: pos[s] for s in new}

class Interner:
    """Adds new entries to every DEX pool and computes the 5 index remaps.

    Adding any entry transitively interns its dependencies (a method pulls in its
    class type, name string and proto; a proto pulls in its types and shorty).
    finalize() re-sorts each pool canonically and builds old->new index maps.
    """

    def __init__(self, dex):
        self.dex = dex
        self.o_strings = [dex.string(i) for i in range(dex.n_str)]
        self.o_types = [dex.type(i) for i in range(dex.n_type)]
        self.o_protos = [(p[0], tuple(p[1]))
                         for p in (dex.proto_parts(i) for i in range(dex.n_proto))]
        self.o_fields = [dex.field_ref(i) for i in range(dex.n_field)]
        self.o_methods = [(m[0], m[1], m[2], tuple(m[3]))
                          for m in (dex.method_full(i) for i in range(dex.n_method))]
        self._st = set(self.o_strings)
        self._ty = set(self.o_types)
        self._pr = set(self.o_protos)
        self._fl = set(self.o_fields)
        self._me = set(self.o_methods)
        self.ns, self.nt, self.np, self.nf, self.nm = set(), set(), set(), set(), set()

    @staticmethod
    def _sh1(de):
        return "L" if de[0] in "L[" else de[0]

    def _shorty(self, ret, params):
        return self._sh1(ret) + "".join(self._sh1(p) for p in params)

    def add_string(self, s):
        if s not in self._st:
            self.ns.add(s)
        return self

    def add_type(self, t):
        self.add_string(t)
        if t not in self._ty:
            self.nt.add(t)
        return self

    def add_proto(self, ret, params):
        params = tuple(params)
        self.add_type(ret)
        for p in params:
            self.add_type(p)
        self.add_string(self._shorty(ret, params))
        if (ret, params) not in self._pr:
            self.np.add((ret, params))
        return self

    def add_field(self, cls, name, typ):
        self.add_type(cls)
        self.add_type(typ)
        self.add_string(name)
        if (cls, name, typ) not in self._fl:
            self.nf.add((cls, name, typ))
        return self

    def add_method(self, cls, name, ret, params):
        params = tuple(params)
        self.add_type(cls)
        self.add_string(name)
        self.add_proto(ret, params)
        if (cls, name, ret, params) not in self._me:
            self.nm.add((cls, name, ret, params))
        return self

    def finalize(self):
        self.S = sorted(self._st | self.ns, key=_u16key)
        self.spos = {s: i for i, s in enumerate(self.S)}
        self.sr = {i: self.spos[s] for i, s in enumerate(self.o_strings)}
        self.T = sorted(self._ty | self.nt, key=_u16key)
        self.tpos = {t: i for i, t in enumerate(self.T)}
        self.tr = {i: self.tpos[t] for i, t in enumerate(self.o_types)}
        self.P = sorted(self._pr | self.np,
                        key=lambda rp: (_u16key(rp[0]), tuple(_u16key(x) for x in rp[1])))
        self.ppos = {rp: i for i, rp in enumerate(self.P)}
        self.pr = {i: self.ppos[rp] for i, rp in enumerate(self.o_protos)}
        self.F = sorted(self._fl | self.nf,
                        key=lambda f: (_u16key(f[0]), _u16key(f[1]), _u16key(f[2])))
        self.fpos = {f: i for i, f in enumerate(self.F)}
        self.fr = {i: self.fpos[f] for i, f in enumerate(self.o_fields)}
        self.M = sorted(self._me | self.nm,
                        key=lambda m: (_u16key(m[0]), _u16key(m[1]), _u16key(m[2]),
                                       tuple(_u16key(x) for x in m[3])))
        self.mpos = {m: i for i, m in enumerate(self.M)}
        self.mr = {i: self.mpos[m] for i, m in enumerate(self.o_methods)}
        return self
