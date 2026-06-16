__all__ = ["hexdump", "show_smali", "dump_dex"]


def hexdump(data, start=0, length=None, width=16):
    """Return a classic offset / hex / ASCII hexdump string."""
    end = len(data) if length is None else start + length
    rows = []
    for base in range(start, end, width):
        chunk = data[base:min(base + width, end)]
        hexs = " ".join("%02x" % b for b in chunk).ljust(width * 3 - 1)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append("%08x  %s  %s" % (base, hexs, text))
    return "\n".join(rows)


def show_smali(lines):
    """Join disassembler output lines into a single printable block."""
    return "\n".join(lines)


_ACCESS_FLAGS = [
    (0x1, "public"), (0x2, "private"), (0x4, "protected"), (0x8, "static"),
    (0x10, "final"), (0x20, "synchronized"), (0x40, "bridge"),
    (0x80, "varargs"), (0x100, "native"), (0x400, "abstract"),
    (0x1000, "synthetic"),
]


def _flags(access):
    return " ".join(name for bit, name in _ACCESS_FLAGS if access & bit)


def dump_dex(dex, max_classes=None, max_methods_per_class=None):
    """Render a DEX as an organized smali listing: class -> methods -> bytecode.

    Walks every class and its methods, disassembling each method body. Pass
    ``max_classes`` / ``max_methods_per_class`` to cap the output on large real
    APKs (a truncation note is printed for anything elided). Returns a string.

    This is a *disassembly* (smali), not Java decompilation.
    """
    from .dex import disassemble

    out = []
    classes = list(dex.classes())
    shown = classes if max_classes is None else classes[:max_classes]
    for c in shown:
        header = ".class %s %s" % (_flags(c["access"]), c["name"])
        out.append(header.replace("  ", " ").rstrip())
        methods = dex.class_methods(c["cdata"])
        ms = methods if max_methods_per_class is None else methods[:max_methods_per_class]
        for m in ms:
            decl = "    .method %s %s%s" % (_flags(m["access"]), m["name"], m["proto"])
            out.append(decl.replace("  ", " "))
            if m["code_off"]:
                _ci, smali = disassemble(dex, m["code_off"])
                out.extend("    " + line for line in smali)
            else:
                out.append("        # no code (abstract/native)")
            out.append("    .end method")
        elided = len(methods) - len(ms)
        if elided:
            out.append("    # ... %d more method(s)" % elided)
        out.append("")
    elided_c = len(classes) - len(shown)
    if elided_c:
        out.append("# ... %d more class(es)" % elided_c)
    return "\n".join(out).rstrip() + "\n"
