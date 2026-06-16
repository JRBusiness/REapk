import struct



def _mutf8(b):
    """Decode Modified UTF-8 (Dalvik string encoding) without lossy collapse."""
    units, i, n = [], 0, len(b)
    while i < n:
        c = b[i]
        if c < 0x80:
            units.append(c); i += 1
        elif (c & 0xE0) == 0xC0 and i + 1 < n:
            units.append(((c & 0x1F) << 6) | (b[i + 1] & 0x3F)); i += 2
        elif (c & 0xF0) == 0xE0 and i + 2 < n:
            units.append(((c & 0x0F) << 12) | ((b[i + 1] & 0x3F) << 6) | (b[i + 2] & 0x3F)); i += 3
        else:
            units.append(0xFFFD); i += 1
    return b"".join(struct.pack("<H", u & 0xFFFF) for u in units).decode("utf-16-le", "surrogatepass")

def _uleb128(data, off):
    result = shift = 0
    while True:
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, off
        shift += 7

def enc_uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | 0x80 if n else b)
        if not n:
            return bytes(out)

def _sleb128(d, p):
    result = shift = 0
    while True:
        b = d[p]
        p += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            if b & 0x40:
                result |= -(1 << shift)
            return result, p

def enc_sleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if (n == 0 and not (b & 0x40)) or (n == -1 and (b & 0x40)):
            out.append(b)
            return bytes(out)
        out.append(b | 0x80)

def enc_mutf8(s):
    u16 = s.encode("utf-16-be", "surrogatepass")
    cu = [(u16[i] << 8) | u16[i + 1] for i in range(0, len(u16), 2)]
    b = bytearray()
    for u in cu:
        if u == 0:
            b += b"\xc0\x80"
        elif u < 0x80:
            b.append(u)
        elif u < 0x800:
            b += bytes([0xC0 | (u >> 6), 0x80 | (u & 0x3F)])
        else:
            b += bytes([0xE0 | (u >> 12), 0x80 | ((u >> 6) & 0x3F), 0x80 | (u & 0x3F)])
    return enc_uleb(len(cu)) + bytes(b) + b"\x00"
