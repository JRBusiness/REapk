import struct
from .errors import ZipError
import zlib


def read_zip_entries(data):
    """Parse a zip's central directory; copy each entry's raw bytes verbatim."""
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0:
        raise ZipError("not a zip")
    total = struct.unpack_from("<H", data, eocd + 10)[0]
    off = struct.unpack_from("<I", data, eocd + 16)[0]
    entries = []
    for _ in range(total):
        if data[off:off + 4] != b"PK\x01\x02":
            break
        flags, method, mtime, mdate = struct.unpack_from("<HHHH", data, off + 8)
        crc, csize, usize = struct.unpack_from("<III", data, off + 16)
        nlen, elen, clen = struct.unpack_from("<HHH", data, off + 28)
        lho = struct.unpack_from("<I", data, off + 42)[0]
        name = data[off + 46:off + 46 + nlen]
        lnlen, lelen = struct.unpack_from("<HH", data, lho + 26)
        dstart = lho + 30 + lnlen + lelen
        entries.append({"name": name, "method": method, "flags": flags,
                        "mtime": mtime, "mdate": mdate, "crc": crc,
                        "csize": csize, "usize": usize,
                        "raw": data[dstart:dstart + csize]})
        off += 46 + nlen + elen + clen
    return entries

def write_aligned_zip(entries):
    out = bytearray()
    records = []
    for e in entries:
        name = e["name"]
        if e["method"] == 0:  # stored -> must be aligned
            align = 4096 if name.endswith(b".so") else 4
        else:
            align = 1
        lho = len(out)
        data_off = lho + 30 + len(name)
        pad = (align - (data_off % align)) % align
        flags = e["flags"] & ~0x08  # no data-descriptor; sizes are in the header
        out += struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, flags, e["method"],
                           e["mtime"], e["mdate"], e["crc"], e["csize"],
                           e["usize"], len(name), pad)
        out += name + b"\x00" * pad + e["raw"]
        records.append((e, lho))
    cd_off = len(out)
    for e, lho in records:
        name = e["name"]
        out += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20,
                           e["flags"] & ~0x08, e["method"], e["mtime"], e["mdate"],
                           e["crc"], e["csize"], e["usize"], len(name),
                           0, 0, 0, 0, 0, lho)
        out += name
    cd_size = len(out) - cd_off
    out += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(records), len(records),
                       cd_size, cd_off, 0)
    return bytes(out)

def stored_entry(name, data):
    return {"name": name if isinstance(name, bytes) else name.encode(), "method": 0,
            "flags": 0, "mtime": 0, "mdate": 0x21, "crc": zlib.crc32(data) & 0xFFFFFFFF,
            "csize": len(data), "usize": len(data), "raw": data}