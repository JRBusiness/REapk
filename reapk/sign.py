import struct
from .errors import SignError
import os



V2_BLOCK_ID = 0x7109871A

V3_BLOCK_ID = 0xF05368C0

SIG_RSA_PKCS1_SHA256 = 0x0103

SIG_BLOCK_MAGIC = b"APK Sig Block 42"

V3_MIN_SDK = 24

V3_MAX_SDK = 0x7FFFFFFF

def _reapk_keypair():
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    import datetime

    home = os.path.expanduser("~/.reapk")
    os.makedirs(home, exist_ok=True)
    kp, cp = os.path.join(home, "signer.key"), os.path.join(home, "signer.crt")
    if os.path.isfile(kp) and os.path.isfile(cp):
        with open(kp, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), None)
        with open(cp, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        return key, cert
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "reapk debug")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2020, 1, 1))
            .not_valid_after(datetime.datetime(2099, 1, 1))
            .sign(key, hashes.SHA256()))
    with open(kp, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    with open(cp, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert

def apk_sign_v2(apk_bytes):
    import hashlib
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    key, cert = _reapk_keypair()
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    eocd_off = apk_bytes.rfind(b"PK\x05\x06")
    if eocd_off < 0:
        raise SignError("not a zip (no EOCD); cannot sign")
    _cd_size, cd_off = struct.unpack_from("<II", apk_bytes, eocd_off + 12)
    section1 = apk_bytes[:cd_off]
    central_dir = apk_bytes[cd_off:eocd_off]
    digest_eocd = apk_bytes[eocd_off:]  # CD-offset field already points to signing-block start

    # Chunked content digest: 1MB chunks, each H(0xa5||len||chunk), then H(0x5a||count||digests)
    def chunks(b):
        for i in range(0, len(b), 1 << 20):
            yield b[i:i + (1 << 20)]

    cds = []
    for sec in (section1, central_dir, digest_eocd):
        for ch in chunks(sec):
            cds.append(hashlib.sha256(b"\xa5" + struct.pack("<I", len(ch)) + ch).digest())
    top = hashlib.sha256(b"\x5a" + struct.pack("<I", len(cds)) + b"".join(cds)).digest()

    def lp(b):
        return struct.pack("<I", len(b)) + b

    def seq(elems):
        return lp(b"".join(lp(e) for e in elems))

    def sign(data):
        return key.sign(data, padding.PKCS1v15(), hashes.SHA256())

    digests = seq([struct.pack("<I", SIG_RSA_PKCS1_SHA256) + lp(top)])
    certs = seq([cert_der])

    # v2 signer: signed_data = digests | certs | attrs
    sd2 = digests + certs + seq([])
    sigs2 = seq([struct.pack("<I", SIG_RSA_PKCS1_SHA256) + lp(sign(sd2))])
    signer2 = lp(sd2) + sigs2 + lp(spki)
    pair_v2 = _sig_pair(V2_BLOCK_ID, seq([signer2]))

    # v3 signer: signed_data adds min/max SDK; signer repeats them outside
    sdk = struct.pack("<II", V3_MIN_SDK, V3_MAX_SDK)
    sd3 = digests + certs + sdk + seq([])
    sigs3 = seq([struct.pack("<I", SIG_RSA_PKCS1_SHA256) + lp(sign(sd3))])
    signer3 = lp(sd3) + sdk + sigs3 + lp(spki)
    pair_v3 = _sig_pair(V3_BLOCK_ID, seq([signer3]))

    body = pair_v2 + pair_v3
    blocklen = len(body) + 8 + 16  # + trailing size(8) + magic(16)
    signing_block = (struct.pack("<Q", blocklen) + body
                     + struct.pack("<Q", blocklen) + SIG_BLOCK_MAGIC)

    eocd2 = bytearray(digest_eocd)
    struct.pack_into("<I", eocd2, 16, len(section1) + len(signing_block))
    return section1 + signing_block + central_dir + bytes(eocd2)

def _sig_pair(block_id, value):
    return struct.pack("<Q", len(value) + 4) + struct.pack("<I", block_id) + value