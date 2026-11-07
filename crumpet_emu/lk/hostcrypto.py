# Generalized from: WS/tools/lk-emu/lk_emu.py
# Upstream: in-repo audit harness (WS tools/lk-emu)
# Generalized 2026-11-01 (Task 11): the donor's pure-python crypto block
#   (lk_emu.py:481-600) extracted verbatim into this host-side module so the
#   crafting kit is importable without the emulation session. No donor line
#   changed; only this provenance header and the imports below were added.
"""Host-side crypto for crafting test vectors (Tier 1, no unicorn).

These mirror the primitives the emulated LK verifier runs (libtomcrypt
RSA-PSS / MGF1 / SHA-256): positive controls sign with gen_rsa +
rsa_pss_sign so signatures fed to the emulated code are REAL signatures.
"""
import hashlib
import os
import struct

# ---------------------------------------------------------------------------
# pure-python crypto for crafting test vectors (no pycryptodome in emu-venv)
# ---------------------------------------------------------------------------
def mgf1(seed, length):
    out = b''
    for i in range((length + 31) // 32):
        out += hashlib.sha256(seed + struct.pack('>I', i)).digest()
    return out[:length]


def pss_encode(msg, salt, embits, hashfn=hashlib.sha256):
    """RFC 8017 EMSA-PSS-ENCODE with sLen == |salt|."""
    hlen, slen = 32, len(salt)
    emlen = (embits + 7) // 8
    mhash = hashfn(msg).digest()
    if emlen < hlen + slen + 2:
        raise ValueError('encoding error')
    mprime = b'\x00' * 8 + mhash + salt
    h = hashfn(mprime).digest()
    ps = b'\x00' * (emlen - slen - hlen - 2)
    db = ps + b'\x01' + salt
    dbmask = mgf1(h, emlen - hlen - 1)
    masked = bytes(a ^ b for a, b in zip(db, dbmask))
    masked = bytes([masked[0] & 0xFF >> (8 * emlen - embits)]) + masked[1:] \
        if 8 * emlen > embits else masked
    return masked + h + b'\xbc'


def gen_rsa(bits=2048, e=65537, seed=None):
    """Small deterministic-ish RSA keygen (Miller-Rabin), pure python."""
    import random
    rng = random.Random(seed if seed is not None else 0xC0FFEE)

    def is_probable_prime(n, k=24):
        if n < 2:
            return False
        for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            if n % p == 0:
                return n == p
        d, r = n - 1, 0
        while d % 2 == 0:
            d //= 2
            r += 1
        for _ in range(k):
            a = rng.randrange(2, n - 1)
            x = pow(a, d, n)
            if x in (1, n - 1):
                continue
            for _ in range(r - 1):
                x = x * x % n
                if x == n - 1:
                    break
            else:
                return False
        return True

    def gen_prime(b):
        while True:
            c = rng.getrandbits(b) | (1 << (b - 1)) | 1
            if is_probable_prime(c):
                return c

    while True:
        p = gen_prime(bits // 2)
        q = gen_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        d = pow(e, -1, phi)
        return (n, e, d, p, q)


def i2b(v, length=None):
    if length:
        return v.to_bytes(length, 'big')
    return v.to_bytes((v.bit_length() + 7) // 8 or 1, 'big')


def b2i(b):
    return int.from_bytes(b, 'big')


def der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def spki_der(n, e):
    mod, exp = i2b(n), i2b(e)
    if mod[0] & 0x80:
        mod = b'\x00' + mod
    ints = b'\x02' + der_len(len(mod)) + mod + b'\x02' + der_len(len(exp)) + exp
    pub = b'\x30' + der_len(len(ints)) + ints      # RSAPublicKey SEQUENCE
    rsaoid = bytes.fromhex('2a864886f70d010101')
    algid = b'\x30' + der_len(len(b'\x06\x09' + rsaoid + b'\x05\x00')) + \
        b'\x06\x09' + rsaoid + b'\x05\x00'
    bitstr = b'\x03' + der_len(len(pub) + 1) + b'\x00' + pub
    spki = b'\x30' + der_len(len(algid) + len(bitstr)) + algid + bitstr
    return spki


def rsa_pss_sign(msg, key, salt=None):
    n, e, d = key[0], key[1], key[2]
    salt = salt if salt is not None else os.urandom(32)
    em = pss_encode(msg, salt, n.bit_length() - 1)
    m = b2i(em)
    if m >= n:
        raise ValueError('em >= n')
    s = pow(m, d, n)
    return i2b(s, 256)
