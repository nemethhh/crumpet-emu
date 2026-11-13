"""Host-side REAL RSA-2048/PSS verification for the preloader LK gate
(guarantee Task 5).

Recipe = the real verify_lk (sub_201D70) semantics, per
WS/recovery-notes/preloader-vuln-signature.md §3.1 (IDA-reconstructed):
data_len = total_size - 0x100, signature = last 0x100 bytes, RSA public
operation with the Amazon LK modulus embedded in the preloader at VMA
0x22244C (file offset 0x02974C, 256 B big-endian, e = 65537), SHA-256
over the signed data, PSS decode with salt length 0x20 and a 0x800-bit
modulus (embits 2047). The end-to-end cross-check is the stock lk
sub-image itself: a wrong key cannot verify Amazon's genuine signature
(pinned by tests/test_pl_hostcrypto.py).
"""
import hashlib

from crumpet_emu.lk.hostcrypto import b2i, i2b, pss_encode

KEY_VMA = 0x00222260                      # from sub_201D70's own pool
KEY_FILE_OFF = 0x029560                 # KEY_VMA - FILE_DELTA
# NOTE: recovery-notes/preloader-vuln-signature.md §2 records VMA
# 0x22244C / file 0x2974C — WRONG for the pinned NS6548 2021 image (the
# bytes there are a pointer table). The verifier's own pc-relative pool
# (ldr r1,[pc,#0x100] @0x201DA0 + add r1,pc) resolves to 0x222260, where
# the recorded modulus fingerprint lives. Guarantee Task 5 finding.
KEY_SHA256 = ('9824ee73c71c4433ba550e4aef304ca5'
              '9046ea9bf7f3817a506456cce6940203')   # recorded fingerprint
E = 65537                               # preloader verify-key exponent
SIG_LEN = 0x100
SALT_LEN = 0x20
EMBITS = 2047                           # modulus_bitlen 0x800 - 1


def load_lk_modulus(pl_bytes: bytes) -> int:
    """Extract + fingerprint-check the embedded LK verify modulus."""
    n_b = pl_bytes[KEY_FILE_OFF:KEY_FILE_OFF + 0x100]
    if len(n_b) != 0x100:
        raise ValueError('short preloader image: no LK modulus')
    if hashlib.sha256(n_b).hexdigest() != KEY_SHA256:
        raise ValueError('LK modulus fingerprint mismatch — not the '
                         'pinned NS6548 2021 preloader?')
    return b2i(n_b)


def verify_lk_signature(image: bytes, pl_bytes: bytes) -> bool:
    """True iff the image carries a genuine Amazon LK signature (the
    silicon verdict for sub_201D70). Anything unsigned or tampered —
    including lk-patched — is False."""
    if len(image) <= SIG_LEN:
        return False
    n = load_lk_modulus(pl_bytes)
    data, sig = image[:-SIG_LEN], image[-SIG_LEN:]
    em = i2b(pow(b2i(sig), E, n), SIG_LEN)
    if em[-1] != 0xBC:
        return False
    # libtomcrypt pkcs_1_pss_decode: em = maskedDB(emLen-hLen-1) || H || bc
    from crumpet_emu.lk.hostcrypto import mgf1
    h_len = 32
    db_len = SIG_LEN - h_len - 1
    masked_db, h = em[:db_len], em[db_len:db_len + h_len]
    db = bytes(a ^ b for a, b in zip(masked_db, mgf1(h, db_len)))
    db = bytes([db[0] & 0x7F]) + db[1:]      # embits 2047: clear top bit
    ps_len = db_len - SALT_LEN - 1
    if db[ps_len] != 0x01 or any(db[:ps_len]):
        return False
    salt = db[db_len - SALT_LEN:]
    return pss_encode(data, salt, EMBITS) == em
