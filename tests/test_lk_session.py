"""Task 11 — lk layer: committed seeds, host crypto, LkSession build.

test_seeds_parse        (Tier 1) the committed crumpet_emu/lk/seeds.json
                        parses to >= 25 named audit-pinned entries incl.
                        rsa_import @0x41E0C95C, and LkSession.load_seeds()
                        yields that same name -> VA map (donor lk_emu.py F
                        table export; R10: restructured, "ida" array is the
                        donor ida_seeds.json list verbatim).
test_host_pss_roundtrip (Tier 1) donor host-crypto primitives are
                        self-consistent: rsa_pss_sign(msg, key, salt)
                        recovers pss_encode(msg, salt, embits) under
                        public-exponent exponentiation; gen_rsa is
                        deterministic per seed; spki_der emits the 294-byte
                        RSA-2048 SPKI shape (the donor battery's 295-byte
                        rodata read is this DER + 1 trailing byte).
test_build_requires_lk  (Tier 2) LkSession.build(resolve('lk','2025'))
                        maps the image raw at LK_BASE with the donor
                        LKEmu.__init__ session state, and the installed
                        platform stub table answers a call (malloc).
"""

import hashlib
import json

import pytest

from crumpet_emu import resources
from crumpet_emu.lk.hostcrypto import (b2i, gen_rsa, i2b, mgf1, pss_encode,
                                       rsa_pss_sign, spki_der)
from crumpet_emu.lk.session import (BSS_END, F, HEAP, LK_BASE, LK_LOAD,
                                    SEEDS_PATH, LkSession)

TIER2 = 'tier2: requires parked vendor binaries — see binaries/README.md'
tier2_lk = pytest.mark.skipif(not resources.available('lk', '2025'), reason=TIER2)


def test_seeds_parse():
    raw = json.loads(SEEDS_PATH.read_text(encoding='utf-8'))
    names = raw['functions']
    assert len(names) >= 25
    assert 'rsa_import' in names
    assert names['rsa_import'].lower() == '0x41e0c95c'
    # the committed export covers the donor F table (37 entries); Task 12
    # appended the USB seam entries, so the export is now a superset
    assert set(F) <= set(names)
    assert names['usb_read'].lower() == '0x41e1dfa8'
    assert names['usb_write'].lower() == '0x41e1e050'
    # load_seeds() parses the same committed file into the session
    lk = LkSession.build(b'\x00' * 0x200)      # minimal fake GFH: Tier 1
    assert lk.seeds == {k: int(v, 16) for k, v in names.items()}
    assert lk.seeds['rsa_import'] == F['rsa_import'] == 0x41E0C95C
    # the donor IDA seed list rides along verbatim
    assert len(raw['ida']) == 839


def test_host_pss_roundtrip():
    key = gen_rsa(2048, seed=7)
    n, e, d = key[0], key[1], key[2]
    assert gen_rsa(2048, seed=7) == key          # deterministic per seed
    msg = b'0x4a616f429e27cf4b'                  # donor UNLOCK_MSG battery.py:32
    salt = bytes(range(32))
    sig = rsa_pss_sign(msg, key, salt=salt)
    assert len(sig) == 256
    # verify via the same primitives: s^e mod n recovers the EMSA-PSS block
    em = i2b(pow(b2i(sig), e, n), 256)
    assert em == pss_encode(msg, salt, n.bit_length() - 1)
    assert em != pss_encode(msg + b'x', salt, n.bit_length() - 1)
    # mgf1 is the mask engine inside pss_encode (sha256 counter mode)
    assert mgf1(b'seed', 100) == b''.join(
        hashlib.sha256(b'seed' + i.to_bytes(4, 'big')).digest()
        for i in range(4))[:100]
    # spki_der: 294-byte RSA-2048 SPKI (SEQUENCE / RSA OID / BIT STRING)
    der = spki_der(n, e)
    assert len(der) == 294
    assert der[:19] == bytes.fromhex('30820122300d06092a864886f70d0101010500')
    assert der[19] == 0x03


@tier2_lk
def test_build_requires_lk():
    img = resources.resolve('lk', '2025').read_bytes()
    lk = LkSession.build(img)
    # donor LKEmu.__init__ mapping: raw image at LK_BASE (VMA = raw + base)
    assert lk.read(LK_BASE, len(img)) == img
    assert lk.rd32(LK_LOAD) == int.from_bytes(img[0x200:0x204], 'little')
    # donor session state (lk_emu.py:128-135)
    assert lk.heap_ptr == HEAP
    assert lk.allocs == {}
    assert lk.fault is None
    assert lk.fault_hits == 0
    assert lk.stop_reason is None
    # seeds loaded from the committed table
    assert lk.seeds['rsa_verify_hash'] == 0x41E0CDA0
    # BSS tail mapped (donor maps 0x41E40000..BSS_END)
    assert lk.rd(BSS_END - 4, 4) == b'\x00' * 4
    # platform stub table armed: malloc(16) hands out the heap base
    assert lk.call_seed('malloc', [16]) == HEAP
    assert lk.heap_ptr == HEAP + 16               # (16 + 15) & ~15 (n aligned)
    # glitch() arms the donor one-shot fault dict
    lk.glitch('full')
    assert lk.fault == {'armed': True, 'mode': 'full', 'once': True}
    assert lk.fault_hits == 0
