# Tier 2: needs the pinned 2021 belt (+ lk-patched).
"""Task 5 (guarantee plan): VERIFY_LK uses REAL host-side RSA-2048/PSS
verification against the Amazon LK modulus embedded in the pinned
2021:brhgptpl_0 (recipe: recovery-notes/preloader-vuln-signature.md §3.1
— data_len = size-0x100, sig = last 0x100 bytes, SHA-256 over the data,
PSS salt 0x20, modulus 0x800 bits; key VMA re-derived from sub_201D70's
own pool = 0x222260 / file 0x029560 — the note's 0x22244C is wrong).
"""
import struct

import pytest

from crumpet_emu import resources

needs_pl = pytest.mark.skipif(
    not (resources.available('brhgptpl_0', '2021')
         and resources.available('lk', '2021')
         and resources.available('lk-patched', '2021')),
    reason='pinned 2021 belt + lk-patched not placed')

LK_SUB_SIZE = 232680     # stock lk sub-image size incl. 0x100 signature


def _sub_image(name):
    img = resources.resolve(name, '2021').read_bytes()
    return img[0x200:0x200 + LK_SUB_SIZE]


@needs_pl
def test_stock_lk_sub_image_verifies():
    from crumpet_emu.preloader.hostcrypto_pl import verify_lk_signature
    pl = resources.resolve('brhgptpl_0', '2021').read_bytes()
    assert verify_lk_signature(_sub_image('lk'), pl) is True


@needs_pl
def test_tampered_lk_fails():
    from crumpet_emu.preloader.hostcrypto_pl import verify_lk_signature
    pl = resources.resolve('brhgptpl_0', '2021').read_bytes()
    bad = bytearray(_sub_image('lk'))
    bad[0x1000] ^= 0xFF                      # tamper signed DATA
    assert verify_lk_signature(bytes(bad), pl) is False
    bad2 = bytearray(_sub_image('lk'))
    bad2[-1] ^= 0xFF                         # tamper the SIGNATURE
    assert verify_lk_signature(bytes(bad2), pl) is False


@needs_pl
def test_patched_lk_fails_verification():
    """The patched LK is genuinely unsigned — real crypto must reject it.
    This is what makes the payload's LK_VERIFY_GATE_PATCH load-bearing:
    without the gate skip, part_load would fail the custom LK every boot
    (the brick-2 mechanism)."""
    from crumpet_emu.preloader.hostcrypto_pl import verify_lk_signature
    pl = resources.resolve('brhgptpl_0', '2021').read_bytes()
    assert verify_lk_signature(_sub_image('lk-patched'), pl) is False


@needs_pl
def test_garbage_fails():
    from crumpet_emu.preloader.hostcrypto_pl import verify_lk_signature
    pl = resources.resolve('brhgptpl_0', '2021').read_bytes()
    assert verify_lk_signature(b'\x00' * 0x1000, pl) is False
    assert verify_lk_signature(b'\x5a' * 0x400, pl) is False


@needs_pl
def test_verify_lk_seam_uses_real_crypto():
    """The VERIFY_LK seam passes the stock sub-image and fails a tampered
    one through the REAL crypto path (events say real-verify)."""
    from crumpet_emu.preloader.emu import Emu
    from crumpet_emu.preloader.constants import VERIFY_LK
    from crumpet_emu.flash.image import Flash
    stock = resources.resolve('lk', '2021').read_bytes()
    emu = Emu(Flash(b'x' * 0x200, stock, b'y' * 0x200), sbc=True)
    sub = stock[0x200:0x200 + LK_SUB_SIZE]
    emu.uc.mem_write(0x42000000, sub)
    ret = emu.call(VERIFY_LK, (0x42000000, LK_SUB_SIZE), timeout=5_000_000)
    assert ret == 0 and emu.verify_calls == 1
    bad = bytearray(sub); bad[0x999] ^= 1
    emu.uc.mem_write(0x42000000, bytes(bad))
    ret2 = emu.call(VERIFY_LK, (0x42000000, LK_SUB_SIZE), timeout=5_000_000)
    assert ret2 == 0xFFFFFFFF and emu.verify_calls == 2
    assert any('real-rsa' in e for e in emu.events)
