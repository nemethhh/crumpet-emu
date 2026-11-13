# Tier 2: needs 2025:lk + 2021:lk-patched (+ any boot for context).
"""Task 6 (guarantee plan): the PATCHED LK executes — the unlock gate
and the unsigned-boot acceptance run as real code on patched bytes, with
the stock 2025 LK as the locked-device differential.
"""
import struct

import pytest

from crumpet_emu import resources

needs_lk = pytest.mark.skipif(
    not (resources.available('lk', '2025')
         and resources.available('lk-patched', '2021')),
    reason='pinned 2025:lk + 2021:lk-patched not placed')

LOCK_GATE = 0x41E0EF18          # cmd_lock_check
VERIFY_AND_VB = 0x41E11548      # boot_image_verify_and_vb
RED_BLOCK = 0x41E1158E          # first PC of the RED abort block
PUBLISH = 0x41E115AE            # the RED-abort branch target (publish path)

# small unsigned custom boot image: fast verify failure (cert parse)
CUSTOM_BOOT = b'CRUMPET-CUSTOM-BOOT' + bytes(0x1000 - 18) + bytes(0x800)


@needs_lk
def test_seed_validity_on_patched_bytes():
    """Every seed/F VMA the unlock legs use disassembles identically on
    patched and stock bytes EXCEPT the three intended patch sites
    (plan Review Focus #3)."""
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    stock = resources.resolve('lk', '2025').read_bytes()
    patched = resources.resolve('lk-patched', '2021').read_bytes()
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    base, hdr = 0x41E00000, 0x200
    sites = {LOCK_GATE, 0x41E114B0, 0x41E1158C}
    for vma in (LOCK_GATE, VERIFY_AND_VB, 0x41E00F58, 0x41E1F5C0,
                0x41E1EA40, 0x41E1DFA8, 0x41E1E050, 0x41E1E1A2):
        s = [i.bytes.hex() for i in md.disasm(
            stock[vma - base + hdr:vma - base + hdr + 8], vma)]
        p = [i.bytes.hex() for i in md.disasm(
            patched[vma - base + hdr:vma - base + hdr + 8], vma)]
        if vma in sites:
            assert s != p, f'{hex(vma)} is a patch site: bytes must differ'
        else:
            assert s == p and s, f'{hex(vma)} drifted between stock/patched'


@needs_lk
def test_lock_gate_differential():
    """REAL cmd_lock_check: stock restricts 'flash:boot' (ret 1), patched
    allows it (ret 0); getvar:version is allowed on both (not blocklisted)."""
    from crumpet_emu.lk.customfw import lock_gate_differential
    d = lock_gate_differential(b'flash:boot')
    assert d['stock'] == 1, 'stock must restrict flash: on a locked device'
    assert d['patched'] == 0, 'patched gate must return allowed (0)'
    g = lock_gate_differential(b'getvar:version')
    assert g['stock'] == 0 and g['patched'] == 0


@needs_lk
def test_verify_and_vb_differential():
    """REAL verify_and_vb on an unsigned custom boot image: stock takes
    the RED block (FAILED AUTHENTICATION, ret -0xD); the patched
    RED-abort branch skips to the publish path."""
    from crumpet_emu.lk.customfw import verify_and_vb_differential
    d = verify_and_vb_differential(CUSTOM_BOOT)
    s, p = d['stock'], d['patched']
    assert s['ret'] == -0xD, f'stock must abort unsigned boot, got {s["ret"]}'
    assert 'FAILED AUTHENTICATION' in '\n'.join(s['logs'])
    assert RED_BLOCK in s['pcs'], 'stock must execute the RED block'
    assert RED_BLOCK not in p['pcs'], 'patched must skip the RED block'
    assert PUBLISH in p['pcs'], 'patched must continue into the publish path'


@needs_lk
def test_patched_getvar_okay():
    """Dispatcher plumbing on patched bytes: getvar:version replies OKAY."""
    from crumpet_emu.lk.customfw import patched_getvar
    status, message = patched_getvar('version')
    assert status == 'OKAY'


@needs_lk
def test_vbstate_stock_red():
    """Stock sets vbstate RED (3) in the guest cell for the unsigned
    image; the patched run never writes RED."""
    from crumpet_emu.lk.customfw import verify_and_vb_differential, VBSTATE_CELL
    d = verify_and_vb_differential(CUSTOM_BOOT)
    assert d['stock']['vbstate'] == 3
    assert d['patched']['vbstate'] != 3
