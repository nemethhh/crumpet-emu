# Tier 2: needs the pinned 2021 belt + committed own artifacts.
"""Task 2 (guarantee plan): the REAL sequential header parser
(sub_20F2D8) and REAL check_part_overlapped (sub_20F398) execute on the
amonet chain — the reimplemented stubs are legacy-only
(``Emu(..., legacy_seams=True)``).

The strongest test drives the REAL stock TEE loader sub_20E19C against
the crafted tz image (the shape the CLI previously fabricated with
``part_load`` at offset 0xE800 + ``*addr == 0``): the loader's own walk
dynamically proves P3 (the crafted sub-image's fallback load address is
the loader's zero-initialized cell), the atf sub-image lands at
TEE_LOAD_ADDR first, and the hijack fires from the REAL copy loop.
"""
import struct

import pytest

from crumpet_emu import resources
from crumpet_emu.flash.image import Flash

needs_pl = pytest.mark.skipif(
    not (resources.available('brhgptpl_0', '2021')
         and resources.available('lk', '2021')
         and resources.available('tee2', '2021')),
    reason='pinned 2021 belt not placed — binaries/vendor/2021/ or env vars')

TEE_LOADER = 0x20E19C          # stock TEE-part loader (port doc §2)
NAME_TABLE = 0x224910          # check_part_overlapped name table (.data)
LK_REGION = NAME_TABLE + 0x10  # claimed-range global (init {0,0} in-file)


def _chain_emu(**kw):
    """Crafted-lka belt with real seams (the new default)."""
    from crumpet_emu.preloader.emu import (Emu, arm_device, part_struct,
                                           parse_elf_symbols)
    from crumpet_emu.preloader.constants import (BDEV, SCRATCH, TEE_LOAD_ADDR)
    tz = resources.own('tz-lka.img').read_bytes()
    stock_lk = resources.resolve('lk', '2021').read_bytes()
    tee2 = resources.resolve('tee2', '2021').read_bytes()
    syms = parse_elf_symbols(resources.own('payload-lka.elf'))
    emu = Emu(Flash(tz, stock_lk, tee2), sbc=True, payload_syms=syms,
              stock_ok=stock_lk, **kw)
    arm_device(emu)
    namep = SCRATCH + 0x90
    emu.uc.mem_write(namep, b'tee1\x00')
    tee_addr, tee_size = SCRATCH + 0x48, SCRATCH + 0x4C
    emu.uc.mem_write(tee_addr, struct.pack('<I', TEE_LOAD_ADDR))
    return emu, (namep, BDEV, tee_addr, 0, tee_size)


@needs_pl
def test_real_loader_walk_crafted_tee1():
    """REAL sub_20E19C on the crafted image: full first-stage exploit on
    real code — atf walked first at TEE_LOAD_ADDR, crafted sub-image
    driven by the loader's own *addr==0 cell, hijack fires, payload
    staged, custom LK loaded, loader returns the tee1-failure error."""
    from crumpet_emu.preloader.constants import PAYLOAD_ADDR, LK_LOAD_ADDR
    emu, args = _chain_emu()
    ret = emu.try_call(TEE_LOADER, args, timeout=120_000_000)
    assert not emu.faulted and not emu.stopped
    assert ret == 0xFFFFFFFF, 'tee1 load must fail (payload aborts the read)'
    payload = resources.own('payload-lka.bin').read_bytes()
    assert bytes(emu.uc.mem_read(PAYLOAD_ADDR, 4)) == payload[:4], \
        'real payload not staged at 0x101000'
    assert bytes(emu.uc.mem_read(LK_LOAD_ADDR, 16)) == \
        resources.resolve('lk', '2021').read_bytes()[0x200:0x210], \
        'stock LK (chain default --lk) not staged at 0x41E00000'
    ev = '\n'.join(emu.events)
    assert "name=b'atf'" in ev and 'start=0x43001000' in ev, \
        'atf sub-image must walk first at TEE_LOAD_ADDR (real loader)'
    assert "name=b'lk'" in ev and 'start=0x0 end=0x108803' in ev, \
        'crafted sub-image load must land at 0 via the loader fallback (P3)'


@needs_pl
def test_guest_lk_region_claimed_by_real_code():
    """The REAL check_part_overlapped claims [0, dsize-1] in the GUEST
    lk_region cells for the crafted 'lk' sub-image (table @0x224910)."""
    emu, args = _chain_emu()
    emu.try_call(TEE_LOADER, args, timeout=120_000_000)
    claimed = struct.unpack('<II', bytes(emu.uc.mem_read(LK_REGION, 8)))
    assert claimed == (0, 0x108803), \
        f'guest lk_region {claimed!r} != claimed (0, 0x108803)'


@needs_pl
def test_crafted_walk_skips_mtee_verify():
    """P1 ordering premise, pinned dynamically: the REAL stock loader's
    walk verifies the GENUINE donor atf sub-image of the crafted tee1
    (mtee event before the crafted sub-image load — that image is
    Amazon-signed and passes on silicon too), but NEVER the CRAFTED
    sub-image: its read aborts inside part_load (copy-before-verify
    order), so the always-OK mtee seam cannot bless the crafted bytes."""
    emu, args = _chain_emu()
    emu.try_call(TEE_LOADER, args, timeout=120_000_000)
    ev = emu.events
    crafted_idx = next(i for i, e in enumerate(ev)
                       if "part_load(part='tee1'" in e and 'off=0xe800' in e)
    after = [e for e in ev[crafted_idx:] if 'mtee_verify' in e]
    assert not after, \
        f'mtee_verify ran on/after the crafted sub-image load: {after}'
    assert any('mtee_verify' in e for e in ev[:crafted_idx]), \
        'the genuine atf sub-image should have been verified first'


@needs_pl
def test_crafted_name_tee_panics_real_overlap():
    """A crafted sub-image named 'TEE' (not in the name table) with
    load address 0 is inside the initial lk_region {0,0} — the REAL
    check_part_overlapped must take the assert path (panic oracle)."""
    from crumpet_emu.preloader.constants import SCRATCH, BDEV, PART_LOAD
    emu, _ = _chain_emu()
    bad = bytearray(resources.own('tz-lka.img').read_bytes())
    bad[0xE800 + 8:0xE800 + 11] = b'TEE'      # sub-image name 'lk' -> 'TEE'
    from crumpet_emu.preloader.emu import part_struct
    from crumpet_emu.flash.image import Flash as F
    stock_lk = resources.resolve('lk', '2021').read_bytes()
    tee2 = resources.resolve('tee2', '2021').read_bytes()
    from crumpet_emu.preloader.emu import parse_elf_symbols
    emu.f = F(bytes(bad), stock_lk, tee2)     # swap the tee1 source
    tee1_part = part_struct(emu, 'tee1', SCRATCH)
    addr_cell, size_cell = SCRATCH + 0x40, SCRATCH + 0x44
    emu.uc.mem_write(addr_cell, struct.pack('<I', 0))
    emu.try_call(PART_LOAD, (BDEV, tee1_part, addr_cell, 0xE800, size_cell),
                 timeout=60_000_000)
    assert emu.stopped, 'real overlap check must panic (assert oracle)'
    assert any('ASSERT' in e for e in emu.events)
    assert any('check_part_overlapped' in l for l in emu.pl_log), \
        'the real failure print must reach the preloader log'


@needs_pl
def test_legacy_seams_differential_stock_boot():
    """Legacy reimplementations vs real code must agree on every stock
    verdict: calibrate (CAL-1/CAL-2) and stock_boot both PASS under
    both seam modes (plan Review Focus #1)."""
    from crumpet_emu.preloader import scenarios
    for legacy in (True, False):
        real_emu_cls = None
        import crumpet_emu.preloader.emu as emu_mod
        orig = emu_mod.Emu

        class Shim(orig):
            def __init__(self, *a, **kw):
                kw.setdefault('legacy_seams', legacy)
                super().__init__(*a, **kw)

        import crumpet_emu.preloader.scenarios as scen
        scen.Emu = Shim
        try:
            assert scen.calibrate(sbc=True) is True, f'calibrate legacy={legacy}'
            assert scen.stock_boot(sbc=True) is True, f'stock_boot legacy={legacy}'
        finally:
            scen.Emu = orig
