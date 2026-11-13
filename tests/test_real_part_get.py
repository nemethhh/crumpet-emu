# Tier 2: needs the pinned 2021 belt + committed own artifacts.
"""Task 3 (guarantee plan): REAL part_get (sub_20F250 + the sub_20F1F8
walk) executes against a staged partition table whose entries come from
the REAL GPT (flash.gpt.parse_gpt_from_image on the pinned
2021:brhgptpl_0). The donor's synthesized part struct is legacy-only.
"""
import struct

import pytest

from crumpet_emu import resources
from crumpet_emu.flash.gpt import parse_gpt_from_image

needs_pl = pytest.mark.skipif(
    not (resources.available('brhgptpl_0', '2021')
         and resources.available('lk', '2021')
         and resources.available('tee2', '2021')),
    reason='pinned 2021 belt not placed — binaries/vendor/2021/ or env vars')

TEE_LOADER = 0x20E19C
PART_GET_OUT = 0x102A5C   # the walk's fixed global output struct (.bss;
                          # computed from the real pool literals — probe)
PART_GET_NAMEBUF = 0x102A70  # part_get's 0x20-byte input-name copy


def _gpt_blocks():
    """Real GPT (LBA4096 units) -> bdev 512-block units, like the
    flash.image GPT table the donor stub synthesized from."""
    img = resources.resolve('brhgptpl_0', '2021').read_bytes()
    return {n: (s * 8, c * 8) for n, (s, c) in parse_gpt_from_image(img).items()}


@needs_pl
def test_real_part_get_walks_staged_table():
    """part_get('lk_a') through the REAL walk returns the staged entry
    (start/nblk from the real GPT, name copied to the walk's buffer);
    an unknown name returns 0."""
    from crumpet_emu.preloader.emu import Emu
    from crumpet_emu.preloader.constants import (BDEV, PART_GET, SCRATCH,
                                                 SRAM_DBUF_PTR, DRAM_BUF)
    from crumpet_emu.flash.image import Flash
    emu = Emu(Flash(b'x' * 0x200, b'y' * 0x200, b'z' * 0x200), sbc=True)
    namep = SCRATCH
    emu.uc.mem_write(namep, b'lk_a\x00')
    ret = emu.call(PART_GET, (namep,), timeout=5_000_000)
    assert not emu.faulted
    gpt = _gpt_blocks()
    assert ret == PART_GET_OUT, \
        f'real walk must return its global struct {hex(PART_GET_OUT)}, got {hex(ret)}'
    start, nblk = struct.unpack('<II', bytes(emu.uc.mem_read(ret, 8)))
    assert (start, nblk) == gpt['lk_a'], \
        f'real walk returned {(start, nblk)!r} != GPT lk_a {gpt["lk_a"]!r}'
    assert bytes(emu.uc.mem_read(PART_GET_NAMEBUF, 8)).split(b'\x00')[0] \
        == b'lk_a', 'the real part_get memcpy must land the name at 0x102A70'
    namep_out = struct.unpack('<I', bytes(emu.uc.mem_read(ret + 0x10, 4)))[0]
    got = bytes(emu.uc.mem_read(namep_out, 8)).split(b'\x00')[0]
    assert got == b'lk_a'
    emu.uc.mem_write(namep, b'nosuchpart\x00')
    ret2 = emu.call(PART_GET, (namep,), timeout=5_000_000)
    assert ret2 == 0, 'unknown partition must not resolve'


@needs_pl
def test_chain_completes_on_real_part_get():
    """The full first-stage chain with REAL part_get: the stock loader,
    the payload's bldr_load_part('lk_a') and phase-2 tee2 loads all
    resolve partitions through the staged real-GPT table."""
    from crumpet_emu.preloader.emu import (Emu, arm_device,
                                           parse_elf_symbols)
    from crumpet_emu.preloader.constants import (BDEV, PAYLOAD_ADDR,
                                                 LK_LOAD_ADDR, SCRATCH,
                                                 TEE_LOAD_ADDR)
    from crumpet_emu.flash.image import Flash
    tz = resources.own('tz-lka.img').read_bytes()
    stock_lk = resources.resolve('lk', '2021').read_bytes()
    tee2 = resources.resolve('tee2', '2021').read_bytes()
    syms = parse_elf_symbols(resources.own('payload-lka.elf'))
    emu = Emu(Flash(tz, stock_lk, tee2), sbc=True, payload_syms=syms,
              stock_ok=stock_lk)
    arm_device(emu)
    namep = SCRATCH + 0x90
    emu.uc.mem_write(namep, b'tee1\x00')
    tee_addr, tee_size = SCRATCH + 0x48, SCRATCH + 0x4C
    emu.uc.mem_write(tee_addr, struct.pack('<I', TEE_LOAD_ADDR))
    ret = emu.try_call(TEE_LOADER, (namep, BDEV, tee_addr, 0, tee_size),
                       timeout=120_000_000)
    assert not emu.faulted and not emu.stopped
    assert ret == 0xFFFFFFFF
    payload = resources.own('payload-lka.bin').read_bytes()
    assert bytes(emu.uc.mem_read(PAYLOAD_ADDR, 4)) == payload[:4]
    assert bytes(emu.uc.mem_read(LK_LOAD_ADDR, 16)) == stock_lk[0x200:0x210]
    gpt = _gpt_blocks()
    ev = '\n'.join(emu.events)
    assert f'READ bdev={hex(BDEV)} blk={gpt["lk_a"][0]} ' in ev, \
        'the custom-LK load must read at the real GPT lk_a start block'
    out = struct.unpack('<II', bytes(emu.uc.mem_read(PART_GET_OUT, 8)))
    assert out == gpt['lk_a'], \
        f'last real part_get (lk_a) global struct {out!r} != GPT {gpt["lk_a"]!r}'


@needs_pl
def test_part_get_legacy_differential():
    """Legacy synthesized struct vs real walk: the chain verdicts agree
    (payload staged, LK bytes, no panic) — plan Review Focus #1."""
    from crumpet_emu.preloader.emu import (Emu, arm_device,
                                           parse_elf_symbols)
    from crumpet_emu.preloader.constants import (BDEV, PAYLOAD_ADDR,
                                                 LK_LOAD_ADDR, SCRATCH,
                                                 TEE_LOAD_ADDR)
    from crumpet_emu.flash.image import Flash
    tz = resources.own('tz-lka.img').read_bytes()
    stock_lk = resources.resolve('lk', '2021').read_bytes()
    tee2 = resources.resolve('tee2', '2021').read_bytes()
    syms = parse_elf_symbols(resources.own('payload-lka.elf'))
    payload = resources.own('payload-lka.bin').read_bytes()
    for legacy in (True, False):
        emu = Emu(Flash(tz, stock_lk, tee2), sbc=True, payload_syms=syms,
                  stock_ok=stock_lk, legacy_seams=legacy)
        arm_device(emu)
        namep = SCRATCH + 0x90
        emu.uc.mem_write(namep, b'tee1\x00')
        tee_addr, tee_size = SCRATCH + 0x48, SCRATCH + 0x4C
        emu.uc.mem_write(tee_addr, struct.pack('<I', TEE_LOAD_ADDR))
        ret = emu.try_call(TEE_LOADER, (namep, BDEV, tee_addr, 0, tee_size),
                           timeout=120_000_000)
        assert not emu.faulted and not emu.stopped, f'legacy={legacy}'
        assert ret == 0xFFFFFFFF, f'legacy={legacy}'
        assert bytes(emu.uc.mem_read(PAYLOAD_ADDR, 4)) == payload[:4], \
            f'legacy={legacy}'
        assert bytes(emu.uc.mem_read(LK_LOAD_ADDR, 16)) == stock_lk[0x200:0x210], \
            f'legacy={legacy}'
