# Donor: WS/tools/amonet-emu/emu_chain.py
# Upstream: in-repo harness (amonet-emu)
# Split 2026-10-31 (Task 10): donor lines 582-673 (calibrate, stock_boot)
#   verbatim except the keyword-only sbc=True defaults (brief interface)
#   and the LK_IMG()/TEE2_IMG() lazy resolvers for the donor's module
#   image Paths. ImageSet/Verdict/PRESETS/run_scenario below are NEW
#   brief-mandated surface (the donor documents the A/A0/B/C scenarios
#   only in its module docstring; no donor code implements a runner).

"""Preloader scenarios: calibration, stock boot, and the A/A0/B/C presets.

calibrate/stock_boot are the donor's known-good baselines against the
real-device UART capture; run_scenario drives one docstring scenario
against a resolved image set (see PRESETS).
"""
import struct
from collections import namedtuple

from crumpet_emu import resources
from crumpet_emu.flash.image import Flash
from crumpet_emu.preloader.constants import (BDEV, LK_LOAD_ADDR, PART_LOAD,
                                             SCRATCH, TEE_LOAD_ADDR)
from crumpet_emu.preloader.emu import (LK_IMG, TEE2_IMG, Emu, arm_device,
                                       part_struct)


def calibrate(*, sbc=True):
    """Known-good baselines against the real-device UART capture
    (no-alexa/logicanalyzer/uart_logs/tp54_gnd.txt)."""
    stock_lk = LK_IMG().read_bytes()
    # RSA oracle: the genuine stock image passes; anything else fails.
    # (Models RSA-2048-PSS over the stock signature bytes.)
    ok = True

    print(f'=== CAL-1: stock lk.img from lk_a, SBC={sbc} '
          '(expect verify called + pass, like the real boot) ===')
    flash = Flash(TEE2_IMG().read_bytes(), stock_lk, TEE2_IMG().read_bytes())
    emu = Emu(flash, sbc=sbc, stock_ok=stock_lk)
    arm_device(emu)
    lk_part = part_struct(emu, 'lk_a', SCRATCH)
    addr_cell, size_cell = SCRATCH + 0x40, SCRATCH + 0x44
    emu.uc.mem_write(addr_cell, struct.pack('<I', LK_LOAD_ADDR))
    ret = emu.try_call(PART_LOAD, (BDEV, lk_part, addr_cell, 0, size_cell),
                   timeout=30_000_000)
    got = bytes(emu.uc.mem_read(LK_LOAD_ADDR, 232680))
    print(f'part_load -> {ret}, verify_calls={emu.verify_calls}, '
          f'bytes_match_stock={got == stock_lk[0x200:0x200 + 232680]}')
    for e in emu.events:
        print(' *', e)
    if sbc:
        ok &= (ret == 0 and emu.verify_calls == 1 and
               got == stock_lk[0x200:0x200 + 232680] and not emu.stopped)
    else:
        ok &= (ret == 0 and emu.verify_calls == 0 and not emu.stopped)
    print(f'CAL-1 {"PASS" if ok else "FAIL"}\n')

    print('=== CAL-2: stock tee1 donor atf sub-image from tee1 '
          '(expect no LK gate, copy ok) ===')
    emu2 = Emu(Flash(TEE2_IMG().read_bytes(), stock_lk, TEE2_IMG().read_bytes()),
               sbc=True, stock_ok=stock_lk)
    arm_device(emu2)
    tee1_part = part_struct(emu2, 'tee1', SCRATCH)
    emu2.uc.mem_write(addr_cell, struct.pack('<I', TEE_LOAD_ADDR))
    ret2 = emu2.try_call(PART_LOAD, (BDEV, tee1_part, addr_cell, 0, size_cell),
                         timeout=30_000_000)
    print(f'part_load -> {ret2}, verify_calls={emu2.verify_calls}')
    for e in emu2.events:
        print(' *', e)
    ok &= (ret2 == 0 and emu2.verify_calls == 0 and not emu2.stopped and
           emu2.last_hdr[2] == b'atf' and emu2.last_hdr[1] == 0xE600)
    print(f'CAL-2 {"PASS" if ok else "FAIL"}')
    return ok


def stock_boot(*, sbc=True):
    """Phase-1 end state: full stock 2021 set boots through the REAL
    preloader paths to the handoff point (TEE loader sub_20E19C, LK
    verify gate, unpatched ARB check)."""
    stock_lk = LK_IMG().read_bytes()
    donor_tee1 = TEE2_IMG().read_bytes()
    emu = Emu(Flash(donor_tee1, stock_lk, TEE2_IMG().read_bytes()),
              sbc=sbc, stock_ok=stock_lk)
    arm_device(emu)

    namep = SCRATCH + 0x90
    emu.uc.mem_write(namep, b'tee1\x00')
    tee_addr, tee_size = SCRATCH + 0x48, SCRATCH + 0x4C
    emu.uc.mem_write(tee_addr, struct.pack('<I', TEE_LOAD_ADDR))
    print('=== STOCK-1: REAL sub_20E19C("tee1") donor ATF+TEE load ===')
    r1 = emu.try_call(0x20E19C, (namep, BDEV, tee_addr, 0, tee_size),
                      timeout=30_000_000)
    tee_bytes = bytes(emu.uc.mem_read(0x600000, 16))
    print(f'sub_20E19C -> {r1}; tee@0x600000 head: {tee_bytes.hex()}')

    print('=== STOCK-2: stock LK from lk_a via gate (verify must PASS) ===')
    lk_part = part_struct(emu, 'lk_a', SCRATCH)
    lk_addr, lk_size = SCRATCH + 0x40, SCRATCH + 0x44
    emu.uc.mem_write(lk_addr, struct.pack('<I', LK_LOAD_ADDR))
    r2 = emu.try_call(PART_LOAD, (BDEV, lk_part, lk_addr, 0, lk_size),
                      timeout=30_000_000)
    print(f'part_load(lk) -> {r2}, verify_calls={emu.verify_calls}')

    print('=== STOCK-3: REAL unpatched ARB check (fuse=1, sw=1) ===')
    emu.fuse_ver = 1
    r3 = emu.try_call(0x2019B0, (), timeout=30_000_000)
    joined = ''.join(emu.pl_log)
    for e in emu.events[-6:]:
        print(' *', e)

    ok = (r1 == 0 and r2 == 0 and emu.verify_calls == 1 and r3 == 0
          and 'All checks passed' in joined
          and 'mismatch' not in joined and not emu.stopped
          and not emu.faulted
          and bytes(emu.uc.mem_read(LK_LOAD_ADDR, 16)) == stock_lk[0x200:0x210])
    print(f'STOCK BOOT {"PASS" if ok else "FAIL"} '
          f'(handoff: LK@0x41E00000 stock bytes, tee staged, ARB pass)\n')
    return ok


ImageSet = namedtuple('ImageSet', 'pl lk tee2 commit_tag')
Verdict = namedtuple('Verdict', 'letter ok detail')

# Donor docstring scenarios (emu_chain.py lines 7-11):
#   A  as-flashed fixed image (commit 3e65ba3), SBC efuse set  -> brick #2 repro
#   A0 original port image (commit 5f5481c),  SBC efuse set    -> brick #1 repro
#   B  as-flashed fixed image, SBC efuse CLEAR                -> would boot
#   C  corrected payload (gate patch + no-hang), SBC set      -> full chain
# A/A0 pin the belt as it stood at those donor commits: the manifest
# names below carry the commit tag and have NO binaries/manifest.json
# entry, so the default presets raise MissingBinary at resolve time —
# documented Tier-2-only behavior (the scenarios run only once
# commit-pinned entries are placed and manifested). B/C name the
# current 2021 belt. The crafted-image exploit chain (tz/payload) is
# not representable in ImageSet and stays CLI-driven
# (scenarios/preloader_chain.py), exactly as the donor shipped it.
PRESETS = {
    'A': ImageSet(pl='brhgptpl_0-3e65ba3', lk='lk-3e65ba3',
                  tee2='tee2-3e65ba3', commit_tag='3e65ba3'),
    'A0': ImageSet(pl='brhgptpl_0-5f5481c', lk='lk-5f5481c',
                   tee2='tee2-5f5481c', commit_tag='5f5481c'),
    'B': ImageSet(pl='brhgptpl_0', lk='lk', tee2='tee2', commit_tag=None),
    'C': ImageSet(pl='brhgptpl_0', lk='lk', tee2='tee2', commit_tag=None),
}


def run_scenario(letter, *, sbc=True, images=None):
    """Run one docstring scenario's belt-level boot and classify it.

    Resolves the ImageSet (default: PRESETS[letter]) through the
    manifest gate, then drives the donor's stock part_load(lk) gate
    flow (the calibrate CAL-1 shape): the REAL preloader loads the
    LK from lk_a through the RSA-verify gate with the resolved belt.
    The verdict classifies the donor's boot-halting oracles (usbdl
    handshake hang / assert panic / verify fail) against a clean boot.

    WARNING: A/A0 with manifested belt images return ok=True via the
    belt's own-lk RSA oracle — letter-faithful brick semantics need
    crafted tz/payload ImageSet (do not silently change the oracle).
    """
    if images is None:
        images = PRESETS[letter]
    pl = resources.resolve(images.pl, '2021')     # MissingBinary for A/A0
    lk = resources.resolve(images.lk, '2021')
    tee2 = resources.resolve(images.tee2, '2021')
    stock_lk = lk.read_bytes()
    donor_tee1 = tee2.read_bytes()
    emu = Emu(Flash(donor_tee1, stock_lk, donor_tee1), sbc=sbc,
              stock_ok=stock_lk)
    arm_device(emu)
    lk_part = part_struct(emu, 'lk_a', SCRATCH)
    addr_cell, size_cell = SCRATCH + 0x40, SCRATCH + 0x44
    emu.uc.mem_write(addr_cell, struct.pack('<I', LK_LOAD_ADDR))
    ret = emu.try_call(PART_LOAD, (BDEV, lk_part, addr_cell, 0, size_cell),
                       timeout=30_000_000)
    if emu.stopped:
        ok = False
        detail = f'boot-halting oracle fired: {emu.events[-1]}'
    elif emu.faulted or ret != 0:
        ok = False
        detail = (f'part_load(lk) -> {ret} '
                  f'(verify_calls={emu.verify_calls}, faulted={emu.faulted})')
    else:
        ok = True
        detail = (f'boot gate passed: part_load(lk) -> 0, '
                  f'verify_calls={emu.verify_calls}, '
                  f'SBC={"set" if sbc else "clear"}, pl={pl.name}')
    return Verdict(letter, ok, detail)
