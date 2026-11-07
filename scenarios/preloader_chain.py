#!/usr/bin/env python3
# Donor: WS/tools/amonet-emu/emu_chain.py
# Upstream: in-repo harness (amonet-emu)
# Split 2026-10-31 (Task 10): donor main() (lines 675-798) verbatim,
#   delegating to crumpet_emu.preloader.{constants,emu,scenarios} and
#   crumpet_emu.flash.image. Non-verbatim hunks (see the task-10
#   report): the repo-root sys.path bootstrap (standalone script, no
#   package context of its own); the donor's workspace module image
#   Paths became lazy resolves (--lk default None -> LK_IMG(),
#   preflight --elf default -> resources.own('payload.elf')).

"""Preloader chain CLI: the donor emu_chain.py argparse surface.

payload tz --lk --no-sbc --skip-tee2 --elf --calibrate --preflight
--from-chip-dump — exactly the donor surface, backed by the ported
modules.
"""
import argparse
import pickle
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from crumpet_emu import resources
from crumpet_emu.flash.image import ChipDumpFlash, Flash
from crumpet_emu.preloader.constants import (BDEV, BDEV_READ, LK_LOAD_ADDR,
                                             PART_LOAD, PAYLOAD_ADDR,
                                             SCRATCH, TEE_LOAD_ADDR)
from crumpet_emu.preloader.emu import (LK_IMG, TEE2_IMG, Emu, arm_device,
                                       parse_elf_symbols, part_struct, rd32)
from crumpet_emu.preloader.scenarios import calibrate, stock_boot


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('payload', type=Path, nargs='?')
    ap.add_argument('tz', type=Path, nargs='?')
    ap.add_argument('--lk', type=Path, default=None)  # donor: LK_IMG
    ap.add_argument('--no-sbc', action='store_true')
    ap.add_argument('--skip-tee2', action='store_true')
    ap.add_argument('--elf', type=Path, default=None)
    ap.add_argument('--calibrate', action='store_true')
    ap.add_argument('--preflight', action='store_true')
    ap.add_argument('--from-chip-dump', type=Path, default=None,
                    metavar='DUMP.pkl',
                    help='serve flash reads from a NandChip.dump()-style '
                         '{page: 4352B} pickle (true NAND placement: '
                         '4096-B LBA == page) instead of image files; '
                         'payload and tz then become optional')
    args = ap.parse_args()

    if args.calibrate:
        ok = calibrate(sbc=not args.no_sbc)
        sys.exit(0 if ok else 1)

    if args.preflight:
        verdict = {}
        print('########## PREFLIGHT for unit 3 flash kit ##########\n')
        verdict['calibration'] = calibrate(sbc=not args.no_sbc)
        verdict['stock-2021-boot'] = stock_boot(sbc=not args.no_sbc)

    if not args.from_chip_dump and (not args.payload or not args.tz):
        ap.error('payload and tz are required unless --calibrate/--preflight '
                 'or --from-chip-dump')
    if args.preflight:
        args.elf = args.elf or resources.own('payload.elf')  # donor: AK build

    verdict = {} if not args.preflight else verdict
    payload_syms = parse_elf_symbols(args.elf) if args.elf and \
        args.elf.exists() else {}

    if args.from_chip_dump:
        # post-flash chip image (Task 10): every read is served from the
        # dumped pages at their true NAND placement
        flash = ChipDumpFlash(pickle.loads(args.from_chip_dump.read_bytes()))
    else:
        tz = args.tz.read_bytes()
        # unsigned custom LK: flip a few bytes mid-image (models lkpatcher
        # output)
        lk = bytearray((args.lk or LK_IMG()).read_bytes())
        lk[0x8000:0x8004] = b'\xDE\xAD\xC0\xDE'
        lk = bytes(lk)

        flash = Flash(tz, lk, TEE2_IMG().read_bytes())
    emu = Emu(flash, sbc=not args.no_sbc, payload_syms=payload_syms,
              stock_ok=LK_IMG().read_bytes())
    uc = emu.uc

    arm_device(emu)

    tee1_part = part_struct(emu, 'tee1', SCRATCH)
    addr_cell, size_cell = SCRATCH + 0x40, SCRATCH + 0x44
    uc.mem_write(addr_cell, struct.pack('<I', 0))  # loader passes *addr == 0

    print('=== phase 1: tee1 crafted-subimage load via REAL part_load '
          '(hijack fires mid-copy) ===')
    ret = emu.call(PART_LOAD, (BDEV, tee1_part, addr_cell, 0xE800, size_cell),
                   timeout=30_000_000)
    print(f'\npart_load -> {ret} ({hex(ret & 0xFFFFFFFF)})')
    for e in emu.events:
        print(' *', e)

    payload_ok = (args.payload is not None and
                  uc.mem_read(PAYLOAD_ADDR, 4) ==
                  args.payload.read_bytes()[:4])
    print(f'payload bytes at 0x101000: {payload_ok}')
    print(f'bdev->read now: {hex(rd32(uc.mem_read(BDEV_READ, 4), 0))}')
    print(f'custom LK at 0x41E00000 head: '
          f'{bytes(uc.mem_read(LK_LOAD_ADDR, 16)).hex()}')

    if emu.stopped:
        print('\nRESULT: emulation stopped on a boot-halting oracle '
              '(see events above).')
        return 0 if input != '' else 0

    if args.skip_tee2:
        return 0

    # --- phase 2: payload's own tee2 loader (REAL payload code) ---
    if args.elf and args.elf.exists():
        syms = parse_elf_symbols(args.elf)
        bltp = syms.get('bldr_load_tee_part')
        if bltp:
            print('\n=== phase 2: REAL bldr_load_tee_part("tee2") ===')
            namep = SCRATCH + 0x80
            uc.mem_write(namep, b'tee2\x00')
            taddr, tsize = SCRATCH + 0x50, SCRATCH + 0x54
            uc.mem_write(taddr, struct.pack('<I', TEE_LOAD_ADDR))
            ret2 = emu.call(bltp, (namep, BDEV, taddr, 0, tsize),
                            timeout=30_000_000)
            print(f'bldr_load_tee_part -> {ret2}')
            # ARB check with the payload's patch applied
            ret3 = emu.call(0x2019B0, (), timeout=5_000_000)
            print(f'ARB check (patched) -> {ret3}  (0 == pass)')
            print(f'RSA verify calls total: {emu.verify_calls}')
            ok = (ret2 == 0 and ret3 == 0 and
                  emu.verify_calls == 0 and not emu.stopped)
            verdict['exploit-chain'] = ok
            print('\nRESULT: ' + ('CHAIN COMPLETE - custom LK staged at '
                                  '0x41E00000, tee2 verified, ARB passes.'
                                  if ok else 'CHAIN INCOMPLETE - see events.'))
    print()
    for e in emu.events:
        print(' *', e)

    if args.preflight:
        print('\n########## PREFLIGHT VERDICT ##########')
        go = all(verdict.values())
        for k, v in verdict.items():
            print(f'  {"PASS" if v else "FAIL"}  {k}')
        print('########## ' + ('GO - kit validated for flashing'
                               if go else 'NO-GO - fix failures first') + ' ##########')
        sys.exit(0 if go else 1)


if __name__ == '__main__':
    main()
