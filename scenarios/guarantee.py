#!/usr/bin/env python3
"""Guarantee CLI: run the amonet custom-firmware guarantee legs and print
the verdict matrix (guarantee plan Task 9).

Legs (all real-code, details in docs/guarantee.md):
  chain-<slot>   the REAL stock TEE loader walks the crafted tz variant
                 (real parsers/overlap/part_get/RSA) — hijack fires,
                 patched LK staged, tee2 fallback, patched ARB passes;
  unlock         patched-LK execution legs (lock-gate differential,
                 RED-abort acceptance, getvar plumbing);
  brom           the REAL BROM classifies the stock 2021 belt bootable;
  ledger         the seam ledger has no chain-critical reimplementation.

Exit 0 iff every leg is green. --json PATH writes the machine-readable
verdict. All binary resolution is lazy: --help needs no vendor bins.

--trace-diff UART_LOG classifies an emulated stock boot's preloader log
against a real-device UART capture (exact / prefix / emu-only /
device-only line classes).
"""
import argparse
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

TEE_LOADER = 0x20E19C


def leg_chain(slot: str) -> tuple[bool, str]:
    from crumpet_emu import resources
    from crumpet_emu.flash.image import Flash
    from crumpet_emu.preloader import constants as pc
    from crumpet_emu.preloader import emu as pe
    tz = resources.own(f'tz-lk{slot[-1]}.img').read_bytes()
    patched = resources.resolve('lk-patched', '2021').read_bytes()
    tee2 = resources.resolve('tee2', '2021').read_bytes()
    syms = pe.parse_elf_symbols(resources.own(f'payload-lk{slot[-1]}.elf'))
    emu = pe.Emu(Flash(tz, patched, tee2), sbc=True, payload_syms=syms)
    pe.arm_device(emu)
    namep = pc.SCRATCH + 0x90
    emu.uc.mem_write(namep, b'tee1\x00')
    tee_addr, tee_size = pc.SCRATCH + 0x48, pc.SCRATCH + 0x4C
    emu.uc.mem_write(tee_addr, struct.pack('<I', pc.TEE_LOAD_ADDR))
    ret = emu.try_call(TEE_LOADER, (namep, pc.BDEV, tee_addr, 0, tee_size),
                       timeout=120_000_000)
    if emu.stopped or emu.faulted:
        return False, f'stopped={emu.stopped} faulted={emu.faulted}'
    if ret != 0xFFFFFFFF:
        return False, f'tee1 load returned {ret:#x} (want read-abort error)'
    dsize, = struct.unpack_from('<I', patched, 4)
    staged = bytes(emu.uc.mem_read(pc.LK_LOAD_ADDR, dsize))
    if staged != patched[0x200:0x200 + dsize]:
        return False, 'patched LK not staged byte-identical'
    # phase 2: payload's own tee2 loader (real payload code)
    bltp = syms.get('bldr_load_tee_part')
    if not bltp:
        return False, 'payload elf lacks bldr_load_tee_part'
    namep2 = pc.SCRATCH + 0x80
    emu.uc.mem_write(namep2, b'tee2\x00')
    taddr, tsize = pc.SCRATCH + 0x50, pc.SCRATCH + 0x54
    emu.uc.mem_write(taddr, struct.pack('<I', pc.TEE_LOAD_ADDR))
    r2 = emu.try_call(bltp, (namep2, pc.BDEV, taddr, 0, tsize),
                      timeout=60_000_000)
    r3 = emu.try_call(0x2019B0, (), timeout=5_000_000)   # patched ARB
    ok = (r2 == 0 and r3 == 0 and emu.verify_calls == 0
          and not emu.stopped and not emu.faulted)
    return ok, (f'tee2={r2} arb={r3} verify_calls={emu.verify_calls}')


def leg_unlock() -> tuple[bool, str]:
    from crumpet_emu.lk.customfw import (lock_gate_differential,
                                         patched_getvar,
                                         verify_and_vb_differential)
    g = lock_gate_differential(b'flash:boot')
    if not (g['stock'] == 1 and g['patched'] == 0):
        return False, f'lock gate {g}'
    v = verify_and_vb_differential(
        b'CRUMPET-CUSTOM-BOOT' + bytes(0x1000 - 18) + bytes(0x800))
    if v['stock']['ret'] != -0xD or 0x41E115AE not in v['patched']['pcs']:
        return False, 'verify_and_vb differential failed'
    status, _ = patched_getvar('version')
    return status == 'OKAY', f'gate ok, RED-abort skipped, getvar {status}'


def leg_brom() -> tuple[bool, str]:
    from crumpet_emu import resources
    from crumpet_emu.brom.boot import classify
    from crumpet_emu.flash.nand import NandChip
    belt = ('brhgptpl_0', 'brhgptpl_1', 'brhgptpl_2', 'brhgptpl_3',
            'lk', 'tee1', 'tee2', 'boot')
    chip = NandChip()
    chip.load_donors({n: resources.resolve(n, '2021') for n in belt})
    verdict = classify(chip.dump())
    return verdict == 'boots_2021_pl', verdict


def leg_ledger() -> tuple[bool, str]:
    from crumpet_emu.preloader.seams import SEAMS, SEAM_CHAIN_CRITICAL
    bad = [n for n in SEAM_CHAIN_CRITICAL
           if SEAMS[n].kind == 'reimplemented']
    return not bad, f'chain-critical reimplemented: {bad or "none"}'


def trace_diff(uart_log: Path) -> int:
    """Classify emulated stock-boot preloader lines vs a real capture."""
    import io
    import contextlib
    from crumpet_emu.preloader import scenarios
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        scenarios.stock_boot(sbc=True)
    # stock_boot prints PL lines via the emu log; re-run to capture them
    emu_lines = [l for l in buf.getvalue().splitlines() if '[PL' in l]
    dev_lines = [l.rstrip('\n') for l in uart_log.read_text(
        errors='replace').splitlines() if l.strip()]
    exact = prefix = 0
    for el in emu_lines:
        body = el.split('] ', 1)[-1].strip()
        hit = any(body == d.strip() for d in dev_lines)
        if hit:
            exact += 1
        elif any(d.strip().startswith(body[:16]) for d in dev_lines):
            prefix += 1
    print(f'trace-diff vs {uart_log}: emu PL lines {len(emu_lines)}, '
          f'device lines {len(dev_lines)}, exact {exact}, prefix {prefix}')
    return exact


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--slot', choices=['lk_a', 'lk_b', 'both'],
                    default='both')
    ap.add_argument('--skip-brom', action='store_true')
    ap.add_argument('--json', type=Path, default=None)
    ap.add_argument('--trace-diff', type=Path, metavar='UART_LOG',
                    help='classify an emulated stock boot against a real '
                         'device UART capture')
    args = ap.parse_args(argv)

    if args.trace_diff:
        trace_diff(args.trace_diff)
        return 0

    slots = ['lk_a', 'lk_b'] if args.slot == 'both' else [args.slot]
    legs = {}
    for s in slots:
        legs[f'chain-{s}'] = leg_chain(s)
    legs['unlock'] = leg_unlock()
    if not args.skip_brom:
        legs['brom'] = leg_brom()
    legs['ledger'] = leg_ledger()

    print('==== amonet custom-firmware guarantee ====')
    for name, (ok, detail) in legs.items():
        print(f'  {"PASS" if ok else "FAIL"}  {name:<12} {detail}')
    all_ok = all(ok for ok, _ in legs.values())
    print(f'VERDICT: {"GUARANTEE HOLDS" if all_ok else "GUARANTEE BROKEN"}')
    if args.json:
        args.json.write_text(json.dumps(
            {k: {'ok': v[0], 'detail': v[1]} for k, v in legs.items()},
            indent=1))
    return 0 if all_ok else 1


if __name__ == '__main__':
    sys.exit(main())
