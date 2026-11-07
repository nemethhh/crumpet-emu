#!/usr/bin/env python3
# Donor: WS/tools/kamakiri/ida/verify_lk_patches.py
# Upstream: R0rt1z2/kamakiri
# Copied verbatim: 2026-10-31 (path fixes: WS/REPO workspace constants and
#   DONOR/KEY_CONTINUITY/PATCHED globals -> lazy stock_lk()/
#   key_continuity_json()/patched_default() resolving through
#   crumpet_emu.resources; identity sibling import of derive_lk_patches
#   kept — the tool ships alongside it in tools/)
"""Verify a patched LK image (default resources.resolve('lk-patched',
'2021')) against the stock 2025 LK donor. `--patched PATH` overrides the
image under test (used by the test suite to exercise tamper detection).

Exit 0 iff ALL of the following hold:
  * the patched image exists and is the same size as the donor
    (resources.resolve('lk', '2025'), sha256 pinned to the
    key_continuity.json lk2025 hash);
  * the three derivation sites (gate / vbstate warning / RED-abort branch)
    are re-derived fresh from the STOCK donor and each patched site's
    disassembly shows the neutered semantics:
      - cmd_lock_check @0x41E0EF18        -> movs r0,#0 ; bx lr
      - vbstate warn    @0x41E114B0       -> movs r0,#0 ; bx lr
      - RED-abort       @0x41E1158C       -> unconditional b <old cbnz target>
  * the patched image differs from the donor ONLY inside those sites
    (byte-diff allowlist) and every site actually differs;
  * the fastboot dispatcher's single call site (bl cmd_lock_check @
    0x41E1E1FC) is byte-identical to stock — the patch lives in the callee,
    not the caller.

Independent of derive_lk_patches.py: no patch table is trusted; sites are
re-derived from the stock binary with the same anchor+signature logic.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # repo root
from crumpet_emu.resources import own, resolve    # noqa: E402


def stock_lk() -> Path:
    """The stock 2025 LK donor (manifest key 2025:lk) — the donor's
    DONOR module global, resolved lazily so import needs no bins."""
    return resolve('lk', '2025')


def key_continuity_json() -> Path:
    """The committed key-continuity record (own artifact, no sha gate)
    — the donor's KEY_CONTINUITY module global, resolved lazily."""
    return own('key_continuity.json')


def patched_default() -> Path:
    """The Tier-2 patched LK build (manifest key 2021:lk-patched,
    parked vendor artifact) — the donor's PATCHED module global,
    resolved lazily."""
    return resolve('lk-patched', '2021')

LK_BASE = 0x41E00000
HDR = 0x200
DISPATCHER_CALL = 0x41E1E1FC        # the single bl cmd_lock_check site

_md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)


def fail(msg):
    print(f'FAIL: {msg}')
    return 1


def disas(code, vma, count=2):
    return list(_md.disasm(code[vma - LK_BASE:], vma, count=count))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--patched', type=Path, default=None,
                    help='patched image to verify (default: the Tier-2 '
                         'lk-patched build, resources.resolve('
                         'lk-patched, 2021) — resolved lazily so --help '
                         'works without parked binaries)')
    args = ap.parse_args(argv)

    # import the derivation logic (same file, fresh re-derivation of sites)
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import derive_lk_patches as D

    # the default resolves lazily, only when the value is actually used
    patched_path = (args.patched if args.patched is not None
                    else patched_default())
    rec = json.loads(key_continuity_json().read_text())
    if rec['lk_year'] != '2025':
        return fail(f'key_continuity lk_year={rec["lk_year"]}, expected 2025')
    stock = stock_lk().read_bytes()
    sha = hashlib.sha256(stock).hexdigest()
    if sha != rec['notes']['lk_images']['lk2025']:
        return fail(f'stock donor sha256 {sha} != key_continuity lk2025')

    if not patched_path.is_file():
        return fail(f'{patched_path} missing (run ida/derive_lk_patches.py)')
    patched = patched_path.read_bytes()
    if len(patched) != len(stock):
        return fail(f'size {len(patched)} != donor {len(stock)}')

    sites = {s['name']: s for s in D.derive_sites(stock[HDR:])}
    rc = 0

    # --- per-site disassembly of the patched image ----------------------
    ins = disas(patched[HDR:], sites['cmd_lock_check']['vma'], 2)
    got = [(i.mnemonic, i.op_str) for i in ins]
    if got != [('movs', 'r0, #0'), ('bx', 'lr')]:
        rc = fail(f'cmd_lock_check not neutered: {got}')

    ins = disas(patched[HDR:], sites['vbstate_warn']['vma'], 2)
    got = [(i.mnemonic, i.op_str) for i in ins]
    if got != [('movs', 'r0, #0'), ('bx', 'lr')]:
        rc = fail(f'vbstate warning decision not neutered: {got}')

    red = sites['red_abort']
    # stock target of the cbnz (re-derived from the donor): locate the
    # cbnz after the bl VERIFY_IMG using the full decoder
    body = list(_md.disasm(stock[HDR:][D.ANCHOR_VBOOT - LK_BASE:
                                        D.ANCHOR_VBOOT - LK_BASE + 0x70],
                           D.ANCHOR_VBOOT))
    bl_idx = next(k for k, i in enumerate(body)
                  if i.mnemonic == 'bl'
                  and int(i.op_str.lstrip('#'), 16) == D.ANCHOR_VERIFY_IMG)
    cbnz = body[bl_idx + 1]
    target = int(cbnz.op_str.split(', ')[-1].lstrip('#'), 16)
    ins = disas(patched[HDR:], red['vma'], 1)
    i0 = ins[0]
    if i0.mnemonic != 'b' or int(i0.op_str.lstrip('#'), 16) != target:
        rc = fail(f'RED-abort branch not neutered (want unconditional b '
                  f'{target:#x}, got {i0.mnemonic} {i0.op_str})')

    # --- byte-diff allowlist --------------------------------------------
    allow = set()
    for s in sites.values():
        allow.update(range(s['file_off'], s['file_off'] + s['size']))
    diff = {i for i in range(len(stock)) if stock[i] != patched[i]}
    if not diff:
        rc = fail('patched image is byte-identical to stock')
    extra = sorted(diff - allow)
    if extra:
        rc = fail(f'bytes changed outside patch sites: {extra[:16]}')
    for name, s in sites.items():
        off = s['file_off']
        if not any(stock[off + k] != patched[off + k]
                   for k in range(s['size'])):
            rc = fail(f'{name}: site identical to stock (patch missing)')
        # exact-bytes: the site must equal the freshly derived replacement
        # (movs r0,#0; bx lr + nop padding, or the recomputed b encoding) —
        # catches corruption inside a site the disasm spot-checks miss
        got = patched[off:off + s['size']].hex()
        if got != s['patched']:
            rc = fail(f'{name}: site bytes {got} != derived replacement '
                      f'{s["patched"]}')

    # --- dispatcher call site must be stock ------------------------------
    d = DISPATCHER_CALL - LK_BASE + HDR
    if stock[d:d + 4] != patched[d:d + 4]:
        rc = fail('dispatcher bl cmd_lock_check @0x41E1E1FC was modified')
    ci = disas(patched[HDR:], DISPATCHER_CALL, 1)[0]
    if ci.mnemonic != 'bl' or \
            int(ci.op_str.lstrip('#'), 16) != sites['cmd_lock_check']['vma']:
        rc = fail(f'dispatcher call no longer targets cmd_lock_check: '
                  f'{ci.mnemonic} {ci.op_str}')

    if rc == 0:
        print('OK: gate neutered, orange/red accepted, dispatcher caller '
              'stock, byte-diff confined to the 3 derived sites')
        print(f'  patched sha256:{hashlib.sha256(patched).hexdigest()}')
        for name in ('cmd_lock_check', 'vbstate_warn', 'red_abort'):
            s = sites[name]
            print(f'  {name:<15} vma {s["vma"]:#010x} '
                  f'{s["stock"]} -> {s["patched"]}')
    return rc


if __name__ == '__main__':
    sys.exit(main())
