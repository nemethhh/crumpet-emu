#!/usr/bin/env python3
# Donor: WS/tools/kamakiri/ida/derive_lk_patches.py
# Upstream: R0rt1z2/kamakiri
# Copied verbatim: 2026-10-31 (path fixes as verify_lk_patches.py:
#   WS/REPO workspace constants and DEFAULT_DONOR/KEY_CONTINUITY/
#   DEFAULT_OUT globals -> lazy default_donor()/key_continuity_json()/
#   default_out() resolving through crumpet_emu.resources; PATCH_TABLE
#   reduced to its basename — only .name is used, the table is written
#   next to --out. Plan amendment: this dependency of
#   tools/verify_lk_patches.py joins the Task 8 port inventory)
"""Derive, apply and emit the crumpet patched-LK patch set (approach B).

Patches the stock LK selected by the committed key_continuity.json
(own artifact; lk_year 2025 -> resources.resolve('lk', '2025'), VMA
0x41E00000, 0x200-byte MTK header) and writes the patched image
(default resources.resolve('lk-patched', '2021')) plus a patch table
(lk_patches.json, written next to the output).

Patch set (surgical, nothing else — design doc §7.5):
  1. cmd_lock_check gate @0x41E0EF18 (recovery-notes/lk-vuln-fastboot-oem.md
     §2.1 / lk-vuln-oem-cmdline-tiebreaker.md §2): the fastboot dispatcher's
     per-command lock gate, fail-closed on locked HW via the "oem"/"flash"
     blocklist. Neutered lkpatcher-style: movs r0,#0; bx lr (0020 7047) —
     the gate returns "allowed" unconditionally, i.e. always passes as
     unlocked. restricted_state (FUN_41e0eef4) itself is NOT patched: it has
     two other callers (SELinux/veritymode cmdline gates) that must keep
     stock behaviour.
  2. vbstate warning decision FUN_41e114b0 @0x41E114B0
     (recovery-notes/lk-vuln-cmdline-vboot.md §3.2): switch over
     *g_vbstate — ORANGE(1) tail-calls the warning printer, YELLOW/RED(2..3)
     prints the warning banner and returns -1; both warning paths end in a
     5-second mdelay(0x1388). Neutered: movs r0,#0; bx lr — no orange/red
     warning, no 5 s stall, caller publishes verifiedbootstate. This is the
     direct analogue of lkpatcher's orange_state patch (same function shape
     in the older Fire LK: 08b5 0a4b 7b44 1b68 ...).
  3. RED-abort branch @0x41E1158C inside boot_image_verify_and_vb
     (FUN_41e11548): "cbnz r0, 0x41e115ae" skips the RED block when the
     SHA/RSA verify (FUN_41e00f58) succeeds. On failure LK sets
     *vbstate=3, returns -0xD and the boot dispatcher falls back to
     fastboot. Rewritten as the unconditional "b 0x41e115ae" (lkpatcher's
     LK_VERIFY_GATE_PATCH idiom, same as amonet-koboreru 0x20F6AA): the
     verify result no longer gates; boot continues down the verified path.
     This is the red_state acceptance.

Site location is re-derived fresh from the binary (signature scan with the
known VMAs from the recovery-notes used only as expected anchors; the
script fails loudly if signature and anchor disagree), then re-verified
after patching. No other byte of the image changes (verify_lk_patches.py
enforces this independently).
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # repo root
from crumpet_emu.resources import own, resolve    # noqa: E402


def default_donor() -> Path:
    """The stock 2025 LK donor (manifest key 2025:lk) — the donor's
    DEFAULT_DONOR module global, resolved lazily so import needs no
    bins."""
    return resolve('lk', '2025')


def key_continuity_json() -> Path:
    """The committed key-continuity record (own artifact, no sha gate)
    — the donor's KEY_CONTINUITY module global, resolved lazily."""
    return own('key_continuity.json')


def default_out() -> Path:
    """The Tier-2 patched-LK output (manifest key 2021:lk-patched,
    parked vendor artifact) — the donor's DEFAULT_OUT module global,
    resolved lazily."""
    return resolve('lk-patched', '2021')


# the donor's build/crumpet/lk_patches.json workspace constant, reduced
# to its basename: only .name is used (the table lands next to --out)
PATCH_TABLE = Path('lk_patches.json')

LK_BASE = 0x41E00000           # code VMA (237568-byte image, 0x200 header)
HDR = 0x200

# --- known anchors (recovery-notes/lk-vuln-fastboot-oem.md,
# --- lk-vuln-oem-cmdline-tiebreaker.md, lk-vuln-cmdline-vboot.md) ---
ANCHOR_CMD_LOCK_CHECK = 0x41E0EF18
ANCHOR_RESTRICTED_STATE = 0x41E0EEF4
ANCHOR_VBWARN = 0x41E114B0     # FUN_41e114b0 (vbstate warning decision)
ANCHOR_VBOOT = 0x41E11548      # FUN_41e11548 (boot_image_verify_and_vb)
ANCHOR_VERIFY_IMG = 0x41E00F58  # SHA/RSA image verify called by VBOOT

RET0 = bytes.fromhex('00207047')      # movs r0,#0 ; bx lr
NOP = bytes.fromhex('00bf')


def vma_off(vma: int) -> int:
    return HDR + (vma - LK_BASE)


def pad(replacement: bytes, sig_len: int) -> bytes:
    assert len(replacement) <= sig_len
    return replacement + NOP * ((sig_len - len(replacement)) // 2)


def find_unique(code: bytes, sig: bytes, expect_vma: int, what: str) -> int:
    hits, i = [], code.find(sig)
    while i != -1:
        hits.append(i + LK_BASE)
        i = code.find(sig, i + 1)
    if len(hits) != 1:
        raise SystemExit(f'{what}: signature not unique ({len(hits)} hits: '
                         f'{[hex(h) for h in hits]})')
    if hits[0] != expect_vma:
        raise SystemExit(f'{what}: signature found at {hits[0]:#x}, expected '
                         f'anchor {expect_vma:#x} — binary does not match the '
                         'analysis notes')
    return hits[0]


def thumb_b(from_vma: int, to_vma: int) -> bytes:
    """Encoding of the T2 unconditional 'b' (halfword 0xE000|imm11)."""
    off = to_vma - (from_vma + 4)
    assert off % 2 == 0 and -(1 << 12) <= off < (1 << 12)
    return struct.pack('<H', 0xE000 | ((off >> 1) & 0x7FF))


def derive_sites(code: bytes) -> list[dict]:
    """Locate all three patch sites in the stock code; return patch table."""
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    sites = []

    # -- 1. cmd_lock_check prologue --------------------------------------
    sig = bytes.fromhex('2de9f34700240546')   # push.w{...}; movs r4,#0; mov r5,r0
    vma = find_unique(code, sig, ANCHOR_CMD_LOCK_CHECK, 'cmd_lock_check')
    # structural corroboration: bl restricted_state at +0xC, cbnz at +0x10
    ins = list(md.disasm(code[vma - LK_BASE: vma - LK_BASE + 0x18], vma))
    mn = [(i.mnemonic, i.op_str) for i in ins]
    if not (mn[5][0] == 'bl' and int(mn[5][1].lstrip('#'), 16) == ANCHOR_RESTRICTED_STATE
            and mn[6][0].startswith('cbnz')):
        raise SystemExit(f'cmd_lock_check@{vma:#x}: expected '
                         f'bl restricted_state+cbnz at +0xC/+0x10, got {mn[5:7]}')
    sites.append({
        'name': 'cmd_lock_check',
        'vma': vma,
        'file_off': vma_off(vma),
        'size': len(sig),
        'stock': code[vma - LK_BASE: vma - LK_BASE + len(sig)].hex(),
        'patched': pad(RET0, len(sig)).hex(),
        'rationale': 'fastboot dispatcher lock gate (single caller bl @'
                     '0x41E1E1FC) returns 0 = allowed: always passes as '
                     'unlocked (lkpatcher "fastboot" idiom)',
    })

    # -- 2. vbstate warning decision -------------------------------------
    sig = bytes.fromhex('08b50a4b7b441b6818680128')
    # push{r3,lr}; ldr r3,[pc,#0x28]; add r3,pc; ldr r3,[r3]; ldr r0,[r3]; cmp r0,#1
    vma = find_unique(code, sig, ANCHOR_VBWARN, 'vbstate_warn')
    ins = list(md.disasm(code[vma - LK_BASE: vma - LK_BASE + 0x2A], vma))
    mn = [(i.mnemonic, i.op_str) for i in ins]
    # the switch: beq -> orange tail-call, yellow/red falls to bl warn + ret -1
    if not (mn[6][0] == 'beq' and mn[10][0] == 'bl'
            and mn[11] == ('mov.w', 'r0, #-1')):
        raise SystemExit(f'vbstate_warn@{vma:#x}: expected ORANGE beq + '
                         f'bl warn + ret -1 switch, got {mn[6:12]}')
    sites.append({
        'name': 'vbstate_warn',
        'vma': vma,
        'file_off': vma_off(vma),
        'size': len(sig),
        'stock': code[vma - LK_BASE: vma - LK_BASE + len(sig)].hex(),
        'patched': pad(RET0, len(sig)).hex(),
        'rationale': 'vbstate warning decision returns 0: no orange/red '
                     'warning banner, no mdelay(5000) stall, verifiedbootstate '
                     'published (lkpatcher orange_state idiom)',
    })

    # -- 3. RED-abort branch inside boot_image_verify_and_vb -------------
    body = code[ANCHOR_VBOOT - LK_BASE: ANCHOR_VBOOT - LK_BASE + 0x70]
    ins = list(md.disasm(body, ANCHOR_VBOOT))
    bl_idx = next((k for k, i in enumerate(ins)
                   if i.mnemonic == 'bl'
                   and int(i.op_str.lstrip('#'), 16) == ANCHOR_VERIFY_IMG), None)
    if bl_idx is None:
        raise SystemExit(f'no bl {ANCHOR_VERIFY_IMG:#x} inside '
                         f'{ANCHOR_VBOOT:#x}..+0x70')
    cbnz = ins[bl_idx + 1]
    if cbnz.mnemonic != 'cbnz' or not cbnz.op_str.startswith('r0, '):
        raise SystemExit(f'instruction after image-verify bl is not '
                         f'cbnz r0: {cbnz.mnemonic} {cbnz.op_str}')
    target = int(cbnz.op_str.split(', ')[-1].lstrip('#'), 16)
    # the skipped block must be the RED write: movs r0,#3; str r0,[rX]; mvn r0,#0xc
    skip = [(i.mnemonic, i.op_str) for i in ins[bl_idx + 2:bl_idx + 10]]
    if not any(m == ('movs', 'r0, #3') for m in skip) or \
            not any(m == ('mvn', 'r0, #0xc') for m in skip):
        raise SystemExit(f'block skipped by cbnz is not the RED write '
                         f'(vbstate=3, ret -0xD): {skip}')
    vma = cbnz.address
    if vma != 0x41E1158C:
        raise SystemExit(f'RED-abort cbnz at {vma:#x}, expected 0x41E1158C')
    sites.append({
        'name': 'red_abort',
        'vma': vma,
        'file_off': vma_off(vma),
        'size': 2,
        'stock': code[vma - LK_BASE: vma - LK_BASE + 2].hex(),
        'patched': thumb_b(vma, target).hex(),
        'rationale': 'verify-fail cbnz rewritten as unconditional b: RED '
                     f'block (vbstate=3, ret -0xD -> fastboot fallback) dead, '
                     f'boot continues (lkpatcher red_state idiom); target '
                     f'{target:#x} unchanged',
    })
    return sites


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--donor', type=Path, default=default_donor())
    ap.add_argument('--out', type=Path, default=default_out())
    args = ap.parse_args()

    rec = json.loads(key_continuity_json().read_text())
    if rec['lk_year'] != '2025':
        raise SystemExit(f'key_continuity lk_year={rec["lk_year"]} — this '
                         'derivation is pinned to the 2025 LK')
    donor = args.donor.read_bytes()
    sha = hashlib.sha256(donor).hexdigest()
    if rec['notes']['lk_images']['lk2025'] != sha:
        raise SystemExit(f'donor sha256 {sha} != key_continuity lk2025 '
                         f'{rec["notes"]["lk_images"]["lk2025"]}')

    code = donor[HDR:]
    sites = derive_sites(code)

    patched = bytearray(donor)
    for s in sites:
        off = s['file_off']
        patched[off:off + s['size']] = bytes.fromhex(s['patched'])
    patched = bytes(patched)

    # self-check: donor untouched elsewhere, sizes preserved
    diff = {i for i in range(len(donor)) if donor[i] != patched[i]}
    allow = set()
    for s in sites:
        allow.update(range(s['file_off'], s['file_off'] + s['size']))
    if not diff or not diff <= allow:
        raise SystemExit(f'patch application touched bytes outside sites: '
                         f'{sorted(diff - allow)[:16]}')

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(patched)
    # the patch table lands NEXT TO the requested output: a custom-OUT
    # build (test/release runs) then never rewrites the tracked canonical
    # build/crumpet/lk_patches.json — only a default-path build refreshes it
    table = args.out.parent / PATCH_TABLE.name
    table.write_text(json.dumps({
        'donor': str(args.donor),
        'donor_sha256': sha,
        'lk_year': rec['lk_year'],
        'out': str(args.out),
        'out_sha256': hashlib.sha256(patched).hexdigest(),
        'sites': sites,
    }, indent=2) + '\n')

    print(f'donor  {args.donor} sha256:{sha}')
    print(f'out    {args.out} sha256:{hashlib.sha256(patched).hexdigest()}')
    for s in sites:
        print(f'  {s["name"]:<15} vma {s["vma"]:#010x} off {s["file_off"]:#07x} '
              f'{s["stock"]} -> {s["patched"]}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
