# Donor: WS/tools/kamakiri/emu/tests/test_lk_patches.py
# Copied 2026-10-31 (Task 9 port; Import Map + ruled path adaptations):
#   STOCK_LK WS/img/lk.img -> resources.resolve('lk', '2025'); LK_PATCHED
#   build/crumpet/lk-patched.img -> resources.resolve('lk-patched', '2021')
#   (both Tier 2); VERIFY_SCRIPT REPO/ida/verify_lk_patches.py ->
#   <repo>/tools/verify_lk_patches.py; per-slot AK build dirs ->
#   committed own artifacts (tz-lka/tz-lkb.img + payload-lka/lkb.{elf,
#   bin}); donor emu_chain -> the Task-10 preloader port
#   (crumpet_emu.preloader) — test_dual_variant_payloads_built
#   importorskips that module as a defensive module gate (no-op since
#   the Task-10 port landed).
"""Task 9 — patched LK + dual-variant payload builds.

test_patch_sites_verified
    Runs tools/verify_lk_patches.py (subprocess) on
    resolve('lk-patched', '2021') and independently re-checks, with
    capstone, that
      * the cmd_lock_check fastboot gate @0x41E0EF18 is neutered
        (movs r0,#0; bx lr -> always "allowed", i.e. passes as unlocked),
      * orange/red verified-boot states are accepted (vbstate warning
        decision @0x41E114b0 neutered; RED-abort branch @0x41e1158c made
        unconditional),
      * every other byte equals the stock 2025 donor
        (resolve('lk', '2025'), sha256 pinned from
        own:key_continuity.json -> lk_year 2025) except the
        three allowlisted patch sites.

test_dual_variant_payloads_built
    Both amonet-koboreru slot variants exist (committed own artifacts),
    differ ONLY in the LK_PART_NAME string bytes, and each runs scenario
    C of the preloader chain (real preloader part_load + real payload):
    the crafted tee1 hijack fires, the payload loads the patched LK from
    its OWN slot (lk_a for the -lka build, lk_b for -lkb — via the GPT
    'lk_b' fixture), stages it at 0x41E00000, and the tee2 fallback +
    patched ARB check complete with zero RSA verify calls.
"""
import struct
import subprocess
import sys

import pytest
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

from crumpet_emu.resources import REPO_ROOT, available, own, resolve

TIER2 = 'tier2: requires parked vendor binaries — see binaries/README.md'
PRELOADER_PENDING = ('awaits the Task-10 preloader port '
                     '(crumpet_emu.preloader, from amonet-emu emu_chain)')

VERIFY_SCRIPT = REPO_ROOT / 'tools' / 'verify_lk_patches.py'


class _SlotArtifacts:
    """The per-slot amonet-koboreru build products (committed own
    artifacts) — the donor's VARIANTS dirs build/crumpet2021-lk{a,b}.
    Resolved lazily so module import never touches the filesystem."""

    def __init__(self, slot: str):
        self._s = slot[-1]                # 'a' | 'b'

    @property
    def tz(self):
        return own(f'tz-lk{self._s}.img')

    @property
    def payload_elf(self):
        return own(f'payload-lk{self._s}.elf')

    @property
    def payload_bin(self):
        return own(f'payload-lk{self._s}.bin')


VARIANTS = {
    'lk_a': _SlotArtifacts('lk_a'),
    'lk_b': _SlotArtifacts('lk_b'),
}

# 2025 LK (per key_continuity.json: lk_year 2025 -> patch this binary)
LK2025_SHA256 = ('c4e87b94b1fb0a39bdf23e4d1aadeee55d'
                 '422072b5a2b43ca3e91275e250b69d')
LK_BASE = 0x41E00000          # code VMA after the 0x200 MTK header
HDR = 0x200

# Patch sites (file offsets = HDR + (vma - LK_BASE)); see the derivation
# evidence in tools/derive_lk_patches.py and the task-9 report.
SITES = {
    'cmd_lock_check': (0x41E0EF18, 8),    # gate -> movs r0,#0; bx lr
    'vbstate_warn':   (0x41E114B0, 12),   # orange/red warn -> movs r0,#0; bx lr
    'red_abort':      (0x41E1158C, 2),    # cbnz r0,pass -> b pass (unconditional)
}

_md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

# tier2_lk gates every parked artifact these tests read: the patch-site
# test reads lk-2025 + lk-patched-2021; dual_variant additionally reads
# 2021:tee2 + 2021:lk (stock_ok) once the preloader port runs it — folded
# in at Task 10 (review minor 2) so partial placement skips, not fails.
tier2_lk = pytest.mark.skipif(
    not (available('lk', '2025') and available('lk-patched', '2021')
         and available('tee2', '2021') and available('lk', '2021')),
    reason=TIER2)


def test_verify_help_needs_no_bins():
    """The --patched default (resolve('lk-patched', '2021')) resolves
    lazily, only when used: --help must work without parked binaries
    (the eager default used to raise MissingBinary before argparse)."""
    proc = subprocess.run([sys.executable, str(VERIFY_SCRIPT), '--help'],
                          capture_output=True, text=True, cwd=REPO_ROOT,
                          timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert '--patched' in proc.stdout


def _disas1(blob, vma):
    ins = list(_md.disasm(blob, vma, count=2))
    assert ins, f'noThumb decode at {vma:#x}'
    return ins


@tier2_lk
def test_patch_sites_verified(tmp_path):
    import hashlib
    stock = resolve('lk', '2025').read_bytes()
    patched = resolve('lk-patched', '2021').read_bytes()

    # donor is the 2025 LK the key-continuity gate selected
    assert hashlib.sha256(stock).hexdigest() == LK2025_SHA256
    assert len(patched) == len(stock), 'patched image must keep donor size'

    # 1. independent verification script exits 0
    proc = subprocess.run([sys.executable, str(VERIFY_SCRIPT)],
                          capture_output=True, text=True, cwd=REPO_ROOT)
    assert proc.returncode == 0, \
        f'verify_lk_patches.py failed:\n{proc.stdout}\n{proc.stderr}'

    # 1b. tamper DETECTION (the committed regression guard for the
    # "NOTHING ELSE" constraint): a copy with one byte flipped OUTSIDE all
    # sites must be rejected by the byte-diff allowlist, and a copy
    # corrupted INSIDE a site must be rejected by the disasm/exact-bytes
    # checks. Both via the --patched override on tmp copies.
    outside = bytearray(patched)
    outside[0x8000] ^= 0xFF          # mid-image, outside every site
    p_out = tmp_path / 'tampered-outside.img'
    p_out.write_bytes(bytes(outside))
    proc = subprocess.run([sys.executable, str(VERIFY_SCRIPT),
                           '--patched', str(p_out)],
                          capture_output=True, text=True, cwd=REPO_ROOT)
    assert proc.returncode != 0, 'verifier accepted an outside-site tamper'
    assert 'outside patch sites' in proc.stdout, \
        f'no allowlist diagnostic:\n{proc.stdout}{proc.stderr}'

    inside = bytearray(patched)
    inside[HDR + (SITES['cmd_lock_check'][0] - LK_BASE)] ^= 0x01  # movs r0 -> r1
    p_in = tmp_path / 'tampered-inside.img'
    p_in.write_bytes(bytes(inside))
    proc = subprocess.run([sys.executable, str(VERIFY_SCRIPT),
                           '--patched', str(p_in)],
                          capture_output=True, text=True, cwd=REPO_ROOT)
    assert proc.returncode != 0, 'verifier accepted an in-site tamper'
    assert 'not neutered' in proc.stdout, \
        f'no disasm diagnostic:\n{proc.stdout}{proc.stderr}'

    code = patched[HDR:]

    # 2. gate neutered: cmd_lock_check now returns 0 (pass as unlocked)
    vma, _ = SITES['cmd_lock_check']
    i0, i1 = _disas1(code[vma - LK_BASE:], vma)[:2]
    assert (i0.mnemonic, i0.op_str) == ('movs', 'r0, #0'), \
        f'gate not neutered: {i0.mnemonic} {i0.op_str}'
    assert (i1.mnemonic, i1.op_str) == ('bx', 'lr'), \
        f'gate does not return: {i1.mnemonic} {i1.op_str}'

    # 3. orange/red accepted: vbstate warning decision neutered (returns 0
    #    -> no orange/yellow/red warning banner, publisher runs)
    vma, _ = SITES['vbstate_warn']
    i0, i1 = _disas1(code[vma - LK_BASE:], vma)[:2]
    assert (i0.mnemonic, i0.op_str) == ('movs', 'r0, #0')
    assert (i1.mnemonic, i1.op_str) == ('bx', 'lr')

    # 4. red accepted: verify-fail branch is now unconditional (RED block
    #    dead; boot continues down the verified path)
    vma, _ = SITES['red_abort']
    i0 = _disas1(code[vma - LK_BASE:], vma)[0]
    assert i0.mnemonic == 'b', \
        f'red-abort branch not unconditional: {i0.mnemonic} {i0.op_str}'
    assert int(i0.op_str.replace('#', ''), 16) == 0x41E115AE, \
        f'red-abort branch retargeted: {i0.op_str}'

    # 5. byte-diff allowlist: patched == stock except inside the 3 sites
    allow = set()
    for vma, size in SITES.values():
        off = HDR + (vma - LK_BASE)
        allow.update(range(off, off + size))
    diff = {i for i in range(len(stock)) if stock[i] != patched[i]}
    assert diff and diff <= allow, \
        f'unexpected byte diffs outside patch sites: {sorted(diff - allow)[:16]}'
    # and every site actually differs (no no-op patches)
    for name, (vma, size) in SITES.items():
        off = HDR + (vma - LK_BASE)
        assert any(stock[off + k] != patched[off + k] for k in range(size)), \
            f'{name}: site bytes identical to stock (patch not applied?)'


@tier2_lk
def test_dual_variant_payloads_built():
    # module gate (defensive importorskip; no-op since the Task-10
    # preloader port landed)
    pytest.importorskip('crumpet_emu.preloader.emu', reason=PRELOADER_PENDING)
    pytest.importorskip('crumpet_emu.preloader.constants',
                        reason=PRELOADER_PENDING)
    from crumpet_emu.flash.image import Flash, GPT
    from crumpet_emu.preloader import constants as pc
    from crumpet_emu.preloader import emu as pe

    tzs, bins = {}, {}
    for slot, d in VARIANTS.items():
        tzs[slot] = d.tz.read_bytes()
        bins[slot] = d.payload_bin.read_bytes()

    # variants differ ONLY in the LK_PART_NAME string bytes ("lk_a"/"lk_b")
    a, b = tzs['lk_a'], tzs['lk_b']
    assert len(a) == len(b)
    diffs = [i for i in range(len(a)) if a[i] != b[i]]
    assert diffs, 'variants are byte-identical (LK_SLOT knob had no effect?)'
    for i in diffs:
        assert (a[i], b[i]) == (0x61, 0x62), \
            f'variant diff at {i:#x} is not lk_a->lk_b: {a[i]:#x}/{b[i]:#x}'
        assert a[i - 3:i + 1] == b'lk_a' and b[i - 3:i + 1] == b'lk_b', \
            f'variant diff at {i:#x} not inside an LK_PART_NAME string'

    # each variant loads in scenario C (real preloader + real payload):
    # crafted tee1 hijack -> payload loads the patched LK from ITS slot ->
    # staged at 0x41E00000 -> tee2 fallback + patched ARB, 0 RSA verifies.
    patched_lk = resolve('lk-patched', '2021').read_bytes()
    dsize, = struct.unpack_from('<I', patched_lk, 4)

    for slot, d in VARIANTS.items():
        flash = Flash(tzs[slot], patched_lk, resolve('tee2', '2021').read_bytes())
        syms = pe.parse_elf_symbols(d.payload_elf)
        emu = pe.Emu(flash, sbc=True, payload_syms=syms,
                     stock_ok=resolve('lk', '2021').read_bytes())
        pe.arm_device(emu)
        uc = emu.uc
        tee1_part = pe.part_struct(emu, 'tee1', pc.SCRATCH)
        addr_cell, size_cell = pc.SCRATCH + 0x40, pc.SCRATCH + 0x44
        uc.mem_write(addr_cell, struct.pack('<I', 0))

        # phase 1: crafted sub-image load via REAL part_load (hijack fires
        # mid-copy; payload main() runs, incl. bldr_load_part(LK_PART_NAME))
        emu.call(pc.PART_LOAD,
                 (pc.BDEV, tee1_part, addr_cell, 0xE800, size_cell),
                 timeout=30_000_000)

        assert bytes(uc.mem_read(pc.PAYLOAD_ADDR, 4)) == \
            bins[slot][:4], f'{slot}: payload not staged at 0x101000'
        lk_loads = [e for e in emu.events if e.startswith(f'part_load(part={slot!r}')]
        assert lk_loads, f'{slot}: payload never part_load()ed its LK slot'
        # data really came from this slot's GPT range (blk = start is the
        # 1-block partition header read, start+1.. is the LK data)
        start_blk = GPT[slot][0]
        assert any(f'blk={start_blk + 1} ' in e for e in emu.events), \
            f'{slot}: no data read from its GPT range'
        staged = bytes(uc.mem_read(pc.LK_LOAD_ADDR, dsize))
        assert staged == patched_lk[HDR:HDR + dsize], \
            f'{slot}: patched LK not staged byte-exact at 0x41E00000'
        assert not emu.stopped and not emu.faulted

        # phase 2: REAL payload tee2 loader + patched ARB check
        bltp = syms.get('bldr_load_tee_part')
        assert bltp, 'payload.elf lacks bldr_load_tee_part'
        namep = pc.SCRATCH + 0x80
        uc.mem_write(namep, b'tee2\x00')
        taddr, tsize = pc.SCRATCH + 0x50, pc.SCRATCH + 0x54
        uc.mem_write(taddr, struct.pack('<I', pc.TEE_LOAD_ADDR))
        ret2 = emu.call(bltp, (namep, pc.BDEV, taddr, 0, tsize),
                        timeout=30_000_000)
        ret3 = emu.call(0x2019B0, (), timeout=5_000_000)
        assert ret2 == 0 and ret3 == 0 and emu.verify_calls == 0 \
            and not emu.stopped, \
            f'{slot}: scenario C incomplete (tee2={ret2} arb={ret3} ' \
            f'rsa={emu.verify_calls})'
