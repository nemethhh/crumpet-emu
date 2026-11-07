# Donor: WS/tools/kamakiri/emu/tests/test_layer4_closedloop.py
# Upstream: R0rt1z2/kamakiri
# Copied 2026-10-31 (Task 9 port; Import Map + ruled path adaptations):
#   LK_PATCHED build/crumpet/lk-patched.img -> resources.resolve(
#   'lk-patched', '2021') (Tier 2); per-slot AK build dirs -> committed
#   own artifacts (tz-lka/tz-lkb.img + payload-lka/lkb.{elf,bin}); the
#   2021 donor belt -> resources.resolve(name, '2021'); record-selected
#   stock LK WS/img/lk.img -> resources.resolve('lk', '2025'); donor
#   emu_chain (WS/tools/amonet-emu) -> the Task-10 preloader port
#   (crumpet_emu.preloader) — this test importorskips that module as a
#   defensive module gate (no-op since the Task-10 port landed) and
#   drives the same scenario-C surface; the donor's
#   'emu_chain.py --from-chip-dump' CLI subprocess ->
#   scenarios/preloader_chain.py (same argparse surface). Fixture-side
#   build-hint asserts dropped: own()/resolve() raise MissingBinary with
#   a provenance pointer.
"""Task 10 — Layer 4: closed-loop boot proof on the post-flash chip.

test_scenario_c_on_postflash_chip
    Runs the REAL deploy() (crumpet_emu.deploy.main) with the REAL Task-9
    artifacts — resolve('lk-patched', '2021') plus the amonet-koboreru
    crumpet2021-lk{a,b} tz.img/payload variants (committed own
    artifacts) — against the emulated NAND chip through
    FakeTransport/ModeledSession (task-7 session ruling), takes the
    final post-flash chip snapshot (a NandChip.dump()-style
    {page: 4352 B} map with true NAND placement: 4096-B LBA == page),
    and boots it inside emu_chain.py scenario C through the chip-dump-
    backed Flash source:

      * the REAL NS6548 2021 preloader part_load() loads the crafted
        tee1 sub-image FROM THE DUMP — its bdev->read block numbers land
        on the dump's true GPT pages, not on any image file;
      * the REAL payload runs (staged at 0x101000), loads the patched LK
        from its own slot IN THE DUMP, and stages it at LK_LOAD_ADDR
        0x41E00000 byte-identical to lk-patched.img;
      * the payload's abort-tee1 -> tee2 fallback machinery is intact:
        phase-2 bldr_load_tee_part("tee2") reads the stock tee2 from the
        DUMP and completes, the patched ARB check passes, and zero RSA
        verify calls happen.

    The scenario-C assertions mirror tests/test_lk_patches.py's
    test_dual_variant_payloads_built, but every byte served to the
    emulator comes from the post-flash chip dump.

Closes ruling R1 (task 7): the synthetic fixture bytes are replaced by
the real binaries, closing the loop deploy() -> flash -> chip -> boot.

Tier gating: the parked 2021 belt + lk-patched + the record-selected
2025 stock LK. The importorskip module gate (not a failure) is retained
defensively now that the Task-10 preloader port has landed.
"""
import pickle
import struct
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from crumpet_emu.deploy.main import DeployConfig, deploy
from crumpet_emu.flash.gpt import parse_gpt_from_image
from crumpet_emu.flash.image import ChipDumpFlash, GPT
from crumpet_emu.flash.nand import NandChip
from crumpet_emu.resources import REPO_ROOT, available, own, resolve
from crumpet_emu.usb.transport import FakeTransport, ModeledSession

TIER2 = 'tier2: requires parked vendor binaries — see binaries/README.md'
PRELOADER_PENDING = ('awaits the Task-10 preloader port '
                     '(crumpet_emu.preloader, from amonet-emu emu_chain)')

# a stock-looking 2021 unit: every donor at its GPT placement
DONOR_NAMES = ('brhgptpl_0', 'brhgptpl_1', 'brhgptpl_2', 'brhgptpl_3',
               'lk', 'tee1', 'tee2', 'boot')

PAGE_DATA = NandChip.PAGE_DATA            # 4096
PAGE_SPARE = NandChip.PAGE_SPARE          # 256
BCB_SLOT_OFFSET = 30                      # task-7 ruling (misc data plane)


class _SlotArtifacts:
    """The per-slot amonet-koboreru build products (committed own
    artifacts) — the donor's VARIANTS dirs build/crumpet2021-lk{a,b}.
    Resolved lazily so module import never touches the filesystem."""

    def __init__(self, slot: str):
        self._s = slot[-1]                # 'a' | 'b'

    @property
    def tz(self) -> Path:
        return own(f'tz-lk{self._s}.img')

    @property
    def payload_elf(self) -> Path:
        return own(f'payload-lk{self._s}.elf')

    @property
    def payload_bin(self) -> Path:
        return own(f'payload-lk{self._s}.bin')


VARIANTS = {'lk_a': _SlotArtifacts('lk_a'), 'lk_b': _SlotArtifacts('lk_b')}

tier2_closedloop = pytest.mark.skipif(
    not (all(available(n, '2021') for n in DONOR_NAMES)
         and available('lk', '2025')
         and available('lk-patched', '2021')),
    reason=TIER2)


def _emu_chain():
    """The donor's `import emu_chain as ec` surface, Task-10 port shape:
    Emu/arm_device/part_struct/parse_elf_symbols from
    crumpet_emu.preloader.emu, address constants from
    crumpet_emu.preloader.constants. importorskip retained as a
    defensive module gate (no-op since Task 10 landed)."""
    pytest.importorskip('crumpet_emu.preloader.emu', reason=PRELOADER_PENDING)
    pytest.importorskip('crumpet_emu.preloader.constants',
                        reason=PRELOADER_PENDING)
    from crumpet_emu.preloader import constants as pc
    from crumpet_emu.preloader import emu as pe
    return SimpleNamespace(Emu=pe.Emu, arm_device=pe.arm_device,
                           part_struct=pe.part_struct,
                           parse_elf_symbols=pe.parse_elf_symbols,
                           PART_LOAD=pc.PART_LOAD, BDEV=pc.BDEV,
                           PAYLOAD_ADDR=pc.PAYLOAD_ADDR,
                           LK_LOAD_ADDR=pc.LK_LOAD_ADDR,
                           TEE_LOAD_ADDR=pc.TEE_LOAD_ADDR,
                           SCRATCH=pc.SCRATCH)


@pytest.fixture(scope='module')
def postflash(tmp_path_factory):
    """One REAL §7.4 deploy on the emulated chip.

    misc's BCB says the ACTIVE slot is lk_b (task-7 suffix convention),
    so the INACTIVE slot is lk_a: deploy() puts the patched LK on lk_a
    and the crafted tz variant keyed by lk_a (the -lka build, whose
    LK_PART_NAME is 'lk_a') on tee1. Returns the chip, the GPT, the
    final snapshot, and the deploy result.
    """
    donors = {name: resolve(name, '2021') for name in DONOR_NAMES}
    # active-slot stock LK year follows key_continuity.json (lk_year=2025
    # -> resolve('lk','2025')) — same donor the donor repo's shipped
    # config flashed (fix 2)
    donors['lk'] = resolve('lk', '2025')
    cfg = DeployConfig(donors=donors,
                       payload_variants={s: VARIANTS[s].tz for s in VARIANTS},
                       patched_lk=resolve('lk-patched', '2021'),
                       backup_dir=tmp_path_factory.mktemp('layer4') / 'backup')

    chip = NandChip()
    chip.load_donors(donors)
    gpt = parse_gpt_from_image(donors['brhgptpl_0'].read_bytes())

    # misc BCB page-0 with an AOSP slot suffix b'_b\\x00\\x00' (active =
    # lk_b): deploy() never writes misc, this is the only seeding
    bcb = bytearray(b'\xff' * PAGE_DATA)
    bcb[BCB_SLOT_OFFSET:BCB_SLOT_OFFSET + 4] = b'_b\x00\x00'
    chip.erase_block(gpt['misc'][0] // NandChip.PAGES_PER_BLOCK)
    chip.program_page(gpt['misc'][0], bytes(bcb) + b'\xff' * PAGE_SPARE)

    snapshots: list = []
    result = deploy(FakeTransport(ModeledSession(chip)), cfg,
                    snapshots=snapshots)
    assert result, 'deploy() wrote and verified nothing'

    final = snapshots[-1]
    assert final == chip.dump(), 'final snapshot is not the chip end state'
    return SimpleNamespace(chip=chip, gpt=gpt, cfg=cfg, final=final,
                           snapshots=snapshots, result=result)


@tier2_closedloop
def test_scenario_c_on_postflash_chip(postflash):
    ec = _emu_chain()

    gpt, dump = postflash.gpt, postflash.final
    patched = resolve('lk-patched', '2021').read_bytes()
    dsize, = struct.unpack_from('<I', patched, 4)

    # --- dump provenance: the deploy really placed the real artifacts ---
    # inactive slot lk_a carries the patched LK at its true GPT page
    lk_a0 = gpt['lk_a'][0]
    assert dump[lk_a0][:PAGE_DATA] == patched[:PAGE_DATA]
    # tee1 carries the -lka crafted tz variant at its true GPT page
    assert dump[gpt['tee1'][0]][:PAGE_DATA] == \
        postflash.cfg.payload_variants['lk_a'].read_bytes()[:PAGE_DATA]

    # --- scenario C on the dump (chip-dump-backed Flash source) ---
    flash = ChipDumpFlash(dump)
    syms = ec.parse_elf_symbols(VARIANTS['lk_a'].payload_elf)
    emu = ec.Emu(flash, sbc=True, payload_syms=syms,
                 stock_ok=resolve('lk', '2021').read_bytes())
    ec.arm_device(emu)
    uc = emu.uc
    tee1_part = ec.part_struct(emu, 'tee1', ec.SCRATCH)
    addr_cell, size_cell = ec.SCRATCH + 0x40, ec.SCRATCH + 0x44
    uc.mem_write(addr_cell, struct.pack('<I', 0))

    # phase 1: crafted tee1 sub-image load via REAL part_load — the
    # mid-copy hijack fires and the REAL payload main() runs
    emu.call(ec.PART_LOAD,
             (ec.BDEV, tee1_part, addr_cell, 0xE800, size_cell),
             timeout=30_000_000)

    payload_bin = VARIANTS['lk_a'].payload_bin.read_bytes()
    assert bytes(uc.mem_read(ec.PAYLOAD_ADDR, 4)) == payload_bin[:4], \
        'real payload not staged at 0x101000 from the dump'
    assert not emu.stopped and not emu.faulted

    # the payload drove the REAL preloader part_load for its LK slot and
    # the bytes came from the dump's true GPT placement (LBA -> page
    # identity: lk_a header read = 512-B block start, data = start+1)
    assert any(e.startswith("part_load(part='lk_a'")
               for e in emu.events), 'payload never part_load()ed lk_a'
    lk_start_blk = GPT['lk_a'][0]
    assert any(f'blk={lk_start_blk + 1} ' in e for e in emu.events), \
        'no LK data read from lk_a\'s GPT range in the dump'

    # patched LK staged at LK_LOAD_ADDR, byte-identical to lk-patched.img
    staged = bytes(uc.mem_read(ec.LK_LOAD_ADDR, dsize))
    assert staged == patched[0x200:0x200 + dsize], \
        'patched LK at 0x41E00000 differs from lk-patched.img'

    # --- phase 2: the payload's abort-tee1 -> tee2 fallback machinery ---
    bltp = syms.get('bldr_load_tee_part')
    assert bltp, 'payload.elf lacks bldr_load_tee_part'
    namep = ec.SCRATCH + 0x80
    uc.mem_write(namep, b'tee2\x00')
    taddr, tsize = ec.SCRATCH + 0x50, ec.SCRATCH + 0x54
    uc.mem_write(taddr, struct.pack('<I', ec.TEE_LOAD_ADDR))
    ret2 = emu.call(bltp, (namep, ec.BDEV, taddr, 0, tsize),
                    timeout=30_000_000)
    ret3 = emu.call(0x2019B0, (), timeout=5_000_000)

    # tee2 really came from the dump's true tee2 placement too
    tee2_start_blk = GPT['tee2'][0]
    assert any(f'blk={tee2_start_blk + 1} ' in e for e in emu.events), \
        'no tee2 data read from tee2\'s GPT range in the dump'

    assert ret2 == 0 and ret3 == 0 and emu.verify_calls == 0 \
        and not emu.stopped and not emu.faulted, \
        f'scenario C incomplete on the dump (tee2={ret2} arb={ret3} ' \
        f'rsa={emu.verify_calls})'

    # --- the --from-chip-dump CLI path runs the same closed loop ---
    dump_path = Path(postflash.cfg.backup_dir) / 'chip-final.pkl'
    dump_path.write_bytes(pickle.dumps(dump))
    proc = subprocess.run(
        [sys.executable, 'scenarios/preloader_chain.py',
         '--from-chip-dump', str(dump_path),
         '--elf', str(VARIANTS['lk_a'].payload_elf)],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, \
        f'--from-chip-dump CLI failed:\n{proc.stdout}\n{proc.stderr}'
    assert 'CHAIN COMPLETE' in proc.stdout, proc.stdout
