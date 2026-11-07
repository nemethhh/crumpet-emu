# Donor: WS/tools/kamakiri/emu/tests/test_layer5_brom_boot.py
# Upstream: R0rt1z2/kamakiri
# Copied 2026-10-31 (Task 9 port; Import Map + ruled path adaptations):
#   LK_PATCHED -> resources.resolve('lk-patched', '2021') (Tier 2);
#   per-slot AK tz builds -> own('tz-lka.img'/'tz-lkb.img'); the 2021
#   donor belt -> resources.resolve(name, '2021'); record-selected stock
#   LK WS/img/lk.img -> resources.resolve('lk', '2025'). Fixture-side
#   build-hint asserts dropped (own/resolve raise MissingBinary with a
#   provenance pointer). The three NandChip/NfiModel-only tests are
#   Tier 1 (no vendor binary read).
"""Task 11 — Layer 5: real-BROM boot-read proof + intermediate replay.

test_final_state_boots
    The final post-flash chip snapshot boots through the REAL BROM:
    rom 0x0 mapped, the BROM's own boot code walks BRLYT (sub_CC4),
    loads a brhgptpl preloader copy through its real NFI DMA read path,
    the signature-verify pass-oracle (keyed on the 2021 Amazon-signed
    donor hashes — the only crypto stub, documented in
    crumpet_emu/brom/boot.py) accepts it, and the jump to the preloader
    entry executes. With final=True, classify() additionally runs the
    per-page donor-equivalence belt: every written boot-region page in
    the snapshot must byte-match its donor image.

test_all_intermediates_bootable_or_brom
    Every Task-7 deploy prefix snapshot (a NandChip.dump() taken after
    each §7.4 step) classifies as boots_2021_pl or brom_usdl_wait —
    never 'invalid' — proving each intermediate state either boots a
    valid stock combination or stalls in BROM USBDL wait (strap-free
    recovery).

test_erased_boot_region_falls_to_usdl
    With all four brhgptpl copies erased, the real BROM fails the boot
    walk and lands in the USBDL handshake wait: brom_usdl_wait.

classify() runs REAL ROM code only; the NFI register model
(crumpet_emu/flash/nfi.py, hardened for the BROM's own reader in the
task-11 WIP commits) serves every NAND read from the snapshot's chip.
"""
from pathlib import Path
from types import SimpleNamespace

import pytest

from crumpet_emu.brom.boot import classify, last_trace
from crumpet_emu.deploy.main import DeployConfig, deploy
from crumpet_emu.flash.gpt import parse_gpt_from_image
from crumpet_emu.flash.nand import NandChip
from crumpet_emu.resources import available, own, resolve
from crumpet_emu.usb.transport import FakeTransport, ModeledSession

TIER2 = 'tier2: requires parked vendor binaries — see binaries/README.md'

# a stock-looking 2021 unit: every donor at its GPT placement
DONOR_NAMES = ('brhgptpl_0', 'brhgptpl_1', 'brhgptpl_2', 'brhgptpl_3',
               'lk', 'tee1', 'tee2', 'boot')

PAGE_DATA = NandChip.PAGE_DATA            # 4096
PAGE_SPARE = NandChip.PAGE_SPARE          # 256
BCB_SLOT_OFFSET = 30                      # task-7 ruling (misc data plane)

# classify() replays the REAL BROM (common:brom) on top of the parked
# 2021 belt (donor windows + allowlist), the record-selected 2025 stock
# LK, and the patched-LK artifact the deploy fixtures place
tier2_bootproof = pytest.mark.skipif(
    not (available('brom', 'common')
         and all(available(n, '2021') for n in DONOR_NAMES)
         and available('lk', '2025')
         and available('lk-patched', '2021')),
    reason=TIER2)


@pytest.fixture(scope='module')
def deployed(tmp_path_factory):
    """One REAL §7.4 deploy on the emulated chip (layer-4 fixture shape).

    Active slot lk_b -> patched LK on lk_a, crafted -lka tz on tee1.
    """
    donors = {name: resolve(name, '2021') for name in DONOR_NAMES}
    # active-slot stock LK year follows key_continuity.json (lk_year=2025
    # -> resolve('lk','2025')) — same donor the donor repo's shipped
    # config flashed (fix 2)
    donors['lk'] = resolve('lk', '2025')
    cfg = DeployConfig(donors=donors,
                       payload_variants={'lk_a': own('tz-lka.img'),
                                         'lk_b': own('tz-lkb.img')},
                       patched_lk=resolve('lk-patched', '2021'),
                       backup_dir=tmp_path_factory.mktemp('layer5') / 'backup')

    chip = NandChip()
    chip.load_donors(donors)
    gpt = parse_gpt_from_image(donors['brhgptpl_0'].read_bytes())

    # misc BCB page-0 with an AOSP slot suffix b'_b\x00\x00' (active =
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
                           snapshots=snapshots, result=result,
                           donors=donors)


@tier2_bootproof
def test_final_state_boots(deployed):
    assert classify(deployed.final, final=True) == 'boots_2021_pl'
    trace = last_trace()
    # the real BROM did the whole walk, not a shortcut
    assert any(t.startswith('brlyt-walk') for t in trace), trace
    assert any(t.startswith('pl-loaded') for t in trace), trace
    assert any(t.startswith('verify-pass') for t in trace), trace
    assert any(t.startswith('jump') for t in trace), trace


@tier2_bootproof
def test_all_intermediates_bootable_or_brom(deployed):
    assert deployed.snapshots, 'no intermediate snapshots recorded'
    for i, snap in enumerate(deployed.snapshots):
        c = classify(snap)
        assert c in ('boots_2021_pl', 'brom_usdl_wait'), \
            f'prefix {i} classifies {c!r}'
        assert c != 'invalid'


@tier2_bootproof
def test_erased_boot_region_falls_to_usdl(deployed):
    chip = NandChip()
    chip.load_dump(deployed.final)
    for name in ('brhgptpl_0', 'brhgptpl_1', 'brhgptpl_2', 'brhgptpl_3'):
        start, size_lbas = deployed.gpt[name]
        first = start // NandChip.PAGES_PER_BLOCK
        nblocks = (size_lbas + NandChip.PAGES_PER_BLOCK - 1) \
            // NandChip.PAGES_PER_BLOCK
        for b in range(first, first + nblocks):
            chip.erase_block(b)
    assert classify(chip.dump()) == 'brom_usdl_wait'


def test_brom_column_engine_read_fifo_starts_at_column():
    """A BROM engine read with a column offset lands the FIFO window
    at the DATA-PLANE offset it stands for. The BROM computes engine
    columns in FIFO coordinates — units of (1024 data + 64 spare) per
    sector (sub_2098: v20 = v13*1024 + v13*spare_per_sector; 4 units
    cover the whole 4096+256 page) — so a final-tail read at FIFO
    column 0x880 (= 2 units) addresses data offset 0x800.

    Pinned by the task-11 replay: with the FIFO read literally at
    0x880 the bounce got raw[0x880:0xC80], the tail memcpy corrupted
    the image's signature tail (first mismatch page 44 off 0x800) and
    the BROM's own case-3 verify (sub_9AAC) failed with 0x6006."""
    from crumpet_emu.flash.nfi import NfiModel
    chip = NandChip()
    page = 44
    data = bytes((i * 7 + 3) & 0xFF for i in range(NandChip.PAGE_DATA))
    spare = bytes((i * 11 + 5) & 0xFF for i in range(NandChip.PAGE_SPARE))
    chip.erase_block(page // NandChip.PAGES_PER_BLOCK)
    chip.program_page(page, data + spare)
    raw = data + spare

    m = NfiModel(chip)
    landed = []
    m.dma_sink = lambda addr, blob: landed.append((addr, blob))
    m.write(0x238, 0xFD1D0000, 4)          # DMA armed (BROM boot read)
    m.write(m.STRADDR, 0x104258, 4)        # bounce buffer
    m.write(m.CMD, m.CMD_READ_1ST, 4)
    m.write(m.ADDR, 0x880, 4)              # FIFO column: 2 units
    m.write(m.ADDRNOB, page, 4)            # row
    m.write(m.CMD, m.CMD_READ_2ND, 4)
    m.write(m.CON, (1 << 12) | 0x100, 4)   # drain phase: 1 unit
    # FIFO column 0x880 == data offset 0x800: the engine's 1-unit
    # (1024 data bytes) burst lands raw[0x800:0xC00] at the bounce
    assert landed == [(0x104258, raw[0x800:0xC00])], landed
    # the CPU drain loop that follows serves the same window
    got = b''.join(m.read(m.DATAR, 4).to_bytes(4, 'little')
                   for _ in range(256))
    assert got == raw[0x800:0xC00], (
        'DATAR drain after a FIFO-column CON reprogram must start at '
        f'the data-plane offset; first mismatch at '
        f'{next(i for i, (a, b) in enumerate(zip(got, raw[0x800:0xC00])) if a != b):#x}')


def test_load_dump_roundtrip():
    """NandChip.load_dump restores a dumped chip state exactly."""
    chip = NandChip()
    data = bytes((i * 13 + 1) & 0xFF for i in range(NandChip.PAGE_DATA))
    spare = bytes((i * 3 + 7) & 0xFF for i in range(NandChip.PAGE_SPARE))
    chip.erase_block(5)
    chip.program_page(5 * NandChip.PAGES_PER_BLOCK + 7, data + spare)
    dump = chip.dump()
    restored = NandChip()
    restored.load_dump(dump)
    assert restored.dump() == dump
    assert restored.read_page(5 * NandChip.PAGES_PER_BLOCK + 7) == \
        data + spare


def test_brom_reader_drains_linear_page():
    """The BROM's own read engine drains the page FIFO word-by-word
    through the CPU (rom 0x1d28 drain loop) on top of the DMA landing —
    the DATAR bytes must be the page's LINEAR layout (data plane then
    spare), not the stage2 driver's interleaved 512+32 sector format.

    Pinned by the task-11 replay: interleaved staging wrote 32 spare
    bytes (0xFF for image-only donors) over every delivered 512-B
    sector; the corrupted image then failed the BROM's own case-3
    signature gate (*(u32*)(base + size - sig) == 1 read garbage) and
    the boot halted at sub_CA1E -> System halt."""
    from crumpet_emu.flash.nfi import NfiModel
    chip = NandChip()
    page = 8
    data = bytes(i & 0xFF for i in range(NandChip.PAGE_DATA))
    spare = bytes(0xA0 + (i & 0x1F) for i in range(NandChip.PAGE_SPARE))
    chip.erase_block(page // NandChip.PAGES_PER_BLOCK)
    chip.program_page(page, data + spare)

    m = NfiModel(chip)
    # BROM addressing: column in ADDR (one 32-bit store), row in ADDRNOB
    m.write(m.CMD, m.CMD_READ_1ST, 4)
    m.write(m.ADDR, 0, 4)
    m.write(m.ADDRNOB, page, 4)
    m.write(m.CMD, m.CMD_READ_2ND, 4)
    got = b''.join(m.read(m.DATAR, 4).to_bytes(4, 'little')
                   for _ in range((NandChip.PAGE_DATA
                                   + NandChip.PAGE_SPARE) // 4))
    assert got == data + spare, (
        'BROM-protocol DATAR drain must serve the linear page; first '
        f'mismatch at {next(i for i, (a, b) in enumerate(zip(got, data + spare)) if a != b):#x}')
