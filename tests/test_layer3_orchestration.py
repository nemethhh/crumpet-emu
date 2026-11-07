# Donor: WS/tools/kamakiri/emu/tests/test_layer3_orchestration.py
# Upstream: R0rt1z2/kamakiri
# Copied 2026-10-31 (Task 9 port; Import Map + ruled path adaptations):
#   DONOR_DIR belt images -> resources.resolve(name, '2021'); the
#   key-continuity-selected stock LK WS/img/lk.img ->
#   resources.resolve('lk', '2025'); stage1/stage2 -> own artifacts (the
#   donor's `make -C brom-payload` build step is dropped — no make in
#   this repo); ROM -> resolve('brom', 'common'). Ruling (task 9): the
#   donor's test_shipped_lk_donor_matches_key_continuity_record also
#   asserted modules.bootrom_main.hardware_donors() — the donor's
#   live-hardware exploit entry, out of emulator-repo scope and never
#   ported; that half is dropped (its assertion duplicated this test's
#   own donor table, see the adapted test below).
"""Layer 3 — orchestration dry-run: spec §7.4 order with fail-closed gates.

The five pinned tests from the task brief plus two consistency proofs:

    test_postflash_state_asserts            — final chip state per §7.4
    test_backup_hashes_recorded             — sha256 manifest + files
    test_slot_undetermined_aborts_before_any_write
                                            — Review Focus #5, zero writes
    test_wdt_cadence_holds_during_full_deploy
                                            — Review Focus #3, modeled WDT
    test_intermediate_states_bootable_or_brom
                                            — snapshot-prefix invariant
    test_transport_framing_against_real_stage2
                                            — FakeTransport byte surface
                                              drives the REAL BROM+stage2
    test_shipped_lk_donor_matches_key_continuity_record
                                            — lk_year record vs fixtures

Session ruling (task 7): the multi-MB full-deploy runs use
usb.transport.ModeledSession — a fast Stage2Session stand-in that fronts
the SAME NandChip model and the SAME harness Watchdog model, advancing
the watchdog by per-op tick costs measured against the real Unicorn
harness (kick 1.6k / erase 2.7k / page-write 256k / page-read 196k
ticks). The real per-op protocol path was pinned in Tasks 4–6 and is
re-pinned here once at the FakeTransport byte-stream level
(test_transport_framing_against_real_stage2); driving ~13k page ops
(~20 min) through Unicorn per orchestration test is not tractable.

Slot-suffix ruling (task 7, binding): the active slot is detected
READ-ONLY from the AOSP boot_control HAL placement inside the 2048-byte
bootloader_message that begins misc's first page — the 4-byte slot
suffix at data-plane offset 30 (b'_a\\x00\\x00' / b'a\\x00\\x00' style,
optional leading underscore, trailing NULs). Anything else (erased
0xFF, zeros, garbage) raises SlotUndetermined and the deploy performs
ZERO writes. misc itself is never written.

Ruling R1: payload_variants and patched_lk are SYNTHETIC deterministic
bytes here (sized like the real artifacts: LK-class 233472 B, tz-class
2367488 B). Task 10 re-runs deploy() with the real binaries. Donors are
the real 2021 set (binaries/vendor/2021/, Tier 2).

Tier gating: every test here reads the parked donor belt (2021
brhgptpl_0..3 + tee1/tee2/boot, 2021 lk for the record cross-check,
2025 lk for the record-selected stock LK); the framing test additionally
needs common:brom.
"""
import json
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from crumpet_emu.brom.harness import BromHarness, Stage2Session
from crumpet_emu.deploy import functions as fc
from crumpet_emu.deploy.main import (DeployConfig, SlotUndetermined,
                                     detect_active_slot, deploy)
from crumpet_emu.flash.gpt import parse_gpt_from_image
from crumpet_emu.flash.nand import NandChip
from crumpet_emu.flash.nfi import NfiModel
from crumpet_emu.resources import available, own, resolve
from crumpet_emu.usb.transport import FakeTransport, ModeledReboot, ModeledSession

TIER2 = 'tier2: requires parked vendor binaries — see binaries/README.md'

PAGE_DATA = NandChip.PAGE_DATA            # 4096
PAGE_TOTAL = NandChip.PAGE_DATA + NandChip.PAGE_SPARE

DONOR_NAMES = ('brhgptpl_0', 'brhgptpl_1', 'brhgptpl_2', 'brhgptpl_3',
               'lk', 'tee1', 'tee2', 'boot')
NEVER_PARTITIONS = ('misc', 'idme_nand', 'persist',
                    'reserve0', 'reserve1', 'reserve2', 'reserve3')

# BCB slot-suffix offset inside the 2048-byte bootloader_message (ruling
# above): 4 bytes at data-plane offset 30
BCB_SLOT_OFFSET = 30


def _belt_ready() -> bool:
    """The full §7.4 donor set the fixtures load: the 2021 belt plus the
    record-selected 2025 stock LK."""
    return (all(available(n, '2021') for n in DONOR_NAMES)
            and available('lk', '2025'))


tier2_belt = pytest.mark.skipif(not _belt_ready(), reason=TIER2)
# tier2_framing gate is intentionally conservative: it requires the whole
# belt + brom, covering more artifacts than the framing test below reads.
tier2_framing = pytest.mark.skipif(
    not (_belt_ready() and available('brom', 'common')), reason=TIER2)
tier2_lk_record = pytest.mark.skipif(
    not (available('lk', '2021') and available('lk', '2025')), reason=TIER2)


def _synth(n: int, seed: int) -> bytes:
    """Deterministic synthetic payload bytes (ruling R1)."""
    return bytes((seed + (i * 31) + (i >> 9) & 0xFF) for i in range(n))


def _donors() -> dict[str, Path]:
    donors = {name: resolve(name, '2021') for name in DONOR_NAMES}
    # The ACTIVE-slot stock LK follows the key-continuity decision record
    # (own:key_continuity.json: lk_year=2025 -> 2025 lk.img):
    # §7.4 step 6 writes the 2025 stock LK into the active slot — the
    # same donor the shipped hardware config flashed. The baseline chip
    # gets it too (both lk slots pre-seeded with 2025 stock — the real
    # unit's state), so the step-6 write is the same-content refresh it
    # is on hardware (final-review fix 2).
    donors['lk'] = resolve('lk', '2025')
    return donors


def _bcb_page(suffix: bytes) -> bytes:
    """A 4352-byte misc page-0 carrying an AOSP bootloader_message whose
    slot suffix (offset 30) is `suffix`; everything else 0xFF."""
    data = bytearray(b'\xff' * PAGE_DATA)
    data[BCB_SLOT_OFFSET:BCB_SLOT_OFFSET + 4] = suffix
    return bytes(data) + b'\xff' * NandChip.PAGE_SPARE


def _stock_chip() -> NandChip:
    """A donor-loaded chip that looks like a 2021 stock unit: every donor
    at its GPT placement, misc erased (caller programs the BCB page)."""
    chip = NandChip()
    chip.load_donors(_donors())
    return chip


def _program_bcb(chip: NandChip, gpt: dict, suffix: bytes) -> None:
    chip.erase_block(gpt['misc'][0] // NandChip.PAGES_PER_BLOCK)
    chip.program_page(gpt['misc'][0], _bcb_page(suffix))


def _part_pages(gpt: dict, part: str):
    start, size = gpt[part]
    return range(start, start + size)


def _read_part_planes(chip: NandChip, gpt: dict, part: str) -> bytes:
    """The partition's full on-flash image as concatenated data planes."""
    return b''.join(chip.read_page(p)[:PAGE_DATA]
                    for p in _part_pages(gpt, part))


@pytest.fixture(scope='module')
def images():
    return own('stage1.bin').read_bytes(), own('stage2.bin').read_bytes()


@pytest.fixture(scope='module')
def deployed(tmp_path_factory):
    """One full §7.4 deploy against the modeled session: active slot lk_a
    (misc BCB b'_a\\x00\\x00'), 2021 donors, synthetic crafted payloads."""
    donors = _donors()
    out = tmp_path_factory.mktemp('layer3')
    patched_lk = out / 'lk-patched.img'
    patched_lk.write_bytes(_synth(233_472, 0x5A))          # LK-sized
    variants = {}
    for slot, seed in (('lk_a', 0xC1), ('lk_b', 0xC2)):
        p = out / f'tz-{slot}.img'
        p.write_bytes(_synth(2_367_488, seed))             # tz-sized
        variants[slot] = p
    cfg = DeployConfig(donors=donors, payload_variants=variants,
                       patched_lk=patched_lk, backup_dir=out / 'backup')

    chip = _stock_chip()
    gpt = parse_gpt_from_image(donors['brhgptpl_0'].read_bytes())
    _program_bcb(chip, gpt, b'_a\x00\x00')                 # active = lk_a
    pre = {p: b for p, b in chip.dump().items()}
    pre_state = {part: _read_part_planes(chip, gpt, part)
                 for part in NEVER_PARTITIONS}

    session = ModeledSession(chip)
    transport = FakeTransport(session)
    snapshots: list = []
    result = deploy(transport, cfg, snapshots=snapshots)
    return SimpleNamespace(chip=chip, gpt=gpt, cfg=cfg, pre=pre,
                           pre_state=pre_state, session=session,
                           transport=transport, snapshots=snapshots,
                           result=result, backup_dir=cfg.backup_dir)


# ---------------------------------------------------------------- tests --

@tier2_belt
def test_postflash_state_asserts(deployed):
    chip, gpt, cfg = deployed.chip, deployed.gpt, deployed.cfg
    donors = cfg.donors

    # GPT intact: the on-flash GPT still parses to the donor table (GPT
    # LBA0 lives at chip page 2 — the MTK preloader header precedes it)
    first = 0x2000 // PAGE_DATA
    blob = b'\x00' * 0x2000 + b''.join(
        chip.read_page(first + lba)[:PAGE_DATA] for lba in range(34))
    assert parse_gpt_from_image(blob) == gpt

    # brhgptpl_0..3 == donors, per copy (per-copy index bytes flow from
    # flashing donor brhgptpl_k images — nothing is synthesized)
    for k in range(4):
        img = donors[f'brhgptpl_{k}'].read_bytes()
        start = gpt[f'brhgptpl_{k}'][0]
        got = b''.join(chip.read_page(start + i)[:PAGE_DATA]
                      for i in range(-(-len(img) // PAGE_DATA)))
        assert got == img

    # tee1 == the selected variant: active slot is lk_a, so the crafted
    # payload that loads the patched (inactive) LK is the lk_b variant
    img = cfg.payload_variants['lk_b'].read_bytes()
    start = gpt['tee1'][0]
    got = b''.join(chip.read_page(start + i)[:PAGE_DATA]
                  for i in range(-(-len(img) // PAGE_DATA)))
    assert got == img

    # tee2 == stock 2021 donor
    img = donors['tee2'].read_bytes()
    start = gpt['tee2'][0]
    got = b''.join(chip.read_page(start + i)[:PAGE_DATA]
                  for i in range(-(-len(img) // PAGE_DATA)))
    assert got == img

    # active slot keeps the config-selected stock LK (the lk_year=2025
    # donor per key_continuity — final-review fix 2); inactive slot ==
    # the patched LK
    for part, path in (('lk_a', donors['lk']), ('lk_b', cfg.patched_lk)):
        img = Path(path).read_bytes()
        start = gpt[part][0]
        got = b''.join(chip.read_page(start + i)[:PAGE_DATA]
                      for i in range(-(-len(img) // PAGE_DATA)))
        assert got == img

    # NEVER partitions byte-identical to the pre-deploy state
    for part in NEVER_PARTITIONS:
        assert _read_part_planes(chip, gpt, part) == deployed.pre_state[part]

    # deploy() returns exactly the readback-verified written pages
    written = set()
    for part, path in (('tee2', donors['tee2']), ('lk_a', donors['lk']),
                       ('lk_b', cfg.patched_lk),
                       ('brhgptpl_0', donors['brhgptpl_0']),
                       ('brhgptpl_1', donors['brhgptpl_1']),
                       ('brhgptpl_2', donors['brhgptpl_2']),
                       ('brhgptpl_3', donors['brhgptpl_3']),
                       ('tee1', cfg.payload_variants['lk_b'])):
        img = Path(path).read_bytes()
        written.update(range(gpt[part][0],
                             gpt[part][0] + -(-len(img) // PAGE_DATA)))
    assert set(deployed.result) == written
    for page, data in deployed.result.items():
        assert data == chip.read_page(page)


@tier2_belt
def test_backup_hashes_recorded(deployed):
    import hashlib
    gpt, pre = deployed.gpt, deployed.pre
    manifest_path = deployed.backup_dir / 'manifest.json'
    assert manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text())

    expected_keys = {'boot_region', 'tee1', 'tee2', 'lk_a', 'lk_b',
                     'brhgptpl_0', 'brhgptpl_1', 'brhgptpl_2', 'brhgptpl_3'}
    assert expected_keys <= set(manifest)

    # per-partition hashes match the PRE-deploy flash contents (erased
    # pages read 0xFF), independently recomputed from the pre dump
    def pre_page(page):
        return pre.get(page, b'\xff' * PAGE_TOTAL)[:PAGE_DATA]

    for part in expected_keys - {'boot_region'}:
        start, size = gpt[part]
        blob = b''.join(pre_page(p) for p in range(start, start + size))
        assert manifest[part] == hashlib.sha256(blob).hexdigest()
        f = deployed.backup_dir / f'{part}.img'
        assert f.is_file() and hashlib.sha256(f.read_bytes()).hexdigest() \
            == manifest[part]

    # the full boot region: LBA 0 .. end of tee2, raw file on the host
    boot_end = gpt['tee2'][0] + gpt['tee2'][1]
    region = deployed.backup_dir / 'boot_region.bin'
    assert region.is_file()
    assert len(region.read_bytes()) == boot_end * PAGE_DATA
    assert hashlib.sha256(region.read_bytes()).hexdigest() \
        == manifest['boot_region']
    assert hashlib.sha256(
        b''.join(pre_page(p) for p in range(boot_end))).hexdigest() \
        == manifest['boot_region']


@tier2_belt
def test_slot_undetermined_aborts_before_any_write(tmp_path):
    donors = _donors()
    gpt = parse_gpt_from_image(donors['brhgptpl_0'].read_bytes())
    cfg = DeployConfig(donors=donors,
                       payload_variants={'lk_a': tmp_path / 'a.img',
                                         'lk_b': tmp_path / 'b.img'},
                       patched_lk=tmp_path / 'p.img',
                       backup_dir=tmp_path / 'backup')
    for slot in ('lk_a', 'lk_b'):
        cfg.payload_variants[slot].write_bytes(_synth(4096, 1))
    cfg.patched_lk.write_bytes(_synth(4096, 2))

    # unit level: every unrecognized/erased format is fail-closed
    chip_page = {'misc': None}

    def read_page_fn(page):
        return chip_page['misc'] if page == gpt['misc'][0] \
            else b'\xff' * PAGE_TOTAL

    for bad in (b'\xff' * 4, b'\x00' * 4, b'ab\x00\x00', b'_c\x00\x00',
                b'ax\x00\x00', b'_\x00\x00\x00', b'ABCD'):
        chip_page['misc'] = _bcb_page(bad)
        with pytest.raises(SlotUndetermined):
            detect_active_slot(read_page_fn, gpt)
    for good, want in ((b'_a\x00\x00', 'lk_a'), (b'b\x00\x00\x00', 'lk_b')):
        chip_page['misc'] = _bcb_page(good)
        assert detect_active_slot(read_page_fn, gpt) == want

    # full deploy: erased misc aborts with the chip untouched (the
    # read-only backup still ran, per §7.4 order, but zero writes)
    chip = _stock_chip()
    pre = {p: b for p, b in chip.dump().items()}
    transport = FakeTransport(ModeledSession(chip))
    with pytest.raises(SlotUndetermined):
        deploy(transport, cfg)
    assert chip.dump() == pre


@tier2_belt
def test_wdt_cadence_holds_during_full_deploy(tmp_path):
    donors = _donors()
    gpt = parse_gpt_from_image(donors['brhgptpl_0'].read_bytes())
    out = tmp_path
    patched_lk = out / 'p.img'
    patched_lk.write_bytes(_synth(233_472, 3))
    variants = {s: out / f'{s}.img' for s in ('lk_a', 'lk_b')}
    for s in variants:
        variants[s].write_bytes(_synth(2_367_488, 4))
    cfg = DeployConfig(donors=donors, payload_variants=variants,
                       patched_lk=patched_lk, backup_dir=out / 'backup')

    chip = _stock_chip()
    _program_bcb(chip, gpt, b'_b\x00\x00')                # active = lk_b
    session = ModeledSession(chip)     # real Watchdog, 286M-tick window
    result = deploy(FakeTransport(session), cfg)
    assert result
    assert session.wdt.reboots == []                      # never fired
    assert session.wdt.enabled and session.wdt.kicks > 0
    # the multi-MB session really streamed: boot region + writes + verify
    n_pages = (gpt['tee2'][0] + gpt['tee2'][1]) + len(result)
    assert session.wdt.kicks >= n_pages // fc.KICK_EVERY_PAGES

    # negative control (the assertion above can actually fail): arm the
    # window on the first kick, ignore every later one -> the modeled
    # timeout fires mid-deploy and the session raises instead of
    # silently continuing
    chip2 = _stock_chip()
    _program_bcb(chip2, gpt, b'_b\x00\x00')
    starving = ModeledSession(chip2, ignore_late_kicks=True)
    with pytest.raises(ModeledReboot):
        deploy(FakeTransport(starving), cfg)
    assert len(starving.wdt.reboots) == 1


@tier2_belt
def test_intermediate_states_bootable_or_brom(deployed):
    gpt, cfg, snaps = deployed.gpt, deployed.cfg, deployed.snapshots
    donors = cfg.donors

    # one snapshot after each step: baseline (post slot-detect, pre
    # write) then after tee2 / active LK / each preloader copy 0..3 /
    # patched LK / crafted tee1
    assert len(snaps) == 9

    def page_of(snap, page):
        return snap.get(page, b'\xff' * PAGE_TOTAL)

    def part_plane(snap, part, n_pages):
        start = gpt[part][0]
        return b''.join(page_of(snap, start + i)[:PAGE_DATA]
                        for i in range(n_pages))

    def n_pages_of(path):
        return -(-Path(path).stat().st_size // PAGE_DATA)

    tee1_pages = n_pages_of(cfg.payload_variants['lk_b'])
    stock_tee1_head = donors['tee1'].read_bytes()[:PAGE_DATA]

    # baseline == the pre-deploy chip, byte for byte
    assert snaps[0] == deployed.pre

    for idx, snap in enumerate(snaps):
        # cheap Task-11 stand-in invariant: no snapshot may pair a
        # wrong-year (non-2021-donor) preloader with a crafted tee1.
        tee1_crafted = (part_plane(snap, 'tee1', 1) != stock_tee1_head)
        if tee1_crafted:
            for k in range(4):
                img = donors[f'brhgptpl_{k}'].read_bytes()
                assert part_plane(snap, f'brhgptpl_{k}',
                                  n_pages_of(donors[f'brhgptpl_{k}'])) == img
        # the crafted tee1 exists ONLY in the final snapshot (§7.4:
        # crafted tee1 LAST) — every earlier prefix leaves stock tee1
        if idx < len(snaps) - 1:
            assert part_plane(snap, 'tee1', 1) == stock_tee1_head
        # preloader copies appear complete, in order 0..3: copy k is
        # donor-complete from its snapshot on, never partial
        for k in range(4):
            img = donors[f'brhgptpl_{k}'].read_bytes()
            complete = part_plane(snap, f'brhgptpl_{k}',
                                  n_pages_of(donors[f'brhgptpl_{k}'])) == img
            if complete:
                later = snaps[idx + 1:]
                for s2 in later:
                    assert part_plane(s2, f'brhgptpl_{k}',
                                      n_pages_of(donors[f'brhgptpl_{k}'])) == img


@tier2_framing
def test_transport_framing_against_real_stage2(images):
    """FakeTransport's read(n)/write(bytes) surface drives the REAL
    BROM+stage2 through Stage2Session — the same path deploy.main
    will use on hardware."""
    stage1_bin, stage2_bin = images
    chip = NandChip()
    chip.load_donors({'brhgptpl_0': resolve('brhgptpl_0', '2021')})
    h = BromHarness(rom_path=resolve('brom', 'common'), nfi=NfiModel(chip))
    h.run_cdc_overflow(stage1_bin)
    assert h.expect_stage1_online(), h.failure_detail()
    transport = FakeTransport(Stage2Session(h, stage2_bin))

    # page read through the byte-stream framing == the chip model
    assert fc.read_page(transport, 0) == chip.read_page(0)

    # page-streaming flash + readback-verify on a scratch block, with
    # kick cadence and the BBM spare exemption, through the real driver
    block = 1500
    image = _synth(3 * PAGE_DATA, 0x77)
    verified = fc.flash_image(transport, block * NandChip.PAGES_PER_BLOCK,
                              image)
    assert set(verified) == set(range(block * NandChip.PAGES_PER_BLOCK,
                                      block * NandChip.PAGES_PER_BLOCK + 3))
    for page, data in verified.items():
        assert data == chip.read_page(page)
    assert verified[block * NandChip.PAGES_PER_BLOCK][PAGE_DATA] == 0xFF  # BBM

    # the session is still framed afterwards: kick through the helper,
    # then one bare framed command at the byte level
    fc.kick(transport)
    st, = struct.unpack('>I', _raw_cmd(transport, 0x3001))
    assert st == 0xD0D0D0D0


def _raw_cmd(transport, code):
    """Send one bare command through the transport; return the 4 status
    bytes (test helper for the framing proof above)."""
    transport.write(struct.pack('>II', 0xf00dd00d, code))
    return transport.read(4)


@tier2_lk_record
def test_shipped_lk_donor_matches_key_continuity_record():
    """Final-review fix 2: the stock LK that goes into the ACTIVE slot
    (§7.4 step 6) must be the year the key-continuity decision record
    selects. Port note (task-9 ruling): the donor additionally asserted
    modules.bootrom_main.hardware_donors() — the donor repo's
    live-hardware exploit entry, never ported into this emulator repo
    (out of scope) — whose assertion duplicated exactly the emu-fixture
    check kept below against the record and this module's own donor
    table; the hardware-config half is therefore dropped, not silently
    lost."""
    rec = json.loads(own('key_continuity.json').read_text())
    year_file = {'2025': resolve('lk', '2025'),
                 '2021': resolve('lk', '2021')}
    want = year_file[rec['lk_year']]

    assert _donors()['lk'] == want, \
        'emu fixtures baseline/step-6 donor diverges from the record'
