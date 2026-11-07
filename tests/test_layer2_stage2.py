# Donor: WS/tools/kamakiri/emu/tests/test_layer2_stage2.py
# Upstream: R0rt1z2/kamakiri
# Copied 2026-10-31 (Task 9 port; Import Map + ruled path adaptations):
#   ROM -> resources.resolve('brom', 'common') (Tier 2); STAGE1/STAGE2 ->
#   resources.own('stage1.bin'/'stage2.bin') — the donor's `make -C
#   brom-payload` build is REPLACED by the committed hash-pinned own
#   artifacts (no make rebuild in this repo); GPT_DONOR ->
#   resources.resolve('brhgptpl_0', '2021') (Tier 2). The byte-identical
#   rebuild test becomes a manifest pin check (Tier 1).
"""Layer 2 — crumpet stage2 skeleton (protocol + watchdog, no flash).

Stage2Session drives the real-BROM harness interactively: after the layer-1
boot (amonet CDC overflow -> stage1 online), it loads the crumpet stage2
image through stage1's own loader commands (0x4000 write-mem to 0x201000,
0x4001 jump) and then speaks the crumpet command protocol over the same
CDC endpoints. One request->reply pair at a time, strictly sequenced: the
BROM/USB layer discards EP1 data pending at handshake entry, so a second
command queued before the reply lands would be lost.

Protocol under test (donut dword convention, ROM recv_dword/send_dword
0xD1CB/0xD1FF pair — big-endian on the wire): magic 0xf00dd00d, then the
command code, then u32 args; every reply starts with a status dword,
0xD0D0D0D0 ok / 0xF0F0F0F0 error. Commands: 0x3000 reboot, 0x3001 kick
watchdog, 0x5000 mem-read {addr,len} -> status + len bytes, 0x5001
mem-write {addr,len} + data -> status. The NAND ops: 0x6101 page-read
{page,length} -> status + 4352 bytes, 0x6102 page-write {page,length} +
4352-B payload -> status, 0x6103 block-erase {block} -> status; lengths
are rejected unless exactly the page size (controller ruling on the
plan's Review Focus #2 — the explicit length dword is what makes the
!= 4352 rejection a device-side check; Task 6 adds the write/erase
siblings). Donut's eMMC/RPMB/fastboot codes are gone.

Tier gating: every real-ROM test needs common:brom; the nand_session
tests additionally need the 2021 brhgptpl_0 donor. The manifest-pin test
reads only committed own artifacts (Tier 1).
"""
import hashlib
import json

import pytest

from crumpet_emu.brom.harness import (BromHarness, Stage2Session, Watchdog,
                                      STAGE1_LOAD, STAGE2_LOAD)
from crumpet_emu.flash.nand import NandChip
from crumpet_emu.flash.nfi import NfiModel
from crumpet_emu.resources import MANIFEST_PATH, available, own, resolve

TIER2 = 'tier2: requires parked vendor binaries — see binaries/README.md'
tier2_rom = pytest.mark.skipif(not available('brom', 'common'), reason=TIER2)
tier2_rom_gpt = pytest.mark.skipif(
    not (available('brom', 'common') and available('brhgptpl_0', '2021')),
    reason=TIER2)

STATUS_OK = 0xD0D0D0D0
STATUS_ERR = 0xF0F0F0F0

CMD_REBOOT = 0x3000
CMD_KICK = 0x3001
CMD_READ = 0x5000
CMD_WRITE = 0x5001
CMD_PAGE_READ = 0x6101
CMD_PAGE_WRITE = 0x6102
CMD_BLOCK_ERASE = 0x6103

# scratch blocks for the write-path tests: 2000..2004 are pages 128000+, far
# beyond every donor image (the donors cover the first few MB of the chip)
BLOCK_ONCE = 2000
BLOCK_ROUNDTRIP = 2001
BLOCK_BBM = 2002
BLOCK_LENGTH = 2003
BLOCK_BOUNDS = 2004

# NAND geometry (crumpet_emu.flash.nand.NandChip): one 4352-byte page/reply
PAGE_DATA = NandChip.PAGE_DATA
PAGE_TOTAL = NandChip.PAGE_DATA + NandChip.PAGE_SPARE

# scratch for the echo test: top 1 KiB of the 32 KiB stage2 SRAM window,
# clear of the image itself and of stage2's (stack-only) locals
SCRATCH = STAGE2_LOAD + 0x7C00


@pytest.fixture(scope='module')
def images():
    """Load both committed own artifacts (the donor ran `make -C
    brom-payload` here; this repo pins the build products instead)."""
    return own('stage1.bin').read_bytes(), own('stage2.bin').read_bytes()


@pytest.fixture(scope='module')
def session(images):
    stage1_bin, stage2_bin = images
    h = BromHarness(rom_path=resolve('brom', 'common'))
    h.run_cdc_overflow(stage1_bin)
    assert h.expect_stage1_online(), h.failure_detail()
    return Stage2Session(h, stage2_bin)


@pytest.fixture(scope='module')
def nand_session(images):
    """Same boot as `session`, but with the NFI controller model wired to
    a donor-loaded chip — the stage2 NFI driver talks to the chip through
    the same register window the real hardware would answer on."""
    stage1_bin, stage2_bin = images
    chip = NandChip()
    chip.load_donors({'brhgptpl_0': resolve('brhgptpl_0', '2021')})
    h = BromHarness(rom_path=resolve('brom', 'common'), nfi=NfiModel(chip))
    h.run_cdc_overflow(stage1_bin)
    assert h.expect_stage1_online(), h.failure_detail()
    return Stage2Session(h, stage2_bin), chip


@tier2_rom
def test_protocol_echo_and_jump(session):
    # stage2 really runs at 0x201000 (stage1 0x4000 write + 0x4001 jump):
    # its first bytes are there, and crumpet's own mem-read agrees
    image_head = bytes(session.h.read_mem(STAGE2_LOAD, 8))
    assert image_head != b'\x00' * 8
    status, data = session.cmd(CMD_READ, STAGE2_LOAD, 8)
    assert status == STATUS_OK
    assert data == image_head
    # and stage1's payload still sits where the exploit put it
    status, data = session.cmd(CMD_READ, STAGE1_LOAD, 4)
    assert status == STATUS_OK
    assert data == session.h.read_mem(STAGE1_LOAD, 4)
    # write/read-back echo through 0x5001 + 0x5000
    pattern = bytes(range(64))
    status, data = session.cmd(CMD_WRITE, SCRATCH, len(pattern),
                               payload=pattern)
    assert status == STATUS_OK
    assert data == b''
    assert session.h.read_mem(SCRATCH, len(pattern)) == pattern
    status, data = session.cmd(CMD_READ, SCRATCH, len(pattern))
    assert status == STATUS_OK
    assert data == pattern


def _payload(tag: int) -> bytes:
    """Deterministic flat data+spare page payload for the write tests."""
    data = bytes((tag + i) & 0xFF for i in range(PAGE_DATA))
    spare = bytes((tag * 7 + i) & 0xFF
                  for i in range(PAGE_TOTAL - PAGE_DATA))
    return data + spare


@tier2_rom_gpt
def test_nand_read_gpt_page(nand_session):
    # 0x6101 {page, 4352} reads the GPT root page — brhgptpl_0 lives at
    # LBA 0, so its first page is page 0: data plane from the donor file,
    # spare all-0xFF (donor files carry no spare bytes)
    session, chip = nand_session
    page = chip.page_of_lba(0)
    assert page == 0
    status, data = session.cmd(CMD_PAGE_READ, page, PAGE_TOTAL)
    assert status == STATUS_OK
    assert len(data) == PAGE_TOTAL
    assert data == chip.read_page(page)
    donor = resolve('brhgptpl_0', '2021').read_bytes()
    assert data[:PAGE_DATA] == donor[:PAGE_DATA]
    assert data[PAGE_DATA:] == b'\xff' * NandChip.PAGE_SPARE
    # the page-sized bulk reply left the session healthy
    status, data = session.cmd(CMD_KICK)
    assert status == STATUS_OK
    assert data == b''


@tier2_rom_gpt
def test_read_rejects_bad_length(nand_session):
    # plan Review Focus #2: lengths != 4352 are rejected with an error
    # status and no data; the stream stays framed for the next command
    session, chip = nand_session
    for bad in (0, 1, PAGE_DATA, PAGE_TOTAL - 1, PAGE_TOTAL + 1,
                2 * PAGE_TOTAL):
        status, data = session.cmd(CMD_PAGE_READ, 0, bad)
        assert status == STATUS_ERR, bad
        assert data == b'', bad
    status, _ = session.cmd(CMD_KICK)
    assert status == STATUS_OK


@tier2_rom
def test_unknown_cmd_returns_error_status(session):
    status, data = session.cmd(0x1234)          # unassigned command code
    assert status == STATUS_ERR
    assert data == b''
    # the dispatcher survives unknown commands and keeps serving
    status, data = session.cmd(CMD_KICK)
    assert status == STATUS_OK
    assert data == b''


@tier2_rom_gpt
def test_erase_program_readback_roundtrip(nand_session):
    # 0x6103 erases; the erased state is verified through the model (the
    # chip reads 0xFF through the controller); erase -> program -> read
    # round-trips the full flat data+spare page, twice in one erase cycle
    session, chip = nand_session
    base = BLOCK_ROUNDTRIP * NandChip.PAGES_PER_BLOCK
    status, data = session.cmd(CMD_BLOCK_ERASE, BLOCK_ROUNDTRIP)
    assert status == STATUS_OK
    assert data == b''
    for off in (0, 1, 5):
        status, data = session.cmd(CMD_PAGE_READ, base + off, PAGE_TOTAL)
        assert status == STATUS_OK
        assert data == b'\xff' * PAGE_TOTAL          # 0xFF state via model
        assert chip.read_page(base + off) == b'\xff' * PAGE_TOTAL
    first = _payload(0xA7)
    status, data = session.cmd(CMD_PAGE_WRITE, base + 5, PAGE_TOTAL,
                               payload=first)
    assert status == STATUS_OK
    assert data == b''
    status, data = session.cmd(CMD_PAGE_READ, base + 5, PAGE_TOTAL)
    assert status == STATUS_OK
    assert data == first                            # flat data+spare
    second = _payload(0x5C)
    status, _ = session.cmd(CMD_PAGE_WRITE, base + 6, PAGE_TOTAL,
                            payload=second)
    assert status == STATUS_OK                      # same erase cycle
    status, data = session.cmd(CMD_PAGE_READ, base + 6, PAGE_TOTAL)
    assert status == STATUS_OK
    assert data == second
    status, data = session.cmd(CMD_PAGE_READ, base + 7, PAGE_TOTAL)
    assert status == STATUS_OK
    assert data == b'\xff' * PAGE_TOTAL             # untouched page


@tier2_rom_gpt
def test_program_once_rejected(nand_session):
    # program-once per erase: a second program of a page is rejected with
    # an error status and leaves the chip state unchanged
    session, chip = nand_session
    # a donor page is programmed (non-0xFF): the driver's erased-state
    # read-back rejects before any program traffic reaches the chip
    gpt = chip.read_page(0)
    status, data = session.cmd(CMD_PAGE_WRITE, 0, PAGE_TOTAL,
                               payload=_payload(0x11))
    assert status == STATUS_ERR
    assert data == b''
    assert chip.read_page(0) == gpt                 # chip state unchanged
    # inside a scratch block: reprogramming a page is rejected
    page = BLOCK_ONCE * NandChip.PAGES_PER_BLOCK + 3
    status, _ = session.cmd(CMD_BLOCK_ERASE, BLOCK_ONCE)
    assert status == STATUS_OK
    status, _ = session.cmd(CMD_PAGE_WRITE, page, PAGE_TOTAL,
                            payload=_payload(0x22))
    assert status == STATUS_OK
    status, _ = session.cmd(CMD_PAGE_WRITE, page, PAGE_TOTAL,
                            payload=_payload(0x33))
    assert status == STATUS_ERR
    assert chip.read_page(page) == _payload(0x22)   # first program stands
    # the pattern hole: an all-0xFF program is still a program — the
    # model's explicit page state rejects the reprogram (read-back alone
    # cannot tell an erased page from an 0xFF-programmed one)
    ff_page = BLOCK_ONCE * NandChip.PAGES_PER_BLOCK + 4
    status, _ = session.cmd(CMD_PAGE_WRITE, ff_page, PAGE_TOTAL,
                            payload=b'\xff' * PAGE_TOTAL)
    assert status == STATUS_OK
    assert ff_page in chip.dump()                   # it did land
    status, _ = session.cmd(CMD_PAGE_WRITE, ff_page, PAGE_TOTAL,
                            payload=_payload(0x44))
    assert status == STATUS_ERR
    assert chip.read_page(ff_page) == b'\xff' * PAGE_TOTAL
    status, _ = session.cmd(CMD_KICK)               # stream still framed
    assert status == STATUS_OK


@tier2_rom_gpt
def test_write_rejects_bad_length(nand_session):
    # R6: the declared length must be exactly 4352. A good write first,
    # so the sweep exercises the 0x6102 length check and not the default
    # invalid-command error status
    session, chip = nand_session
    page = BLOCK_LENGTH * NandChip.PAGES_PER_BLOCK + 8   # not a BBM page
    status, _ = session.cmd(CMD_BLOCK_ERASE, BLOCK_LENGTH)
    assert status == STATUS_OK
    status, _ = session.cmd(CMD_PAGE_WRITE, page, PAGE_TOTAL,
                            payload=_payload(0x55))
    assert status == STATUS_OK
    for bad in (0, 1, PAGE_DATA, PAGE_TOTAL - 1, PAGE_TOTAL + 1,
                2 * PAGE_TOTAL):
        status, data = session.cmd(CMD_PAGE_WRITE, page + 1, bad)
        assert status == STATUS_ERR, bad
        assert data == b'', bad
    status, data = session.cmd(CMD_PAGE_READ, page, PAGE_TOTAL)
    assert status == STATUS_OK
    assert data == _payload(0x55)                   # nothing was clobbered
    status, _ = session.cmd(CMD_KICK)
    assert status == STATUS_OK


@tier2_rom_gpt
def test_bad_page_and_block_bounds(nand_session):
    # page >= 131072 is -EINVAL on read (the Task 5 review follow-up) and
    # on program (payload consumed first, then rejected); block >= 2048
    # on erase. A good erase first pins these as bound checks
    session, chip = nand_session
    status, _ = session.cmd(CMD_BLOCK_ERASE, BLOCK_BOUNDS)
    assert status == STATUS_OK
    bad_page = NandChip.BLOCKS * NandChip.PAGES_PER_BLOCK
    status, data = session.cmd(CMD_PAGE_READ, bad_page, PAGE_TOTAL)
    assert status == STATUS_ERR
    assert data == b''
    status, data = session.cmd(CMD_PAGE_WRITE, bad_page, PAGE_TOTAL,
                               payload=_payload(0x66))
    assert status == STATUS_ERR
    assert data == b''
    assert bad_page not in chip.dump()
    status, _ = session.cmd(CMD_BLOCK_ERASE, NandChip.BLOCKS)
    assert status == STATUS_ERR
    status, _ = session.cmd(CMD_KICK)
    assert status == STATUS_OK


@tier2_rom_gpt
def test_boot_region_program_preserves_bbm(nand_session):
    # pages 0/1 of every block carry the bad-block marker in spare byte 0;
    # the write path routes spare through the chip model's BBM masking,
    # so a programmed BBM byte reads back erased
    session, chip = nand_session
    for off in (0, 1):
        page = BLOCK_BBM * NandChip.PAGES_PER_BLOCK + off
        status, _ = session.cmd(CMD_BLOCK_ERASE, BLOCK_BBM)
        assert status == STATUS_OK
        payload = bytearray(_payload(0x70 + off))
        payload[NandChip.PAGE_DATA] = 0x00          # spare byte 0 = BBM
        status, _ = session.cmd(CMD_PAGE_WRITE, page, PAGE_TOTAL,
                                payload=bytes(payload))
        assert status == STATUS_OK
        status, data = session.cmd(CMD_PAGE_READ, page, PAGE_TOTAL)
        assert status == STATUS_OK
        assert data[:PAGE_DATA] == bytes(payload[:PAGE_DATA])
        assert data[PAGE_DATA] == 0xFF              # BBM kept erased
        assert data[PAGE_DATA + 1:] == bytes(payload[PAGE_DATA + 1:])
        assert chip.read_page(page)[NandChip.PAGE_DATA] == 0xFF


@tier2_rom
def test_watchdog_timeout_detected(images):
    # a fresh harness models the post-reboot device: the harness Watchdog
    # is exactly-once-per-arming
    stage1_bin, stage2_bin = images
    h = BromHarness(rom_path=resolve('brom', 'common'))
    h.wdt = Watchdog(timeout_ticks=1_000_000)   # short modeled window
    h.run_cdc_overflow(stage1_bin)
    assert h.expect_stage1_online(), h.failure_detail()
    s = Stage2Session(h, stage2_bin)
    status, _ = s.cmd(CMD_KICK)                 # kick arms the window
    assert status == STATUS_OK
    assert h.wdt.enabled
    assert h.wdt.kicks == 1
    status, _ = s.cmd(CMD_KICK)                 # second kick pushes it out
    assert status == STATUS_OK
    assert h.wdt.kicks == 2
    # stop kicking: the device idles in its recv poll and the modeled
    # window closes on it
    reason = s.run_until_stop()
    assert reason == 'wdt-reboot'
    assert h.stop_reason == 'wdt-reboot'
    assert len(h.wdt.reboots) == 1              # fired exactly once
    assert any('watchdog reboot' in e for e in h.events)


def test_crumpet_stage1_pinned_to_manifest(images):
    """Ruling R2 port: the donor rebuilt the payload tree twice (`make`
    default vs `crumpet` target) to pin the crumpet stage1.bin
    byte-identical to the default target's — same source, same link map.
    This repo has no make rebuild: the committed own:stage1.bin IS that
    byte-identical artifact, and its manifest pin is the regression
    guard. Stays last in this module (donor ordering)."""
    booted_stage1, _ = images
    entry = json.loads(MANIFEST_PATH.read_text())['own:stage1.bin']
    assert hashlib.sha256(booted_stage1).hexdigest() == entry['sha256'], \
        'own:stage1.bin drifted from its manifest pin'
    assert len(booted_stage1) == entry['size']
    assert booted_stage1 == own('stage1.bin').read_bytes()
