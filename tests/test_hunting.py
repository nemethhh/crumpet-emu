"""Hunting instrumentation tests (Task 15) — Tier 1, fully synthetic.

No vendor binaries anywhere: inject runs against constructed
Flash/ChipDumpFlash models and a TrackedSession, fuzz against a real
TrackedSession checkpoint file, coverage against the Task-1 thumb
add-function, differential against synthetic result objects.
"""

from collections import namedtuple

import pytest
from unicorn import UC_ERR_READ_UNMAPPED, UcError

from crumpet_emu.core.checkpoints import TrackedSession, save
from crumpet_emu.core.session import Session
from crumpet_emu.flash.image import GPT, ChipDumpFlash, Flash
from crumpet_emu.hunting.coverage import EdgeBitmap
from crumpet_emu.hunting.differential import first_divergence, run_variants
from crumpet_emu.hunting.fuzz import CaseResult, FuzzLoop
from crumpet_emu.hunting.inject import apply_flash, apply_mem

CODE = 0x00100000  # 4 KiB code page (Session/TrackedSession map their stack)
ADD_THUMB = bytes.fromhex('4018') + bytes.fromhex('7047')  # adds r0,r0,r1; bx lr


def test_inject_flash_patch():
    # block-aligned (512-B) lk image: patch visibility with untouched bytes
    # exact; the SHORT-trailing-block canonicalization is pinned separately
    # by test_inject_flash_short_trailing_block_never_clamps
    lk = b'LK-IMAGE-BYTES'.ljust(512, b'\x00')
    flash = Flash(b'TEE1' + bytes(64), lk, b'TEE2' + bytes(64))
    start = GPT['lk_a'][0]

    # patch form: overwrite bytes at a partition-relative offset
    apply_flash(flash, {'target': 'lk_a', 'offset': 0, 'patch': b'CRUMPET'})
    served = flash.read(start, 1)
    assert served.startswith(b'CRUMPET')      # patch visible through Flash.read
    assert served[7:] == lk[7:512]            # untouched image bytes intact

    # fill form: erase a byte range inside the twin slot
    apply_flash(flash, {'target': 'lk_b', 'fill': 0, 'start': 4, 'end': 12})
    lk_b0 = flash.read(GPT['lk_b'][0], 1)
    assert lk_b0[4:12] == bytes(8)
    assert lk_b0[:4] == lk[:4]

    # ChipDumpFlash is the closed-loop drop-in: patches land in its page
    # map at the same bdev placement, and the spare plane survives
    dump = {GPT['lk_a'][0] // 8: b'\x11' * 4096 + b'\x22' * 256}
    chip = ChipDumpFlash(dump)
    apply_flash(chip, {'target': 'lk_a', 'offset': 8, 'patch': b'XX'})
    served = chip.read(start, 1)
    assert served[8:10] == b'XX'
    assert served[0] == 0x11
    assert chip.pages[GPT['lk_a'][0] // 8][4096:] == b'\x22' * 256

    # memory form: same recipes against session addresses
    s = TrackedSession()
    s.map(CODE, 0x1000)
    apply_mem(s, {'target': CODE, 'offset': 0, 'patch': ADD_THUMB})
    assert s.read(CODE, 4) == ADD_THUMB
    apply_mem(s, {'target': CODE + 0x100, 'fill': 0xAB, 'start': 0, 'end': 4})
    assert s.read(CODE + 0x100, 4) == b'\xAB' * 4

    # unknown target and out-of-partition writes refuse loudly
    with pytest.raises(ValueError):
        apply_flash(flash, {'target': 'tz9', 'offset': 0, 'patch': b'x'})
    with pytest.raises(ValueError):
        apply_flash(flash, {'target': 'lk_a', 'offset': GPT['lk_a'][1] * 512 - 1,
                            'patch': b'overflow'})


def test_inject_refuses_non_int_offsets_and_noop_at_end():
    # type symmetry with the unknown-target rule: non-int offsets/starts
    # ValueError (never TypeError), and an empty patch at offset == limit
    # (a silent no-op at the partition end) is refused
    flash = Flash(b'T', b'LK-IMAGE-BYTES'.ljust(512, b'\x00'), b'T')
    limit = GPT['lk_a'][1] * 512
    with pytest.raises(ValueError):
        apply_flash(flash, {'target': 'lk_a', 'offset': '0', 'patch': b'x'})
    with pytest.raises(ValueError):
        apply_flash(flash, {'target': 'lk_a', 'offset': True, 'patch': b'x'})
    with pytest.raises(ValueError):
        apply_flash(flash, {'target': 'lk_a', 'fill': 0,
                            'start': '0', 'end': 4})
    with pytest.raises(ValueError) as ei:
        apply_flash(flash, {'target': 'lk_a', 'offset': limit, 'patch': b''})
    assert 'no-op patch at partition end' in str(ei.value)
    # a patch strictly inside stays legal (empty patch before the end is
    # a harmless no-op and keeps succeeding)
    apply_flash(flash, {'target': 'lk_a', 'offset': 0, 'patch': b''})


def test_inject_flash_short_trailing_block_never_clamps():
    # A 12-byte lk image stores one SHORT trailing block; donor read() serves
    # it as the short slice. A patch PAST its end must land at the target
    # offset (erase-filled), never clamp to the block end (review repro 1).
    flash = Flash(b'T', b'LK-IMAGE-12B', b'T')
    start = GPT['lk_a'][0]
    assert flash.read(start, 1) == b'LK-IMAGE-12B'   # donor short slice

    apply_flash(flash, {'target': 'lk_a', 'offset': 20, 'patch': b'X'})
    served = flash.read(start, 1)
    assert served[20:21] == b'X'                     # lands at 20, not at 12
    assert served[:12] == b'LK-IMAGE-12B'            # original bytes intact
    assert served[12:20] == b'\xFF' * 8              # gap = erase-fill
    assert len(served) == 512   # patched short block -> canonical 512-B block


def test_inject_chipdump_absent_page_materializes_full_data_plane():
    # An absent page must materialize as the FULL 4096-B data plane, not
    # just the one touched 512-B block — every later block of the page must
    # still serve 0xFF erase-fill, never b'' (review repro 2).
    chip = ChipDumpFlash({})
    apply_flash(chip, {'target': 'lk_a', 'offset': 0, 'patch': b'ZZ'})
    page = chip.pages[GPT['lk_a'][0] // 8]
    assert page[:2] == b'ZZ'
    assert len(page) == ChipDumpFlash.SECTORS_PER_PAGE * 512
    assert page[2:] == b'\xFF' * (ChipDumpFlash.SECTORS_PER_PAGE * 512 - 2)
    served = chip.read(GPT['lk_a'][0], 2)   # second block of the same page
    assert served == b'ZZ' + b'\xFF' * (2 * 512 - 2)   # exact read-back


def test_fuzz_survives_crash(tmp_path):
    s = TrackedSession()
    s.map(CODE, 0x1000)
    s.write(CODE, ADD_THUMB)
    cp = save(s, tmp_path / 'fastboot.bin')

    def mutate(i):
        return {'id': i}

    def run_case(cfg):
        case_s = cfg['session']               # loop-injected restored session
        assert case_s.read(CODE, 4) == ADD_THUMB  # restored per case, not dirty
        case_s.write(CODE, b'\xDE\xAD\xBE\xEF')  # dirt the next restore undoes
        if cfg['id'] == 7:
            raise UcError(UC_ERR_READ_UNMAPPED)  # the emulated path faults here
        return CaseResult(cfg['id'], True, 'ok')

    report = FuzzLoop(cp, mutate, run_case, max_cases=10)
    assert len(report.cases) == 10              # loop completed, crash absorbed
    assert report.cases[-1].input_id == 9
    assert len(report.crashes) == 1
    assert report.crashes[0].input_id == 7
    assert report.crashes[0].ok is False
    assert report.crashes[0].verdict == 'UcError'
    assert report.verdicts == {'ok': 9, 'UcError': 1}


def test_coverage_counts_edges():
    s = Session()
    s.map(CODE, 0x1000)
    s.write(CODE, ADD_THUMB)                    # the Task-1 add function
    eb = EdgeBitmap()
    eb.install(s)
    assert s.call(CODE, [2, 3]) == 5            # entry edge + adds->bx lr edge
    assert s.stop_reason == 'magic_ret'
    assert len(eb.bitmap) == 0x10000            # 64 KiB AFL-style map
    assert eb.edges() >= 2


def test_differential_first_divergence():
    R = namedtuple('R', 'uart_text verdict')

    def build(cfg):
        return R(cfg['uart'], cfg['verdict'])

    variants = {
        'sbc_on': {'uart': 'boot\nauth ok\nfastboot', 'verdict': 'authenticated'},
        'sbc_off': {'uart': 'boot\nauth ok\nfastboot', 'verdict': 'authenticated'},
    }
    assert first_divergence(run_variants(build, variants)) is None

    variants['sbc_off'] = {'uart': 'boot\nauth FAIL\nfastboot',
                           'verdict': 'refused'}
    pair, line = first_divergence(run_variants(build, variants))
    assert pair == 'sbc_on vs sbc_off'
    assert line == 'auth ok'   # first variant's line at the first differing index
