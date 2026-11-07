# Donor: WS/tools/kamakiri/emu/tests/test_nand_model.py
# Upstream: R0rt1z2/kamakiri
# Copied 2026-10-31: verbatim; Import Map + donor paths via manifest sources
"""Tests for the crumpet NAND chip model and 2021-donor GPT placement.

Donor images live outside this repo, read-only, under the donor (WS)
workspace: ota-crumpet/2021/ota_out/. Their paths come from the 'source'
fields of the committed binaries/manifest.json (this repo's only record
of the donor workspace layout), independent of cwd.

Per-copy index bytes in the brhgptpl donors: the four brhgptpl_*.img files
are byte-identical except four bytes in the BRLYT header on page 1 of the
image (file offset 0x1000). The differing u32 fields encode each copy's own
placement: BRLYT+0x0C and BRLYT+0x1C hold 0x8 + 0x400*copy, and BRLYT+0x10
and BRLYT+0x20 hold 0x108 + 0x400*copy (0x400 = 1024 4096-byte LBAs, the
stride between brhgptpl copies; brhgptpl_k starts at LBA 1024*k). The four
differing byte offsets within the file are 0x100D, 0x1011, 0x101D, 0x1021.
"""

import pytest

from crumpet_emu import resources
from crumpet_emu.flash import gpt
from crumpet_emu.flash.nand import NandChip, PageNotErased

# donor bytes come from the placement system itself (pinned builds) —
# nothing reads manifest 'source' paths
DONOR_NAMES = ('brhgptpl_0', 'brhgptpl_1', 'brhgptpl_2', 'brhgptpl_3',
               'lk', 'tee1', 'tee2', 'boot')


def _donors(names=DONOR_NAMES):
    """Resolve pinned donor images lazily (never at import time)."""
    return {n: resources.resolve(n, '2021') for n in names}


# guard follows the approved tests/test_resources.py needs_* skipif pattern:
# this tier reads pinned donors via the placement system, so a fresh clone
# without placed bins must skip, not fail
needs_donors = pytest.mark.skipif(
    not all(resources.available(n, '2021') for n in DONOR_NAMES),
    reason='pinned 2021 donors not placed — binaries/vendor/2021/ or env vars')


# donor file name -> GPT partition carrying it (A-slot for the two-slot parts)
DONOR_PART = {'lk': 'lk_a', 'boot': 'boot_a'}
# per-copy index byte offsets; see module docstring
PER_COPY_INDEX_OFFSETS = {0x100D, 0x1011, 0x101D, 0x1021}


def split_page(raw):
    return raw[:NandChip.PAGE_DATA], raw[NandChip.PAGE_DATA:]


def test_geometry():
    assert NandChip.PAGE_DATA == 4096
    assert NandChip.PAGE_SPARE == 256
    assert NandChip.PAGES_PER_BLOCK == 64
    assert NandChip.BLOCKS == 2048
    # data-plane capacity: 2048 blocks x 64 pages x 4096 B == 512 MiB
    assert NandChip.BLOCKS * NandChip.PAGES_PER_BLOCK * NandChip.PAGE_DATA \
        == 512 * 1024 * 1024
    chip = NandChip()
    assert len(chip.read_page(0)) == 4352
    assert chip.read_page(0) == b'\xff' * 4352  # fresh chip is fully erased


def test_erase_then_program_roundtrip():
    chip = NandChip()
    chip.erase_block(3)
    payload = bytes(range(256)) * 17  # 4352 B, distinct data plane vs spare
    page = 3 * 64 + 5
    chip.program_page(page, payload)
    assert chip.read_page(page) == payload
    assert chip.dump() == {page: payload}


def test_program_once_rejected():
    chip = NandChip()
    chip.erase_block(0)
    chip.program_page(2, b'\x00' * 4352)
    with pytest.raises(PageNotErased):
        chip.program_page(2, b'\x00' * 4352)
    # erasing the containing block makes the page programmable again
    chip.erase_block(0)
    chip.program_page(2, b'\x11' * 4352)
    assert chip.read_page(2) == b'\x11' * 4352


def test_bbm_bytes_survive_program():
    chip = NandChip()
    chip.erase_block(7)
    payload = bytearray(b'\x2a' * 4352)
    payload[NandChip.PAGE_DATA] = 0x00  # spare byte 0 == the BBM position
    # pages 0 and 1 of every block carry the BBM in spare byte 0
    for p in (7 * 64, 7 * 64 + 1):
        chip.program_page(p, bytes(payload))
        page = chip.read_page(p)
        data, spare = split_page(page)
        assert data == b'\x2a' * NandChip.PAGE_DATA
        assert spare[0] == 0xFF  # BBM position masked from the program payload
        assert spare[1:] == b'\x2a' * (NandChip.PAGE_SPARE - 1)
    # page 2 of the block has no BBM: spare byte 0 programs normally
    chip.program_page(7 * 64 + 2, bytes(payload))
    assert chip.read_page(7 * 64 + 2) == bytes(payload)


@needs_donors
def test_donor_placement_matches_files():
    table = gpt.parse_gpt_from_image(
        resources.resolve('brhgptpl_0', '2021').read_bytes())
    # anchor against the proven amonet-emu emu_chain.py values (which hold
    # the same LBAs x8 for its 512-byte block device)
    assert table['tee1'] == (3584, 1280)
    assert table['lk_a'] == (256, 384)
    assert table['tee2'] == (8768, 1280)

    donors = _donors()
    chip = NandChip()
    chip.load_donors(donors)
    for name, path in donors.items():
        start = table[DONOR_PART.get(name, name)][0]
        data, spare = split_page(chip.read_page(chip.page_of_lba(start)))
        assert data == path.read_bytes()[:NandChip.PAGE_DATA], name
        assert spare == b'\xff' * NandChip.PAGE_SPARE, name


@needs_donors
def test_per_copy_index_bytes():
    blobs = {n: p.read_bytes() for n, p in
             _donors(('brhgptpl_0', 'brhgptpl_1', 'brhgptpl_2',
                      'brhgptpl_3')).items()}
    for name, blob in blobs.items():
        if name == 'brhgptpl_0':
            continue
        differing = {i for i, (a, b) in
                     enumerate(zip(blobs['brhgptpl_0'], blob)) if a != b}
        assert differing == PER_COPY_INDEX_OFFSETS, name

    table = gpt.parse_gpt_from_image(blobs['brhgptpl_0'])
    chip = NandChip()
    chip.load_donors(_donors(('brhgptpl_0', 'brhgptpl_1',
                              'brhgptpl_2', 'brhgptpl_3')))
    for k, name in enumerate(('brhgptpl_0', 'brhgptpl_1',
                              'brhgptpl_2', 'brhgptpl_3')):
        start = table[name][0]
        assert start == 1024 * k, name
        # the model reproduces each copy's first two pages (page 1 of the
        # image carries the per-copy BRLYT index bytes)
        for i in (0, 1):
            page = chip.read_page(chip.page_of_lba(start + i))
            data, _ = split_page(page)
            assert data == blobs[name][i * NandChip.PAGE_DATA:
                                       (i + 1) * NandChip.PAGE_DATA], (name, i)
