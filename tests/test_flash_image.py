# Donor: WS/tools/amonet-emu/emu_chain.py
# Upstream: in-repo harness (amonet-emu), classes Flash/ChipDumpFlash
# Extracted 2026-10-31 (Task 5): read() semantics pinned to donor lines,
# cited per assert below. Line numbers refer to the donor file as of this
# extraction.
"""Pins for the extracted image-backed flash models (flash/image.py).

Every expected value below is derived by reading the donor read() path,
per the task brief ("read the donor first and pin its actual clipping
behavior"). Two behaviors differ from the plan's shorthand sketch and are
pinned to the donor instead:

1. Flash does NOT clip a partition read to len(image): donor line 111
   `data = self.blocks.get(blk + i, b'\xFF' * 512)` erase-fills every
   requested block past the image bytes, so read() always yields
   count * 512 bytes.
2. ChipDumpFlash addresses pages by bdev block, not page number: donor
   lines 134/142/146 map bdev block b -> page b // SECTORS_PER_PAGE (8)
   at intra-page offset (b % 8) * 512. Page 5 is therefore served at
   blocks 40..47; the sketch's read(5, 8) reads pages 0/1, which are
   absent from the dump and read erased (all 0xFF).
"""
from crumpet_emu.core.session import Session
from crumpet_emu.flash.image import GPT, ChipDumpFlash, Flash

# GPT['lk_a'] == (256*8, 384*8) in bdev 512-B blocks (donor lines 77-79)
LK_A_START, LK_A_COUNT = GPT['lk_a']
LK_A_SPAN = LK_A_COUNT * 512                 # 384*8*512 = 1,572,864


def test_flash_lk_a_slice():
    lk = bytes(range(256)) * 600              # 153,600 B: 512-multiple, < span
    tee1, tee2 = b'\x11' * 1024, b'\x22' * 1024
    f = Flash(tee1, lk, tee2)

    # Donor read() serves EVERY requested block: image blocks as stored
    # (put() chunks at 512 B, donor line 103), missing blocks erase-filled
    # 0xFF (donor line 111). Not clipped to len(lk) -- the tail past the
    # image reads as erased flash.
    out = f.read(LK_A_START, LK_A_COUNT)
    assert out == lk + b'\xFF' * (LK_A_SPAN - len(lk))
    assert len(out) == LK_A_SPAN              # 1,572,864

    # Out-of-range blocks (never populated by put(), donor lines 102-108)
    # hit the same erase-fill default.
    assert f.read(0, 1) == b'\xFF' * 512                # block 0: no image
    assert f.read(3_000, 2) == b'\xFF' * 1024           # in-span, past image

    # GPT map verbatim (donor lines 78-79): tee1 at 3584*8, and lk_b
    # (640*8) is served the same lk bytes as lk_a (donor line 106
    # `put(GPT['lk_b'][0], lk_bytes)`).
    assert f.read(3584 * 8, 2) == tee1[:1024]
    assert f.read(640 * 8, 2) == lk[:1024]

    # install() ports the donor arm_device() body (lines 561-569) onto
    # session.write: bdev struct fields and the trampoline pointers.
    s = Session()
    s.map(0x100000, 0x10000)                  # covers HEAD_CELL..BDEV+0x20
    f.install(s)
    assert s.rd32(0x102188) == 0x1086EC       # HEAD_CELL -> BDEV
    assert s.rd32(0x1086EC + 0x00) == 0       # id
    assert s.rd32(0x1086EC + 0x04) == 0x200   # blksize BLKSZ (donor line 77;
    #                                    constant owned by preloader/constants.py)
    assert s.rd32(0x1086EC + 0x14) == 0x42056800   # BOUNCE (DRAM_BUF+0x56800)
    assert s.rd32(0x1086EC + 0x1C) == 0       # next
    assert s.rd32(0x1086EC + 0x20) == 0x120000     # bdev->read == TRAMP
    assert s.rd32(0x102994) == 0x42000000     # SRAM_DBUF_PTR -> DRAM_BUF


def test_chipdump_page_reads():
    # Sector-identifiable page: 512-B sector k filled with byte k+1.
    page = bytes(i // 512 + 1 for i in range(4096))
    cdf = ChipDumpFlash({5: page})

    # Page 5 lives at bdev blocks 40..47 (b // 8 == 5): a full-page read
    # returns the page bytes at their true NAND placement (donor lines
    # 142-147).
    assert cdf.read(40, 8) == page

    # Intra-page offset (b % 8) * 512 (donor line 146): blocks 43,44 are
    # sectors 3,4 of page 5.
    assert cdf.read(43, 2) == b'\x04' * 512 + b'\x05' * 512

    # Blocks 5..12 map to pages 0 (b=5,6,7) and 1 (b=8..12): absent from
    # the dump -> erased 0xFF fill (donor lines 142-144). This pins the
    # donor truth behind the plan sketch's `read(5, 8)` wording.
    assert cdf.read(5, 8) == b'\xFF' * 4096

    # Reads entirely past the dumped pages are erased too.
    assert cdf.read(48, 3) == b'\xFF' * 1536
