# Donor: WS/tools/amonet-emu/emu_chain.py
# Upstream: in-repo harness (amonet-emu)
# Extracted 2026-10-31 (Task 5): classes Flash/ChipDumpFlash and their GPT
# map, donor semantics preserved exactly; read() now returns bytes instead
# of writing through uc (the preloader Emu port, Task 10, serves the
# bdev->read trampoline by calling read(blk, count) and writing the bytes
# to dst, exactly as the donor's hook_code dispatch does).

"""Image-backed flash models serving the preloader's bdev->read path.

Extraction of the flash DATA half of the donor harness: the images placed
at the GPT map's bdev blocks (Flash) or a NandChip.dump()-style page map
at true NAND placement (ChipDumpFlash). The BDEV shim plumbing the donor
spreads over module constants plus arm_device() is ported here only as
install(), which takes every shim constant as a keyword with the
donor-verbatim default; the constants themselves are owned by the
preloader layer (crumpet_emu/preloader/constants.py, Task 10), which
re-exports them and forwards them here — one owner per constant.
"""
import struct

# GPT (4096-byte LBAs) from brhgptpl_0.img -> bdev start blocks (512B units)
# lk_b added (crumpet kamakiri task 9): start 640 LBA4096 directly after
# lk_a's 384-LBA span, from the real GPT (emu/gpt.py parse). Appended at the
# END so every existing scenario's part_get scratch indices are unchanged.
GPT = {'tee1': (3584 * 8, 1280 * 8), 'lk_a': (256 * 8, 384 * 8),
       'tee2': (8768 * 8, 1280 * 8), 'lk_b': (640 * 8, 384 * 8)}


class _BdevFlash:
    """Shared bdev shim install() for the flash sources (donor arm_device)."""

    def install(self, session, *, tramp=0x120000, stack=0x12F000,
                bdev=0x1086EC, bdev_read=None, blksz=0x200,
                head_cell=0x102188, bounce=0x42056800,
                sram_dbuf_ptr=0x102994, dram_buf=0x42000000, **shim):
        """Arm the boot-device struct on `session`.

        Donor arm_device() body (emu_chain.py lines 561-569) verbatim,
        writing through Session instead of uc. The shim address constants
        default to the donor values (lines 61-83) but are owned by the
        preloader layer's constants module; they are keywords so that
        module can forward its own copies. bdev_read defaults to
        bdev + 0x20 (donor line 62: BDEV_READ = BDEV + 0x20). `stack`
        (donor line 83) belongs to the preloader's call driver, not to
        this shim, and extra `shim` keywords carry no shim state here —
        both are accepted so the whole shim constant set can be passed
        through unchanged.
        """
        if bdev_read is None:
            bdev_read = bdev + 0x20   # donor: BDEV_READ = BDEV + 0x20
        session.write(head_cell, struct.pack('<I', bdev))
        session.write(bdev + 0x00, struct.pack('<I', 0))          # id
        session.write(bdev + 0x04, struct.pack('<I', blksz))      # blksize
        session.write(bdev + 0x14, struct.pack('<I', bounce))
        session.write(bdev + 0x1C, struct.pack('<I', 0))          # next
        session.write(bdev_read, struct.pack('<I', tramp))        # bdev->read
        session.write(sram_dbuf_ptr, struct.pack('<I', dram_buf))


class Flash(_BdevFlash):
    """Global 4096-LBA flash model. Serves bdev->read(blk, count)."""

    def __init__(self, tee1_bytes, lk_bytes, tee2_bytes):
        self.blocks = {}
        def put(startblk, data):
            for i in range(0, len(data), 512):
                self.blocks[startblk + i // 512] = data[i:i + 512]
        put(GPT['tee1'][0], tee1_bytes)
        put(GPT['lk_a'][0], lk_bytes)
        put(GPT['lk_b'][0], lk_bytes)
        put(GPT['tee2'][0], tee2_bytes)

    def read(self, blk, count):
        """Return `count` bdev blocks (512 B each) starting at `blk`.

        Donor semantics (emu_chain.py lines 109-118): every requested
        block is served — blocks populated from the images as stored,
        blocks past the image bytes erase-filled 0xFF, so the result is
        never clipped to the image length. A trailing image block
        shorter than 512 B is served as the short slice, exactly as the
        donor writes it.
        """
        return b''.join(self.blocks.get(blk + i, b'\xFF' * 512)
                        for i in range(count))


class ChipDumpFlash(_BdevFlash):
    """Chip-dump-backed flash source (closed loop, Task 10): serves
    bdev->read(blk, count) from a NandChip.dump()-style {page: 4352-B
    page} map with TRUE NAND placement — the 4096-B LBA == page identity
    of emu/nand_model — instead of from image files.

    Reads arrive as 512-B boot-device blocks: block b maps to page
    b // 8 at intra-page offset (b % 8) * 512 inside the page's data
    plane (the first 4096 B; the 256-B spare plane carries ECC and is
    never addressed). Pages absent from the dump are erased and read
    as 0xFF. Drop-in replacement for Flash in every scenario.
    """

    SECTORS_PER_PAGE = 4096 // 512     # 8 bdev blocks per NAND page

    def __init__(self, dump):
        self.pages = {int(p): bytes(v) for p, v in dict(dump).items()}

    def read(self, blk, count):
        """Return `count` bdev blocks (512 B each) starting at `blk`.

        Donor semantics (emu_chain.py lines 140-147): block b is served
        from page b // SECTORS_PER_PAGE at offset (b % 8) * 512; absent
        pages read erased (0xFF-filled 512 B).
        """
        out = []
        for i in range(count):
            b = blk + i
            page = self.pages.get(b // self.SECTORS_PER_PAGE)
            if page is None:
                data = b'\xFF' * 512
            else:
                off = (b % self.SECTORS_PER_PAGE) * 512
                data = page[off:off + 512]
            out.append(data)
        return b''.join(out)
