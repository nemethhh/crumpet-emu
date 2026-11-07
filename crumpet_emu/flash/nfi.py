# Donor: WS/tools/kamakiri/emu/nfi_model.py
# Upstream: R0rt1z2/kamakiri
# Copied 2026-10-31: verbatim; emu.nand_model -> crumpet_emu.flash.nand

"""NFI controller model for the crumpet harness (MMIO @0x11001000).

Answers the register traffic of the stage2 NFI driver
(brom-payload/drivers/nfi.c — a clean-room transcription of the pl2021
mtk_nfc driver per emu/nfi_regs.json) against a NandChip. The controller
is driven only by the firmware's real writes; nothing shortcuts to the
chip from the host side:

- NFI_CMD stores select the opcode. 0x00 (READ_1ST) starts address
  collection; the 0x30 (READ_2ND) trailer — hardcoded inside cmdfunc's
  READ_1ST path, issued once — executes chip.read_page() and stages the
  4352-byte page for the FIFO. 0x80 (PROG_1ST) arms a program: NFI_REG_50
  stores feed the FIFO one byte or word at a time and the 0x10 (PROG_2ND)
  trailer executes chip.program_page() over the fed bytes. 0x60/0xD0 do
  the same for an erase (three row cycles, no column). 0x70 (STATUS)
  stages one status byte for the byte-wide DATAR read (bit7 = no
  failure; program-once refusals clear it). 0xFF (RESET) drops the
  transaction.
- NFI_ADDR stores carry the address cycles one byte at a time (column,
  column>>8, then the three row bytes); NFI_ADDRNOB stays cleared in
  this controller generation, exactly as the driver writes it.
- NFI_DATAR drains the staged page one little-endian word per read (or
  one byte for the status read); NFI_DATAR_STAT bit0 reports data-ready
  for reads and FIFO-ready for the program feed (waited before every
  word in both directions); NFI_ADDRCNTR[16:12] counts completed read
  sectors and NFI_REG_70[16:12] completed write sectors. A sector is the
  controller's interleaved 512 data + 32 spare unit, so a full page is
  8 sectors — matching the driver's `CON = sectors << 12` and the
  counter bookkeeping.

Program-once is enforced twice over: the chip's own pattern check, and
an explicit set of pages programmed through this controller (erased
again by an erase through it). The explicit state closes the pattern
hole where an all-0xFF program would otherwise read back as erased and
re-program silently.

BROM DMA reads (layer 5): when NFI+0x238 is armed (bit16, rom 0x10f0),
READ_2ND lands the page's data plane at the STRADDR buffer through the
harness dma_sink hook and latches STA bit9 (0x200); the disarm store or
the next command drops the latch. The BROM ALSO drains the staged page
word-by-word through NFI_DATAR (rom 0x1d28 drain loop) into the same
buffer — so BROM-protocol reads stage the LINEAR page, not the driver's
interleaved sector format.

NFI_STA reads return 0x20: no command/address busy bits, R/B# (bit8)
ready, no transfer error (bit18); bit5 set is the ECC-decode-path
ready state the BROM's boot reader waits on (rom 0x232c — the real
finding of the layer-5 replay: the BROM drives the HW ECC decoder
through NFI+0x240/0x244/0x248 and the 0x11002000 ECC register block
before draining any page). Plain storage registers (CNFG,
PAGEFMT, CON, CSN_CON, DATA_CON, INTR_EN, STRADDR, REG_90) keep
the last written value so the driver's read-modify-writes compose.
"""
from crumpet_emu.flash.nand import NandChip, PageNotErased  # noqa: F401 (refs)

NFI_BASE = 0x11001000


class NfiModelError(RuntimeError):
    """The firmware issued register traffic this model cannot answer."""


class NfiModel:
    """Register-level NFI model over one NandChip.

    Wired into BromHarness(nfi=...); the harness forwards every mapped
    read/write in the 0x11001000 window to read()/write() with the
    register offset and access size (2 or 4 bytes; the driver only
    issues aligned u16/u32 accesses).
    """

    # register offsets (emu/nfi_regs.json regs, base 0x11001000)
    CNFG = 0x00          # 16-bit RMW config
    PAGEFMT = 0x04
    CON = 0x08
    DATA_CON = 0x10      # 16-bit
    CMD = 0x20
    CSN_CON = 0x30       # 16-bit
    ADDR = 0x34
    ADDRNOB = 0x38
    INTR_EN = 0x40       # 16-bit
    DATAW = 0x50         # FIFO write port (driver NFI_REG_50)
    DATAR = 0x54         # data FIFO word port (byte-wide for status)
    DATAR_STAT = 0x58    # bit0: data ready (read) / FIFO ready (write)
    STA = 0x60           # bits 0/1 busy, 8 R/B#, 18 error
    REG_70 = 0x70        # write-phase completed sectors, bits 16:12
    STRADDR = 0x80
    ADDRCNTR = 0x84      # bits 16:12: completed sectors (read phase)
    REG_90 = 0x90
    REG_224 = 0x224      # hw_reset poll target
    DMA_CTL = 0x238      # BROM DMA arm/disarm (bit16 armed; rom 0x10f0/0x10f8)
    REG_26x = 0x264      # BROM zeroes 0x264..0x278 when arming

    # opcodes (emu/nfi_regs.json ops)
    CMD_READ_1ST = 0x00
    CMD_READ_2ND = 0x30
    CMD_PROG_1ST = 0x80
    CMD_PROG_2ND = 0x10
    CMD_ERASE_1ST = 0x60
    CMD_ERASE_2ND = 0xD0
    CMD_STATUS = 0x70
    CMD_RESET = 0xFF
    CMD_COL_1ST = 0x05      # ONFI read-data-column (BROM rom 0x1b3a)
    CMD_COL_2ND = 0xE0      # its trailer (rom 0x1b82)

    # controller sector: 512 data + 32 spare interleaved in the FIFO
    SECTOR_UNIT = NandChip.PAGE_DATA // 8 + NandChip.PAGE_SPARE // 8  # 544
    # BROM engine FIFO unit: 1024 data + 64 spare per sector (sub_2098's
    # v20 = sectors*1024 + sectors*spare_per_sector column math; 4 units
    # cover the whole 4096+256 page) — engine columns are in THESE units
    BROM_FIFO_UNIT = NandChip.PAGE_DATA // 4 + NandChip.PAGE_SPARE // 4  # 1088

    _COLUMN_CYCLES = 2   # column low, column high — then the row bytes
    _ROW_CYCLES = 3      # erase takes the row only
    STATUS_PASS = 0xC0   # bit7 set: no failure (do_write_ops @0x213C38)
    STATUS_FAIL = 0x00
    STA_ECC_READY = 0x20   # STA bit5: ECC-decode path ready (rom 0x232c)
    STA_DMA_DONE = 0x200   # STA bit9: BROM DMA read completion (rom 0x1180)

    def __init__(self, chip: NandChip):
        self.chip = chip
        self._regs: dict[int, int] = {}
        self._addr_cycles: list[int] = []   # stage2 byte-cycle stream
        self._addr_full: int | None = None  # BROM single row store
        self._staged = b''
        self._drained = 0
        self._feed = bytearray()
        self._prog_armed = False
        self._prog_con = 0          # CON as the data phase was armed
        self._programed: set[int] = set()
        self._status_byte = self.STATUS_PASS
        self._dma_done = False
        self.dma_sink = None    # harness hook: dma_sink(sram_addr, page_data)
        self._raw_page = b''         # raw page of the last READ_2ND
        self._col_off = 0            # column offset latched by 0x05
        self._dma_cntr = 0           # sectors completed in the DMA read phase
        self._brom_protocol = False  # last READ_2ND used ADDRNOB row addressing

    # ------------------------------------------------------------- hooks --
    def read(self, offset: int, size: int) -> int:
        if offset == self.DATAR:
            if size not in (1, 4):
                raise NfiModelError(f'DATAR access size {size} at '
                                    f'+{offset:#x}')
            if self._drained + size > len(self._staged):
                raise NfiModelError(
                    f'DATAR over-drain: {self._drained} of '
                    f'{len(self._staged)} staged bytes')
            word = int.from_bytes(
                self._staged[self._drained:self._drained + size], 'little')
            self._drained += size
            return word
        if offset == self.DATAR_STAT:
            if self._prog_armed:
                return 1            # FIFO has room for the next feed word
            return 1 if self._drained < len(self._staged) else 0
        if offset == self.STA:
            # never busy, never erroring; bit5 (the BROM's ECC-path
            # ready bit, rom 0x232c) stays set, and bit9 latches the
            # BROM's DMA read completion — the stage2 driver only ever
            # waits bits 0/1/8/18 to CLEAR, which stay 0 here
            return self.STA_ECC_READY | (self.STA_DMA_DONE if self._dma_done else 0)
        if offset == self.ADDRCNTR:
            # DMA phase (BROM reader): counts sectors the engine landed;
            # FIFO phase (stage2 driver): counts DATAR words drained
            if self._regs.get(self.DMA_CTL, 0) & 0x10000:
                return (self._dma_cntr & 0x1F) << 12
            return (self._drained // self.SECTOR_UNIT & 0x1F) << 12
        if offset == self.REG_70:
            # rom 0x1d96+: the BROM's read drain watches this counter's
            # [16:12] sector count up to the requested one — the same
            # counter serves the write phase for the stage2 driver
            if self._regs.get(self.DMA_CTL, 0) & 0x10000:
                return (self._dma_cntr & 0x1F) << 12
            return (len(self._feed) // self.SECTOR_UNIT & 0x1F) << 12
        return self._regs.get(offset, 0) & ((1 << (8 * size)) - 1)

    def write(self, offset: int, value: int, size: int) -> None:
        if offset == self.CMD:
            self._regs[offset] = value & 0xFFFFFFFF
            self._dma_done = False      # any command drops the done latch
            self._on_command(value & 0xFF)
            return
        if offset == self.CON and self._regs.get(self.DMA_CTL, 0) & 0x10000:
            # the BROM's drain phase reprograms CON right after READ_2ND
            # (rom 0x1c00) with `units << 12 | 0x100`, counting 1024-B
            # units in this page format (4 = a full 4096-B page, 2 = the
            # image's trailing half page — pinned against the 37-page
            # preloader load: 72x CON=0x4100 + 2x 0x2100). The engine
            # lands units*1024 bytes of the last-read page at STRADDR
            # (which advances 0x1000 per page, rom 0x1912) and the
            # REG_70 counter the drain waits on (rom 0x1d96) reflects
            # the completed units.
            self._regs[offset] = value & 0xFFFFFFFF
            units = (value >> 12) & 0x1F
            self._dma_cntr = units
            if units and self.dma_sink is not None:
                base = self._regs.get(self.STRADDR, 0)
                if base:
                    col = self._fifo_col_to_data(
                        self._regs.get(self.ADDR, 0) & 0xFFFF)
                    end = min(col + units * 1024, NandChip.PAGE_DATA)
                    self.dma_sink(base, self._raw_page[col:end])
                    # the drain-phase reprogram is where the engine's
                    # read window opens: the FIFO position follows the
                    # (data-plane) column — the CPU drain loop that
                    # lands the same bytes word-by-word starts there too
                    # (task-11 finding: with the FIFO at 0 a
                    # column-offset sub-read overwrote its own
                    # DMA-landed bounce buffer with page-offset-0 bytes)
                    if self._staged:
                        self._drained = col
            return
        if offset == self.DMA_CTL:
            # the BROM arms the DMA engine (bit16, rom 0x10f0) before a
            # read and disarms it (0, rom 0x10f8) after; the rest of the
            # stored word is a static page-format config it derives from
            # a ROM LUT and never varies
            self._regs[offset] = value & 0xFFFFFFFF
            if not (value & 0x10000):
                self._dma_done = False
            return
        if offset == self.ADDR:
            self._regs[offset] = value & 0xFFFFFFFF
            # Two addressing protocols hit this port: the stage2 driver
            # streams one byte per store (5 stores for a page op, 3 for
            # an erase — the controller latches the low byte of each),
            # while the BROM's own boot reader (rom 0x19a0) stores the
            # whole row address in ONE 32-bit write, with NFI_ADDRNOB
            # carrying the cycle count it stands for. The store count
            # between commands separates them exactly.
            if self._addr_full is not None:
                self._addr_cycles.append(self._addr_full & 0xFF)
                self._addr_full = None
            if not self._addr_cycles:
                self._addr_full = value        # lone store so far
            else:
                self._addr_cycles.append(value & 0xFF)
            return
        if offset == self.DATAW:
            self._feed_fifo(value, size)
            return
        if offset == self.DATAR_STAT:
            return             # read-only status port
        self._regs[offset] = value & ((1 << (8 * size)) - 1)

    # ------------------------------------------------------ command exec --
    def _on_command(self, cmd: int) -> None:
        if cmd == self.CMD_READ_1ST:
            self._addr_cycles = []
            self._addr_full = None
            self._dma_cntr = 0        # per-transaction sector counter
        elif cmd == self.CMD_READ_2ND:
            self._exec_read()
        elif cmd == self.CMD_PROG_1ST:
            self._addr_cycles = []
            self._feed = bytearray()
            self._prog_armed = True
            self._prog_con = 0
        elif cmd == self.CMD_PROG_2ND:
            self._exec_program()
        elif cmd == self.CMD_ERASE_1ST:
            self._addr_cycles = []
            self._feed = bytearray()
            self._prog_armed = False
        elif cmd == self.CMD_ERASE_2ND:
            self._exec_erase()
        elif cmd == self.CMD_STATUS:
            self._staged = bytes([self._status_byte])
            self._drained = 0
        elif cmd == self.CMD_COL_1ST:
            # the lone 32-bit ADDR store preceding 0x05 carries the
            # column offset in its low half (rom 0x1b3a)
            self._col_off = (self._addr_full & 0xFFFF) \
                if self._addr_full is not None else self._col_off
            self._addr_full = None
        elif cmd == self.CMD_COL_2ND:
            self._exec_column_read()
        elif cmd == self.CMD_RESET:
            self._addr_cycles = []
            self._addr_full = None
            self._staged = b''
            self._drained = 0
            self._feed = bytearray()
            self._prog_armed = False

    def _feed_fifo(self, value: int, size: int) -> None:
        if size not in (1, 4):
            raise NfiModelError(f'DATAW access size {size} at '
                                f'+{self.DATAW:#x}')
        if not self._prog_armed:
            raise NfiModelError('DATAW store outside a program data phase')
        if not self._feed:
            # CON as the data phase began — the completion tail clears
            # CON before PROG_2ND, so the sector count is captured here
            self._prog_con = self._regs.get(self.CON, 0)
        chunk = (value & ((1 << (8 * size)) - 1)).to_bytes(size, 'little')
        page = NandChip.PAGE_DATA + NandChip.PAGE_SPARE
        if len(self._feed) + size > page:
            raise NfiModelError(f'DATAW over-feed: {len(self._feed) + size} '
                                f'> {page} page bytes')
        self._feed += chunk

    def _fifo_col_to_data(self, col: int) -> int:
        """Translate a BROM engine column (FIFO units of 1024 data + 64
        spare per sector, sub_2098's v20 math) to its data-plane offset
        inside the page. Sector-aligned columns land on the sector's
        data start (0x880 -> 0x800); a column inside a unit's spare
        stretch clamps to that sector's data start (the engine only
        ever issues sector-aligned columns; spare reads go through the
        0x05/0xE0 column path instead)."""
        sec, off = divmod(col, self.BROM_FIFO_UNIT)
        return sec * 1024 + min(off, 1024)

    def _page_of_rows(self, column_cycles: int) -> int:
        row = self._addr_cycles[column_cycles:]
        return row[0] | row[1] << 8 | row[2] << 16

    def _read_page_arg(self) -> int:
        """Row address of a read.

        Two protocols reach the READ_2ND trailer (rom 0x19e4):
        - the stage2 driver streams 2 column + 3 row byte cycles into
          NFI_ADDR (the low byte of each store latches) and leaves
          NFI_ADDRNOB cleared;
        - the BROM's own boot reader (rom 0x16e4 engine) writes the
          COLUMN into NFI_ADDR (0 in every observed transaction) and
          the ROW into NFI_ADDRNOB (rom 0x19a4: page-1 BRLYT read
          stores 1, the offset-0x400 GFH retry stores 0x400 — pinned
          by instruction-level traces, scripts/boot_drive.py).
        The ADDR store count between commands separates them exactly.
        (NFI_CON bits 25:12 stay the SECTOR count in both protocols —
        the 0x1100 store at rom 0x1c00 is `1 sector | bit8`, not a
        row.)"""
        if self._addr_full is not None and not self._addr_cycles:
            page = self._regs.get(self.ADDRNOB, 0) & 0x3FFFF
            self._addr_full = None
            self._brom_protocol = True
            return page
        if len(self._addr_cycles) < self._COLUMN_CYCLES + 3:
            raise NfiModelError(
                f'READ_2ND after only {len(self._addr_cycles)} address '
                'cycles (need 2 column + 3 row)')
        self._brom_protocol = False
        return self._page_of_rows(self._COLUMN_CYCLES)

    def _exec_program(self) -> None:
        self._prog_armed = False
        if len(self._addr_cycles) != self._COLUMN_CYCLES + self._ROW_CYCLES:
            raise NfiModelError(
                f'PROG_2ND after {len(self._addr_cycles)} address '
                'cycles (need 2 column + 3 row)')
        column = self._addr_cycles[:self._COLUMN_CYCLES]
        if any(column):
            raise NfiModelError(f'program column cycles {column} != 0 '
                                '(whole-page programs only)')
        sectors = (self._prog_con >> 12) & 0x1F
        want = NandChip.PAGE_DATA // 512
        if sectors != want:
            raise NfiModelError(f'CON sector count {sectors} != {want}')
        payload = sectors * self.SECTOR_UNIT
        if len(self._feed) != payload:
            raise NfiModelError(f'FIFO fed {len(self._feed)} bytes, '
                                f'program needs {payload}')
        if not self._regs.get(self.STRADDR, 0):
            raise NfiModelError('STRADDR not set for the program data '
                                'phase')
        page = self._page_of_rows(self._COLUMN_CYCLES)
        if page in self._programed:
            self._status_byte = self.STATUS_FAIL   # program-once refusal
            return
        try:
            self.chip.program_page(page, self._deinterleave(
                bytes(self._feed)))
        except PageNotErased:
            self._status_byte = self.STATUS_FAIL   # chip refusal
            return
        self._programed.add(page)
        self._status_byte = self.STATUS_PASS

    def _exec_erase(self) -> None:
        if len(self._addr_cycles) != self._ROW_CYCLES:
            raise NfiModelError(
                f'ERASE_2ND after {len(self._addr_cycles)} address '
                'cycles (need 3 row)')
        page = self._page_of_rows(0)      # erase rows carry no column
        block = page // NandChip.PAGES_PER_BLOCK
        self.chip.erase_block(block)   # ValueError on a bad block
        for p in range(block * NandChip.PAGES_PER_BLOCK,
                       (block + 1) * NandChip.PAGES_PER_BLOCK):
            self._programed.discard(p)

    def _exec_column_read(self) -> None:
        """ONFI 0x05/0xE0 random data output: serve the 512-B sector at
        the latched column offset of the last-read page.

        The BROM's boot reader reads a page sector-by-sector: READ_2ND
        lands sector 0 at STRADDR, then each 0x05/0xE0 pair at column
        512*n lands sector n (rom 0x1b3a/0x1b82) — the address arrives
        as the lone 32-bit ADDR store's low half. The sector is served
        from the RAW page (column addressing is over the data plane;
        the FIFO interleave is a DATAR-drain format the BROM never
        uses), and the FIFO state is left untouched: the stage2 driver
        never issues column reads."""
        off = self._col_off
        raw = self._raw_page
        if off + 512 > len(raw):
            raise NfiModelError(
                f'column read at {off:#x} beyond the page '
                f'({len(raw)} bytes)')
        if self._regs.get(self.DMA_CTL, 0) & 0x10000 and self.dma_sink:
            base = self._regs.get(self.STRADDR, 0)
            if base:
                self.dma_sink(base, raw[off:off + 512])
            self._dma_done = True
            self._dma_cntr += 1

    def _exec_read(self) -> None:
        page = self._read_page_arg()
        raw = self.chip.read_page(page)      # ValueError on bad page
        self._raw_page = raw          # column reads address into this page
        # FIFO staging depends on the protocol: the stage2 driver drains
        # the controller's interleaved 512+32 sector format (its readers
        # deinterleave), while the BROM's own engine drains DATAR
        # word-by-word straight into the load buffer (rom 0x1d28) AND
        # lands the same bytes through the DMA path — both must see the
        # LINEAR page or the delivered image corrupts (task-11 finding:
        # interleave staging put 32 spare bytes over every 512-B sector
        # and the BROM's case-3 signature gate then read garbage).
        self._staged = raw if self._brom_protocol else self._interleave(raw)
        self._drained = 0
        if self._regs.get(self.DMA_CTL, 0) & 0x10000:
            # the BROM's DMA read path: READ_2ND completes the chip
            # transaction and latches STA bit9 (rom 0x1180 waits on it;
            # the ROM itself never writes STA — the disarm store or the
            # next command is the clear). The data landing happens at
            # the drain-phase CON reprogram (see write()) so the burst
            # size matches the units the drain expects — landing here
            # instead would overrun BROM SRAM globals on 1-unit reads
            # (a full-page store at 0x100048 clobbers the device-pointer
            # cell at 0x100914 with page-zero zeros).
            self._dma_done = True

    @staticmethod
    def _interleave(raw: bytes) -> bytes:
        """Stage the page in the controller's sector format: the FIFO
        streams 512 data bytes then 32 spare bytes per sector, per the
        PAGEFMT the driver programs (read_subpage's word drain and the
        deinterleave in its callers rely on exactly this order)."""
        data, spare = raw[:NandChip.PAGE_DATA], raw[NandChip.PAGE_DATA:]
        out = bytearray()
        for sec in range(NandChip.PAGE_DATA // 512):
            out += data[sec * 512:(sec + 1) * 512]
            out += spare[sec * 32:(sec + 1) * 32]
        return bytes(out)

    @staticmethod
    def _deinterleave(sector_bytes: bytes) -> bytes:
        """Inverse of _interleave: the fed 512+32-per-sector FIFO bytes
        back into the chip's flat 4096 data + 256 spare page."""
        data = bytearray(NandChip.PAGE_DATA)
        spare = bytearray(NandChip.PAGE_SPARE)
        unit = NandChip.PAGE_DATA // 8 + NandChip.PAGE_SPARE // 8
        for sec in range(NandChip.PAGE_DATA // 512):
            base = sec * unit
            data[sec * 512:(sec + 1) * 512] = \
                sector_bytes[base:base + 512]
            spare[sec * 32:(sec + 1) * 32] = \
                sector_bytes[base + 512:base + unit]
        return bytes(data) + bytes(spare)
