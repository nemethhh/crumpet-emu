# Donor: WS/tools/kamakiri/emu/brom_boot.py
# Upstream: R0rt1z2/kamakiri
# Copied verbatim: 2026-10-31 (Task 7 lazy paths: import-time ROM/DONOR_DIR
#   workspace reads -> resources resolve; _trace/_verdict_cache module
#   globals -> BootContext; _BootReplay -> public BootReplay + alias)

"""Layer 5 — real-BROM boot-read proof + intermediate-state replay.

classify(snapshot) replays the REAL MT8167 BROM boot code (no-alexa
brom_MT8167_*.bin mapped at 0x0, started at sub_C634 boot main) against
a NandChip restored from a NandChip.dump() snapshot:

  boot-source detect -> NFI init -> GFH scan (27-slot config sweep)
  -> BRLYT walk (page 1) -> GPT (page 3) -> parts table -> per-part
  load with real bad-block probes -> the full 37-page preloader DMA/FIFO
  load -> SBC chain -> signature verify -> "Jump to BL" -> the real
  preloader's first instructions.

Verdicts:
  'boots_2021_pl'  — the BROM jumped: execution crossed into the loaded
                     preloader window (0x200D00..0x226000, entry 0x201000)
  'brom_usdl_wait' — the boot walk failed and the BROM landed in the
                     USBDL handshake wait (sub_5BA8 loop) — strap-free
                     recovery: the device is BROM-recoverable. With no
                     host attached the real connect wait (sub_71C4)
                     times out to System halt (observed in replay); the
                     verdict therefore comes from classify()'s
                     recovery retry with the cable present — the
                     host-attached box the recovery scenario assumes.
                     The USB connect/enumeration wait itself is the one
                     USB boundary emulated in this replay (see
                     M_USBCONNECT; layer-1's harness likewise seeds
                     ENUM_STATE=3 instead of replaying enumeration).
  'invalid'        — anything else (halt, stall, budget, fault)

Crypto stub (the ONE permitted, per the plan): the BROM's image
signature verify — sub_A08E walking the GFH and dispatching into the
sub_9882 crypto library — is answered by a pass-oracle keyed on the
2021 Amazon-signed donors: it accepts iff the delivered image's content
hash equals the hash embedded in its own signature block AND the full
load window hashes to a donor window. Anything else runs the real code
and fails honestly. (Exploratory note: with the delivery pipeline
corrected, the REAL crypto path also passes in emulation — observed
during the task-11 bring-up; the stub stays for determinism, per the
plan.) The streaming-verify setup (sub_E524) is accepted
unconditionally, exactly as in the exploration driver.

classify(final=True) additionally runs the per-page donor-equivalence
belt: every written page inside the four brhgptpl partitions must
byte-match its donor image (data plane, all-0xFF spare) — assert-fail
otherwise.

Boot-region memoization: the BROM boot reads only the four brhgptpl
partitions (BRLYT/GPT pages included), so snapshots whose boot regions
are byte-identical classify identically — verdicts are cached by the
sha256 of those pages, keeping the intermediate-replay test tractable.
"""
import hashlib
import struct
from collections import OrderedDict

from unicorn import Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB, \
    UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, \
    UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R8, UC_ARM_REG_SP, \
    UC_ARM_REG_LR, UC_ARM_REG_PC

from crumpet_emu.core.devices import (TIMER_REG as GPT_TIMER, UART_LSR,
                                      UART_THR, WDT_BASE)
from crumpet_emu.core.session import MAGIC_RET
from crumpet_emu.flash.gpt import parse_gpt_from_image
from crumpet_emu.flash.nand import NandChip
from crumpet_emu.flash.nfi import NfiModel
from crumpet_emu.resources import resolve


def load_rom() -> bytes:
    """The no-alexa BROM blob (manifest key common:brom), read lazily:
    the donor read it at import time from a workspace-relative path."""
    return resolve('brom', 'common').read_bytes()


PAGE = NandChip.PAGE_DATA
PAGES_PER_BLOCK = NandChip.PAGES_PER_BLOCK

# MAGIC_RET / UART_THR / UART_LSR / GPT_TIMER (= core's TIMER_REG) /
# WDT_BASE: values donor-verbatim (donor lk_emu.py); single-sourced from
# core (crumpet_emu.core.session / crumpet_emu.core.devices).
NFI_BASE = 0x11001000
ECC_BASE = 0x11002000
USB_BASE = 0x11100000

SP_INIT = 0x00102738
TICKS_PER_INSTR = 16        # modeled GPT: hardware timeouts complete fast
PL_WINDOW = (0x200D00, 0x226000)      # the loaded preloader (GFH..file end)

BOOT_MAIN = 0xC634          # sub_C634 — the BROM boot main
# loops the ROM never leaves once reached — terminal states
TERMINAL_SPINS = {0xC9BE: 'system-halt-spin',
                  0xC9CA: 'system-halt-drain',
                  0x5BA8: 'usdl-handshake-wait',
                  0x7284: 'uart-drain-spin'}
# milestone entry points the trace names (same sites as the pinned
# instruction-level exploration, scripts/boot_drive.py)
M_BRLYT = 0xCC4             # sub_CC4 — BRLYT walk
M_LOADED = 0xE5FE           # the loaded-flag STRB in sub_E5xx
M_VERIFY = 0xE524           # sub_E524 — streaming-verify setup (oracle)
M_A08E = 0xA08E             # sub_A08E — GFH walk + signature verify
M_L2A = 0x10098             # L2-aux config helper bodies (MRRC/MCRR —
M_L2B = 0x100B0             #   unicorn-invalid: emulate at boundaries)
M_DMACPY = 0x10294          # ROM DMA block copier (done-bit can't set)
M_BBCHECK = 0x1FC8          # sub_1FC8 — bad-block probe (bbm capture)
M_BBTEST = 0x2078           # the BBM consumer inside sub_2078
M_DISPATCH = 0xDFF6         # sub_DFF6 — the USBDL command dispatcher
M_USBDL_DEC = 0x5DEC        # the USBDL-fallback decision
M_HANDSHAKE = 0x5BA8        # the USBDL handshake itself
M_USBCONNECT = 0x71C4       # sub_71C4 — the USB connect/enumeration wait

# the four boot partitions the BROM walks (memo key + belt scope)
BOOT_PARTS = ('brhgptpl_0', 'brhgptpl_1', 'brhgptpl_2', 'brhgptpl_3')

class BootContext:
    """classify()'s former module globals — the last run's trace and the
    boot-region verdict cache (donor ``_trace``/``_verdict_cache``) —
    moved into a class per the plan's module-global refactor. classify()
    keeps its exact public signature by using the module-level default
    instance below; last_trace() reads the same instance, so the public
    API and behavior are unchanged."""

    def __init__(self):
        self.trace: list[str] = []      # the last classify() run's trace
        self.verdict_cache: dict[str, tuple[str, list[str]]] = {}


_default_ctx = BootContext()    # classify()/last_trace() default context


def last_trace() -> list[str]:
    """Trace lines of the most recent classify() run (test assertions
    key on the prefixes: brlyt-walk / pl-loaded / verify-pass / jump)."""
    return list(_default_ctx.trace)


class BootReplay:
    """The real-BROM replay engine (scripts/boot_drive.py, distilled
    to the layer-5 proof surface)."""

    def __init__(self, chip: NandChip, budget: int = 2_000_000_000,
                 cable: bool = False):
        self.chip = chip
        self.nfi = NfiModel(chip)
        self.nfi.dma_sink = self._dma_sink
        self.budget = budget
        self.cable = cable
        self.now = 0
        self.stop_reason: str | None = None
        self.last_pc = 0
        self.trace: list[str] = []
        self.uart_out = bytearray()
        self._loop_guard: dict[int, int] = {}
        self._last_spare_bbm: bytes | None = None
        self._dispatch_seen = False
        self.wait_lrs: dict[int, int] = {}      # debug: sub_1DC callers
        self.wait_polls: dict[tuple, int] = {}   # debug: sub_10FE args
        self.poll_lrs: dict[int, int] = {}       # debug: sub_10FE callers
        self.pc_ring: OrderedDict[int, int] = OrderedDict()
        self.progress = None    # probe hook: fn(replay) every ~16M instrs
        self.allowlist = _donor_window_hashes()

        uc = self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.mem_map(0x0, 0x20000)                    # BROM
        uc.mem_write(0x0, load_rom())
        uc.mem_map(0x100000, 0x21000)               # SRAM + stack headroom
        uc.mem_map(0x200000, 0x80000)               # preloader load window
        uc.mem_map(WDT_BASE, 0x1000)
        uc.mem_map(0x10008000, 0x1000)              # GPT timer
        uc.mem_map(0x10009000, 0x1000)              # eFuse
        uc.mem_map(0x1000A000, 0x1000)              # strap/boot-mode latch
        uc.mem_map(0x10209000, 0x1000)              # DRAM-cal result struct
        uc.mem_map(0x10200000, 0x1000)              # clk/cfg window
        uc.mem_map(0x10005000, 0x1000)              # infra cfg RMWs
        uc.mem_map(0x11120000, 0x1000)              # pericfg RMWs
        uc.mem_map(NFI_BASE, 0x1000)
        uc.mem_map(ECC_BASE, 0x1000)
        uc.mem_map(UART_THR & ~0xFFF, 0x1000)
        uc.mem_write(UART_LSR, struct.pack('<I', 0x20))
        uc.mem_map(USB_BASE, 0x1000)                # dead (zero) page

        uc.hook_add(UC_HOOK_CODE, self._hook_code)
        uc.hook_add(UC_HOOK_MEM_INVALID, self._hook_invalid)
        uc.hook_add(UC_HOOK_MEM_READ, self._hook_timer_read,
                    begin=GPT_TIMER, end=GPT_TIMER + 3)
        uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_uart_write,
                    begin=UART_THR, end=UART_THR + 3)
        uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_wdt_write,
                    begin=WDT_BASE, end=WDT_BASE + 0x40)
        uc.hook_add(UC_HOOK_MEM_READ, self._hook_ecc_read,
                    begin=ECC_BASE, end=ECC_BASE + 0xFFF)
        uc.hook_add(UC_HOOK_MEM_READ, self._hook_nfi_read,
                    begin=NFI_BASE, end=NFI_BASE + 0xFFF)
        uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_nfi_write,
                    begin=NFI_BASE, end=NFI_BASE + 0xFFF)

        # ---- seeds (harness precedent, scripts/boot_drive.py) ----
        uc.mem_write(0x1000A000, struct.pack('<I', 2))   # strap: NAND boot
        # USB cable detection OUTPUT cell: sub_71C4 stores sub_5EE4's
        # detection result here (rom 0x71cc) — an output, not an input;
        # seeded for parity with the layer-1 harness snapshot. The
        # cable's actual effect is the M_USBCONNECT boundary above.
        uc.mem_write(0x001028D4, bytes([1 if self.cable else 0]))
        # DRAM-calibration result magic (the cal itself is not modeled)
        uc.mem_write(0x1020905C, struct.pack('<I', 0x504D454D))  # 'MEMP'

    # ------------------------------------------------------------ run --
    def run(self, entry: int = BOOT_MAIN) -> int:
        uc = self.uc
        uc.reg_write(UC_ARM_REG_SP, SP_INIT - 0x800)
        uc.reg_write(UC_ARM_REG_LR, MAGIC_RET | 1)
        try:
            uc.emu_start(entry | 1, MAGIC_RET)
        except UcError as e:
            if self.stop_reason is None:
                self.stop_reason = f'uc-error {e} pc={self.last_pc:#x}'
        return uc.reg_read(UC_ARM_REG_R0)

    # ---------------------------------------------------------- hooks --
    def _dma_sink(self, addr, data):
        self.uc.mem_write(addr, data)

    def _hook_code(self, uc, address, size, user):
        self.now += 1
        if self.now > self.budget:
            self.stop_reason = 'budget'
            uc.emu_stop()
            return
        self.last_pc = address
        if not self.now & 0xF:               # rolling distinct-PC ring
            ring = self.pc_ring
            ring[address] = self.now
            if len(ring) > 96:
                ring.popitem(False)
        if address == 0x1DC:    # the wait-with-timeout helper
            lr = uc.reg_read(UC_ARM_REG_LR)
            if len(self.wait_lrs) < 64 or lr in self.wait_lrs:
                self.wait_lrs[lr] = self.wait_lrs.get(lr, 0) + 1
        if address == 0x10FE:   # the reg-poll-with-timeout helper
            args = (uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1),
                    uc.reg_read(UC_ARM_REG_R2))
            if len(self.wait_polls) < 64 or args in self.wait_polls:
                self.wait_polls[args] = self.wait_polls.get(args, 0) + 1
            lr = uc.reg_read(UC_ARM_REG_LR) & ~1
            self.poll_lrs[lr] = self.poll_lrs.get(lr, 0) + 1
        if PL_WINDOW[0] <= address < PL_WINDOW[1]:
            # execution crossed into the loaded preloader: the jump
            # happened — real BROM code brought us here, layer-5's proof
            self.trace.append(
                f'jump: PC={address:#x} (preloader entry 0x201000, '
                f'after {self.now} instrs)')
            self.stop_reason = 'jumped'
            uc.emu_stop()
            return
        if address in TERMINAL_SPINS:
            self.trace.append(
                f'terminal: {TERMINAL_SPINS[address]} @{address:#x}')
            self.stop_reason = TERMINAL_SPINS[address]
            uc.emu_stop()
            return
        if address == M_BRLYT:
            self.trace.append(f'brlyt-walk @{address:#x}')
        elif address == M_USBDL_DEC:
            self.trace.append('usdl-decision entered')
        elif address == M_HANDSHAKE:
            self.trace.append('usdl-handshake entered')
        elif address == M_DISPATCH:
            if not self._dispatch_seen:
                self.trace.append('usdl-dispatcher entered (waiting '
                                  'for a download host)')
                self._dispatch_seen = True
        elif address == M_LOADED:
            self.trace.append(f'pl-loaded @{address:#x}')
        elif address == M_L2A:
            uc.reg_write(UC_ARM_REG_R0, uc.reg_read(UC_ARM_REG_R0) | 0x40)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        elif address == M_L2B:
            uc.reg_write(UC_ARM_REG_R0, uc.reg_read(UC_ARM_REG_R0) & ~0x40)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        elif address == M_DMACPY:
            self._emu_dma_memcpy(uc)
        elif address == M_BBTEST:
            # the engine's BBM extraction is engine-internal (the ctx
            # cell gets rewritten by the engine's own post-read code):
            # publish the captured spare byte 0 at the consumer
            if self._last_spare_bbm is not None:
                uc.mem_write(uc.reg_read(UC_ARM_REG_R8),
                             self._last_spare_bbm)
                self._last_spare_bbm = None
        elif address == M_VERIFY:
            # streaming-verify SETUP: accept unconditionally (the donor
            # identity gate lives in the a08e oracle + the final belt)
            self.trace.append(f'verify-setup accepted @{address:#x}')
            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        elif address == M_USBCONNECT:
            # sub_71C4 — the USB connect/enumeration wait: polls the
            # MUSB PHY event machine (sub_6D5E: INTRUSB +0xA bit4
            # connect, POWER +0x1 bit5 VBUS, INTRTX/RX +2/+4 driving
            # the driver callbacks that advance ENUM_STATE 0x103941 to
            # 3) for a HOST to enumerate the device — interaction this
            # replay does not model (the USB page is intentionally
            # dead; layer-1's harness likewise seeds ENUM_STATE=3
            # post-enumeration instead of replaying enumeration). With
            # a cable present (the recovery retry) the wait succeeds;
            # without one the REAL code runs and times out honestly
            # (observed: 16M instrs polling the dead page -> return 0
            # -> sub_5DEC falls to System halt).
            if self.cable:
                self.trace.append('usb-connect wait: emulated success '
                                  '(cable present)')
                uc.reg_write(UC_ARM_REG_R0, 1)
                uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        elif address == M_A08E:
            self._verify_oracle(uc)
        # loop guard (sampled every 256 instrs): a tight region burning
        # hundreds of millions of instructions = a never-ready wait.
        # Region 0x0 (the shared sub_1D0/sub_1DC tick/timeout helpers at
        # 0x1d0..0x218) is exempt: EVERY wait funnels through it, so a
        # legitimate long flow (the erased-boot retry loop: up to 15
        # full boot attempts, ~700M instructions, before the USBDL
        # fallback) would dilute-and-trip the sampler long before the
        # real terminal state.
        if not self.now & 0xFF:
            if not self.now & 0xFFFFFF and self.progress is not None:
                self.progress(self)
            key = address & ~0x3FF
            if key:
                n = self._loop_guard.get(key, 0) + 1
                self._loop_guard[key] = n
                if n > 1_500_000:
                    self.stop_reason = 'stall'
                    self.trace.append(
                        f'stall near {address:#x} (never-ready wait, '
                        f'{self.now} instrs)')
                    uc.emu_stop()

    def _verify_oracle(self, uc):
        """sub_A08E — the BROM's image signature verify (the plan's one
        permitted crypto stub): accept iff the delivered image's content
        hash equals the hash embedded in its own signature block AND
        the full window hashes to a 2021 donor window."""
        try:
            a3 = uc.reg_read(UC_ARM_REG_R2)
            base = struct.unpack('<I', bytes(uc.mem_read(a3, 4)))[0]
            fsize, sigsz = (
                struct.unpack('<I', bytes(uc.mem_read(base + o, 4)))[0]
                for o in (0x20, 0x2C))
            content = fsize - sigsz
            blob = bytes(uc.mem_read(base, fsize))
            chash = hashlib.sha256(blob[:content]).digest()
            embedded = blob[content + 4:content + 36]
            window = hashlib.sha256(blob).hexdigest()
            ok = chash == embedded and window in self.allowlist
        except Exception as e:                      # noqa: BLE001
            self.trace.append(f'verify-pass oracle read-fail {e}')
            return                                  # run the real code
        if ok:
            self.trace.append(
                f'verify-pass: base={base:#x} content={content:#x} '
                f'sig-hash == content-hash, window in donor allowlist')
            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        else:
            self.trace.append(
                f'verify REJECT: base={base:#x} content={content:#x} '
                f'hash-match={chash == embedded} '
                f'donor={window in self.allowlist}')

    def _emu_dma_memcpy(self, uc):
        # sub_10294(r0=src, r1=dst, r2=bytes): ROM DMA block copier —
        # the engine's done bit can never set in flat memory; it
        # returns the ADVANCED source pointer (16-B rounded)
        src = uc.reg_read(UC_ARM_REG_R0)
        dst = uc.reg_read(UC_ARM_REG_R1)
        n = uc.reg_read(UC_ARM_REG_R2)
        if n:
            uc.mem_write(dst, bytes(uc.mem_read(src, n)))
        uc.reg_write(UC_ARM_REG_R0, src + ((n + 15) & ~15))
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    def _hook_invalid(self, uc, access, address, size, value, user):
        if access != 16:
            base = address & ~0xFFF
            try:
                uc.mem_map(base, 0x1000)
                return True
            except Exception:                       # noqa: BLE001
                pass
        self.stop_reason = 'fault'
        self.trace.append(
            f'fault: unmapped {"FETCH" if access == 16 else "MEM"} '
            f'at {address:#x} pc={self.last_pc:#x}')
        uc.emu_stop()
        return False

    def _hook_timer_read(self, uc, access, address, size, value, user):
        uc.mem_write(address, struct.pack(
            '<I', (self.now * TICKS_PER_INSTR) & 0xFFFFFFFF)[:size])

    def _hook_uart_write(self, uc, access, address, size, value, user):
        if address == UART_THR:
            self.uart_out += bytes([value & 0xFF])

    def _hook_wdt_write(self, uc, access, address, size, value, user):
        pass    # not modeled (no WDT expiry during the boot proof)

    def _hook_ecc_read(self, uc, access, address, size, value, user):
        off = address - ECC_BASE
        if off in (0x0C, 0x10C):        # decode-done: set
            uc.mem_write(address, (1).to_bytes(4, 'little'))
        elif off == 0x90:              # parity-port ready (bit0): the
            # sub_12D8 feed loop polls it before every ECC+0x94 parity
            # word and IGNORES the timeout — on real HW it sets in ~1
            # tick; unserved, every poll burns ~413K modeled instrs and
            # the erased boot's full 27-config x 10-offset identity
            # sweep (sub_2CF0, ~270 attempts, 2 x ~155 words each)
            # exceeds any budget — the task-11 'never-ready spin'.
            uc.mem_write(address, (1).to_bytes(4, 'little'))
        elif off == 0x124:              # per-sector done bitmap: all
            uc.mem_write(address, (0xFFFFFFFF).to_bytes(4, 'little'))
        elif off in (0x110, 0x114):     # error bitmap / counts: clean
            uc.mem_write(address, (0).to_bytes(4, 'little'))

    def _hook_nfi_read(self, uc, access, address, size, value, user):
        v = self.nfi.read(address - NFI_BASE, size)
        uc.mem_write(address, v.to_bytes(size, 'little'))

    def _hook_nfi_write(self, uc, access, address, size, value, user):
        off = address - NFI_BASE
        if off == self.nfi.CMD and (value & 0xFF) == 0x30:
            self.nfi.write(off, value, size)
            self._bbm_publish(uc)
            return
        self.nfi.write(off, value, size)

    def _bbm_publish(self, uc):
        """After a spare-flagged READ_2ND (rom 0x1fc8's bad-block probe
        reads the first pages of a block and tests the BBM the engine
        extracted into the driver ctx), capture the last-read page's
        spare byte 0 — engine-internal behavior the register-level NFI
        model cannot express (the publish happens at M_BBTEST)."""
        raw = getattr(self.nfi, '_raw_page', b'')
        if not raw:
            return
        gptr = struct.unpack('<I', bytes(uc.mem_read(0x11C24, 4)))[0]
        if not 0x100000 < gptr < 0x300000:
            return
        inner = struct.unpack('<I', bytes(uc.mem_read(gptr, 4)))[0]
        if not 0x100000 < inner < 0x300000:
            return
        spare_flag = struct.unpack('<B',
                                   bytes(uc.mem_read(inner + 7101, 1)))[0]
        if spare_flag:
            self._last_spare_bbm = raw[NandChip.PAGE_DATA:
                                       NandChip.PAGE_DATA + 1]


_BootReplay = BootReplay    # donor name kept as an alias (task-9 tests
                            # and donor scripts import _BootReplay)


# ------------------------------------------------------------- donors --
_donor_cache: dict = {}


def _donor_windows() -> dict[str, bytes]:
    if 'win' not in _donor_cache:
        _donor_cache['win'] = {
            n: resolve(n, '2021').read_bytes() for n in BOOT_PARTS}
    return _donor_cache['win']


def _donor_window_hashes() -> set[str]:
    """sha256 of each donor's LOAD WINDOW: the image content the BROM
    actually lands at 0x200D00 (from partition page 8, FILE_INFO length
    bytes — the per-copy index bytes keep the four copies' hashes
    distinct)."""
    if 'hash' not in _donor_cache:
        hs = set()
        for name, d in _donor_windows().items():
            win = d[8 * PAGE:]
            fsize = struct.unpack_from('<I', win, 0x20)[0]
            hs.add(hashlib.sha256(win[:fsize]).hexdigest())
        _donor_cache['hash'] = hs
    return _donor_cache['hash']


def _boot_ranges() -> dict[str, tuple[int, int]]:
    """(start_page, n_pages) of each brhgptpl partition, from the GPT
    donor (the layout is fixed across snapshots)."""
    if 'ranges' not in _donor_cache:
        table = parse_gpt_from_image(
            _donor_windows()['brhgptpl_0'])
        _donor_cache['ranges'] = {
            n: (table[n][0],
                (len(_donor_windows()[n]) + PAGE - 1) // PAGE)
            for n in BOOT_PARTS}
    return _donor_cache['ranges']


# ---------------------------------------------------------- classify --
def _boot_region_key(snapshot: dict[int, bytes]) -> str:
    h = hashlib.sha256()
    for name in BOOT_PARTS:
        start, npages = _boot_ranges()[name]
        for p in range(start, start + npages):
            h.update(snapshot.get(p, b''))
    return h.hexdigest()


def _donor_belt(snapshot: dict[int, bytes]) -> None:
    """Final-state belt: every WRITTEN boot-region page byte-matches its
    donor (data plane, all-0xFF spare — the model's flash format)."""
    for name in BOOT_PARTS:
        img = _donor_windows()[name]
        start, npages = _boot_ranges()[name]
        for i in range(npages):
            page = start + i
            if page not in snapshot:
                continue        # erased pages are not 'written'
            want = img[i * PAGE:(i + 1) * PAGE].ljust(PAGE, b'\xff') \
                + b'\xff' * NandChip.PAGE_SPARE
            assert snapshot[page] == want, (
                f'{name} page {page} (donor page {i}) diverges from the '
                f'donor image')


def classify(snapshot: dict[int, bytes], final: bool = False) -> str:
    """Replay the real BROM boot against the snapshot; see the module
    docstring for the verdicts and the (single) crypto stub."""
    ctx = _default_ctx    # module-global refactor: state via BootContext
    if final:
        _donor_belt(snapshot)
    key = _boot_region_key(snapshot)
    hit = ctx.verdict_cache.get(key)
    if hit is not None:
        ctx.trace = list(hit[1])
        return hit[0]

    chip = NandChip()
    chip.load_dump(snapshot)
    r = BootReplay(chip)
    r.run(BOOT_MAIN)
    if r.stop_reason == 'jumped':
        verdict = 'boots_2021_pl'
    elif r.stop_reason == 'usdl-handshake-wait':
        verdict = 'brom_usdl_wait'
    else:
        # recovery retry: a boot that failed with no host attached is
        # still BROM-recoverable if the USBDL handshake wait catches it
        # once a cable is present — the strap-free recovery path the
        # erased-boot proof pins. Only reached when the primary failed.
        chip2 = NandChip()
        chip2.load_dump(snapshot)
        r2 = BootReplay(chip2, budget=r.budget, cable=True)
        r2.run(BOOT_MAIN)
        r.trace.append(
            f'recovery-retry (cable present): {r2.stop_reason!r}')
        r.trace += r2.trace
        if r2.stop_reason == 'usdl-handshake-wait':
            verdict = 'brom_usdl_wait'
        else:
            verdict = 'invalid'
    trace = r.trace + [f'stop: {r.stop_reason!r} after {r.now} instrs']
    if r.uart_out:
        trace.append(f'uart-tail: {bytes(r.uart_out[-120:])!r}')
    ctx.trace = trace
    ctx.verdict_cache[key] = (verdict, trace)
    return verdict
