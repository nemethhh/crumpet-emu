# Generalized from: WS/tools/lk-emu/lk_emu.py (M2 boot
# entry; the donor harness only drives surgical function entries — the
# natural boot walk below is Task 13 work).
# STATUS: M2 WIP xfail. Stub-chain state (docs/porting-notes.md section
#   "platform"): items 1-5b solved (Task 13/13b); CURRENT blocker = item 5c,
#   the idle-thread wfi park — main-thread dispatch needs the system-timer
#   IRQ and unicorn 2.1.4 exposes no interrupt-injection API. boot()
#   honestly returns reached_fastboot=False (stop_reason 'PARKED ...',
#   lk.pc_ring last-50-PC evidence) until that gap is bridged in-emulator.
"""Natural LK boot entry (Task 13, milestone M2): reset entry -> fastboot loop.

boot(lk_bytes, *, budget) maps the REAL lk.img into an LkSession, arms the
boot-path platform stubs (crumpet_emu.lk.platform), and runs the reset entry
NATURALLY (no surgical entry): init-time parsing (IDME / deviceinfo /
boot-mode) executes as real code and joins the huntable surface.

Entry VMA 0x41E00000 — donor lk.elf e_entry (readelf) == the ATF handover
address in the live UART capture ("Entry point address = 0x41e00000",
no-alexa/logicanalyzer/uart_logs/uart_fastboot_w_usb.txt). The entry is an
ARM-mode vector table (thumb entry faults at pc=0x41E00024 reading 0x4 —
probe-verified), so the boot starts ARM and the C entry (blx 0x41E1B2B0)
switches to thumb itself.

The fastboot top level 0x41E1DAEC (seed ``fastboot_main`` in
crumpet_emu/lk/seeds.json "functions", R10 append convention) is the
success address: reached_fastboot is True iff PC lands there within the
instruction budget. When it is reached, the fastboot-loop-entry checkpoint
for Task 15 is snapshotted onto the session as ``lk.fastboot_checkpoint``
(pc, sp, heap_ptr, uart byte count, usb queue lengths) — that dict is the
checkpoint duty; BootOutcome itself stays the ruled 3-field namedtuple.
"""
import time
from collections import deque, namedtuple

from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_SP

from crumpet_emu.lk.platform import install_platform
from crumpet_emu.lk.session import BSS_END, LK_BASE, LK_LOAD, LkSession

#: fastboot top level (seed 'fastboot_main'); Task 14 handoff detection and
#: Task 15 checkpoint both hang off this address.
FASTBOOT_MAIN = 0x41E1DAEC

#: ruled BootOutcome shape ('None-ok' token in the plan text was a ruled
#: transcription artifact — the shape is these three fields).
BootOutcome = namedtuple('BootOutcome', 'reached_fastboot uart_trace handoff')


def boot(lk_bytes: bytes, *, budget: int = 2_000_000_000,
         verbose: bool = False) -> BootOutcome:
    """Boot the 2025 LK image from its reset entry within `budget` insns.

    Returns BootOutcome(reached_fastboot, uart_trace, handoff):
      reached_fastboot -- PC reached FASTBOOT_MAIN within budget;
      uart_trace       -- the boot console: raw UART bytes (UART_THR writes,
                          donor lk_emu.py:193-197) decoded + the log() stub
                          lines (on hardware both paths print to the same
                          UART; the emu splits them);
      handoff          -- kernel-jump address if the boot leaves the LK
                          image (Task 14 consumes; None expected on the
                          fastboot path).
    No faked success path: an early stop (fault, budget, spin) returns
    reached_fastboot=False with whatever trace exists.
    """
    lk = LkSession(lk_bytes, verbose=verbose)
    install_platform(lk)
    uc = lk.uc
    hit = {'fastboot': None, 'handoff': None}
    ring = deque(maxlen=50)

    def on_pc(uc, address, size, user):
        ring.append(address)

    def on_fastboot(uc, address, size, user):
        if hit['fastboot'] is None:
            hit['fastboot'] = address
            # Task-15 fastboot-loop-entry checkpoint (see module docstring)
            lk.fastboot_checkpoint = {
                'pc': address,
                'sp': uc.reg_read(UC_ARM_REG_SP),
                'heap_ptr': lk.heap_ptr,
                'uart_bytes': len(lk.uart_out),
                'usb_rx': len(lk.usb_rx),
                'usb_tx': len(lk.usb_tx),
            }
        uc.emu_stop()

    def on_leave(uc, address, size, user):
        # kernel-jump handoff: execution left the LK image region
        if hit['handoff'] is None:
            hit['handoff'] = address
        uc.emu_stop()

    uc.hook_add(UC_HOOK_CODE, on_fastboot,
                begin=FASTBOOT_MAIN, end=FASTBOOT_MAIN)
    uc.hook_add(UC_HOOK_CODE, on_leave, begin=0, end=LK_BASE - 1)
    uc.hook_add(UC_HOOK_CODE, on_leave, begin=BSS_END + 1, end=(1 << 32) - 1)
    # last-50-PC ring over the image: fault/park evidence for the blocking
    # chain in docs/porting-notes.md section "platform" (probe duty)
    uc.hook_add(UC_HOOK_CODE, on_pc, begin=LK_BASE, end=BSS_END)

    t0 = time.time()
    try:
        # ARM-mode entry: bit0 clear (module docstring — the reset entry is
        # the ARM vector table; thumb entry faults at 0x41E00024).
        uc.emu_start(LK_LOAD, 0, count=budget)
    except Exception as e:
        if not lk.stop_reason:
            lk.stop_reason = f'BOOT-STOP {e!r}'
    lk.boot_seconds = time.time() - t0
    if hit['fastboot'] is None and hit['handoff'] is None \
            and not lk.stop_reason:
        # emu_start returned without a fault and without reaching the
        # fastboot top level: the walk parked (wfi halts unicorn emu_start —
        # see the idle-thread park in porting-notes section "platform").
        lk.stop_reason = f'PARKED last-pc={ring[-1]:#x}' if ring else 'PARKED'
    lk.pc_ring = [f'{a:#x}' for a in ring]

    trace = [bytes(lk.uart_out).decode('latin1')] + list(lk.log_out)
    return BootOutcome(hit['fastboot'] is not None, trace, hit['handoff'])
