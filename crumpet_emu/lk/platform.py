# Generalized from: WS/tools/lk-emu/lk_emu.py
# Upstream: in-repo audit harness (WS tools/lk-emu)
# Generalized 2026-11-02 (Task 13): boot-path platform stubs. The donor
#   harness only ever drives surgical function entries, so its stub table
#   (ported in crumpet_emu/lk/session.py) covers libc + audit seams only.
#   The init-path stubs below arm the natural boot from the reset entry
#   0x41E00000 to the fastboot top level 0x41E1DAEC; every stubbed function
#   is recorded in docs/porting-notes.md section "platform".
"""LK boot-path platform stubs (Task 13): init-path clock/pmic/battery/WDT/NFI
surroundings, so REAL init code runs from the reset entry to the fastboot
loop naturally (no surgical entry)."""
import struct

from unicorn import UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0,
                              UC_ARM_REG_R1, UC_ARM_REG_R2)

from crumpet_emu.lk.session import F

# MMIO pages the init path touches, mapped as plain RAM (donor maps the
# UART/timer pages the same way, lk_emu.py:128-129). Page list = the
# union of pages the boot walk touched on the way to 0x41E1DAEC.
MMIO_PAGES = [
    (0x10200000, 0x1000),
    (0x10310000, 0x1000),
    (0x10320000, 0x1000),
    (0x10001000, 0x1000),
    (0x10003000, 0x1000),
    (0x10005000, 0x1000),
    (0x10011000, 0x1000),
    (0x11007000, 0x1000),
    (0x10006000, 0x1000),
    (0x10007000, 0x1000),
]

# boot-path function stubs (see docs/porting-notes.md section "platform")
SRAM_REPAIR = 0x41E143EC     # sw sram repair driver (live unit skips it)
MEMSET = F['memset']         # 0x41E20964 ARM builtin cluster (see _boot_stub)
MEMCPY = F['memcpy']         # 0x41E20858 ARM builtin cluster (see _boot_stub)
SCTLR_WRITE = 0x41E1A560     # generic `mcr p15,0,r0,c1,c0,0` accessor (SCTLR)

# device-info source staged for the boot-stage handoff (see _stage_boot_state)
DI_MAGIC = 0x504C504C
DI_SRC = 0x72010000          # scratch inside the donor ARGS page
DI_PTR_SLOT = 0x41E00020     # cold-default target of the source-pointer cell
DI_SRC_PTR_CELL = 0x41E38E0C  # ctx 0x41E38C98 + 0x174


def install_platform(lk) -> None:
    """Arm the boot-path stub set on an LkSession (idempotent per session)."""
    uc = lk.uc
    for base, size in MMIO_PAGES:
        try:
            uc.mem_map(base, size)
        except Exception:
            pass
    _stage_boot_state(lk)
    if getattr(lk, '_plat_installed', False):
        return
    lk._plat_installed = True
    uc.hook_add(UC_HOOK_CODE, _boot_stub, begin=0, end=(1 << 32) - 1)


def _stage_boot_state(lk) -> None:
    """Boot-stage state the reset entry expects to find already in RAM.

    Donor pattern: lk_emu.py _boot_globals (lk_emu.py:141-153) stages the
    device-info pointer chain the same way for surgical entry. Here the
    REAL init at 0x41E102D4 consumes the chain: it reads the source
    pointer at *(vector-gap slot 0x41E00020), checks the 0x504c504c stamp
    and memcpy(0x200)es the table into the BSS mirror at *(0x41E38D18)
    (0x41E45C10); the prod flag it later reads is byte [di+0x1E2] of the
    SAME table (session._boot_globals docstring). A cold image has no
    earlier boot stage to stamp it, so the table is staged at DI_SRC with
    the stamp + the boot-argument content the live unit logged
    (no-alexa/logicanalyzer/uart_logs/uart_fastboot_w_usb.txt):
    BOOT_REASON 4, BOOT_MODE 0, MEM_NUM 1, mblock0 size 0xF9C0000
    (start implied 0x40000000, u32-per-mblock layout read by the validator
    at 0x41E104EC), prod flag 1. The copy and the field checks stay REAL
    code.
    """
    di = bytearray(0x200)
    struct.pack_into('<I', di, 0x00, DI_MAGIC)
    struct.pack_into('<I', di, 0x08, 4)           # BOOT_REASON 4 (unit log)
    struct.pack_into('<I', di, 0x0C, 0)           # BOOT_MODE 0 (unit log)
    struct.pack_into('<I', di, 0x18, 1)           # MEM_NUM 1 (checked 1..4)
    struct.pack_into('<I', di, 0x1C, 0x0F9C0000)  # mblock0 size (unit log)
    di[0x1E2] = 0x01                              # prod flag, unit-3 live state
    lk.wr(DI_SRC, bytes(di))
    lk.uc.hook_add(UC_HOOK_CODE, _di_stage_hook,
                   begin=0x41E102D4, end=0x41E102D4)


def _di_stage_hook(uc, address, size, user):
    """Stage the boot-stage table pointer at the consumer's first entry."""
    uc.mem_write(DI_PTR_SLOT, struct.pack('<I', DI_SRC))


def _boot_stub(uc, address, size, user):
    pc = address
    if pc == SRAM_REPAIR:
        # Live unit: "[3] SKIP sw sram repair" (uart_fastboot_w_usb.txt);
        # the driver reads MBIST result registers (0x267x600c cluster)
        # absent from the emu MMIO model, so it is skipped with r0=0
        # exactly like the skipped live path.
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
    elif pc == SCTLR_WRITE:
        # Environment fidelity (same class as the MMIO page map above): LK's
        # arch init enables the page-table MMU (SCTLR.M) through this generic
        # accessor during natural boot (observed write value 0x00C5007B,
        # bit0 set; trace: mrc@0x41E1A558 -> orr #1 -> mcr here). The
        # ATF-built page tables do not exist in the flat-memory emu, so after
        # the real mcr every CPU-mode data store raises EXCP_DATA_ABORT
        # (UC_HOOK_INTR intno 4; e.g. the first heap store `str r3,[r0],#0x44`
        # at 0x41E1B4BE). The donor never runs this path (surgical entries,
        # MMU never enabled), so keeping the emu flat (M cleared, caches and
        # everything else in the written value preserved) mirrors the
        # environment the donor's stubs assume. The mcr itself still executes
        # as REAL code.
        uc.reg_write(UC_ARM_REG_R0, uc.reg_read(UC_ARM_REG_R0) & ~1)
    elif pc == MEMSET:
        # Semantic stub: memset(dst, c, n) -> dst. The body at 0x41E20964
        # is an ARM-encoded builtin (capstone ARM: cmp r2,#0; bxeq lr;
        # mov ip,r0; cmp r2,#0x30 ...), but the thumb C init reaches it via
        # plain `bl` (mode-preserving), so Unicorn decodes it as thumb and
        # faults. The donor never executes this path (F-table entry
        # lk_emu.py:83, no _stub branch; its one needed copy is pre-staged
        # in _ltc_init lk_emu.py:155-165) — so host semantics ARE the
        # ground truth: fill dst with (c & 0xFF), return dst (AAPCS r0).
        dst, c, n = (uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1),
                     uc.reg_read(UC_ARM_REG_R2))
        if n:
            uc.mem_write(dst, bytes([c & 0xFF]) * n)
        uc.reg_write(UC_ARM_REG_R0, dst)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
    elif pc == MEMCPY:
        # Semantic stub: memcpy(dst, src, n) -> dst. Same ARM builtin
        # cluster as memset (capstone ARM: cmp r2,#0; cmpne r1,r0; bxeq
        # lr; push {r0,r4,r5,lr} ...; overlaps-after check in the real
        # body is irrelevant for a host copy). Donor treatment identical
        # (F-table entry lk_emu.py:82, never stubbed/never run).
        dst, src, n = (uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1),
                       uc.reg_read(UC_ARM_REG_R2))
        if n:
            uc.mem_write(dst, bytes(uc.mem_read(src, n)))
        uc.reg_write(UC_ARM_REG_R0, dst)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
