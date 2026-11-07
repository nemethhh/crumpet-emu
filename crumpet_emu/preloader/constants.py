# Donor: WS/tools/amonet-emu/emu_chain.py
# Upstream: in-repo harness (amonet-emu)
# Split 2026-10-31 (Task 10): donor lines 44-89 verbatim. Single-source
#   re-exports (one owner per constant, plan decider rule): GPT <-
#   flash.image (Task 5), MAGIC_RET <- core.session (Task 1),
#   UART/eFuse/timer MMIO words <- core.devices (Task 1).

"""NS6548 2021 preloader address constants, verbatim from the donor.

Every value is a device fact validated against the donor's IDA db
(pl2021.i64). Constants a reviewed module already owns are re-exported
here, not redefined, so each name has exactly one definition:
GPT (crumpet_emu.flash.image), MAGIC_RET (crumpet_emu.core.session),
and UART_THR/UART_LSR/EFUSE_SBC/TIMER_REG
(crumpet_emu.core.devices).
"""

from crumpet_emu.core.devices import EFUSE_SBC, TIMER_REG, UART_LSR, UART_THR
from crumpet_emu.core.session import MAGIC_RET
from crumpet_emu.flash.image import GPT

# ---- NS6548 2021 constants (validated against IDA db pl2021.i64) ----
TEXT_BASE = 0x201000          # preloader content VMA
FILE_DELTA = 0x1F8D00         # vma -> file offset (vma - 0x1F8D00)
PART_LOAD = 0x20F4A8
PART_GET = 0x20F250
BDEV_INIT = 0x212EFC
USB_HANDSHAKE = 0x20D7DC
TEE_SET_ENTRY = 0x2160A8
MTEE_VERIFY = 0x216140
SECMEM_REARM = 0x216170       # sub_216170: secmem bookkeeping (called by part_load)
VERIFY_LK = 0x201D70          # RSA-2048 verify ("VERIFY_LK")
PRINTF = 0x2110F4
MEMCPY = 0x215B70
ASSERT = 0x21082C
TIMER_GET = 0x215C5C
HDR_PARSE = 0x20F2D8          # sequential sub-image header parse from ctx
OVERLAP_CHK = 0x20F398        # check_part_overlapped (name table @0x224910)
BDEV = 0x1086EC
BDEV_READ = BDEV + 0x20       # 0x10870C
HEAD_CELL = 0x102188
BSS_START = 0x102180
PAYLOAD_ADDR = 0x101000
DRAM_BUF = 0x42000000
BOUNCE = DRAM_BUF + 0x56800
CTX_HDR = DRAM_BUF + 0x666F0  # v10 in part_load
LK_LOAD_ADDR = 0x41E00000
TEE_LOAD_ADDR = 0x43001000
SRAM_DBUF_PTR = 0x102994

# GPT (4096-byte LBAs) from brhgptpl_0.img -> bdev start blocks (512B units)
# lk_b added (crumpet kamakiri task 9): start 640 LBA4096 directly after
# lk_a's 384-LBA span, from the real GPT (emu/gpt.py parse). Appended at the
# END so every existing scenario's part_get scratch indices are unchanged.
# The dict itself is owned by crumpet_emu.flash.image (Task 5); re-exported
# at the top of this module.
BLKSZ = 0x200

# Unicorn-placed regions
TRAMP = 0x120000              # bdev->read shim vector
STACK = 0x12F000
SCRATCH = 0x42070000          # fake part structs / strings (DRAM)
# Donor line 85 (MAGIC_RET, "return here" sentinel 0x0011F000) and donor
# lines 87-89 (UART_THR/UART_LSR, EFUSE_SBC, TIMER_REG) are re-exported at
# the top from core.session / core.devices (single source).
