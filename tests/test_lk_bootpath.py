"""Task 13 (M2) — lk boot path: reset entry -> fastboot loop.

test_mkelf_wrap      (Tier 1) the mkelf_lk.py port wraps raw bytes into the
                     donor ELF32 shape: e_entry 0x41E00000, phdr loads the
                     image at BASE 0x41DFFE00 from data_off 0x54, p_flags 7.
test_seeds_fastboot_main (Tier 1) seeds.json "functions" carries the
                     fastboot top-level seed 'fastboot_main' @0x41E1DAEC
                     (R10 append convention; "ida" untouched).
test_boots_to_fastboot (Tier 2, WIP xfail) boot(lk) reaches the fastboot
                     top level within budget and the UART trace carries the
                     donor fastboot banner. Currently xfail: the M2 platform
                     stub surface is incomplete — the blocking chain is
                     documented in docs/porting-notes.md §platform; no
                     faked success path exists.
"""

import struct

import pytest

from crumpet_emu import resources
from crumpet_emu.lk.boot import FASTBOOT_MAIN, BootOutcome, boot
from crumpet_emu.lk.mkelf import BASE, ENTRY, wrap
from crumpet_emu.lk.session import LkSession

TIER2 = 'tier2: requires parked vendor binaries — see binaries/README.md'
tier2_lk = pytest.mark.skipif(not resources.available('lk', '2025'), reason=TIER2)

XFFAIL = ('M2 platform stub surface incomplete — blocking stubs in '
          'docs/porting-notes.md §platform')


def test_mkelf_wrap():
    raw = b'\xAA' * 0x200
    blob = wrap(raw)
    assert blob[:4] == b'\x7fELF'
    assert struct.unpack_from('<H', blob, 16)[0] == 2          # ET_EXEC
    assert struct.unpack_from('<I', blob, 24)[0] == ENTRY == 0x41E00000
    assert struct.unpack_from('<I', blob, 28)[0] == 52         # e_phoff
    phoff = struct.unpack_from('<I', blob, 28)[0]
    p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, _ = \
        struct.unpack_from('<8I', blob, phoff)
    assert (p_type, p_offset, p_vaddr, p_paddr) == (1, 84, BASE, BASE)
    # donor packs p_filesz == p_memsz == len(raw) (image only, no header)
    assert p_filesz == p_memsz == 0x200
    assert p_flags == 7
    assert blob[84:84 + 0x200] == raw                          # image verbatim


def test_seeds_fastboot_main():
    lk = LkSession.__new__(LkSession)      # load_seeds only (no uc needed)
    lk.seeds = {}
    seeds = LkSession.load_seeds(lk)
    assert seeds['fastboot_main'] == 0x41E1DAEC
    assert FASTBOOT_MAIN == seeds['fastboot_main']


@pytest.mark.xfail(strict=False, reason=XFFAIL)
@tier2_lk
def test_boots_to_fastboot():
    img = resources.resolve('lk', '2025').read_bytes()
    out = boot(img, budget=3_000_000)
    assert isinstance(out, BootOutcome)
    assert out.reached_fastboot is True
    # donor fastboot banner, pinned from the live UART capture
    # (no-alexa/logicanalyzer/uart_logs/uart_fastboot_w_usb.txt, cat -A:
    # "[1824] fastboot_init()" / "[2485] fastboot: processing commands:
    # fastboot_mode=2"; the [NNNN] prefix is the emulated tick counter, the
    # pinned strings are the rodata banners the boot prints)
    trace = '\n'.join(out.uart_trace)
    assert 'fastboot_init()' in trace
    assert 'fastboot: processing commands: fastboot_mode=' in trace
    # fastboot path never jumps to the kernel (Task 14 consumes handoff)
    assert out.handoff is None
