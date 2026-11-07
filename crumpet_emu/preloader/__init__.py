# Donor: WS/tools/amonet-emu/emu_chain.py
# Upstream: in-repo harness (amonet-emu)
# Split 2026-10-31 (Task 10): single donor file -> constants.py (lines
#   44-89), emu.py (92-580 minus the Task-5 Flash extraction),
#   scenarios.py (582-673 + the brief-mandated run_scenario surface),
#   scenarios/preloader_chain.py CLI (675-798). This docstring is the
#   donor module docstring verbatim.

"""End-to-end emulator harness for the amonet-koboreru crumpet2021 chain.

Runs REAL NS6548 2021 preloader code (part_load sub_20F4A8, the block copy
sub_20240C, the LK verify gate, check_part_overlapped sub_20F398, strcmp,
the verify-name table, the eFuse SBC read) plus the REAL compiled payload
(start.S, main, usbdl, patches) inside Unicorn. Only true I/O is stubbed:
UART, timer, eFuse register, flash reads (served from image files), RSA
verify (models "unsigned -> fail"), and a handful of preloader helpers whose
semantics are replicated faithfully (part_get, header parse, memcpy,
boot_device_init re-arm, usb_handshake hang oracle).

Scenarios:
  A  as-flashed fixed image (commit 3e65ba3), SBC efuse set   -> brick #2 repro
  A0 original port image (commit 5f5481c),  SBC efuse set     -> brick #1 repro
  B  as-flashed fixed image, SBC efuse CLEAR                  -> would boot
  C  corrected payload (gate patch + no-hang), SBC set        -> full chain

With --from-chip-dump DUMP.pkl the flash model is instead backed by a
NandChip.dump()-style post-flash chip image (ChipDumpFlash): the same
scenarios boot the bytes a real deploy() actually placed on the chip,
at their true NAND placement (closed loop, kamakiri task 10).
"""
