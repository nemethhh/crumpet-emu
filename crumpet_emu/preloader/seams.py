"""Seam inventory for the amonet chain (guarantee plan Task 1).

One row per address `Emu.hook_code` intercepts on the amonet-koboreru
crumpet2021 chain, with an honest classification and a citation. The
ledger test (`tests/test_seam_ledger.py`) cross-checks every VMA against
`crumpet_emu.preloader.constants`, so code and ledger cannot drift.

Kinds:
  real                the vendor code at the VMA executes (hook observes)
  staged              vendor code executes against staged state, or true
                      I/O is served host-side at a boundary the real code
                      calls through (pointer indirection itself is real)
  oracle-conservative the seam MODELS a silicon outcome in the direction
                      that can only make the emu MORE pessimistic than
                      silicon for the chain verdict (fail/halt/verify-fail)
  reimplemented       host code replaces a real vendor function whose
                      semantics matter to the chain verdict — upgrade
                      target (see SEAM_CHAIN_CRITICAL)
  stub                side effect skipped or identity-returned; recorded
                      non-load-bearing for the chain verdict with the
                      reason

Chain-critical seams (plan: hdr_parse, overlap_chk, part_get) must not
remain 'reimplemented'; the ledger test is the forcing function.
"""
from collections import namedtuple

Seam = namedtuple('Seam', 'vma kind citation')

KINDS = ('real', 'staged', 'oracle-conservative', 'reimplemented', 'stub')

SEAM_CHAIN_CRITICAL = frozenset({'hdr_parse', 'overlap_chk', 'part_get'})

SEAMS = {
    'hdr_parse': Seam(0x20F2D8, 'reimplemented',
                      'host parser replaces sub_20F2D8 (sequential sub-image '
                      'header parse); donor emu_chain stub kept verbatim in '
                      'the Task-10 port — port doc §6 constants table'),
    'overlap_chk': Seam(0x20F398, 'reimplemented',
                        'host replication of check_part_overlapped '
                        '(README semantics; name table @0x224910) — the '
                        'vulnerability function itself; port doc §3'),
    'part_get': Seam(0x20F250, 'reimplemented',
                     'synthesized partition struct from the GPT dict '
                     'replaces sub_20F250 (name compare + partition walk)'),
    'bdev_init': Seam(0x212EFC, 'reimplemented',
                      'host re-arm of the bdev struct fields replaces '
                      'sub_212EFC boot_device_init (NAND driver init)'),
    'part_load': Seam(0x20F4A8, 'real',
                      'hook observes entry args only; the real NS6548 '
                      'part_load runs (donor emu_chain docstring)'),
    'verify_lk': Seam(0x201D70, 'oracle-conservative',
                      'RSA oracle: genuine stock image -> PASS, anything '
                      'else -> FAIL (more pessimistic than silicon: no '
                      'custom image can accidentally pass)'),
    'mtee_verify': Seam(0x216140, 'oracle-conservative',
                        'always-OK for the genuine donor tee2 images the '
                      'chain loads; the crafted tee1 aborts its read '
                      'before any verify (real part_load order)'),
    'tee_set_entry': Seam(0x2160A8, 'stub',
                          'entry-cell store (0x108736) skipped; the cell '
                          'has no consumer on the emu chain path (handoff '
                          'is modeled by the harness return)'),
    'secmem_rearm': Seam(0x216170, 'stub',
                         'identity return; real body is mblock/secmem '
                         'bookkeeping needing live DRAM-layout globals — '
                         'load-address passthrough is the only observed '
                         'consumer (part_load verify re-arm)'),
    'assert': Seam(0x21082C, 'oracle-conservative',
                   'panic oracle: models assert -> boot halt (the '
                   'check_part_overlapped assert(239) family)'),
    'usb_handshake': Seam(0x20D7DC, 'oracle-conservative',
                          'hang oracle: models do_usb_handshake while(1) '
                          '— the headless brick (crumpet2021.c '
                          'on_lk_load_failure rationale)'),
    'memcpy': Seam(0x215B70, 'reimplemented',
                   'host mem_copy with AAPCS return; donor F-table '
                   'treatment — unicorn cannot decode the ARM builtin '
                   'cluster (porting-notes §platform item 5, Task 13b)'),
    'timer_get': Seam(0x215C5C, 'stub',
                      'monotonic counter; polled MMIO time never advances '
                      'under unicorn (same class as payload mdelay/udelay '
                      'timer stubs)'),
    'arb_fuse_read': Seam(0x20192C, 'staged',
                          'staged efuse version word (fuse_ver=1; family '
                          'evidence antirback_*_version=0x1) — the payload '
                          'patches the ARB check + burn regardless '
                          '(crumpet2021.c apply_patches)'),
    'tee_ver_get': Seam(0x21A560, 'staged',
                        'staged version stamp 1 — internally consistent '
                        'with the stock 2021 set the chain boots'),
    'lk_ver_get': Seam(0x201EE8, 'staged',
                       'staged version stamp 1 — same consistency note'),
    'tramp': Seam(0x120000, 'staged',
                  'bdev->read boundary (TRAMP shim vector in SRAM): flash '
                  'bytes served host-side from the Flash/ChipDumpFlash '
                  'source; the pointer call through bdev+0x20 is REAL '
                  'vendor code (the exploit\'s hijack mechanism)'),
    'uart_thr': Seam(0x11005000, 'staged',
                     'true I/O: UART THR writes logged host-side; LSR '
                     'staged THR-empty (I/O class)'),
    'printf': Seam(0x2110F4, 'staged',
                   'true I/O: printf decode (fmt_stub) — log surface '
                   'only, no control-flow effect'),
    'efuse_sbc': Seam(0x10009060, 'staged',
                      'SBC eFuse bit staged per scenario (sbc=True -> '
                      'bit 1 set, production-die state per '
                      'brom-sbc-revalidation.md)'),
}
