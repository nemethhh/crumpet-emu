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

KINDS = ('real', 'staged', 'oracle-conservative', 'reimplemented',
         'stub', 'real-crypto-host')

SEAM_CHAIN_CRITICAL = frozenset({'hdr_parse', 'overlap_chk', 'part_get'})

SEAMS = {
    'hdr_parse': Seam(0x20F2D8, 'real',
                      'REAL sub_20F2D8 executes (guarantee Task 2); the hook '
                      'only mirrors its ctx into last_hdr. Donor host-parser '
                      'reimplementation kept behind legacy_seams=True '
                      '(tests/test_real_parse_overlap.py differential)'),
    'overlap_chk': Seam(0x20F398, 'real',
                        'REAL check_part_overlapped executes (guarantee Task '
                        '2); claim state = guest cells at name-table+0x10 '
                        '(0x224920, in-file {0,0}); legacy host replication '
                        'behind legacy_seams=True'),
    'part_get': Seam(0x20F250, 'real',
                     'REAL sub_20F250 + sub_20F1F8 walk execute against the '
                     'staged real-GPT entry table at *SRAM_DBUF_PTR+0x69244 '
                     '(guarantee Task 3); donor synthesized struct behind '
                     'legacy_seams=True'),
    'bdev_init': Seam(0x212EFC, 'staged',
                      'host re-arm of the bdev struct replaces sub_212EFC '
                      'boot_device_init. DECODED (guarantee Task 4 probe): '
                      'real init memsets 0x2C B at the same 0x1086EC and '
                      'writes read-fn 0x212AA1 @+0x20 (+0x24 get/erase '
                      '0x2127B3) — stub writes the same field layout with '
                      'observed stock values. Real init needs the pl2021 '
                      'NAND-probe handshake (NFI+0x14/0x220 polling) the '
                      'NfiModel does not answer (built for BROM-era traffic) '
                      '— extension deferred, see porting-notes Task-4 ruling'),
    'part_load': Seam(0x20F4A8, 'real',
                      'hook observes entry args only; the real NS6548 '
                      'part_load runs (donor emu_chain docstring)'),
    'verify_lk': Seam(0x201D70, 'real-crypto-host',
                      'REAL host-side RSA-2048/PSS vs the Amazon LK modulus '
                      'embedded in the pinned preloader (guarantee Task 5; '
                      'key VMA 0x222260 from sub_201D70\'s own pool — the '
                      'recovery-note 0x22244C is wrong for this build). '
                      'Silicon truth: only genuinely Amazon-signed images '
                      'pass; tests/test_pl_hostcrypto.py'),
    'mtee_verify': Seam(0x216140, 'stub',
                        'always-OK — fail-open for arbitrary inputs, NOT '
                        'conservative (final-review P1). Silicon-equivalent '
                        'on chain paths: the loader verifies only the '
                        'GENUINE donor atf sub-image of the crafted tee1 '
                        '(passes on silicon); the crafted sub-image aborts '
                        'its read before any verify (real part_load order — '
                        'pinned dynamically by test_real_parse_overlap::'
                        'test_crafted_walk_skips_mtee_verify), and the tee2 '
                        'sub-images it passes are the genuine donor pair'),
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
