# SDD ledger — plan: docs/superpowers/plans/2026-11-08-amonet-customfw-guarantee.md

Worktree: .worktrees/amonet-guarantee (branch amonet-guarantee, base 7216d95+plan commit).
Baseline: 97 passed, 2 skipped, 1 xfailed (bins pinned, venv symlinked).

Pre-flight interface rows:
- T1 SEAM_CHAIN_CRITICAL {hdr_parse,overlap_chk,part_get} vs T2/T3 upgrades vs T4 bdev_init ruling — consistent: bdev_init intentionally outside the critical set (kind 'staged' allowed).
- T5 VERIFY_LK change vs T7/closed-loop verify_calls==0 assertion — T5 step 3 explicitly re-runs closed-loop; compatible (gate patch skips the call either way).
- T7 consumes T6 names (lock_gate_differential, patched_fastboot_flash, verify_and_vb) — pinned in plan §Task 6 Interfaces. Verified exist-next: brom classify returns 'boots_2021_pl'; VARIANTS in tests/test_layer4_closedloop.py; deploy(payload_variants).
- T9 CLI consumes T2-T7 surfaces — thin argparse, no new interfaces.
Setup: Ruling: worktree created without re-asking consent — user said "dive in" and executing-plans mandates isolation; protects main. Cost if wrong: none (removable worktree).
Task 1: complete (commits 7216d95..8cd7991, tests: test_seam_ledger → 2 passed, 1 xfailed)
Task 2: complete (commits 8cd7991..480d21c, tests: real_parse_overlap+seam_ledger → 7 passed, 1 xfailed)
Task 3: complete (commits 480d21c..9107f97, tests: real_part_get+seam_ledger → 6 passed)
Task 4: complete (commits 9107f97..a94cc65, tests: seam_ledger → 3 passed; ruling: NfiModel extension deferred)
Task 5: complete (commits a94cc65..b863b01, tests: pl_hostcrypto 5 passed, suite 112 passed; finding: key VMA 0x222260 not 0x22244C)
Task 6: complete (commits b863b01..97fbd61, tests: lk_customfw 5 passed)
Task 7: complete (commits 97fbd61..0fbe8f3, tests: customfw_guarantee[lk_b,lk_a] 2 passed)
Task 8: complete (probe + ruling, no code; commits ..a313016)
Task 9: complete (CLI green: chain-lka/lkb+unlock+brom+ledger all PASS, exit 0, 39s; trace-diff vs tp54_gnd recorded)
Task 10: complete (docs/guarantee.md full; README + WS PROJECT-STATE cross-linked)

Final review: reviewer subagent (fresh context), verdict "OK with notes".
Final: fixed P1 mtee classification — test_seam_ledger::test_mtee_kind_not_conservative RED→GREEN + dynamic ordering pin test_crafted_walk_skips_mtee_verify (refined: genuine atf IS verified, crafted sub-image never — premise was too strong initially, test failed and tightened the citation). Suite 123/123 (2 skip, 1 xfail).
Final: Ruling: promoted minors #5/#6/#7 (doc factual errors in the deliverable doc + stale prose contradicting new code) into the P1 fix pass — accuracy of the honesty artifact is the product; pure doc edits, no test cost.
Final: Ruling (declined-to-judge items, closed with fresh evidence): full suite + CLI re-run green; bins-absent rerun 71 passed/55 skipped/0 fail (Review Focus #5); trace-diff re-derived: 14 emu, 8 exact, 3 prefix, 3 emu-only vs 558-line capture.
Final: minor (deferred): staged part-table margin unguarded at >=23 partitions (fits today; add assert later).
Final: minor (deferred): Review Focus #2 partial — 'LK' vs 'lk' case-sensitivity and maddr!=0xFFFFFFFF crafted-header cases untested.
Final: minor (deferred): differential tests compare verdicts/end-state, not full event streams (plan wanted event-stream agreement).
Final: minor (deferred): ledger INTERCEPTED set hand-maintained (a NEW hook_code address goes undetected); guest_lk_region() has no callers; self.lk_region stale in real mode; scenarios.py stock_ok docstring donor-era; customfw._vbstate unused img arg; dead local in test_real_parse_overlap; test_lk_customfw sites set covers 2 unreachable entries.
