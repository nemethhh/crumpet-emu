# Guarantee — amonet-koboreru crumpet2021 on real silicon

**Status: IN PROGRESS** (plan: `docs/superpowers/plans/2026-11-08-amonet-customfw-guarantee.md`).
This document is the deliverable of the guarantee plan: what the emulator
PROVES about the amonet chain + patched-LK custom-firmware path, seam by
seam, and what it can never prove (the irreducible hardware risks, each
with an on-device check).

Scope statement: an emulator cannot *guarantee* silicon behavior. What it
can deliver — and this document tracks — is a **bounded guarantee**:

1. every pure-code step of the chain executes REAL vendor/payload bytes
   under emulation and passes (test-pinned);
2. every seam where the emu substitutes for silicon is classified and
   cited (`crumpet_emu/preloader/seams.py` + the LK seam notes), and is
   either real, staged-with-citation, or provably conservative (can only
   make the emu more pessimistic than silicon for the chain verdict);
3. irreducible hardware risks are enumerated with impact + on-device
   check (§risk-register).

## 1. Seam fidelity matrix (preloader layer)

Authoritative source: `crumpet_emu/preloader/seams.py` (kept in sync by
`tests/test_seam_ledger.py`). Rows are filled as plan Tasks 2–4 upgrade
the four reimplemented seams.

| seam | VMA | kind today | target kind | test |
|------|-----|-----------|-------------|------|
| hdr_parse | 0x20F2D8 | **real** (Task 2) | real | tests/test_real_parse_overlap.py |
| overlap_chk | 0x20F398 | **real** (Task 2) | real | tests/test_real_parse_overlap.py |
| part_get | 0x20F250 | **real** (Task 3, staged real-GPT table) | real | tests/test_real_part_get.py |
| bdev_init | 0x212EFC | **staged** (Task 4 ruling: re-arm stub, real init fully decoded; NfiModel extension deferred) | real (deferred) | porting-notes §guarantee Task 4 |

## 2. What the emulator proves (per leg)

(filled by Task 7/9: preloader chain leg, unlock leg, BROM belt leg,
closed-loop deploy leg — each with the test id that pins it)

## 3. LK unlock-leg seams

- Patch-set byte verification: tests/test_lk_patches.py (three sites
  re-derived from the stock donor, byte-diff allowlist).
- Executed on real patched bytes (Task 6): cmd_lock_check differential,
  verify_and_vb RED-abort acceptance, getvar plumbing
  (crumpet_emu/lk/customfw.py, tests/test_lk_customfw.py).
- Task-8 probe: the REAL fastboot dispatcher loop (0x41E1E1A2) is NOT
  reachable surgically — fastboot_init (0x41E1E3B4) faults at its
  handler-registration list (NULL head, boot-time heap state; probe:
  INVALID read addr=0x8 @0x41E1BA90 after logging 'fastboot_init()').
  Ceiling is M2-class (same boot-state staging family as the wfi/IRQ
  blocker, porting-notes §platform 5c). FastbootHost's per-handler
  surgical dispatch remains the unlock-leg execution surface; the lock
  gate itself is proven at its real callee with the real call-site
  argument shape.

## 4. Risk register (irreducible hardware risks)

(filled by Task 10; each row: risk, impact, on-device check, first-boot
observation plan)

## 5. Pre-flash checklist

(filled by Task 10)
