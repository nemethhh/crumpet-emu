# Guarantee — amonet-koboreru crumpet2021 on real silicon

**Status: COMPLETE (plan: `docs/superpowers/plans/2026-11-08-amonet-customfw-guarantee.md`)** ·
Run it: `venv/bin/python scenarios/guarantee.py` (exit 0 iff every leg is green; `--json` for machine-readable, `--trace-diff UART_LOG` for the capture comparison).

Scope statement: an emulator cannot *guarantee* silicon behavior. What
this repo delivers is a **bounded guarantee**:

1. every pure-code step of the chain executes REAL vendor/payload bytes
   under emulation and passes (test-pinned, below);
2. every seam where the emulator substitutes for silicon is classified
   and cited (`crumpet_emu/preloader/seams.py`, kept honest by
   `tests/test_seam_ledger.py`) and is real, staged-with-citation,
   real-crypto, or provably conservative;
3. the irreducible hardware risks are enumerated with impact and an
   on-device check (§4) — those are the residual, and no emulator can
   clear them.

## 1. Seam fidelity matrix (preloader layer)

Authoritative source: `crumpet_emu/preloader/seams.py`. Chain-critical
seams must not be reimplementations — enforced by
`tests/test_seam_ledger.py::test_chain_critical_seams_not_reimplemented`.

| seam | VMA | kind | pinned by |
|------|-----|------|-----------|
| hdr_parse | 0x20F2D8 | **real** | tests/test_real_parse_overlap.py |
| overlap_chk | 0x20F398 | **real** (the vulnerability itself; claim state = guest cells @0x224920) | tests/test_real_parse_overlap.py |
| part_get | 0x20F250 | **real** (walk @0x20F1F8 over the staged real-GPT table @DRAM_BUF+0x69244) | tests/test_real_part_get.py |
| bdev_init | 0x212EFC | staged (re-arm; real init fully decoded incl. read-fn 0x212AA1 @+0x20 — NfiModel extension deferred) | porting-notes §guarantee Task 4 |
| verify_lk | 0x201D70 | **real-crypto-host** (RSA-2048/PSS vs the embedded Amazon modulus, key VMA 0x222260) | tests/test_pl_hostcrypto.py |
| part_load | 0x20F4A8 | real (always was) | suite (38 donor tests + chain) |
| mtee_verify | 0x216140 | stub, fail-open by construction but silicon-equivalent on chain paths (ordering premise test-pinned; only genuine donor tee2 ever passes) | tests/test_real_parse_overlap.py::test_crafted_walk_skips_mtee_verify |
| assert / usbdl handshake | 0x21082C / 0x20D7DC | oracle-conservative (panic/halt oracles) | suite (brick repros) |
| tramp (bdev->read) | SRAM shim | staged (flash bytes host-side; the pointer indirection through bdev+0x20 — the hijack mechanism — is REAL code) | chain tests |
| fuse/stamps/timers/uart/printf | — | staged (I/O class; ARB patched by the payload regardless) | suite |

## 2. What the emulator proves (per leg, with the test that pins it)

- **P3 / the exploit's load-bearing fallback** — the REAL stock TEE
  loader `sub_20E19C` walks the crafted tee1: atf sub-image at
  TEE_LOAD_ADDR first, then the crafted sub-image against the loader's
  own zero-initialized `*addr` cell (dynamically proving the port-doc
  premise; the old harness fabricated this call shape). Real
  `check_part_overlapped` claims `[0, 0x108803]` for name `lk` and
  returns — no panic; the copy to 0 fires the hijack through the real
  block loop; the real payload runs; the patched LK lands at
  0x41E00000; tee2 fallback completes; patched ARB passes with zero
  RSA calls.
  → phase 1: `tests/test_real_parse_overlap.py`; both slots from a real
  deploy's chip dump: `tests/test_customfw_guarantee.py`; the phase-2
  tee2-fallback + patched-ARB + zero-RSA legs:
  `tests/test_layer4_closedloop.py::test_scenario_c_on_postflash_chip`
  and `scenarios/guarantee.py` chain legs.
- **RSA gate is load-bearing** — real crypto rejects `lk-patched` (the
  brick-2 mechanism) while the payload's gate patch skips the call:
  `verify_calls == 0` on the chain.
  → `tests/test_pl_hostcrypto.py::test_patched_lk_fails_verification`, leg-2 assertion.
- **Unlock gate** — REAL `cmd_lock_check`: stock restricts
  `flash:boot` (1) on the locked device; patched returns allowed (0).
  → `tests/test_lk_customfw.py::test_lock_gate_differential`.
- **Unsigned boot acceptance** — REAL `verify_and_vb` on an unsigned
  custom image: stock executes the RED block (FAILED AUTHENTICATION,
  vbstate 3, ret −0xD); the patched RED-abort branch skips to the
  publish path.
  → `tests/test_lk_customfw.py::test_verify_and_vb_differential`.
- **Downgrade precondition** — the REAL BROM classifies the 2021 belt
  (and the post-deploy dump) as `boots_2021_pl`.
  → `tests/test_customfw_guarantee.py` leg 4, `scenarios/boot_brom.py`.
- **Closed loop** — `deploy()` places the real artifacts on the
  emulated NAND; the chain boots the dump's bytes at true placement.
  → `tests/test_layer4_closedloop.py`, `tests/test_customfw_guarantee.py`.
- **UART agreement** — `scenarios/guarantee.py --trace-diff
  no-alexa/…/tp54_gnd.txt`: of 14 emulated stock-boot PL lines, 8
  exact + 3 prefix matches in the 558-line real capture; 3 emu-only
  (the device log's PLFM/PMIC init phase is outside the emulated
  surgical surface, and the surgical runs add no device-side lines).

### Audit findings landed during this work

- The LK-verify key lives at VMA **0x222260** (file 0x29560), not the
  0x22244C recorded in `recovery-notes/preloader-vuln-signature.md` §2 —
  recovered from `sub_201D70`'s own pc-relative pool and
  fingerprint-matched (porting-notes §guarantee Task 5).
- The donor `emu_chain.py` docstring claimed `check_part_overlapped`
  ran real while the port stubbed it — the docstring was wrong; the
  stub is now real code (Task 2).

## 3. LK unlock-leg seams

- Patch-set byte verification: `tests/test_lk_patches.py` (three sites
  re-derived from the stock donor, byte-diff allowlist).
- Executed on real patched bytes: `crumpet_emu/lk/customfw.py` +
  `tests/test_lk_customfw.py`.
- **Ceilings (M2 class, honestly parked):** (1) the real fastboot
  dispatcher loop (0x41E1E1A2) is unreachable surgically —
  fastboot_init faults at its NULL handler-registration list
  (boot-time heap state; porting-notes §guarantee Task 8); per-handler
  surgical dispatch + the real-callee lock-gate differential are the
  execution surface. (2) `verify_and_vb`'s publish path beyond its
  first stages needs natural-boot state (wfi/IRQ blocker, porting-notes
  §platform 5c). (3) The fastboot flash WRITE path needs LK's
  boot-built partition table + mmc stack — the operator's actual flash
  routes (Linux-root dd; mtkclient through the DA-patched preloader
  USBDL) are covered by the deploy pipeline against the emulated chip.

## 4. Risk register (irreducible hardware risks)

| # | risk | impact | on-device check / mitigation |
|---|------|--------|------------------------------|
| 1 | NFI/DMA read behavior during the mid-transfer bdev overwrite: the emu serves flash bytes host-side at the `bdev->read` boundary. The per-block pointer re-fetch is real preloader code, but silicon read granularity, ECC-retry re-reads, or DMA chunking could differ. | hijack may fire at a different block boundary — payload is position-staged by header, not block index, so the class of divergence is "would have fired anyway or never"; no partial state | first boot with UART attached; abort-power plan if the `[BLDR] tee1 part. TEE load fail` line does not appear where the emu shows it |
| 2 | Per-unit eFuse ARB state | stock ARB check would halt on fuse>sw before the TEE loads — but the payload patches the check AND the burn pre-execution every boot (proven order: patch before check) | read `getvar` antirback versions on the live unit pre-flash; the exploit's belt includes the 2021 preloader whose stamps the emu verified pass (fuse=1 case) |
| 3 | Active slot (lk_a vs lk_b) unknown per unit | flashing the exploit to the ACTIVE slot's LK position would be wrong | both slot variants built + emu-tested; detect via the misc BCB page (deploy does), `unit3-preflight-fastboot-vars.txt`, or the no-alexa convention (boots lk_b) |
| 4 | BROM SBC enforcement (live on production dies) | only Amazon-signed preloaders boot; the 2021 NS6548 belt is Amazon-signed (BROM leg proves it boots) | no unsigned preloader is ever flashed; the belt comes from the OTA set |
| 5 | NAND placement exactness | misplaced pages = unbootable | closed-loop leg proves the deploy places at true GPT pages and the chain boots them from the dump |
| 6 | USB timing (USBDL recovery path) | headless unit hangs in handshake (brick class) | crumpet2021.c never forces USBDL on normal boots (`usbdl_detect_key()==0`); on_lk_load_failure falls back to stock boot; USBDL is recovery-only via the physical key combo |
| 7 | M2 ceilings (§3) | unlock-leg behaviors beyond the pinned surfaces are surgical, not natural-boot | first boot observation: fastboot comes up (getvar answers), then flash via the proven deploy route |

## 5. Pre-flash checklist (ordered)

1. **Backup first** — `deploy()` writes a verified backup before any
   flash (§7.4 pipeline; keep the backup dir off-device).
2. **Slot detection** — read misc BCB / unit preflight vars; pick the
   matching build (`crumpet2021-lka` / `-lkb`).
3. **Belt precondition** — the unit must be on the 2021 NS6548
   preloader belt (or be downgraded to it first: LK does not enforce
   rollback; BROM accepts the signed belt — both emu-proven).
4. **ARB read** — capture `getvar` antirback values before flashing
   (risk #2).
5. **UART attached for first boot** — expect the emu's exact line
   sequence (`[BLDR] tee1 part. TEE load fail`, `check_part_overlapped
   done`, patched ARB pass, fastboot banner).
6. **Abort-power plan** — if the first boot diverges from the emu trace
   before the payload banner, cut power: the exploit is staged in
   tee1/lk_a only, and the stock boot fallback (tee2 + active-slot LK)
   is intact until the custom LK is written to a slot you boot from.
7. **Re-generate the guarantee** before any artifact change:
   `venv/bin/python scenarios/guarantee.py` must print
   `VERDICT: GUARANTEE HOLDS`.
