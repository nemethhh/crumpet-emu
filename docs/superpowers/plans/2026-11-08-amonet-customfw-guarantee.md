# Amonet custom-firmware guarantee Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make crumpet-emu a bounded pre-flight oracle proving the amonet-koboreru `crumpet2021` chain + patched-LK path can create/run custom firmware on real crumpet silicon: every pure-code step executes real vendor/payload bytes, every seam is real / staged-with-citation / provably-conservative, and one CLI prints the verdict matrix plus the irreducible hardware-risk register.

**Architecture:** Three fidelity upgrades. (1) Preloader layer: the four reimplemented seam functions (header parse, `check_part_overlapped`, `part_get`, `boot_device_init`) move to REAL code execution — reimplementations stay behind `legacy_seams=True` for differential comparison. (2) LK layer: the patched LK (`2021:lk-patched`) is executed, not just byte-verified — lock gate differential, fastboot e2e on patched bytes, and a surgical `verify_and_vb` (0x41E11548) unsigned-boot.img acceptance test. (3) Glue: the patched-LK bytes the preloader chain stages at 0x41E00000 feed `LkSession` for the unlock leg, making one end-to-end pinned test: deploy → chip dump → exploit → patched LK → custom boot.img accepted.

**Tech Stack:** Python 3 in the repo venv (`venv/`), Unicorn 2.1.4, capstone, pytest (tier-gated), existing `crumpet_emu` package. IDA/capstone for disasm ground truth where a real function's state needs are derived.

**Spec:** this plan + audit findings embedded in it; supporting evidence: `WS/recovery-notes/amonet-crumpet-2019-port.md` (constants, §3 vulnerability), `WS/recovery-notes/preloader-vuln-signature.md` §2 (key VMAs), `tools/derive_lk_patches.py` docstring (patch set), `docs/porting-notes.md` (donor-verbatim rule, staging precedent), `WS/no-alexa/logicanalyzer/uart_logs/` (real-device UART ground truth). `WS` = `/home/am/Work/SRE-Device`.

## Global Constraints

- **Never modify `WS/tools/amonet-koboreru`** — its AGENTS.md forbids LLM code changes. Read/build only.
- **Donor-verbatim rule:** changes to ported donor modules (`crumpet_emu/preloader/emu.py` etc.) require a ruling appended to `docs/porting-notes.md` (§seam-style) naming the delta and its justification. Keep legacy behavior reachable (`legacy_seams=True`).
- **No fabricated semantics:** every new staging state or stub needs a citation (real-device UART line, IDA finding, or real-image byte offset) recorded in the code comment and the ledger. Fabricated-platform territory is out (porting-notes M2 ruling stands).
- Use `venv/bin/python` for everything; never system pip (global AGENTS.md venv policy).
- Tier gating: every new test that needs vendor bins gates via the existing `resources`/manifest pattern; Tier 1 must stay green with zero bins.
- All 20 vendor slots + 12 own artifacts are currently placed/pinned — keep tests passing when bins are absent (skip, don't fail).
- Commit after every task; repo is a fresh clone at `7a99249`.

## Review Focus

1. **A real-seam upgrade silently changing semantics** — real parser/gate must reproduce every stock case the reimplementation passed; differential legacy-vs-real must agree on the stock belt before the legacy path is demoted. Test: Task 2 step 4 (differential over CAL-1/CAL-2 + scenario C).
2. **Crafted-header edge cases** (`maddr != 0xFFFFFFFF`, name case `'LK'` vs `'lk'`, non-`lk` crafted name) — real `check_part_overlapped`/parse must not panic where silicon wouldn't. Test: Task 2 step 5.
3. **Patched LK vs 2025-derived seeds** — `lk-patched` is the 2025 donor + 3 patches; every seed/F-table address used by the new legs must be asserted valid against patched bytes. Test: Task 6 step 2.
4. **Both slot variants** — lka and lkb payloads must each chain-complete; a slot-specific GPT/offset bug must fail loudly. Test: Task 7 step 3.
5. **Missing bins** — new tier-2 tests skip cleanly (no traceback, provenance pointer) with zero bins placed. Test: Task 7 step 5 (rerun of `pytest -q` in a bins-absent tree, mirroring `tests/test_tiers.py` practice).

---

### Task 1: Seam inventory + ledger

**Files:**
- Create: `crumpet_emu/preloader/seams.py`
- Create: `docs/guarantee.md` (skeleton: matrix + risk register sections, empty rows)
- Modify: `docs/porting-notes.md` (new §guarantee section: this effort's charter)
- Test: `tests/test_seam_ledger.py`

**Interfaces:**
- Produces: `SEAMS: dict[str, Seam]` where `Seam = namedtuple('Seam', 'vma kind citation')`, `kind ∈ {'real', 'staged', 'oracle-conservative', 'reimplemented'}`; `SEAM_CHAIN_CRITICAL: frozenset[str]` (names whose kind must not be `'reimplemented'` once Tasks 2–4 land: `hdr_parse`, `overlap_chk`, `part_get`).

- [ ] **Step 1: Write the failing test** — `test_seam_ledger.py` with two tests: (a) `test_every_intercepted_seam_documented`: every entry in `Emu.hook_code`'s intercepted-address set used by the amonet chain (`HDR_PARSE, OVERLAP_CHK, PART_GET, BDEV_INIT, PART_LOAD, VERIFY_LK, MTEE_VERIFY, TEE_SET_ENTRY, SECMEM_REARM, ASSERT, USB_HANDSHAKE, MEMCPY, TIMER_GET, 0x20192C, 0x21A560, 0x201EE8, TRAMP, UART_THR, PRINTF`) has a `SEAMS` entry with a non-empty citation; (b) `test_chain_critical_seams_real` (the forcing function): each name in `SEAM_CHAIN_CRITICAL` (`hdr_parse`, `overlap_chk`, `part_get`) has kind in `{'real','staged','oracle-conservative'}` — shipped `xfail(strict=True, reason='Tasks 2-3 upgrade the reimplemented seams')`.

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/python -m pytest tests/test_seam_ledger.py -q`
Expected: FAIL listing the four reimplemented chain-critical seams.

- [ ] **Step 3: Implement `seams.py`** — the inventory above with today's honest classifications + one-line citations (port doc §3, README seam list, porting-notes §seam). Write the `docs/guarantee.md` skeleton and the porting-notes charter paragraph.

- [ ] **Step 4: Run test to verify it passes** — expected PASS: (a) green as written; (b) xfail as marked. Tasks 2/3 flip the two upgraded seams' kind and remove the xfail (their own steps say so).

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(guarantee): seam inventory ledger + charter"`

### Task 2: Real header-parse + real check_part_overlapped

**Files:**
- Modify: `crumpet_emu/preloader/emu.py` (constructor flag `legacy_seams=False`; `hook_code` branches for `HDR_PARSE`/`OVERLAP_CHK` only when `legacy_seams`)
- Modify: `crumpet_emu/preloader/seams.py` (kinds → `'real'`), `docs/porting-notes.md` (ruling), `docs/guarantee.md` (rows)
- Test: `tests/test_real_parse_overlap.py`

**Interfaces:**
- Consumes: `Emu.__init__(flash, sbc, log, payload_syms, stock_ok, legacy_seams=False)`.
- Produces: real-code execution at `0x20F2D8`/`0x20F398`; `Emu.lk_region` now mirrors the guest global after each call (host copy for assertions only).

- [ ] **Step 1: Probe first.** One-off script (not committed): build the CAL-1/CAL-2/chain calls with the two stub branches deleted, run under `try_call`, log first fault pc + unmapped accesses (pattern: porting-notes §platform probe). Determine what real state each function needs (`ctx` fields for parse at `DRAM_BUF+0x666F0`; `lk_region` global cell for overlap — locate via disasm of `sub_20F398` stores using capstone on `PL_IMG` bytes at `0x20F398 - FILE_DELTA`).
- [ ] **Step 2: Write failing tests** — (a) chain (lka variant, own artifacts) completes with real parsers: payload staged, patched LK staged at 0x41E00000, no fault/stop; (b) crafted sub-image named `'TEE'` (not `'lk'`) hits the REAL assert path: `emu.stopped` with the ASSERT oracle event (real `assert(239)` → `sub_21082C`); (c) guest `lk_region` global equals claimed range `[0, dsize-1]` after the crafted load (read the cell the probe located); (d) differential: with `legacy_seams=True` vs `False`, the stock CAL-1/CAL-2 verdicts and event streams (minus the two seam's own event lines) agree.
- [ ] **Step 3: Run to verify failures** (ImportError/TypeError on `legacy_seams` first).
- [ ] **Step 4: Implement** — gate the two branches behind `legacy_seams`; zero any BSS cell the probe identified as `lk_region` in `__init__` (citation comment); re-arm `self.lk_region` mirror from the guest cell inside a small `hook_code` observer at the overlap function's return (no semantic writes — observation only, LK-platform.py precedent).
- [ ] **Step 5: Run tests; then full suite** `venv/bin/python -m pytest -q` — everything green including `tests/test_layer4_closedloop.py` (its scenario-C boot now runs the real parsers).
- [ ] **Step 6: Update ledger kinds + porting-notes ruling; commit.**

### Task 3: Real part_get via staged partition table

**Files:**
- Modify: `crumpet_emu/preloader/emu.py` (`PART_GET` branch gated by `legacy_seams`; staging helper), `crumpet_emu/preloader/seams.py`, `docs/porting-notes.md`, `docs/guarantee.md`
- Test: `tests/test_real_part_get.py`

**Interfaces:**
- Consumes: `crumpet_emu.flash.gpt.parse_gpt_from_image` (real GPT from `2021:brhgptpl_0`).
- Produces: `Emu._stage_part_table()` — writes the real preloader partition-table structures (layout per disasm of `sub_20F250`: entry fields + `char*` names + list linkage) into SRAM scratch; `part_get` then runs REAL.

- [ ] **Step 1: Probe.** Disassemble `sub_20F250` (capstone on image bytes) to recover the walked structure: global list head cell, per-entry field offsets (name ptr / start / blocks / next). Also disasm `sub_212EFC` head only (Task 4 input).
- [ ] **Step 2: Write failing tests** — (a) real `part_get('lk_a')` returns a struct whose start/nblk match `parse_gpt_from_image()['lk_a']`; unknown name → 0; (b) chain completes end-to-end on real `part_get`; (c) differential legacy-vs-real event agreement.
- [ ] **Step 3: Verify failures; implement staging + ungate; run tests + full suite.**
- [ ] **Step 4: Ledger/ruling updates; commit.**

### Task 4: BDEV_INIT ruling (probe, no forced upgrade)

**Files:**
- Modify: `crumpet_emu/preloader/seams.py` (kind → `'staged'` with justification, or `'real'` if the probe lands), `docs/porting-notes.md`, `docs/guarantee.md`
- Test: extend `tests/test_seam_ledger.py` only

- [ ] **Step 1: Probe `sub_212EFC` under Unicorn** with the `flash/nfi.py` `NfiModel` mapped at the NFI register window: does the real init complete (chip-id read path) and re-arm `bdev->read` to the real driver read function? Record what breaks first.
- [ ] **Step 2: Ruling.** If real init + real driver reads work: gate behind `legacy_seams` same as Tasks 2–3, add chain test. Otherwise: reclassify the re-arm stub `'staged'` with citation (which fields the real init writes — from disasm) and a guarantee-doc paragraph explaining why the payload's own `boot_device_init()` call is state-equivalent on silicon. Either outcome closes the ledger row honestly.
- [ ] **Step 3: Test/ledger updates; full suite; commit.**

### Task 5: RSA oracle → real-crypto check (host-side, real keys)

**Files:**
- Create: `crumpet_emu/preloader/hostcrypto_pl.py`
- Modify: `crumpet_emu/preloader/emu.py` (`VERIFY_LK` branch), seams/notes/guarantee docs
- Test: `tests/test_pl_hostcrypto.py`

**Interfaces:**
- Consumes: preloader key VMAs from `WS/recovery-notes/preloader-vuln-signature.md` §2 (LK verify key @ VMA 0x22244C region — re-locate by entropy scan + xref, don't trust blindly).
- Produces: `verify_lk_signature(image_bytes, pl_bytes) -> bool` (real RSA-2048/PSS vs the key embedded in the real pl image), used by the `VERIFY_LK` seam instead of the stock-bytes equality oracle.

- [ ] **Step 1: Failing tests** — stock `2021:lk` sub-image verifies True; single-byte tamper → False; `2021:lk-patched` sub-image → False (proves the gate patch is load-bearing); garbage → False.
- [ ] **Step 2: Implement** — parse the 256-B modulus/exponent from `PL_IMG` at the located offset (entropy + xref verification documented in-code); mirror `crumpet_emu/lk/hostcrypto.py` patterns for the math. Oracle semantics preserved: verify still happens AFTER the copy (real `part_load` order — unchanged).
- [ ] **Step 3: Full suite (scenario C / closed-loop must stay green: patched LK now FAILS RSA but the gate patch skips it — assert `verify_calls` still 0 there). Ledger: kind `'oracle-conservative'` → `'real-crypto-host'`. Commit.**

### Task 6: Execute the patched LK (unlock leg)

**Files:**
- Create: `crumpet_emu/lk/customfw.py`
- Test: `tests/test_lk_customfw.py`

**Interfaces:**
- Consumes: `LkSession.build(bytes)`; `resources.resolve('lk-patched','2021')`; `FastbootHost`; `observe_auth`.
- Produces:
  - `lock_gate_differential() -> dict` — real `cmd_lock_check` @0x41E0EF18 called at its real call-site shape: stock → "locked" verdict, patched → "allowed".
  - `patched_fastboot_flash(boot_bytes) -> (status, message)` — `FastbootHost` `download` + `flash:boot` on patched bytes → expect OKAY.
  - `verify_and_vb(lk, boot_bytes) -> (ret, vbstate)` — surgical call of 0x41E11548 with staged `*g_vbstate` + deviceinfo (platform.py staging precedent): patched → ret 0 / published state; stock → ret -0xD / RED.

- [ ] **Step 1: Probe** seed validity on patched bytes: assert every seeds.json VMA used (`usb_read`, `usb_write`, dispatcher/handler VMAs, 0x41E11548, 0x41E00F58) disassembles to the expected prologue in `lk-patched` (capstone; catches any drift).
- [ ] **Step 2: Failing tests** — (a) stock vs patched `cmd_lock_check` differential; (b) patched flash:boot custom bytes → OKAY, stock → FAIL (locked); (c) `verify_and_vb`: patched accepts unsigned custom boot.img (build a minimal boot.img from `2025:boot` with tampered signature page — must NOT verify under `observe_auth`, proving it is genuinely unsigned), stock rejects same bytes; (d) `getvar:version` replies OKAY on the patched session through `FastbootHost` (dispatcher plumbing on patched bytes); unlocked-state *reporting* (`deviceinfo+0x1E2` publish) is natural-boot-only (M2 ceiling) and is documented, not tested, in `docs/guarantee.md`.
- [ ] **Step 3: Implement** (`customfw.py`, thin orchestration over existing session surfaces; staging cited from porting-notes §platform table).
- [ ] **Step 4: Full suite; commit.**

### Task 7: End-to-end custom-firmware guarantee test (pinned, tier 2)

**Files:**
- Create: `tests/test_customfw_guarantee.py`
- Test: itself

**Interfaces:**
- Consumes: Tasks 2–6 surfaces + `crumpet_emu.deploy.main` + `ChipDumpFlash` + `boot_brom` classifier + `tests/test_layer4_closedloop.py` fixture pattern.

- [ ] **Step 1: Failing test** — one test, four legs: (1) `deploy()` onto emulated NAND (both slot variants), chip dump; (2) preloader chain boots from dump with real seams → patched LK staged at 0x41E00000, byte-identical to `2021:lk-patched`; (3) those staged bytes → `LkSession` → Task-6 legs all pass; (4) BROM classifier accepts the dumped 2021 belt (`boots_2021_pl`). Verdict object: `CustomFwGuarantee(chain_ok, unlock_ok, brom_ok, seam_ledger_ok)` — all True.
- [ ] **Step 2: Implement glue** (reuse closed-loop fixtures; parametrize lka/lkb).
- [ ] **Step 3: Run both slot variants** — both must pass; a slot failure is a loud bug, not a skip.
- [ ] **Step 4: Full suite green; commit.**

### Task 8: Real fastboot dispatcher loop (stretch probe)

**Files:**
- Modify (only if probe lands): `crumpet_emu/usb/fastboot.py` (`loop_send()` alternative entry), notes/guarantee docs
- Test: extend `tests/test_lk_customfw.py`

- [ ] **Step 1: Probe.** Surgically call `fastboot_init` (0x41E1E3B4) on a patched session, then enter the real command loop 0x41E1E1A2 with the usb seam queued (`getvar:version`, then `download`+`flash:boot`). Record the first unmapped/fault (the handler-list boot state is the known risk — porting-notes §seam).
- [ ] **Step 2: If it runs:** add `FastbootHost.loop_send()` driving the REAL loop (usb_read/write seams only) and re-run the Task-6 flash through it — now `cmd_lock_check` executes in its real call-site context 0x41E1E1FC. If it does not: ledger + guarantee-doc paragraph recording the surgical-dispatch ceiling (M2-class), no code. Either way: commit.

### Task 9: `scenarios/guarantee.py` CLI + UART trace-diff

**Files:**
- Create: `scenarios/guarantee.py`
- Modify: `README.md` (CLI table row), `docs/guarantee.md` (final content)
- Test: `tests/test_scenario_clis.py` (extend)

**Interfaces:**
- Produces: `python scenarios/guarantee.py [--slot lk_a|lk_b|both] [--skip-brom]` → prints the verdict matrix (per-leg PASS/FAIL + seam-ledger status) and, `--json` path, machine-readable verdict; exit 0 iff all green. `--trace-diff` mode: emu stock-boot `pl_log` vs `WS/no-alexa/logicanalyzer/uart_logs/tp54_gnd.txt` — line-classified agreement report (exact/prefix-only/emu-only/device-only), written into `docs/guarantee.md` by hand after review.

- [ ] **Step 1: Failing CLI test** (pattern of `tests/test_scenario_clis.py`: `--help` Tier-1 green without bins; full run Tier-2 gated).
- [ ] **Step 2: Implement CLI** (thin argparse over Task 2–7 surfaces).
- [ ] **Step 3: Run it for real; capture output; commit.**

### Task 10: Guarantee document (the deliverable)

**Files:**
- Modify: `docs/guarantee.md` (full), `README.md` (link), `docs/porting-notes.md` (final ruling cross-refs)

- [ ] **Step 1: Write the doc** — (a) fidelity matrix: every seam row (name, VMA, class, citation, test that pins it); (b) what the emu PROVES (each leg → real bytes executed → test id); (c) residual hardware-risk register, each with impact + on-device check: NFI/DMA mid-transfer timing (bdev read re-fetch is real code, but silicon read granularity/ECC retry can differ → check: first boot with UART attached, abort-power plan), per-unit eFuse ARB state (patch neuters check + burn; verify fuse version via `getvar` before flashing), active-slot unknown (both variants built + tested; detect via BCB/misc page or unit3 preflight vars), NAND placement exactness (closed-loop covers), M2 wfi ceiling (unlock leg is surgical, not natural-boot), USB timing (n/a — headless unit, USBDL only as recovery); (d) pre-flash checklist ordering (backup via deploy → slot detect → belt downgrade precondition → flash → first-boot observation).
- [ ] **Step 2: Cross-link** from `WS/recovery-notes/PROJECT-STATE.md` (one paragraph, pointer to `docs/guarantee.md`).
- [ ] **Step 3: Final full suite + `scenarios/guarantee.py` run; commit.**
