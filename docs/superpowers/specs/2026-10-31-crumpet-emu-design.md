# crumpet-emu — design document

**Date:** 2026-10-31
**Status:** approved by nemethhh; builder check integrated (same day)
**Author:** session notes (brainstorming with nemethhh)
**Reviewer:** builder check done — 5 findings, all resolved; calls marked (§8)

## 1. Intent and why

Build a **hunting instrument for the Amazon Echo Dot 3rd-gen refresh
("crumpet", MT8167) load chain**: one standalone, GitHub-hosted emulator
repo that boots real vendor code (BROM → preloader → LK) under Unicorn
and lets the operator hunt for vulnerabilities across the whole chain —
not merely replay known scenarios.

Today that capability lives in two places inside a private workspace
(`WS`, stays untouched and read-only):

- `tools/kamakiri/emu/` — a layered package that boots a dumped MT8167
  BROM from reset through a modeled NAND/NFI flash and drives the
  kamakiri BROM exploit (stage1/stage2 transport); its layer-4 closed
  loop already stages LK at `0x41E00000` byte-identical to the donor
  image. 38 of 39 tests pass.
- `tools/amonet-emu/emu_chain.py` — a single-file surgical harness
  inside the 2021 preloader: IDA-validated constants, image-backed
  flash, the A/A0/B/C brick/chain scenarios, SBC-eFuse gating.
- `tools/lk-emu/lk_emu.py` (+ `battery.py`, `ida_seeds.json`,
  `mkelf_lk.py`) — a working Unicorn harness for the exact 2025 LK
  target (`img/lk.img`): audit-pinned ~30-entry function table
  (RSA-PSS/SHA-256/base64/malloc/plat_read/idme_update…), verified
  memory map, single-instruction fault model at the RSA gate
  (`otu-glitch` @ 0x41E019F4), and end-to-end fastboot-handler runs
  (`run-flash-e2e.log`: `0x41E1F5C0` → `>> OKAY`). Found during the
  builder check; absorbed as the third donor (§8, call C1).

They duplicate infrastructure (flash serving, UART/timer/eFuse, USB
model, LK staging) and neither can reach the newest hunting target:
LK's fastboot unlock surface and the kernel-load handoff. The new repo
unifies them into one layered core with multiple entry points, then
adds the missing layers.

Why a combined instrument matters for hunting specifically:

- **Checkpoint/restore at layer boundaries** — snapshot at fastboot-loop
  entry, restore per fuzz case; no per-case boot cost.
- **Fault injection at layer boundaries** — corrupt any image the flash
  model serves; differential runs (SBC set/clear, slot a/b, locked
  flags, firmware generations).
- **Dynamic confirmation of static verdicts** — e.g. the RSA-PSS
  "no forge path" audit becomes a testable, repeatable claim.

## 2. Goals, non-goals, anti-goals

### Goals

1. One standalone repo (`<REPO-ROOT>`), pushed to GitHub as
   `nemethhh/crumpet-emu`, containing: the layered emulator package,
   entry-point scripts, tests, docs, and binary manifests (see §8 for
   the binaries policy).
2. Layered core, multiple entry points:
   - **BROM layer** (from `kamakiri/emu`): reset → NAND/NFI → BROM
     exploit stages, closed-loop boot.
   - **Preloader layer** (from `amonet-emu`): the validated 2021
     preloader segment — part_load, verify gates, SBC eFuse, scenarios
     A/A0/B/C — as a library and as presets, not a separate universe.
   - **LK layer** (new): execute the LK build at `0x41E00000`, drive
     its fastboot dispatcher over the USB model, and observe the
     unlock-token surface (`flash:unlock` / `flash:otucert` /
     `flash:otucode`).
   - **Kernel-load observability** (new): LK boot-image authentication
     (`0x41E11548`, `verify_with_hash`), cmdline construction,
     anti-rollback reads, and detection of the kernel/TEE handoff
     point.
3. Hunting instrumentation as first-class, cross-cutting modules:
   checkpoints, fault injection, differential runner, fuzz harnesses
   (fastboot verbs/blobs, DER/cert parsing, GPT/part headers), and
   edge-coverage tracing.
4. All 38 passing donor tests ported and green in the new repo.
5. Docs: architecture, hunting guide, provenance/licensing, porting
   notes (what changed vs donors and why).

### Non-goals

- No Linux kernel execution — the chain ends at the handoff point
  (kernel-load observability), by explicit scope decision.
- No hardware interaction; emulator only.
- No modification of any existing workspace project (donors are
  read-only; the new repo contains copies).
- No new exploit authoring as a repo goal; reproducing/hunting is in
  scope, weaponization is not.

### Anti-goals (what would make this a failure)

- Committing vendor-proprietary binaries to the public repo while the
  binaries question is parked (see §8).
- Silently diverging duplicated infrastructure — flash/USB/session
  utilities must exist once.
- Import-time file reads or hardcoded absolute paths anywhere in the
  package (a donor bug class this port must fix: `brom_boot.py` reads
  the BROM at import time).
- Breaking the donor fidelity that makes scenario A/A0 brick repros
  meaningful (validated constants carried over verbatim).

## 3. Constraints

- Repo location: `<REPO-ROOT>` (sibling of other hobby
  projects; name chosen to avoid collisions).
- GitHub: `nemethhh/crumpet-emu`, created with `gh` (authenticated).
  **Private at creation** — one-command flip to public later
  (`gh repo edit nemethhh/crumpet-emu --visibility public`).
- Donor projects remain as-is at their current paths; the new package
  must run without them present.
- Vendor binaries are **parked**: no committed vendor blobs. All
  binary paths resolve through environment overrides with repo-local
  defaults, so bins drop in later without code changes (§8).
- Python: system 3.14, unicorn 2.1.4 (matches donor behavior);
  pin `unicorn>=2.1,<3`.

## 4. Approaches considered

1. **Layered core, multiple entry points (chosen).** One package;
   boot stages as composable layers; emu_chain's surgical harness
   becomes a preloader-segment library + presets; hunting
   instrumentation is cross-cutting; checkpoints give the purist
   full-chain mode too. Trade-off: most up-front refactoring, but the
   38 passing closed-loop tests carry over as the foundation.
2. **Minimal merge** — share only infra, keep three thin frontends.
   Rejected: hunting instrumentation (checkpoints, injection,
   coverage) would be built three times and diverge.
3. **Purist single boot session** — one continuous reset→handoff run,
   inputs-only injection. Rejected as the primary mode: worst hunting
   ergonomics (per-case boot cost kills fuzzing; scenario A/A0
   isolation becomes hard). Subsumed by approach 1's checkpointing.

## 5. Decided design

### 5.1 Repo layout

```
<REPO-ROOT>/
├── README.md
├── LICENSE                      # MIT (nemethhh), see provenance for upstreams
├── requirements.txt             # unicorn>=2.1,<3, pytest; capstone optional
├── .gitignore                   # __pycache__, .pytest_cache, binaries/vendor/
├── docs/
│   ├── superpowers/specs/       # this document
│   ├── architecture.md          # layers, entry points, memory maps
│   ├── hunting.md               # checkpoints, injection, differential, fuzzing
│   ├── porting-notes.md         # deltas vs donors, fixed path bugs
│   └── provenance.md            # every binary + upstream attribution
├── crumpet_emu/                 # single importable package (replaces `emu`)
│   ├── core/                    # session, mem map, hooks, devices, checkpoints
│   ├── flash/                   # NandChip, NfiModel (+nfi_regs.json), GPT,
│   │                            #   image-backed Flash (absorbs emu_chain's), ChipDump
│   ├── brom/                    # BROM boot replay + exploit stages (from brom_boot)
│   ├── preloader/               # 2021 PL segment: validated constants, Emu,
│   │                            #   scenarios A/A0/B/C, calibrate/preflight
│   ├── lk/                      # LK exec @0x41E00000 (generalized lk_emu), fastboot
│   │                            #   driver, unlock lab + battery, seeds.json,
│   │                            #   boot-image auth + handoff observability
│   ├── deploy/                  # ported modules/{functions,main}_crumpet (~443 ln):
│   │                            #   DeployConfig, deploy(), slot logic — the
│   │                            #   closed-loop chip fixtures' support code
│   ├── usb/                     # usb_model, stage2 transport, fastboot host driver
│   └── hunting/                 # injection, differential, fuzzers, coverage map
├── scenarios/                   # runnable entry points (one CLI per layer + diff/fuzz)
├── tests/                       # ported donor tests + new core/LK tests
└── binaries/
    ├── README.md                # what goes here, SHA256 manifest, env vars
    ├── own/                     # committed own-source artifacts (see §6)
    └── vendor/
        ├── 2021/                # gitignored; parked 2021 OTA donor blobs
        └── 2025/                # gitignored; parked 2025-generation blobs
```

### 5.2 Porting rules

- Package renamed `emu` → `crumpet_emu`; imports updated everywhere
  (including test conftest, which becomes a plain package layout with
  no `sys.path` hack).
- Every donor file gets a header comment: original path in the
  workspace, upstream attribution, and the date/commit it was copied
  from (`kamakiri` = local work on `R0rt1z2/kamakiri`; payload sources
  under MIT `R0rt1z2/amonet-koboreru`).
- Fix at port time: import-time reads become lazy; `Path` resolution
  via env vars (§8); no absolute workspace paths.
- Third donor (`lk-emu`) ports as: `lk_emu.py` → generalized
  `crumpet_emu/lk/` harness (its direct-call scenarios become the
  surgical entry mode + battery fixtures), `ida_seeds.json` →
  `crumpet_emu/lk/seeds.json`, `battery.py` → unlock-battery fixtures
  inside `crumpet_emu/lk/`; `mkelf_lk.py`/`static_scan.py`/decomp C
  files stay workspace-only (not ported).
- Closed-loop support code: `tools/kamakiri/modules/functions_crumpet.py`
  (150 ln) and `main_crumpet.py` (293 ln) port into
  `crumpet_emu/deploy/` (pure `hashlib`/`struct`, session-abstraction
  seam preserved). Sixteen donor tests keep their real semantics
  because this code moves with them (§8, call C2).

### 5.3 Layer specifics (validated facts the builder must preserve)

**BROM / kamakiri (from donors):**
- BROM dump: `brom_MT8167_MT8516_MT8362_8167.bin`, 131,072 B, at 0x0.
- Stage1 payload staged at `0x100A00`; stage2 SRAM window
  `0x00201000`, ≤ 0x8000; exploit byte-math follows amonet
  `modules/load_payload.py` (`da_read_write`, write-mem + jump).
- Closed loop: real preloader served from NAND pages; patched LK
  staged at `LK_LOAD_ADDR = 0x41E00000` byte-identical to
  `lk-patched.img`; slot convention: misc BCB names the active slot
  (task-7 suffix convention: active `lk_b` → deploy on `lk_a`).
- NFI: `nfi_regs.json` register inventory drives the NFI model;
  watchdog/NFI/ECC hooks from `brom_boot.py` carried as-is.
- Donor windows/hashes: `brhgptpl_0..3` donor belt for classify().

**Preloader (from emu_chain.py, validated against IDA db pl2021.i64):**
- `TEXT_BASE 0x201000`, `FILE_DELTA 0x1F8D00`;
  `PART_LOAD 0x20F4A8`, `PART_GET 0x20F250`, `BDEV_INIT 0x212EFC`,
  `USB_HANDSHAKE 0x20D7DC`, `TEE_SET_ENTRY 0x2160A8`,
  `MTEE_VERIFY 0x216140`, `SECMEM_REARM 0x216170`,
  `VERIFY_LK 0x201D70`, `PRINTF 0x2110F4`, `MEMCPY 0x215B70`,
  `ASSERT 0x21082C`, `TIMER_GET 0x215C5C`, `HDR_PARSE 0x20F2D8`,
  `OVERLAP_CHK 0x20F398` (name table `0x224910`), `BDEV 0x1086EC`
  (read at `+0x20`), `HEAD_CELL 0x102188`, `BSS_START 0x102180`,
  `PAYLOAD_ADDR 0x101000`, `DRAM_BUF 0x42000000`,
  `BOUNCE +0x56800`, `CTX_HDR +0x666F0`, `TEE_LOAD_ADDR 0x43001000`,
  `SRAM_DBUF_PTR 0x102994`, UART `0x11005000/0x11005014`,
  `EFUSE_SBC 0x10009060`, timer `0x10008048`.
- GPT (4096-B LBAs, expressed in 512-B units): `tee1 (3584·8, 1280·8)`,
  `lk_a (256·8, 384·8)`, `tee2 (8768·8, 1280·8)`, `lk_b (640·8, 384·8)`.
- Scenarios: A (as-flashed 2021 image, SBC set → brick #2), A0 (port
  image 5f5481c, SBC set → brick #1), B (SBC clear → boots), C
  (corrected payload → full chain); CLI flags `--no-sbc`,
  `--skip-tee2`, `--calibrate`, `--preflight`, `--from-chip-dump`.
- Scenarios A/A0 depend on specific historical image commits
  (3e65ba3 / 5f5481c); while bins are parked these presets stay
  documented but inactive (manifest-gated).

**LK layer (new; facts from the workspace audits):**
- Target build: workspace `img/lk.img`, 237,056 B, load VMA
  `0x41E00000`, MTK GFH header 0x200 B, `VMA = file_off + 0x41dffe00`.
  (2021 `ota_out/lk.img`, 233,472 B, remains a second profile.)
- Verify driver (monolithic RSA-PSS cert chain): `0x41E0120C`;
  dual-attempt wrapper `0x41E00F58`; boot-image auth `0x41E11548`;
  fastboot top-level `FUN_41e1daec`; flash handler `FUN_41e1f5c0`;
  `flash:unlock` → `FUN_41e01a48` → IDME persist `"unlock_code"`
  (0x100 B) via `idme_update_var` (`FUN_41e00208`); `flash:otucert` →
  `FUN_41e01bc8`; `flash:otucode` → `FUN_41e01c18`; dispatcher table
  `0x37400..0x37654` (22 Thumb handlers). NOTE: `0x41E25030` /
  `0x41E252F4` are rodata `__FUNCTION__` strings, **not** entries.
- Crypto: libtomcrypt, RSA-PSS + SHA-256 + MGF1; audit verdict "no
  forge path" — the unlock lab's crafted-token assertions must expect
  verify-FAIL; success criteria are observation, not forgery.
- **USB boundary decision:** drive fastboot at LK's USB transport
  function boundary first (stub `usb_read`/`usb_write`-class helpers
  identified by IDA, fed by the host-side fastboot driver), not at
  register level. Register-level fidelity is a later deepening, done
  only if a hunt needs it — this keeps the layer reachable without
  emulating MT USB controllers twice.
- **Validated facts absorbed from `lk_emu.py` (preserve verbatim):**
  memory map `VMA = raw_off + 0x41DFFE00` (GFH 0x200 B), code at
  `0x41E00000`, BSS through `0x41E60000`, stack `0x70000000`
  (0x100000), heap `0x71000000` (0x400000), args `0x72000000`
  (0x100000), magic-return sentinel `0x0011F000`; UART/timer at the
  usual `0x11005000`/`0x10008048`; `ida_seeds.json` (~30 audit-pinned
  function VMAs incl. `rsa_import 0x41E0C95C`) becomes
  `crumpet_emu/lk/seeds.json`; proven scenarios: unlock verify forge
  battery (`sub_41E01A48`), `amzn_verify_code_internal`
  (`sub_41E01910`), full OTU chain (`sub_41E01C84`), single-instruction
  fault at RSA gate `0x41E019F4` (`otu-glitch`), boot-image auth driver
  (`sub_41E00F58 → 0x41E0120C`), base64 edge cases, end-to-end
  `0x41E1F5C0` → `>> OKAY`.
- **Entry-mode phasing (§8, call C4):** v1 = surgical entry (handlers
  and fastboot top-level called directly — both donors' precedent),
  plus function-seam fastboot driving; milestone M2 = LK boot-path
  entry (reset → platform init → fastboot loop reached naturally) so
  init-time parsing (IDME, deviceinfo, boot-mode) joins the huntable
  surface and the fastboot-entry checkpoint is naturally reached;
  kernel-load observability v1 = auth wrapper invoked on a staged
  `boot.img`, M2 upgrades it to watching the boot path run.

**Kernel-load observability (new):**
- Watch `0x41E11548` region: `verify_with_hash` calls/results,
  `androidboot.*` cmdline strings, anti-rollback reads at
  `deviceinfo+0x1E4/+0x1E6/+0x1E8`, TEE staging at `0x43001000`,
  and the final handoff (jump to kernel entry). Stop-and-report at
  handoff; no kernel execution.

### 5.4 Hunting instrumentation

- **Checkpoints** (`core/checkpoints.py`): serialize unicorn context
  (u2 context save/restore) + all mapped regions + model states
  (flash/NFI/USB/transport/RNG seeds) to a pickle; restore rebuilds
  the session. Checkpoint points offered at each layer boundary.
- **Fault injection** (`hunting/inject.py`): corrupt/skip/truncate any
  image or page the flash model serves, per-run, via a simple recipe
  dict (offsets, byte masks, range fills).
- **Differential runner** (`hunting/differential.py`): same input,
  varied parameters (SBC, slot, locked flags, firmware profile);
  aligns UART traces + verdicts; reports first divergence.
- **Fuzz harnesses** (`hunting/fuzz.py`): deterministic loops over
  fastboot verb/blob inputs, DER/cert blobs into the verify path,
  crafted GPT/part headers into part_load; restore-from-checkpoint
  per case; optional edge-coverage bitmap via `UC_HOOK_CODE` to score
  inputs (AFL-style map; full coverage-guided engine is a non-goal
  for v1).
- **Coverage/traces**: UART sink + per-layer trace log (donor
  `last_trace()` pattern), optional capstone disasm of recent tail.

### 5.5 Tests

- Donor suite measured at builder check: **40 collected, 38 pass, 2
  fail** (both failures in `test_build_reproducible.py`). Port all
  except that file, parked in `tests/attic/` with a skip note.
- **Tiered gate (§8, call C3):** *Tier 1* — green with zero parked
  vendor bins (everything not needing `binaries/vendor/`, incl. the
  deploy-port tests against committed own artifacts). *Tier 2* — green
  when the parked set is placed (closed-loop byte-identical staging,
  scenarios A/A0, donor-belt tests). Pre-push gate = Tier 1 + Tier 2
  when bins are present; README states exactly which tests are which.
- The 16 workspace-dependent tests (layer3 orchestration ×7, layer4
  ×1, layer5 ×6, lk_patches ×2) run against `crumpet_emu/deploy/` and
  committed own artifacts (`key_continuity.json`, patched-LK metadata,
  per-slot tz variants) — real semantics, no synthesis, no gutting.
- New: checkpoint round-trip identity; fastboot host driver vs stubbed
  LK; fault-injection recipes; path/env resolution with no vendor
  bins present (graceful skip with pointer to provenance doc).

### 5.6 GitHub / release steps

1. `git init` done; initial commit = this design doc only.
2. After design approval + plan: implement, test (38 green + new),
   commit in logical units on `main`.
3. `gh repo create nemethhh/crumpet-emu --private --source . --push`
   with description "Layered Unicorn emulator for the Amazon Echo Dot
   3rd-gen (crumpet/MT8167) load chain — BROM/preloader/LK hunting lab".

## 6. Binaries policy (parked, but designed-for)

- The repo never vendors vendor-proprietary blobs. `binaries/vendor/`
  is gitignored; `docs/provenance.md` lists every needed file with
  SHA256, origin, and where the operator places it.
- **Generations are namespaced** (two identically-named OTA sets exist
  in the workspace — 2021 `ota-crumpet/2021/ota_out/` and 2025 `img/`):
  vendor files land under `binaries/vendor/2021/` or `/2025/`, env
  vars follow `CRUMPET_EMU_<GEN>_<NAME>` (e.g. `CRUMPET_EMU_2025_LK`),
  and every loader takes the generation profile explicitly. Serving
  the wrong generation silently changes verdicts — the loader refuses
  when the SHA256 doesn't match the manifest for the chosen profile.
- Resolution order per binary: explicit CLI arg → env var, else
  `binaries/vendor/<GEN>/<name>` → error with provenance pointer.
- Needed **parked** set (largest 2.3 MB; per generation where noted):
  BROM dump (131,072 B, gen-neutral boot ROM), SRAM snapshot
  (2,097,152 B, boot seeds), `brhgptpl_0..3` (184,320 B each, both
  gens), 2021 `lk.img` (233,472 B), `tee1`/`tee2` (2,367,488 B,
  both gens), 2025 `lk.img` (237,056 B), **`boot.img` both gens
  (2021: 10,354,688 B; 2025 per manifest) — added at builder check;
  needed by chip fixtures and boot-image auth**, optional `pl2025`.
  `build/crumpet/lk-patched.img` (99.99% vendor bytes) → parked,
  gen-2021; the tests needing it sit in Tier 2.
- **Own-source artifacts ARE committed** under `binaries/own/` (built
  from this project's MIT-licensable sources; build instructions in
  provenance): `stage1.bin` (624 B), `payload.elf`/`payload.bin`
  (10,660 / 2,484 B), per-slot TEE variants (`tz-lka`/`tz-lkb` /
  `crumpet2021-lk{a,b}` builds), and analysis metadata
  (`key_continuity.json`, LK patch-site table). If the operator later
  rules otherwise, they move to the env-var pattern like vendor bins.

## 7. What's left to the builder

- Exact module APIs and the `core/session.py` shape (hook registries,
  call-with-timeout helper shared by all layers).
- Checkpoint serialization details (versioned dict; unicorn context
  handle reuse) and its test.
- Fastboot host-driver protocol details (verb framing: `download:`,
  `flash:`, `getvar:`; response parsing `OKAY/FAIL/DATA`).
- USB transport seam functions in LK: **IDA 9.3 + idalib are
  available in this environment** (`<IDA-INSTALL>/`) and the
  databases exist (`tools/lk-emu/lk.i64`, `tools/crumpet2019/pl202*.i64`),
  so the seam is a routine early task; fallback if IDA friction: find
  the seam dynamically (call-scan inside the dispatcher path under
  Unicorn) — sequence the task early either way.
- README polish; fuzz corpus formats; scenario CLI ergonomics.

## 8. Calls made by the assistant (invitable)

- Repo name `crumpet-emu`; package `crumpet_emu`; MIT LICENSE with
  `Oleksandr Martynenko (nemethhh)`; private-at-creation on GitHub.
- `img/lk.img` is the primary LK profile ("2025 LK"); 2021 `lk.img`
  kept as a second profile.
- Fastboot driven at function-boundary seam, not register-level USB.
- `test_build_reproducible.py` parked in `tests/attic/`.
- **C1 (builder-check Q1):** `tools/lk-emu/` absorbed as third donor,
  not excluded — it is a working harness for the exact target build;
  excluding it would greenfield-rebuild the same functionality and
  violate the anti-goal on duplicated infrastructure.
- **C2 (Q2):** closed-loop support code ported (`crumpet_emu/deploy/`)
  so the 16 workspace-dependent tests keep real semantics; option (b)
  synthesis and option (c) gutting rejected.
- **C3 (Q3):** generation-namespaced vendor tree + `CRUMPET_EMU_<GEN>_<NAME>`
  env scheme + SHA256-profile check; `boot.img` added to the parked
  set; `lk-patched.img` parked (vendor-derived); per-slot tz variants
  and analysis metadata committed under `binaries/own/`; test gate
  split Tier 1/Tier 2.
- **C4 (Q4):** entry-mode phasing — surgical v1, boot-path entry as
  milestone M2 (design already chose multiple entry points; this
  sequences them).
- **C5 (Q5):** builder has IDA 9.3 + idalib here; seam task scheduled
  early with a dynamic call-scan fallback.
