# crumpet-emu public release — design

**Date:** 2026-11-07
**Status:** approved by nemethhh (same day); builder check integrated
**Author:** session notes (brainstorming with nemethhh)

## Intent and why

`nemethhh/crumpet-emu` (currently private) becomes a public research lab.
Two jobs:

1. **Publish safely.** The tree and its git history currently carry the
   operator's local workspace paths (`WS/...`) and a
   placeholder commit identity (`am <am@local>`). The public repo must leak
   none of it.
2. **Let strangers run their own dumps.** Today `resources.resolve`
   *refuses* any vendor image whose sha256 differs from
   `binaries/manifest.json`. A researcher with their own device dump (other
   OTA version, own chip-off BROM/SRAM) cannot run anything. The gate must
   become a *label*, not a wall: drop a file in, it runs.

## Goals

- **G1 — place-and-run.** Anyone can drop any image at
  `binaries/vendor/<gen>/<file>` (or set `CRUMPET_EMU_<GEN>_<NAME>`) and run
  every scenario/CLI without editing any manifest, computing a hash, or
  registering anything.
- **G2 — pinned remains the reproducibility path.** A manifest-matching
  build runs quietly and is called out as pinned; an unpinned build runs
  with a loud, unmissable warning naming the slot and both hash prefixes.
  Nothing ever runs *silently* wrong.
- **G3 — clean public tree.** The published history is exactly one fresh
  initial commit containing zero `/home/...` paths, zero workspace-name, zero placeholder
  authorship, zero vendor blobs.
- **G4 — clear posture.** CONTRIBUTING.md (code; optional pinned-hash PRs)
  and a responsible-use note (own devices, lawful access) exist before
  flip.

## Non-goals

- No user-authored manifest UX (operator rejected hash registration).
- No multi-version manifest schema; no `--gen` selection CLI for scenarios
  (deferred until someone actually contributes a third generation).
- No CI, packaging, or PyPI.
- Kernel execution beyond the LK handoff remains out of scope (unchanged).

## Anti-goals (failure even if it works)

- **Silent wrong-generation serving.** If any code path can execute image
  bytes without either a pinned hash match or an explicit warning having
  been emitted, the design failed.
- **Traceback-first UX.** A stranger following README who lacks a file must
  get a placement message that teaches G1, not an exception dump.

## Constraints

- Vendor blobs are never committed (unchanged: `binaries/vendor/**`
  gitignored, provenance discipline intact).
- Tier 1 stays green with zero vendor bins (`python3 -m pytest`).
- Tier-2 tests assert pinned-build-exact behavior (pinned UART banners,
  patch offsets) — the battery therefore stays gated on *pinned-clean*
  availability, while scenarios accept any placed image.
- The fresh initial commit is authored as
  `Oleksandr Martynenko <30444314+nemethhh@users.noreply.github.com>`.

## Approaches considered (image acceptance)

- **A. Strict pinning + placement helper** — gate unchanged, helper CLI
  installs manifest-matching files only. Rejected: a stranger's own dump
  still refused; doesn't meet G1.
- **B. Opt-in user manifest** — second, gitignored, user-authored manifest.
  Rejected: hash-registration UX the operator explicitly declined
  ("without hashes and all"); extra layer for no extra safety over C.
- **C. Drop-in with warning (CHOSEN).** Placement is the only act. Resolve
  serves whatever is placed; pinned → quiet, unpinned → loud warning.
  `bins` CLI (status/place) ships as the guide. Community manifest PRs
  remain welcome as a *contributing policy* (G4), not a requirement.

### Publish vehicle (approaches)

- **Force-push squashed `main` to the same repo** — rejected: GitHub
  keeps old commits fetchable by SHA until GC; flipping visibility
  exposes orphans on the very platform going public.
- **Delete private repo + recreate fresh (CHOSEN, operator picked).**
  Verified nothing of value exists to lose: 0 stars/watchers/issues/PRs,
  no releases, no wiki. Local archive bundle keeps the old history.

## Decided (the operator picked; the rest are builder calls marked ✓)

1. **`resources.resolve(name, gen)`** — behavior change: a placed vendor
   file is served even when its sha256 differs from the manifest. Pinned
   match: serve quietly. Unpinned: serve + emit one warning per slot per
   process (module-level seen-set), naming slot, expected vs actual sha
   prefixes, and that verdicts are not comparable to pinned builds.
   `ShaMismatch` is no longer raised by `resolve` (class kept for API
   compat). `MissingBinary` message rewritten to teach drop-in placement.
   Warnings go to **stderr only** — never into UART/trace streams the
   differential runner compares. The differential runner never refuses
   mixed pin-state comparisons (stock-pinned vs own-build is its core
   use); annotating report headers with pin-state is the builder's call.
2. **Availability split.** `available(name, gen)` keeps pinned-clean
   semantics for Tier-2 gating (unchanged callers in tests). New
   `present(name, gen)` (✓ name is builder's to adjust) reports
   placement-only existence for scenarios/status UX.
3. **`crumpet_emu/bins.py`** — `python3 -m crumpet_emu.bins`:
   `status` (default) prints a per-slot table: slot, expected sha prefix,
   placed file, state pinned/unpinned/missing, and which scenarios unlock;
   `place FILE --as gen:name` copies the file into place and reports the
   resulting state. No hash registration; `place` never invents slots.

3b. **Slot universe stays manifest-defined.** Unknown `gen:name` stays
   refused (`resources._entry`) with a teaching message: rename your dump
   to the manifest's `file` name under `binaries/vendor/<gen>/`; new
   slots require a manifest PR. G1 frees *bytes at existing slots*, not
   the slot universe.
4. **Sanitization pass** (all tracked files):
   - `binaries/manifest.json`: 32 `source` fields → `WS/...` placeholder
     form already used by `docs/provenance.md`. After this change
     `source` is documentation-only.
   - **Test donor-discovery re-pointed** (builder check found four test
     files deriving paths from `source` — it is NOT code-only metadata):
     tests needing *vendor images* re-point to the placement system
     itself (`resources.present()` — tests exercise what users run);
     operator-local *tool-tree crosschecks* (`test_nfi_inventory.py`,
     preloader/IDA crosschecks) gate on a new env var
     `CRUMPET_EMU_WS` (absolute workspace root; unset in a fresh
     clone → clean skips with teaching reasons). Operator picked this
     over dropping the crosschecks.
   - ~21 donor-attribution header comments across `crumpet_emu/`,
     `scenarios/`, `tests/`: `WS/tools/<donor>/...`
     → `WS/tools/<donor>/...`.
   - `docs/superpowers/{plans,specs}`: local paths → placeholders; docs
     stay public (operator calls: design history is part of the lab's
     method transparency).
5. **Fresh publish vehicle (operator picked: delete + recreate).**
   Archive old history locally
   (`git bundle create ../crumpet-emu-history.bundle --all`, never
   pushed); build the sanitized tree as **one fresh initial commit** on
   `main`; delete the private GitHub repo and recreate it, then push.
   No force-push, no SHA-reachable orphans. Untracked root strays
   (`backlog-fix-impl.txt`, `backlog-fix-report.md`) are not carried
   into the fresh commit.
6. **Docs.** `binaries/README.md` placement section rewritten around
   place-and-run (pinned vs unpinned states); main `README.md` quickstart
   + Tier-2 paragraph updated to match; `docs/provenance.md` gains a line
   noting resolve no longer refuses unpinned images; new top-level
   `CONTRIBUTING.md` (dev setup, tier discipline, optional pinned-hash PRs
   with provenance) and a short responsible-use section in the README
   (own devices, lawful access; research lab, not an attack tool).
7. **Publish.** On the recreated repo: set description + topics (✓
   wording builder-proposed), push the single commit, done — the repo is
   created public. Commit order is sequential, not conceptual: sanitize
   + re-point tests → suite green → write ALL docs (README, binaries/
   README, provenance line, CONTRIBUTING.md) → then create the single
   fresh commit → delete + recreate repo → push. The published history
   is exactly one commit.

## Left to the builder

- Exact warning wording and channel (stderr via `logging` vs `print`).
- `bins` table columns, flag names, exit codes.
- Test updates: `tests/test_resources.py` mismatch-refusal cases →
  warning-and-serve cases; new `bins` tests; keep Tier-1 green no-bins.
- The fresh initial commit's message (project summary + donor
  attribution, self-contained since history is squashed).
- GitHub description/topics final wording.
