# crumpet-emu Public Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `nemethhh/crumpet-emu` public with zero personal-data leakage, and let any researcher run their own dumps by placing files — no hashes, no manifest editing.

**Architecture:** `resources.resolve` changes from refuse-on-mismatch to serve-plus-warn (stderr, once per slot per process); a new `present()` reports placement-only existence; a new `python3 -m crumpet_emu.bins` CLI gives status/placement. Test donor-discovery re-points to the placement system (or `CRUMPET_EMU_WS` for tool-tree crosschecks). The whole sanitized tree is then republished as one fresh commit to a deleted-and-recreated GitHub repo.

**Tech Stack:** Python 3 (stdlib only for the new code), pytest, `gh` CLI for repo operations.

**Spec:** `docs/superpowers/specs/2026-11-07-public-release-design.md`

## Global Constraints

- Tier 1 green with zero vendor bins: `python3 -m pytest` → 0 failures (baseline today: 64 passed / 29 skipped; rebaseline after Task 2 and record).
- Vendor blobs are never committed (`binaries/vendor/**` stays gitignored).
- At publish time the tracked tree contains **no** `/home/` or `am@local` strings (`git grep` proves it).
- Unpinned warnings go to **stderr only** — never into UART/trace streams the differential runner compares.
- Fresh commit authored AND committed as `Oleksandr Martynenko <30444314+nemethhh@users.noreply.github.com>`.
- Dev installs use a venv (`python3 -m venv venv; venv/bin/pip install -r requirements.txt`) — never system pip.
- Repo history style: conventional commit subjects (`feat(resources): …`).

## Review Focus

1. **Silent unpinned run** — a placed file whose sha differs from the manifest must print the UNPINNED stderr warning naming slot + both sha prefixes, exactly once per slot per process. → Task 1 tests.
2. **Stranger traceback** — a missing image must raise `MissingBinary` whose message teaches placement (default drop-in path + env var + provenance pointer), and an unknown slot name must refuse with a teaching message. → Task 1 tests.
3. **Warning leaking into compared streams** — the UNPINNED text must appear on stderr while stdout/UART capture stays clean. → Task 1 test.
4. **`bins place` inventing slots** — `--as gen:name` with an unknown key must exit 2 with the teaching message and create nothing. → Task 3 test.
5. **Personal strings surviving into the fresh commit** — the publish task greps the orphan tree for `/home/`, `am@local` before any `gh` command runs. → Task 6 step.

---

### Task 1: resources — place-and-run semantics

**Files:**
- Modify: `crumpet_emu/resources.py` (whole file is ~135 lines; rewrite `resolve`, add `present`, reword `_entry`/`MissingBinary` messages, add module-level `_unpinned_warned: set[str]`)
- Modify: `tests/test_resources.py` (mismatch-refusal cases → warning-and-serve; new `present` tests)

**Interfaces:**
- Consumes: existing `_manifest()`, `_candidate(name, gen, entry)`, `_sha256(path)`, `_env_var(name, gen)`, `MissingBinary`, `ShaMismatch` (kept, no longer raised by `resolve`).
- Produces: `resolve(name: str, gen: str = '2021') -> Path` (new semantics below); `present(name: str, gen: str = '2021') -> bool` (placement-only, never raises, unknown slot → False). Later tasks (2, 3) call `available` / `present` / `resolve` and read `resources._manifest()`.

- [ ] **Step 1: Write the failing tests** in `tests/test_resources.py`

Replace the existing sha-mismatch-refusal test(s) (they monkeypatch `VENDOR_DIR`, drop a wrong-hash file, and assert `pytest.raises(resources.ShaMismatch)`) with:

```python
def test_unpinned_served_with_stderr_warning(tmp_path, monkeypatch, capsys):
    vendor = tmp_path / 'vendor'
    (vendor / 'common').mkdir(parents=True)
    rogue = vendor / 'common' / 'brom_MT8167_MT8516_MT8362_8167.bin'
    rogue.write_bytes(b'not-a-brom')          # wrong size AND hash
    monkeypatch.setattr(resources, 'VENDOR_DIR', vendor)
    monkeypatch.delenv('CRUMPET_EMU_COMMON_BROM', raising=False)

    out = resources.resolve('brom', 'common')   # must NOT raise

    assert out == rogue
    err = capsys.readouterr().err
    assert '[crumpet-emu] UNPINNED common:brom' in err
    assert 'binaries/README.md' in err
    assert 'not-a-brom' not in capsys.readouterr().out  # stdout clean

def test_unpinned_warning_once_per_slot(tmp_path, monkeypatch, capsys):
    ... same setup, resolve twice ...
    first = capsys.readouterr().err
    resources.resolve('brom', 'common')
    assert capsys.readouterr().err == ''          # second call: silent
    resources._unpinned_warned.clear()            # don't leak into other tests

def test_present_placement_only(tmp_path, monkeypatch):
    monkeypatch.setattr(resources, 'VENDOR_DIR', tmp_path)
    assert resources.present('brom', 'common') is False
    slot = tmp_path / 'common'; slot.mkdir()
    (slot / 'brom_MT8167_MT8516_MT8362_8167.bin').write_bytes(b'x')
    assert resources.present('brom', 'common') is True   # unpinned still present
    assert resources.present('nope', 'common') is False  # unknown slot: False, never raises

def test_unknown_slot_teaches(tmp_path, monkeypatch):
    monkeypatch.setattr(resources, 'VENDOR_DIR', tmp_path)
    with pytest.raises(resources.MissingBinary) as exc:
        resources.resolve('lk', '2030')
    assert 'no manifest slot' in str(exc.value)
    assert 'manifest PR' in str(exc.value)
```

Also add to the existing `test_missing_binary_pointer`: assert the message contains the env var name `CRUMPET_EMU_2025_PL` and the default path text `binaries/vendor/2025/pl2025.bin`.

- [ ] **Step 2: Run to verify failure**

Run: `venv/bin/python -m pytest tests/test_resources.py -x -q`
Expected: FAIL (resolve raises `ShaMismatch`; `present`/`_unpinned_warned` don't exist).

- [ ] **Step 3: Implement in `crumpet_emu/resources.py`**

```python
_unpinned_warned: set[str] = set()

def _warn_unpinned(key: str, path: Path, expected: str | None, actual: str) -> None:
    if key in _unpinned_warned:
        return
    _unpinned_warned.add(key)
    print(f"[crumpet-emu] UNPINNED {key} at {path}: sha256 {actual[:16]}… "
          f"!= manifest {(expected or '?')[:16]}… — running your bytes; "
          f"verdicts not comparable to pinned builds (binaries/README.md)",
          file=sys.stderr)
```

`resolve` body: after the `is_file()` check, for non-own entries compute sha; on mismatch call `_warn_unpinned(f'{gen}:{name}', path, entry.get('sha256'), actual)`; return path in all cases. Delete the `raise ShaMismatch(...)` block (keep the class + its docstring, reworded "kept for API compat; resolve no longer refuses"). `present`: manifest lookup → `_candidate(...).is_file()` (own entries included; unknown key → False). `MissingBinary` message (absent file) becomes:
`f'{gen}:{name}: not placed — drop your image at {path} or set {_env_var(name, gen)}; any dump runs once placed (unpinned images get a warning) — {PROVENANCE_POINTER}'`.
`_entry` unknown-key message becomes:
`f'{key}: no manifest slot — place your dump under the manifest\'s file name in binaries/vendor/<gen>/; new slots require a manifest PR — {PROVENANCE_POINTER}'`.
Add `import sys` to the imports. Update the module docstring's gate paragraph to place-and-run semantics.

- [ ] **Step 4: Run to verify pass**

Run: `venv/bin/python -m pytest tests/test_resources.py -q`
Expected: PASS, 0 failures. Then `venv/bin/python -m pytest -q` — 0 failures (some previously-passing source-path tests still pass; Task 2 changes their gating).

- [ ] **Step 5: Commit**

```bash
git add crumpet_emu/resources.py tests/test_resources.py
git commit -m "feat(resources): place-and-run — serve unpinned images with a loud once-per-slot stderr warning"
```

---

### Task 2: tests — re-point donor discovery off manifest `source`

**Files:**
- Modify: `tests/test_resources.py:22-31` (module constants block), plus `PL`-constant uses inside `tests/test_preloader_ports.py:28-33`, `tests/test_nand_model.py:27-40`, `tests/test_nfi_inventory.py:30-45`

**Interfaces:**
- Consumes: Task 1's `resolve`/`present`, existing `available`.

- [ ] **Step 1: Rewrite the gating blocks**

`tests/test_resources.py` — delete `BROM`/`LK_2021`/`LK_2025` module constants and the source-based `needs_brom`/`needs_lk`; replace with:

```python
needs_brom = pytest.mark.skipif(
    not resources.available('brom', 'common'),
    reason='pinned common:brom not placed — binaries/vendor/ or env var')
needs_lk = pytest.mark.skipif(
    not (resources.available('lk', '2021') and resources.available('lk', '2025')),
    reason='pinned 2021/2025 lk not placed')
```

Inside test bodies, replace each donor-bytes use (`shutil.copy(BROM, …)` etc.) with the lazy call `resources.resolve('brom', 'common')` / `resources.resolve('lk', '2021')` / `resources.resolve('lk', '2025')` (never at import time). Keep the workspace-agnostic monkeypatch tests unchanged.

`tests/test_preloader_ports.py` — delete the `PL_2021` source constant; gate `needs_pl` on `resources.available('brhgptpl_0', '2021')`; in bodies replace `PL_2021` with `resources.resolve('brhgptpl_0', '2021')`.

`tests/test_nand_model.py` — delete `DONOR_DIR`/`DONORS` source derivation; gate `needs_donors` on `all(resources.available(n, '2021') for n in ('brhgptpl_0','brhgptpl_1','brhgptpl_2','brhgptpl_3','lk','tee1','tee2','boot'))`; bodies resolve per name (`resources.resolve(name, '2021')`).

`tests/test_nfi_inventory.py` — replace the `KAMAKIRI`/`WS` manifest-source derivation with:

```python
WS = Path(os.environ['CRUMPET_EMU_WS']) if os.environ.get('CRUMPET_EMU_WS') else None
KAMAKIRI = WS / 'tools' / 'kamakiri' if WS else None
needs_ws = pytest.mark.skipif(
    WS is None, reason='set CRUMPET_EMU_WS=<donor workspace root> for tool-tree crosschecks')
```

Keep the venv-python paths derived from `WS` as today; apply `needs_ws` (combined with existing guards) to the crosscheck tests.

- [ ] **Step 2: Run to verify**

Run: `venv/bin/python -m pytest tests/test_resources.py tests/test_preloader_ports.py tests/test_nand_model.py tests/test_nfi_inventory.py -q`
Expected: 0 failures; workspace-agnostic tests pass; donor/crosscheck tests skip or pass per this machine's placement state. Then `venv/bin/python -m pytest -q` — record the new no-bins baseline (0 failures required).

- [ ] **Step 3: Commit**

```bash
git add tests/test_resources.py tests/test_preloader_ports.py tests/test_nand_model.py tests/test_nfi_inventory.py
git commit -m "test: donor discovery via placement system + CRUMPET_EMU_WS, not manifest source paths"
```

---

### Task 3: bins CLI — status + place

**Files:**
- Create: `crumpet_emu/bins.py`
- Test: `tests/test_bins.py`

**Interfaces:**
- Consumes: `resources._manifest()`, `resources.present(name, gen)`, `resources.available(name, gen)`, `resources.VENDOR_DIR`, `resources._env_var(name, gen)`, `resources.PROVENANCE_POINTER`.
- Produces: `slot_rows() -> list[dict]` (keys: `key, gen, name, file, expected, path, state`; state ∈ `own|pinned|unpinned|missing`, manifest order); `main(argv: list[str] | None = None) -> int`. CLI: `python3 -m crumpet_emu.bins` (= `status`), `python3 -m crumpet_emu.bins place FILE --as gen:name`.

- [ ] **Step 1: Write the failing tests** in `tests/test_bins.py`

```python
def test_status_states(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(resources, 'VENDOR_DIR', tmp_path)
    slot = tmp_path / 'common'; slot.mkdir()
    (slot / 'brom_MT8167_MT8516_MT8362_8167.bin').write_bytes(b'x')  # unpinned
    from crumpet_emu.bins import main
    assert main(['status']) == 0
    out = capsys.readouterr().out
    assert 'unpinned' in out and 'missing' in out and 'own' in out
    assert 'common:brom' in out

def test_place_pinned_and_unknown_slot(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(resources, 'VENDOR_DIR', tmp_path)
    donor = tmp_path / 'd.bin'; donor.write_bytes(b'x')
    from crumpet_emu.bins import main
    assert main(['place', str(donor), '--as', 'common:brom']) == 0       # unpinned warn-free note
    assert (tmp_path / 'common' / 'brom_MT8167_MT8516_MT8362_8167.bin').is_file()
    capsys.readouterr()
    assert main(['place', str(donor), '--as', '2030:lk']) == 2           # unknown slot
    err = capsys.readouterr().err
    assert 'no manifest slot' in err
    assert not (tmp_path / '2030').exists()                              # invented nothing
```

- [ ] **Step 2: Run to verify failure**

Run: `venv/bin/python -m pytest tests/test_bins.py -q`
Expected: FAIL (`crumpet_emu.bins` doesn't exist).

- [ ] **Step 3: Implement `crumpet_emu/bins.py`**

Module docstring mirrors the design: "placement status + installer; no hash registration". `slot_rows()` iterates `resources._manifest().items()` in file order, computing state via `present`/`available` (own → `'own'`). `main`: argparse with `status` (default) and `place`; `place` validates `--as` against the manifest (unknown → print the `no manifest slot` teaching line to stderr, return 2; source file must exist, else return 1), `mkdir(parents=True)` the gen dir under `VENDOR_DIR`, `shutil.copyfile` to `entry['file']`, then print resulting state: `pinned ✓` / `unpinned ⚠ (sha256 <16-hex>… — scenarios run it; pytest tier-2 wants the pinned build)` / and the env-var alternative line `or set CRUMPET_EMU_<GEN>_<NAME>=<path>`. `status` prints a aligned table: `slot | state | expected-sha16 | placed file (basename)` plus a footer hinting `python3 scenarios/…` CLIs unlock per gen (`common`→`boot_brom`, `2021`→`preloader_chain/boot_brom/differential`, `2025`→`lk_unlock/lk_fastboot`) and the `binaries/README.md` pointer. `if __name__ == '__main__': raise SystemExit(main())`.

- [ ] **Step 4: Run to verify pass**

Run: `venv/bin/python -m pytest tests/test_bins.py -q` then `venv/bin/python -m crumpet_emu.bins` (smoke: table renders on this machine).
Expected: PASS; table renders.

- [ ] **Step 5: Commit**

```bash
git add crumpet_emu/bins.py tests/test_bins.py
git commit -m "feat(bins): placement status + place CLI — drop-in images with no hash registration"
```

---

### Task 4: sanitize every personal path out of the tree

**Files:**
- Modify: every tracked file still containing `/home/` — exactly the list from `git grep -l '/home/'`: `binaries/manifest.json` (32 `source` fields), 21 package/scenario files' donor header comments, 14 test files' header comments (incl. `tests/attic/`, `tests/conftest.py`), `tools/derive_lk_patches.py`, `tools/verify_lk_patches.py`, `docs/superpowers/plans/2026-10-31-crumpet-emu.md`, `docs/superpowers/specs/2026-10-31-crumpet-emu-design.md`, `docs/superpowers/specs/2026-11-07-public-release-design.md`.

**Interfaces:**
- Consumes: nothing from Tasks 1–3 except that their new/edited files are already clean.
- Produces: tree with zero `/home/`, `am@local` strings.

- [ ] **Step 1: Apply substitutions**

```bash
git grep -l 'WS' | xargs sed -i 's|WS|WS|g'
git grep -l '<IDA-INSTALL>' | xargs sed -i 's|<IDA-INSTALL>|<IDA-INSTALL>|g'
git grep -l '<REPO-ROOT>' | xargs sed -i 's|<REPO-ROOT>|<REPO-ROOT>|g'
```

(The new spec's `CRUMPET_EMU_WS` example line becomes `CRUMPET_EMU_WS=<your-workspace-root>` — reword that one line by hand so it reads as an instruction, not a residue.)

- [ ] **Step 2: Verify zero residue**

Run: `git grep -n '/home/\|~/\|am@local' -- .`
Expected: empty output.

- [ ] **Step 3: Suite still green**

Run: `venv/bin/python -m pytest -q`
Expected: 0 failures (substitutions touch comments/manifest metadata only — `source` is documentation-only since Task 2).

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "chore: sanitize local workspace paths to WS/ placeholders for public release"
```

---

### Task 5: docs — README, binaries/README, provenance, CONTRIBUTING

**Files:**
- Modify: `README.md` (quickstart + Tier-2 paragraph + new responsible-use section), `binaries/README.md` (placement section rewrite), `docs/provenance.md` (one paragraph)
- Create: `CONTRIBUTING.md`

**Interfaces:**
- Consumes: Task 3's CLI name (`python3 -m crumpet_emu.bins`), Task 1's warning behavior, Task 2's `CRUMPET_EMU_WS`.

- [ ] **Step 1: `binaries/README.md`** — rewrite the resolution section: two states now (pinned = sha matches manifest → runs quietly, reproducible; unpinned = any other dump at the slot → runs with an UNPINNED stderr warning). Document `python3 -m crumpet_emu.bins status` / `place FILE --as gen:name`, keep the env-var order (env wins), keep the placement table as-is. Add a short "Donor tool-tree crosschecks" note: `CRUMPET_EMU_WS=<workspace root>` enables operator-local pytest crosschecks; unset in fresh clones → clean skips.

- [ ] **Step 2: `README.md`** — quickstart becomes venv-first:

```bash
python3 -m venv venv && venv/bin/pip install -r requirements.txt
venv/bin/python -m pytest                 # Tier 1: green with ZERO vendor bins
venv/bin/python -m crumpet_emu.bins       # what's placed, what's missing
venv/bin/python -m crumpet_emu.bins place /path/to/your/lk.img --as 2025:lk
```

Tier-2 paragraph: "Tier 2 (pinned builds): the assertion battery gates on manifest-pinned images (present **and** sha-clean) because it pins exact vendor behavior. Your own dumps run everywhere else — every scenario CLI accepts any placed image (unpinned images print a warning; verdicts are yours)." Add a short **Responsible use** section: research lab for boot-chain vulnerability study; dump and emulate only devices you own / have lawful access to; vendor images stay Amazon/MTK property and are never distributed here.

- [ ] **Step 3: `docs/provenance.md`** — add under "Parked vendor set": manifest `source` fields are `WS/…` placeholders (documentation only); since the place-and-run change, `resources.resolve` serves any placed image at a manifest slot — pinned quietly, unpinned with a warning (see `binaries/README.md`).

- [ ] **Step 4: `CONTRIBUTING.md`** — sections: dev setup (venv, `python3 -m pytest`, tier discipline: Tier 1 green no-bins is the CI promise), "Running your own dumps" (point at `bins place` + binaries/README), "Adding pinned builds" (PR a manifest entry: generation, OTA/chip provenance, extraction steps, sha256, size — the provenance discipline), code style (match donor-citation header convention, `WS/…` upstream pointers).

- [ ] **Step 5: Verify docs build no broken promises**

Run: `venv/bin/python -m crumpet_emu.bins >/dev/null && venv/bin/python -m pytest -q`
Expected: both succeed; 0 failures.

- [ ] **Step 6: Commit**

```bash
git add README.md binaries/README.md docs/provenance.md CONTRIBUTING.md
git commit -m "docs: place-and-run story, responsible use, contributing guide"
```

---

### Task 6: fresh history + delete/recreate publish

**Files:**
- Modify: git history (one orphan commit replaces `main`); GitHub repo `nemethhh/crumpet-emu` (deleted + recreated public).

**Interfaces:**
- Consumes: fully green tree from Tasks 1–5.

- [ ] **Step 0: Preconditions**

Run: `gh auth status` (must be authenticated as `nemethhh`; if `delete_repo` scope is missing, `gh auth refresh -h github.com -s delete_repo`). Confirm `gh api repos/nemethhh/crumpet-emu --jq '.stargazers_count + .open_issues_count'` → 0 (nothing to lose).

- [ ] **Step 1: Move strays out of the tree**

```bash
mv backlog-fix-impl.txt backlog-fix-report.md ../
```

- [ ] **Step 2: Final leak grep on the tracked tree**

Run: `git grep -n '/home/\|~/\|am@local' -- .`
Expected: empty. If not empty: STOP, fix, re-run Task 4's verification.

- [ ] **Step 3: Full suite + record numbers**

Run: `venv/bin/python -m pytest -q` → 0 failures; record pass/skip counts for the commit message trailer.

- [ ] **Step 4: Archive old history locally (never pushed)**

```bash
git bundle create ../crumpet-emu-history-pre-public.bundle --all
```

- [ ] **Step 5: Build the single fresh commit**

```bash
git checkout --orphan release-main
git add -A
GIT_COMMITTER_NAME='Oleksandr Martynenko' GIT_COMMITTER_EMAIL='30444314+nemethhh@users.noreply.github.com' \
git commit --author='Oleksandr Martynenko <30444314+nemethhh@users.noreply.github.com>' \
  -m "crumpet-emu: layered Unicorn emulator for the Echo Dot 3 (MT8167) boot chain

BROM → preloader → LK hunting lab: real vendor code executes under
Unicorn with libc/MMIO stubs cited from donor evidence; checkpoints,
fault injection, differential runner, crash-tolerant fuzzing. Vendor
images are never committed — drop your own dumps into binaries/vendor/
(pinned builds unlock the reproducible test battery; anything placed
runs, unpinned with a warning). Donors: kamakiri + amonet-koboreru
(R0rt1z2), MIT; see docs/provenance.md. Tier 1 green with zero bins."
git branch -D main && git branch -m main
```

- [ ] **Step 6: Delete + recreate the GitHub repo public**

```bash
git remote remove origin
gh repo delete nemethhh/crumpet-emu --yes
gh repo create nemethhh/crumpet-emu --public --source . --remote origin --push \
  --description "Layered Unicorn emulator for the Amazon Echo Dot 3rd gen (crumpet/MT8167) boot chain — BROM → preloader → LK research lab"
gh repo edit nemethhh/crumpet-emu --add-topic firmware-research --add-topic unicorn-emulator \
  --add-topic mediatek --add-topic bootrom --add-topic reverse-engineering \
  --add-topic fastboot --add-topic security-research --add-topic echo-dot
```

- [ ] **Step 7: Verify the stranger experience end-to-end**

```bash
cd "$(mktemp -d)" && gh repo clone nemethhh/crumpet-emu && cd crumpet-emu
python3 -m venv venv && venv/bin/pip install -r requirements.txt
venv/bin/python -m pytest -q            # 0 failures
venv/bin/python -m crumpet_emu.bins     # table renders, all vendor slots missing
grep -rn '/home/\|~/\|am@local' --exclude-dir=.git .   # empty
gh repo view nemethhh/crumpet-emu --json visibility,url   # {"visibility":"PUBLIC",…}
```

Expected: all four checks pass. Report the clone URL, suite counts, and bundle path to the operator.
