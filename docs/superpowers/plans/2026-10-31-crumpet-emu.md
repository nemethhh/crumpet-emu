# crumpet-emu Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `crumpet_emu`, a layered Unicorn emulator for the crumpet/MT8167 load chain (BROM → preloader → LK → kernel-handoff), as a standalone private GitHub repo, with the 38 donor tests ported green plus new hunting instrumentation.

**Architecture:** One importable package with a shared core (session/devices/checkpoints), a unified flash layer (NAND/NFI + image-backed views + GPT), boot layers (brom, preloader, lk, deploy) ported from three donor harnesses, and a cross-cutting hunting module (injection, differential, fuzzing, coverage). Thin CLI scripts in `scenarios/` expose entry points.

**Tech Stack:** Python 3.14, unicorn 2.1.x, capstone ≥5, pytest.

**Spec:** `docs/superpowers/specs/2026-10-31-crumpet-emu-design.md` (§5.3 constants/addresses are verbatim-copied into the package by Tasks 7 and 10; the spec travels with this plan — executors read both).

**Donors (read-only, never modified):**
- `WS` = `WS`
- `WS/tools/kamakiri/emu/` (package `emu`), `WS/tools/kamakiri/modules/{functions_crumpet,main_crumpet}.py`, `WS/tools/kamakiri/ida/verify_lk_patches.py`
- `WS/tools/amonet-emu/emu_chain.py`
- `WS/tools/lk-emu/{lk_emu.py,battery.py,ida_seeds.json,mkelf_lk.py}`

## Global Constraints

- Repo root `<REPO-ROOT>`; package dir `crumpet_emu/` at repo root.
- `requirements.txt`: `unicorn>=2.1,<3`, `capstone>=5`, `pytest>=8`. No other runtime deps.
- Vendor binaries are **never committed**: `binaries/vendor/{common,2021,2025}/` are gitignored (Task 1's `.gitignore`).
- Binary resolution: explicit arg → env var `CRUMPET_EMU_<GEN>_<NAME>` → `binaries/vendor/<gen>/<file>` → `MissingBinary` error with provenance pointer. SHA256 checked against `binaries/manifest.json`; present-but-mismatched raises `ShaMismatch`.
- Committed own artifacts live in `binaries/own/` (Task 8 inventory; build instructions in `docs/provenance.md`).
- All addresses/constants in spec §5.3 are copied **verbatim** from donors — no "cleaning up" values.
- Donor file ports get a 3-line header comment: donor path, upstream (`R0rt1z2/kamakiri`, `R0rt1z2/amonet-koboreru`), copy date.
- No import-time file reads; no absolute workspace paths anywhere in `crumpet_emu/` (donor bug class, spec anti-goal).
- Test gate: donor suite minus `test_build_reproducible.py` = **38 tests** ported, green (Tier 1 + Tier 2 as available). Tier 2 tests `pytest.skip` (never FAIL) when parked bins are absent.
- Git identity already configured; commits on `main` after every task.

## Import Map (applies to every ported test)

| donor import | new import |
|---|---|
| `emu.gpt` | `crumpet_emu.flash.gpt` |
| `emu.nand_model` | `crumpet_emu.flash.nand` |
| `emu.nfi_model` | `crumpet_emu.flash.nfi` |
| `emu.harness` | `crumpet_emu.brom.harness` |
| `emu.brom_boot` | `crumpet_emu.brom.boot` |
| `emu.transport` | `crumpet_emu.usb.transport` |
| `emu.usb_model` | `crumpet_emu.usb.model` |
| `modules.functions_crumpet` | `crumpet_emu.deploy.functions` |
| `modules.main_crumpet` | `crumpet_emu.deploy.main` |
| `REPO/'brom-payload'/...` products | `binaries/own/...` (hash-pinned; no `make` rebuild) |
| `AK/'build'/...` products | `binaries/own/...` |
| workspace donor images | `crumpet_emu.resources.resolve(...)` |

## Review Focus

1. **Wrong-generation image served silently** (2021 vs 2025 same-named files): every loader must refuse on manifest SHA mismatch — pinned by Task 3's `test_wrong_generation_refused`.
2. **Missing vendor binary**: error at call time with provenance pointer, never at import and never a bare `FileNotFoundError` — pinned by Task 3's `test_missing_binary_pointer` and Task 7's lazy-ROM test.
3. **Fuzz case crash** (UcError / invalid mem): loop must record the case and continue, not abort the run — pinned by Task 15's `test_fuzz_survives_crash`.
4. **Checkpoint mid-USB-transaction**: restore must reproduce observable state including the transport queue, not just RAM — pinned by Task 2's `test_restore_preserves_transport_state`.
5. **Tier 2 test without bins**: must `pytest.skip` with the provenance pointer, never FAIL — pinned by Task 9's `test_tier2_skips_cleanly` and re-checked in Task 17's gate.

---

### Task 1: Repo scaffold + core session/devices

**Files:**
- Create: `README.md` (stub: one paragraph, "docs coming in Task 16"), `LICENSE` (MIT, `Copyright (c) 2026 Oleksandr Martynenko (nemethhh)`), `requirements.txt`, `.gitignore` (`__pycache__/`, `*.pyc`, `.pytest_cache/`, `binaries/vendor/`), `crumpet_emu/__init__.py` (`__version__ = '0.1.0'`)
- Create: `crumpet_emu/core/__init__.py`, `crumpet_emu/core/session.py`, `crumpet_emu/core/devices.py`
- Test: `tests/test_core_session.py`

**Interfaces:**
- Produces: `Session`, `MAGIC_RET = 0x0011F000`, device stubs — consumed by every later task.
  - `class Session`: `__init__(self)` → `Uc(UC_ARCH_ARM, UC_MODE_THUMB)`; `map(addr: int, size: int) -> None`; `write(addr: int, data: bytes) -> None`; `read(addr: int, n: int) -> bytes`; `rd32(addr: int) -> int`; `hook_code(fn)`, `hook_mem_invalid(fn)` (pass-through to Uc); `call(addr: int, args: list[int], *, timeout: int = 10_000_000) -> int` (sets r0–r3 from args, SP = top of `self.stack`, LR = `MAGIC_RET`, returns r0 after stop); `self.trace: list[str]`; `self.stop_reason: str` (`'magic_ret'|'timeout'|'invalid'|'insn'`).
  - `class UartSink`: `install(uc)` hooks MMIO at `UART_THR=0x11005000`, `UART_LSR=0x11005014` (LSR reads return `0x20`); accumulates `self.lines: list[str]` and `self.text`.
  - `class TimerStub`: word at `TIMER_REG=0x10008048`, +1 per read.
  - `class EfuseStub(sbc: bool)`: word at `EFUSE_SBC=0x10009060`, bit 1 set iff `sbc`.
  - `arm_devices(session, *, uart=True, timer=True, efuse=None) -> list` — installs stubs, returns them.

- [ ] **Step 1: Write failing tests** — `tests/test_core_session.py`: map 4 KiB code+stack pages; emit Thumb `adds r0, r0, r1; bx lr` bytes at code addr; `assert session.call(code, [2, 3]) == 5`; write `b'hi'` to UART_THR → `assert 'hi' in sink.text`; `EfuseStub(sbc=True)` → `assert session.rd32(EFUSE_SBC) & 0b10`.
- [ ] **Step 2:** `python3 -m pytest tests/test_core_session.py -v` → FAIL (ModuleNotFoundError).
- [ ] **Step 3: Implement** session + devices per signatures; `call()` catches `UcError` and sets `stop_reason`.
- [ ] **Step 4:** same command → PASS (3 tests).
- [ ] **Step 5:** `git add -A && git commit -m "core: Session + device stubs (UART/timer/eFuse)"`

### Task 2: core/checkpoints

**Files:**
- Create: `crumpet_emu/core/checkpoints.py`
- Test: `tests/test_checkpoints.py`

**Interfaces:**
- Consumes: `Session` (Task 1).
- Produces: `save(session, path: Path, extra: dict[str, bytes] | None = None) -> Path`; `restore(path: Path) -> tuple[Session, dict[str, bytes]]` — versioned dict `{'v': 1, 'regions': [[addr, bytes], ...], 'context': blob, 'extra': {...}}` pickle; uses `uc.context_save()/context_write()`; restores mapped regions + all regs.

- [ ] **Step 1: Failing test** `test_roundtrip_identity`: run add-function, write sentinel to RAM, save, write different sentinel, restore → `rd32` equals first sentinel; `test_restore_preserves_transport_state`: `extra={'usb_rx': b'\x1\x2'}` round-trips.
- [ ] **Step 2:** run → FAIL (not implemented).
- [ ] **Step 3:** implement.
- [ ] **Step 4:** run → PASS (2 tests).
- [ ] **Step 5:** commit `"core: checkpoint save/restore"`.

### Task 3: resources + binaries manifest

**Files:**
- Create: `crumpet_emu/resources.py`, `binaries/manifest.json`, `binaries/README.md`, `binaries/own/.gitkeep`, `binaries/vendor/common/`, `binaries/vendor/2021/`, `binaries/vendor/2025/` (dirs with .gitkeep; vendor gitignored)
- Test: `tests/test_resources.py`

**Interfaces:**
- Produces: `class MissingBinary(RuntimeError)` (message includes provenance pointer text `see binaries/README.md + docs/provenance.md`), `class ShaMismatch(RuntimeError)`; `resolve(name: str, gen: str = '2021') -> Path` (checked as above; manifest lookup key `f'{gen}:{name}'`); `own(name: str) -> Path` (under `binaries/own/`, committed, no sha gate at resolve time — manifest lists them as `gen: 'own'` for documentation).
- `binaries/manifest.json` entries (built now by reading workspace files read-only; `sha256`+`size`+`source` fields): `common:brom` → `WS/no-alexa/brom_MT8167_MT8516_MT8362_8167.bin` (131072 B); `common:sram` → `WS/no-alexa/sram_MT8167_MT8516_MT8362_8167.bin` (2097152 B); `2021:brhgptpl_0..3` → `WS/ota-crumpet/2021/ota_out/` (184320 B each); `2021:lk` (233472 B), `2021:tee1`, `2021:tee2` (2367488 B), `2021:boot` (10354688 B), `2021:lk-patched` → `WS/tools/kamakiri/build/crumpet/lk-patched.img`; `2025:brhgptpl_0..3`, `2025:lk` (WS/img/lk.img, 237056 B), `2025:tee1`, `2025:tee2`, `2025:boot`, `2025:pl` → `WS/tools/crumpet2019/pl2025.bin`; `own:*` for the Task 8 artifact inventory. Vendor filenames on disk: manifest stores a `file` field mapping each key → e.g. `lk.img`.
- env var name derivation: `CRUMPET_EMU_` + gen.upper() + `_` + name.upper() (e.g. `CRUMPET_EMU_2025_LK`).

- [ ] **Step 1: Failing tests**: `test_env_override_wins` (monkeypatch env to a temp copy of a workspace file); `test_missing_binary_pointer` (resolve of absent `2025:pl` raises `MissingBinary`, message contains `provenance`); `test_wrong_generation_refused` (place the 2021 lk.img bytes at the `2025:lk` path → `ShaMismatch`); `test_own_resolves` (own/key_continuity.json after Task 8; until then use a temp file via `monkeypatch` on `OWN_DIR` — keep test independent of Task 8).
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3:** implement `resolve`/`own` + write manifest (script the manifest generation inline in the task — a one-off `python3 - <<EOF` computing sha256s from workspace paths listed above is fine; commit the JSON).
- [ ] **Step 4:** run → PASS (4 tests).
- [ ] **Step 5:** commit `"resources: env-resolved binary paths + generation manifest"`.

### Task 4: flash ports — gpt, nand, nfi

**Files:**
- Create: `crumpet_emu/flash/__init__.py`, `crumpet_emu/flash/gpt.py`, `crumpet_emu/flash/nand.py`, `crumpet_emu/flash/nfi.py`, `crumpet_emu/flash/nfi_regs.json` (copy of `WS/tools/kamakiri/emu/nfi_regs.json`)
- Test: `tests/test_flash_ports.py`

**Interfaces:**
- Produces (verbatim donor APIs, module rename only): `parse_gpt_from_image(brhgptpl0_bytes: bytes) -> dict[str, tuple[int, int]]`; `class PageNotErased(Exception)`; `class NandChip` (incl. `.dump()` / restore); `class NfiModelError(RuntimeError)`; `class NfiModel` (loads `nfi_regs.json` via `importlib.resources` / `Path(__file__).parent` — no workspace path).
- Porting rule: verbatim copy, swap `from emu.X import` → intra-package `from crumpet_emu.flash.X import`, add donor header comment.

- [ ] **Step 1: Port tests** — copy `WS/tools/kamakiri/emu/tests/test_nand_model.py` and `test_nfi_inventory.py` into `tests/`, apply the Import Map, expected: FAIL on imports.
- [ ] **Step 2:** port the three modules.
- [ ] **Step 3:** `python3 -m pytest tests/test_nand_model.py tests/test_nfi_inventory.py -v` → PASS (unchanged test bodies).
- [ ] **Step 4:** commit `"flash: port gpt/nand/nfi from kamakiri emu"`.

### Task 5: flash — image-backed Flash + ChipDumpFlash

**Files:**
- Create: `crumpet_emu/flash/image.py`
- Test: `tests/test_flash_image.py`

**Interfaces:**
- Consumes: `parse_gpt_from_image` (Task 4).
- Produces (extracted from `WS/tools/amonet-emu/emu_chain.py` `class Flash` and `class ChipDumpFlash`, verbatim semantics): `class Flash` — `__init__(self, tee1_bytes: bytes, lk_bytes: bytes, tee2_bytes: bytes)`; serves `bdev->read(blk, count, dst_addr, uc)`-style `(blk, count) -> bytes` slices per the donor's `GPT = {'tee1': (3584*8, 1280*8), 'lk_a': (256*8, 384*8), 'tee2': (8768*8, 1280*8), 'lk_b': (640*8, 384*8)}` map (copy the donor dict verbatim); `class ChipDumpFlash` — `__init__(self, pages: dict[int, bytes])` (4096-B pages; LBA == page); both expose `read(blk: int, count: int) -> bytes` and `install(session)` hooking the donor's BDEV shim (`TRAMP=0x120000` vector) exactly as `emu_chain.py`'s `arm_device` does. Extraction must keep the donor's address constants (`BDEV=0x1086EC`, `BDEV_READ=0x10870C`, `TRAMP`, `STACK=0x12F000`) — they land here if donor code couples them to Flash, else they belong to Task 10's `preloader/emu.py`; decider: keep each constant in exactly one module, referenced by the other.

- [ ] **Step 1: Failing test** `test_flash_lk_a_slice`: `Flash(tee1, lk, tee2).read(256*8, 384*8)` == `lk` bytes prefix (len `384*8*512` = 1,572,864 clipped to `len(lk)` — assert against `lk[:n]` exactly as donor code computes it; read the donor first and pin its actual clipping behavior in the assert); `test_chipdump_page_reads`: `ChipDumpFlash({5: bytes(4096)}).read(5, 8)` returns page 5 bytes.
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3:** implement by extraction.
- [ ] **Step 4:** run → PASS (2 tests).
- [ ] **Step 5:** commit `"flash: image-backed Flash + ChipDumpFlash (from amonet-emu)"`.

### Task 6: usb — UsbMac/CdcDevice port

**Files:**
- Create: `crumpet_emu/usb/__init__.py`, `crumpet_emu/usb/model.py`
- Test: `tests/test_usb_model.py`

**Interfaces:**
- Produces (verbatim from `WS/tools/kamakiri/emu/usb_model.py`): `class UsbMac`, `class CdcDevice`.
- Porting rule: Task 4's verbatim-copy rule.

- [ ] **Step 1:** copy donor `usb_model.py` with Import Map swap (it imports nothing from `emu` — verify with grep before copying).
- [ ] **Step 2:** new smoke test `test_usb_model.py::test_cdc_enumeration` — instantiate `UsbMac`+`CdcDevice`, drive one enumeration cycle per the donor's own docstring/comments, assert the descriptor bytes the donor docs (read donor lines around class definitions; pin the first descriptor byte the donor asserts in its own usage, e.g. `0x12` device-descriptor length — verify in donor source, adjust test to the value the donor code produces).
- [ ] **Step 3:** run → PASS.
- [ ] **Step 4:** commit `"usb: port UsbMac/CdcDevice"`.

### Task 7: brom — boot, harness, transport ports

**Files:**
- Create: `crumpet_emu/brom/__init__.py`, `crumpet_emu/brom/boot.py` (from `emu/brom_boot.py`), `crumpet_emu/brom/harness.py` (from `emu/harness.py`), `crumpet_emu/usb/transport.py` (from `emu/transport.py`)
- Test: (donor brom tests arrive in Task 9; here only a lazy-load regression test) `tests/test_brom_lazy.py`

**Interfaces:**
- Consumes: `resources.resolve` (Task 3), `own` (Task 3), flash/nand/nfi (Tasks 4–5), usb.model (Task 6).
- Produces (verbatim APIs): `last_trace() -> list[str]`; `class BootReplay` (donor `_BootReplay`, public alias `_BootReplay = BootReplay` kept); `classify(snapshot: dict[int, bytes], final: bool = False) -> str`; `_donor_windows()` via `resolve('brhgptpl_0'..'brhgptpl_3', '2021')`; `class Watchdog`, `class BromHarness`, `class Stage2Error(RuntimeError)`, `class Stage2Session`; `class TransportError(RuntimeError)`, `class ModeledReboot(RuntimeError)`, `class FakeTransport`, `class ModeledSession`.
- **Path fixes (spec anti-goal):** donor `brom_boot.py:68` module-level `ROM = (WS/'no-alexa'/...).read_bytes()` becomes `load_rom() -> bytes` = `resolve('brom', 'common').read_bytes()`; every former `ROM` user calls `load_rom()`. Donor `harness.py` `DEFAULT_ROM` → lazy `default_rom()` = `resolve('brom', 'common')`; `DEFAULT_STAGE1` → `default_stage1()` = `own('stage1.bin')`.
- **Module-global refactor (decided here):** `brom_boot.classify()`'s module-global `_trace`/verdict cache moves into a `class BootContext` held by `BootReplay`; `classify` keeps its exact signature, using a context param internally defaulting to a module-level instance — behavior identical, API identical (spec §7 notes this consequence).

- [ ] **Step 1: Failing test** `tests/test_brom_lazy.py::test_no_import_time_read` — `import crumpet_emu.brom.boot` must succeed with `CRUMPET_EMU_COMMON_BROM` pointing at a nonexistent path (import-time read would raise); then `load_rom()` raises `MissingBinary`.
- [ ] **Step 2:** run → FAIL (port hasn't happened; even a stub raises at import).
- [ ] **Step 3:** port the three files verbatim + the fixes above (donor header comments; `Watchdog` import inside `transport.py` → `from crumpet_emu.brom.harness import Watchdog`).
- [ ] **Step 4:** run → PASS (1 test); `python3 -c "import crumpet_emu.brom.harness"` clean with no bins.
- [ ] **Step 5:** commit `"brom: port boot replay + harness + stage2 transport (lazy paths)"`.

### Task 8: deploy port + own artifacts + verify_lk_patches tool

**Files:**
- Create: `crumpet_emu/deploy/__init__.py`, `crumpet_emu/deploy/functions.py`, `crumpet_emu/deploy/main.py`, `tools/verify_lk_patches.py` (from `WS/tools/kamakiri/ida/verify_lk_patches.py`, workspace paths → `resources`/`own`)
- Create: `binaries/own/{stage1.bin,stage1.elf,payload.elf,payload.bin,tz-lka.img,tz-lkb.img,key_continuity.json}` copied from `WS/tools/kamakiri/brom-payload/stage1/{stage1.bin,stage1.elf}`, `WS/tools/amonet-koboreru/build/crumpet2021/{payload.elf,payload.bin}`, `WS/tools/amonet-koboreru/build/crumpet2021-lka/tz.img` → `tz-lka.img`, `...-lkb/tz.img` → `tz-lkb.img`, `WS/tools/kamakiri/build/crumpet/key_continuity.json`; append the own-artifact inventory + sha256s to `binaries/manifest.json`
- Test: `tests/test_deploy_units.py` (new, small)

**Interfaces:**
- Produces (verbatim): `FlashError`, `command(transport, code, *args, payload=b'', ...)`, `kick(transport)`, `read_page(transport, page)`, `read_page_range(transport, first_page, n_pages)`, `flash_image(transport, first_page, image, ...)`; `SlotUndetermined(RuntimeError)`, `class DeployConfig`, `detect_active_slot(read_page_fn, gpt)`, `read_gpt_from_flash(transport)`, `sanity_check_gpt(gpt, donor_gpt)`, `backup_partitions(transport, gpt, partitions, backup_dir)`, `deploy(transport, cfg, snapshots=None, ...)`.
- `tools/verify_lk_patches.py` path fixes: donor stock-LK path → `resolve('lk', '2025')`; `key_continuity.json` → `own('key_continuity.json')`; patched-image default → `resolve('lk-patched', '2021')` (Tier 2). No IDA imports (verified: argparse/hashlib/json/capstone only).

- [ ] **Step 1: Failing test** `tests/test_deploy_units.py::test_detect_active_slot_undetermined` — feed `detect_active_slot` a GPT without misc → `SlotUndetermined` (donor contract: zero writes on undetermined); `::test_dword_roundtrip` — `command()` framing `_dword` matches donor byte order (pin: little-endian `<I`, assert against donor line 57–59 semantics).
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3:** port both modules verbatim + copy artifacts + extend manifest.
- [ ] **Step 4:** run → PASS.
- [ ] **Step 5:** commit `"deploy: port deploy pipeline + commit own-built artifacts"`.

### Task 9: donor test suite port (the 38)

**Files:**
- Create: `tests/conftest.py` (empty of sys.path hacks — package layout makes it unnecessary), ported from donors with Import Map:
  - `tests/test_layer1_brom.py` (from `emu/tests/`; replace donor's `make -C brom-payload` rebuild with hash assert against `own('stage1.bin')` manifest entry)
  - `tests/test_layer2_stage2.py`, `tests/test_layer3_orchestration.py`, `tests/test_layer4_closedloop.py`, `tests/test_layer5_brom_boot.py`, `tests/test_key_continuity.py`, `tests/test_lk_patches.py`
- Test: `tests/test_tiers.py` (new)

**Interfaces:**
- Consumes: everything from Tasks 1–8.
- Porting rules (all decided):
  - Per-slot tz paths `AK/'build'/crumpet2021-lk{a,b}/tz.img` → `own('tz-lka.img')` / `own('tz-lkb.img')`.
  - `build/crumpet/lk-patched.img` → `resolve('lk-patched', '2021')` inside a `pytest.skipif`/Tier-2 guard helper `tier2 = pytest.mark.skipif(not resources.available('lk-patched', '2021'), reason=...)`; add `resources.available(name, gen) -> bool` to Task 3's module (add it in this task if missing).
  - `test_lk_patches.py` subprocess target → `<repo>/tools/verify_lk_patches.py`.
  - Tests needing `lk-patched.img`, scenario A/A0 images, or the donor belt are marked `tier2`; all others Tier 1.
- Produces: `tests/test_tiers.py::test_tier2_skips_cleanly` — runs a tier2-marked probe test via `pytest.main` in a tmp copy with env cleared → outcome is all-skipped, not failed.

- [ ] **Step 1:** port the 7 test files with the Import Map + rules above.
- [ ] **Step 2:** `python3 -m pytest tests/ -v` → Tier 1 tests PASS; tier2 tests SKIP (no vendor bins yet). Total collected ≥ 38 − (tier2 count); zero FAIL.
- [ ] **Step 3:** place bins locally (read-only copy out of workspace: `cp WS/no-alexa/*.bin binaries/vendor/common/; cp WS/ota-crumpet/2021/ota_out/{brhgptpl_0..3,lk,tee1,tee2,boot}.img binaries/vendor/2021/; cp WS/img/*.img binaries/vendor/2025/; cp WS/tools/kamakiri/build/crumpet/lk-patched.img binaries/vendor/2021/`), rerun → **all 38 PASS**.
- [ ] **Step 4:** remove the copied bins again (keep the tree clean), commit `"tests: port donor suite (38) with tier gating"`.

### Task 10: preloader port (amonet-emu → preloader layer)

**Files:**
- Create: `crumpet_emu/preloader/__init__.py`, `crumpet_emu/preloader/constants.py`, `crumpet_emu/preloader/emu.py`, `crumpet_emu/preloader/scenarios.py`, `scenarios/preloader_chain.py`
- Test: `tests/test_preloader_ports.py`

**Interfaces:**
- Consumes: `flash.image.Flash/ChipDumpFlash` (Task 5), `Session` (Task 1), `own`/`resolve` (Tasks 3/8), `parse_elf_symbols` (moved here from donor).
- Produces (verbatim from `WS/tools/amonet-emu/emu_chain.py`): `constants.py` = donor lines 44–77 constants (`TEXT_BASE 0x201000` … `SRAM_DBUF_PTR 0x102994`, UART/eFuse/timer addrs, `GPT` dict — split only by moving the `GPT` map ownership here if Task 5 left it in `flash/image.py`; one owner, other imports); `class Emu(flash, sbc=True, payload_syms=None, stock_ok=None)`; `arm_device(emu)`; `part_struct(emu, name, scratch) -> (addr_cell, size_cell)` (donor helper); `parse_elf_symbols(path) -> dict`; `calibrate(*, sbc=True) -> bool`; `stock_boot(*, sbc=True) -> bool`; `run_scenario(letter: str, *, sbc: bool, images: ImageSet) -> Verdict` where `ImageSet = namedtuple('ImageSet', 'pl lk tee2 commit_tag')` and `Verdict = namedtuple('Verdict', 'letter ok detail')`; presets `A`/`A0` pin donor commit images (`3e65ba3` / `5f5481c`) which are **not in the manifest** → `run_scenario('A')` without a manifest entry raises `MissingBinary` (documented Tier-2-only behavior).
- Image loading: `PL_IMG/LK_IMG/TEE2_IMG` defaults → `resolve('brhgptpl_0'/'lk'/'tee2', '2021')`; payload default → `own('payload.elf')`.
- `scenarios/preloader_chain.py`: argparse surface mirrors donor exactly (`payload tz --lk --no-sbc --skip-tee2 --elf --calibrate --preflight --from-chip-dump`), delegating to the module functions.

- [ ] **Step 1: Failing test** `tests/test_preloader_ports.py::test_constants_verbatim` — spot-pin six values (`PART_LOAD == 0x20F4A8`, `FILE_DELTA == 0x1F8D00`, `EFUSE_SBC == 0x10009060`, `LK_LOAD_ADDR == 0x41E00000`, `TEE_LOAD_ADDR == 0x43001000`, `GPT['lk_b'] == (640*8, 384*8)`); `::test_scenario_a_requires_manifest` — `run_scenario('A')` with default images raises `MissingBinary` (commit-tag images not in manifest) **even when** `2021:brhgptpl_0` is present (proves A/A0 are manifest-gated, not silently served by same-named files).
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3:** port (extraction + thin refactor into the three modules; CLI delegates).
- [ ] **Step 4:** run → PASS; with vendor bins placed: `python3 scenarios/preloader_chain.py --preflight` reproduces donor `calibrate` + `stock-boot PASS` output lines (manual check, note result in commit body).
- [ ] **Step 5:** commit `"preloader: port emu_chain (constants/Emu/scenarios) + CLI"`.

### Task 11: lk — seeds, session, battery, host crypto helpers

**Files:**
- Create: `crumpet_emu/lk/__init__.py`, `crumpet_emu/lk/seeds.json` (copy of `WS/tools/lk-emu/ida_seeds.json`), `crumpet_emu/lk/session.py`, `crumpet_emu/lk/battery.py`, `crumpet_emu/lk/hostcrypto.py`
- Test: `tests/test_lk_session.py`

**Interfaces:**
- Consumes: `Session`, devices (Task 1), `resolve('lk', '2025')` (Task 3).
- Produces:
  - `session.py`: constants `LK_BASE=0x41DFFE00`, `LK_LOAD=0x41E00000`, `BSS_END=0x41E60000`, `STACK=0x70000000`, `STACK_SZ=0x100000`, `HEAP=0x71000000`, `HEAP_SZ=0x400000`, `ARGS=0x72000000`, `ARGS_SZ=0x100000`, `GLITCH_ADDR=0x41E019F4`; `class LkSession` (subclass or wrapper of `Session`): `build(lk_bytes: bytes) -> LkSession` (map image at `LK_BASE` raw, regs per donor `LKEmu.__init__` mapping), `load_seeds()` (parses `seeds.json` → `self.seeds`), `call_seed(name: str, args: list[int], *, timeout=...) -> int` (VA from seeds, Thumb bit handling per donor `call6`), `glitch(mode: str)` — install a one-shot code hook at `GLITCH_ADDR` implementing the donor `otu-glitch` single-instruction fault (copy donor hook semantics verbatim); platform stubs (malloc/free/plat_read/idme_update per donor function table) as instance hooks, sourced verbatim from `lk_emu.py`.
  - `battery.py`: verbatim port of `WS/tools/lk-emu/battery.py` (`call6`, `pk`, `scenario_keydump/vcode/vunlock/otu/otu_glitch/bootimg/certdriver`, `derive_challenge`, `stage_cert`, `stage_code`, `make_cert`) — signatures take `emu: LkSession` instead of donor `LKEmu`.
  - `hostcrypto.py`: verbatim `mgf1`, `pss_encode`, `gen_rsa`, `i2b`, `b2i`, `der_len`, `spki_der`, `rsa_pss_sign` (host-side, pure stdlib — Tier 1 testable).
- `scenarios/lk_unlock.py` lands in Task 16; not here.

- [ ] **Step 1: Failing tests** `test_seeds_parse` (≥ 25 named entries incl. `rsa_import`); `test_host_pss_roundtrip` — `pss_encode` + `spki_der`/`rsa_pss_sign` self-consistency per donor math (assert `rsa_pss_sign(msg, key)` verifies via the same primitives — host-side only, no unicorn); `test_build_requires_lk` — `LkSession.build(resolve('lk','2025').read_bytes())` skips cleanly under tier2 marker when bin absent.
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3:** port (`session.py` is the donor `LKEmu` class generalized: same memory map, same stub table, session-based).
- [ ] **Step 4:** run → PASS (Tier 1: seeds/hostcrypto; Tier 2: build).
- [ ] **Step 5:** commit `"lk: seeds + generalized LkSession + forge battery + host crypto"`.

### Task 12: lk seam — IDA identification + fastboot host driver + e2e

**Files:**
- Create: `crumpet_emu/usb/fastboot.py`, `scenarios/lk_fastboot.py`; Modify: `crumpet_emu/lk/seeds.json` (append seam entries)
- Test: `tests/test_fastboot_e2e.py` (Tier 2)

**Interfaces:**
- Consumes: `LkSession` (Task 11), donor IDA db `WS/tools/lk-emu/lk.i64` (read-only).
- Produces:
  - Seam identification (use IDA headless via `python3` + idalib from `<IDA-INSTALL>/idalib`, or `idat -A -S`): find LK's USB transport boundary functions called by the fastboot read/write path (the functions `FUN_41e1daec`/`FUN_41e1f5c0` use for rx/tx). Record their VMAs in `seeds.json` as `usb_read`, `usb_write` (plus any init thunk the handler path calls before first read). Document in `docs/porting-notes.md` §seam with the call-chain evidence. **Fallback (if IDA friction):** dynamic call-scan — run `LkSession` into `FUN_41e1f5c0` with a code hook logging `bl` targets, pick the rx/tx leaf functions from the trace.
  - `crumpet_emu/usb/fastboot.py`: `class FastbootHost` — `__init__(self, lk: LkSession)` wires the seam stubs (donor-style platform stub replaced by queue-backed `usb_read`/`usb_write` implementations installed as seed-function hooks); `send(verb: str, arg: str = '', data: bytes = b'') -> tuple[str, str, bytes]` — writes the fastboot command line (`verb:arg`), streams `data` via the download path, parses replies (`OKAY`/`FAIL`/`INFO`/`DATA`), returns `(status, message, payload)`; `getvar(name: str) -> tuple[str, str]`.
  - `scenarios/lk_fastboot.py`: CLI `--cmd 'flash:unlock' --data FILE` / `--getvar all` against the emulated LK.

- [ ] **Step 1:** seam identification (IDA or fallback); append seeds; record evidence in porting-notes (this step's deliverable is the two+ seed entries + doc section).
- [ ] **Step 2: Failing test** `tests/test_fastboot_e2e.py::test_flash_okay` (tier2): boot LK (Task 11 `build`), drive `FastbootHost.send('flash:nand0', data=...)` or the donor `run-flash-e2e` equivalent, assert final reply status `OKAY` and UART contains the donor log's `>> OKAY` marker (pin exact marker line from `WS/tools/lk-emu/run-flash-e2e.log`).
- [ ] **Step 3:** implement `FastbootHost`.
- [ ] **Step 4:** with `2025:lk` present: run → PASS; without: SKIP cleanly.
- [ ] **Step 5:** commit `"lk: USB seam + FastbootHost, e2e flash OKAY"`.

### Task 13: lk boot-path entry (M2)

**Files:**
- Create: `crumpet_emu/lk/boot.py`, `crumpet_emu/lk/mkelf.py` (port of `WS/tools/lk-emu/mkelf_lk.py`), `crumpet_emu/lk/platform.py`
- Test: `tests/test_lk_bootpath.py` (Tier 2)

**Interfaces:**
- Consumes: `LkSession` (Task 11), seam seeds (Task 12), `battery.py`'s platform/battery model.
- Produces: `boot(lk_bytes: bytes, *, budget: int = 2_000_000_000) -> BootOutcome`; `BootOutcome = namedtuple('BootOutcome', 'reached_fastboot uart_trace handoff None-ok')` — `reached_fastboot: bool` is True iff PC reaches the fastboot top-level `0x41E1DAEC` (seed `fastboot_main`) within the instruction budget; `handoff` is the kernel-jump address if observed (Task 14 hook supplies detection). `platform.py`: the init-path stub set (clock/pmic/battery/NAND probe/WDT) ported from donor `lk_emu.py` platform stubs + `battery.py`'s battery model, exposed as `install_platform(lk: LkSession) -> None`. Success criterion: real init code runs from LK entry and **naturally** reaches the fastboot loop; the fastboot-loop-entry checkpoint (Task 15 consumers) snapshots this state.
- This task is expected to need stub iteration — the plan pins the success check and the donor-stub source; the builder adjusts stub semantics until the check passes. Record every stubmed function in `docs/porting-notes.md` §platform.

- [ ] **Step 1: Failing test** `tests/test_lk_bootpath.py::test_boots_to_fastboot` (tier2): `boot(lk)` → `reached_fastboot is True`; UART trace contains the donor fastboot banner string (pin exact banner from `WS/tools/lk-emu/run-*.log` or donor UART output).
- [ ] **Step 2:** implement `mkelf.py` port + `platform.py` stub set + `boot()` loop; iterate stubs against the budget check.
- [ ] **Step 3:** with `2025:lk`: PASS; without: SKIP.
- [ ] **Step 4:** commit `"lk: boot-path entry, platform stubs, natural fastboot-loop reach (M2)"`.

### Task 14: lk boot-image auth observability (kernel-load)

**Files:**
- Create: `crumpet_emu/lk/bootimg.py`
- Test: `tests/test_bootimg_observe.py` (Tier 2)

**Interfaces:**
- Consumes: `LkSession`, `battery.scenario_bootimg` (Task 11), handoff hooks from Task 13.
- Produces: `class AuthReport` (dataclass: `verdict: str`, `cmdline: list[str]`, `rollback: dict[str, int]`, `handoff: int | None`); `observe_auth(lk: LkSession, boot_bytes: bytes) -> AuthReport` — stages `boot_bytes` and invokes the boot-image auth driver (`0x41E00F58` wrapper → `0x41E0120C`), hooking: `verify_with_hash` call/return, `androidboot.` cmdline string writes, anti-rollback reads at `deviceinfo+0x1E4/0x1E6/0x1E8` (addresses per spec §5.3), kernel-jump handoff. Verdict strings pinned to donor literals (`'Image AUTHENTICATED with PRODUCTION certificate'` and the donor failure strings — copy verbatim from donor `lk_emu.py` string table).
- Kernel execution remains a non-goal: `observe_auth` stops at handoff detection.

- [ ] **Step 1: Failing test** `test_observe_auth_reports` (tier2): stage the `2025:boot` image (or a tampered copy via Task 15 inject), assert `verdict` matches the donor's authenticated/failure literal accordingly, `rollback` keys == `{'v_xxx': ...}` per donor offsets (pin the three dict keys to the donor's deviceinfo offsets `0x1E4/0x1E6/0x1E8`).
- [ ] **Step 2:** implement.
- [ ] **Step 3:** with `2025:lk` + `2025:boot`: PASS; else SKIP.
- [ ] **Step 4:** commit `"lk: boot-image auth observability to handoff"`.

### Task 15: hunting — inject, differential, fuzz, coverage

**Files:**
- Create: `crumpet_emu/hunting/__init__.py`, `crumpet_emu/hunting/inject.py`, `crumpet_emu/hunting/differential.py`, `crumpet_emu/hunting/fuzz.py`, `crumpet_emu/hunting/coverage.py`
- Test: `tests/test_hunting.py`

**Interfaces:**
- Consumes: checkpoints (Task 2), `Flash`/`ChipDumpFlash` (Task 5), `FastbootHost` (Task 12).
- Produces:
  - `inject.apply_flash(flash, recipe: dict) -> None` — recipe `{'target': 'lk_a', 'offset': int, 'patch': bytes}` or `{'target': ..., 'fill': int, 'start': int, 'end': int}`; mutates the flash model's backing bytes. `inject.apply_mem(session, recipe)` for memory recipes.
  - `differential.run_variants(build_fn: Callable[[dict], R], variants: dict[str, dict]) -> dict[str, R]` where `R` has `.uart_text` and `.verdict`; returns per-variant results; `differential.first_divergence(results) -> tuple[str, str] | None` (variant pair + first differing UART line).
  - `fuzz.FuzzLoop(cp_path: Path, mutate: Callable[[int], dict], run_case: Callable[[dict], CaseResult], *, max_cases: int = 1000) -> FuzzReport` — restores checkpoint per case; `CaseResult = namedtuple('CaseResult', 'input_id ok verdict')`; `UcError`/invalid-mem during `run_case` records `ok=False` and continues; `FuzzReport` has `.crashes: list[CaseResult]`, `.verdicts: dict[str, int]` (histogram).
  - `coverage.EdgeBitmap` — `install(uc)` code hook into a 64 KiB AFL-style bitmap (`self.bitmap`), `edges() -> int`.
- `scenarios/{differential,fuzz_fastboot}.py` thin CLIs land in Task 16.

- [ ] **Step 1: Failing tests** `test_inject_flash_patch` (patch visible through `Flash.read`); `test_fuzz_survives_crash` (run_case raises `UcError` for input 7 of 10 → report has 9 ok + 1 crash, loop completes); `test_coverage_counts_edges` (execute the Task-1 add-function under `EdgeBitmap`, `edges() >= 2`).
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** run → PASS (3+ tests).
- [ ] **Step 5:** commit `"hunting: injection, differential, crash-tolerant fuzzing, coverage"`.

### Task 16: scenario CLIs + docs + README

**Files:**
- Create: `scenarios/boot_brom.py`, `scenarios/differential.py`, `scenarios/fuzz_fastboot.py`, `scenarios/lk_unlock.py`
- Create: `docs/architecture.md`, `docs/hunting.md`, `docs/porting-notes.md`, `docs/provenance.md`
- Modify: `README.md` (full), `binaries/README.md` (final)

**Interfaces:**
- Consumes: all package APIs (Tasks 1–15).
- Produces: runnable entry points only — `boot_brom.py` (BROM replay + classify), `lk_unlock.py` (donor scenario names as subcommands: `keydump vcode vunlock otu otu-glitch bootimg certdriver b64 otucode-derive`), `differential.py` (`--variants sbc=on,off slot=a,b`), `fuzz_fastboot.py` (`--cp CHECKPOINT --cases N`), each `--gen {2021,2025}` where relevant. Docs content is specified in the spec §2 goal 5 and §6; `docs/provenance.md` must list every manifest entry with origin + upstream attribution (`R0rt1z2/kamakiri`, `R0rt1z2/amonet-koboreru`) + the park/own classification; `docs/hunting.md` documents checkpoint points, recipe format, and the five Review-Focus behaviors from the operator's seat.

- [ ] **Step 1:** write the four thin CLIs (argparse delegating to package functions; ≤ 60 lines each).
- [ ] **Step 2:** smoke each: `python3 scenarios/boot_brom.py --help`; with bins: `lk_unlock.py keydump`, `preloader_chain.py --calibrate` (already exists from Task 10).
- [ ] **Step 3:** write the five docs + README (quickstart per layer, tier explanation, provenance table).
- [ ] **Step 4:** commit `"docs + scenario CLIs"`.

### Task 17: final gate + GitHub

**Files:** none (verification + publish)

- [ ] **Step 1:** `python3 -m pytest tests/ -v` without vendor bins → all Tier 1 PASS, Tier 2 SKIP, zero FAIL.
- [ ] **Step 2:** place bins (Task 9 recipe) → `python3 -m pytest tests/ -v` → **all 38 donor tests + all new tests PASS**; remove bins.
- [ ] **Step 3:** `grep -rn "WS" crumpet_emu/ scenarios/ tests/` → zero hits (workspace-independence gate).
- [ ] **Step 4:** `git log --oneline` sanity; `gh repo create nemethhh/crumpet-emu --private --source . --push --description "Layered Unicorn emulator for the Amazon Echo Dot 3rd-gen (crumpet/MT8167) load chain - BROM/preloader/LK hunting lab"`.
- [ ] **Step 5:** `gh repo view nemethhh/crumpet-emu --json visibility,url` → private + pushed; report URL.

## Self-Review

- **Spec coverage:** §5.1 layout → Tasks 1–16 (every listed dir/file has an owning task); §5.2 porting rules → Tasks 4/7/11 rules + header comments; §5.3 facts → Tasks 7/10/11 verbatim constants + Task 12 seam; §5.4 hunting → Task 15 + checkpoint points (Tasks 2/13); §5.5 tests → Tasks 9/17 tiers; §5.6 GitHub → Task 17; §6 binaries → Tasks 3/8; §7 builder-left items → Tasks 12 (seam), 11 (APIs), 12 (framing), 16 (docs). No orphan requirements found.
- **Step scan:** every step is one action; ported-test steps point at the Import Map instead of repeating bodies; algorithmic bodies only where the donor doesn't determine them (checkpoint format, fuzz loop).
- **Type consistency:** `Session.call`/`LkSession.call_seed`/`FastbootHost.send`/`run_variants`/`FuzzLoop` signatures match their consumers across tasks; `resolve(name, gen)` used identically in Tasks 7/8/10/11.
- **Review Focus:** all five have owning-task tests (Tasks 3, 3+7, 15, 2, 9+17).
- **Proportion:** plan ≈ spec length — signatures and pinned values, no transcripts.
