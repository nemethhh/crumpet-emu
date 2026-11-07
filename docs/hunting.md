# Hunting guide — crumpet-emu

The hunting instrumentation is first-class and cross-cutting
(`crumpet_emu.hunting`): checkpoints, fault injection, a differential
runner, a crash-tolerant fuzz loop and AFL-style edge coverage. This
guide is written from the operator's seat: what you run, what you see,
and the five behaviors that reviews pinned as must-never-break.

All Tier-1 hunting functionality runs with **zero vendor binaries**; the
fastboot fuzz targets and the preloader/LK builders resolve parked bins
through `crumpet_emu.resources` at call time (see the tier section at the
bottom).

## Checkpoints (`crumpet_emu.core.checkpoints`)

`save(session, path, extra=None) -> Path` serializes: every region a
`TrackedSession` recorded via `map()` (plus its internal stack), the
unicorn CPU context, and `extra` — opaque caller blobs. On-disk format is
a versioned pickle: `{'v': 1, 'regions': [[addr, bytes], ...],
'context': blob, 'extra': {...}}` (`context` is
`pickle.dumps(uc.context_save())` — unicorn 2.1.4 has no
context_write, so a raw bytes form is impossible; verified to round-trip
across processes). `restore(path) -> (session, extra)` rebuilds a fresh
`TrackedSession` with all registers restored — a restored session is
itself checkpointable again. Never hand an untrusted checkpoint file to
`pickle.load`.

Checkpoint points offered today:

- **Layer boundaries**: anything holding a `TrackedSession` can snapshot.
  Observable transport state is the model for the `extra` contract:
  `test_restore_preserves_transport_state` feeds a `usb_rx` queue through
  a save/restore round trip and pins it byte-identical (see behavior #4
  below).
- **LK fastboot-loop entry**: when `crumpet_emu.lk.boot.boot()` reaches
  the fastboot top level (`FASTBOOT_MAIN` 0x41E1DAEC) it snapshots the
  entry state onto the session as `lk.fastboot_checkpoint`
  (pc, sp, heap_ptr, uart byte count, usb queue lengths) — that dict is
  the checkpoint duty; `BootOutcome` itself stays the ruled 3-field
  namedtuple. Note the M2 status: `boot()` currently parks at the wfi
  wall before the fastboot loop
  ([porting-notes §platform](porting-notes.md)), so the surgical
  baseline below is the practical fuzz target today.

**Integration limit (Task 15 ruling, honored by `scenarios/fuzz_fastboot.py`):**
`restore()` returns a **core** `TrackedSession` — mapped regions and the
register context survive, but LkSession-only state does not (Python-side
hooks cannot ride the unicorn context). An LK harness therefore rebuilds
that state from `extra` before running a case: usb queues
(`usb_rx`/`usb_tx` raw bytes), seeds (re-parsed from the committed
`seeds.json` via `load_seeds()`), and the donor stub hooks (re-armed from
`LkSession`'s own machinery). This is documented in the CLI help and
implemented as `_adopt()` in `scenarios/fuzz_fastboot.py`.

**Writer recipe (Tier 2)** for a fastboot baseline checkpoint:
`checkpoints.save()` demands a `TrackedSession`; `LkSession`'s donor map
rules keep its regions fixed (the seven `(addr, size)` pairs mapped in
`crumpet_emu/lk/session.py __init__` — image page 0x41DF0000+0x50000,
0x41E40000..0x41E60000, stack 0x70000000+0x100000, heap 0x71000000+0x400000,
args 0x72000000+0x100000, UART page 0x11005000+0x1000, timer page
0x10008000+0x1000), so attach the region registry and save:

```python
from pathlib import Path
from crumpet_emu import resources
from crumpet_emu.core import checkpoints
from crumpet_emu.lk.session import (ARGS, ARGS_SZ, BSS_END, HEAP, HEAP_SZ,
                                    LK_BASE, LkSession, STACK, STACK_SZ)
from crumpet_emu.core.devices import TIMER_REG, UART_THR

REGIONS = ((LK_BASE & ~0xFFFF, 0x50000),
           (0x41E40000, BSS_END - 0x41E40000),
           (STACK, STACK_SZ), (HEAP, HEAP_SZ), (ARGS, ARGS_SZ),
           (UART_THR & ~0xFFF, 0x1000), (TIMER_REG & ~0xFFF, 0x1000))

lk = LkSession(resources.resolve('lk', '2025').read_bytes(), verbose=False)
lk._regions = REGIONS                      # save() duck-types on this
checkpoints.save(lk, Path('fb.cp'), extra={'usb_rx': bytes(lk.usb_rx),
                                           'usb_tx': bytes(lk.usb_tx),
                                           'heap_ptr': lk.heap_ptr})
```

## Fault injection (`crumpet_emu.hunting.inject`)

A recipe is one dict with two forms, against flash partitions or memory:

```python
{'target': 'lk_a', 'offset': 0x800, 'patch': b'\xDE\xAD\xC0\xDE'}   # overwrite
{'target': 'tee1', 'fill': 0xFF, 'start': 0, 'end': 0x1000}         # range fill
```

- `apply_flash(flash, recipe)` — `target` is a partition name from the
  GPT map (`lk_a`/`lk_b`/`tee1`/`tee2`/...), offsets are
  partition-relative bytes. The GPT map in `crumpet_emu.flash.image` is
  the single placement owner; `Flash` and `ChipDumpFlash` serve identical
  bdev block numbering, so a recipe means the same bytes through either
  model (closed-loop drop-in). Unknown target → `ValueError`; a write
  past the partition end → `ValueError` — a recipe can never silently
  corrupt the neighbouring partition.
- `apply_mem(session, recipe)` — same two forms, `target` is a base
  ADDRESS (int); unmapped writes fault loudly through unicorn.

**Canonicalization semantics** (pinned by
`tests/test_hunting.py::test_inject_flash_short_trailing_block_never_clamps`,
the Task-15 review repro): a patch must never silently move or clamp.

- **Patched short block → full 512 B**: donor `Flash.read()` serves a
  short trailing block as the short slice; a write past its end
  materializes the block to its canonical 512-B size first (erase-fill
  0xFF), then splices — the patch lands at the target offset.
- **Absent `ChipDumpFlash` page → full 4096-B data plane**: patching an
  absent (or sub-page) page materializes the FULL 4096-B data plane as
  erase-fill — never just the touched 512-B slice — and preserves the
  256-B spare plane byte-for-byte. This matches exactly what `read()`
  would have served, so a recipe changes only the bytes it names.
- Cross-block patches splice into each touched block/page separately
  (a 512-B straddle never corrupts the neighbour).

## Differential runner (`crumpet_emu.hunting.differential`)

Same input, varied parameters:

```python
results = run_variants(build_fn, {'sbc=on': {'sbc': 'on'},
                                  'sbc=off': {'sbc': 'off'}})
first_divergence(results)   # -> ('sbc=on vs sbc=off', '<first differing line>') | None
```

`build_fn` receives a shallow copy of each override dict (a mutating
builder cannot leak state between variants); results need `.uart_text`
(str — split on lines — or a list of lines; `boot()`'s `uart_trace`
shape qualifies) and `.verdict` (a plain value; compare it yourself —
`first_divergence` intentionally reports only the UART alignment).
Pair naming is insertion-order deterministic; a line present in one
trace only counts as a divergence.

CLI: `scenarios/differential.py --variants 'sbc=on,off' --layer preloader`
(stock 2021 boot; captured stdout is the trace) or
`--layer lk --variants 'budget=1000000,3000000' --gen 2025` (the natural
boot walk's uart_trace; today all budgets honestly end `unreached` — the
wfi park — so the lk layer differentiates best on fault/park evidence
until the IRQ model lands).

## Fuzzing (`crumpet_emu.hunting.fuzz`)

```python
report = FuzzLoop(cp_path, mutate, run_case, max_cases=1000)
# FuzzReport(cases=[CaseResult(input_id, ok, verdict), ...],
#            crashes=[...not-ok cases...], verdicts={'verdict': count, ...})
```

`FuzzLoop` restores the checkpoint before EVERY case, so a faulting case
can never poison the next one. `mutate(case_index)` must be deterministic
(same index → same input); `run_case(cfg)` gets a shallow dict with two
reserved keys — `cfg['session']` (the restored TrackedSession) and
`cfg['extra']` (the checkpoint's opaque caller blobs, e.g. transport
queues). Any exception inside `run_case` (UcError, anything) is recorded
as a not-ok case and the loop CONTINUES — pinned by
`test_fuzz_survives_crash` (a UcError at input 7 of 10 still completes
the run: 9 ok + 1 crash).

CLI: `scenarios/fuzz_fastboot.py --cp CHECKPOINT --cases N`. Its
`run_case` rebuilds the LkSession-only state from `cfg['extra']` before
driving `FastbootHost` (usb queues from `extra`, seeds via
`load_seeds()`, donor stub hooks re-armed — see the checkpoint section);
a structured `OKAY`/`FAIL` reply is the clean case ending, any fault is
a crash with the reason as its verdict. Harness contract per spec §5.4:
fastboot verb/blob inputs, DER/cert blobs into the verify path, crafted
GPT/part headers (drive the latter through `apply_flash` +
`deploy.functions` readers on a flash-backed session).

## Edge coverage (`crumpet_emu.hunting.coverage`)

`EdgeBitmap` is the AFL-classic map shape: 64 KiB of 1-byte saturating
hit counters. Edge index `((from ^ to) >> 1) & 0xFFFF` over consecutive
PCs (XOR keys the CFG transition, the shift discards the carry bit,
`from` starts 0 so the entry PC is encoded). `install(uc)` accepts a
core Session or a raw unicorn `Uc`; `edges()` counts NONZERO slots —
distinct edges executed, the coverage signal for input scoring. The
full coverage-guided engine is a non-goal for v1 (per spec §5.4).

## The five Review-Focus behaviors, operator's seat

1. **Unpinned image never served silently** — every vendor loader goes
   through `crumpet_emu.resources.resolve`, which labels any file whose
   sha256 differs from `binaries/manifest.json`: a loud one-time-per-slot
   `UNPINNED` warning on stderr naming the slot and both hashes
   ("running your bytes; verdicts not comparable to pinned builds").
   Placed images always run (place-and-run), but never without either a
   pinned match or that warning; the warning goes to stderr only, never
   into UART/trace streams the differential runner compares. Pinned by
   `test_unpinned_served_with_stderr_warning` +
   `test_wrong_generation_served_with_warning`.
2. **Missing vendor binary** — resolution order env var
   `CRUMPET_EMU_<GEN>_<NAME>` → `binaries/vendor/<gen>/<file>`; absent →
   `resources.MissingBinary` **at call time** (never at import — every
   path is lazy), message carries the env var to set and the provenance
   pointer. The CLIs catch it and print `error: ...` with exit 1; pytest
   tiers skip (behavior #5). Pinned by `test_missing_binary_pointer`.
3. **Fuzz case crash** — the loop records the case and continues; one
   bad input cannot abort the run or poison the next case (per-case
   restore). See `FuzzLoop` above; operator-visible as `crashes=N` with
   the exception class as the verdict histogram key.
4. **Checkpoint mid-USB-transaction** — restore must reproduce
   *observable* state, not just RAM: the transport queue bytes ride the
   checkpoint's `extra` dict and come back byte-identical
   (`test_restore_preserves_transport_state`). Operator-visible: a
   checkpoint saved with pending wire bytes restores the same pending
   wire bytes.
5. **Tier 2 without bins** — a tier2-marked test `pytest.skip`s cleanly
   with the provenance pointer as the reason; it never FAILs and never
   fabricates. `resources.available(name, gen)` never raises, so gates
   compose: `python3 -m pytest` is green with zero parked bins and
   greener with them. Pinned by `test_tier2_skips_cleanly` (subprocess
   probe with every `CRUMPET_EMU_*` var cleared).
