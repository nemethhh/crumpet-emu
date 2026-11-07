# crumpet-emu

Layered Unicorn-based emulator for the Amazon Echo Dot 3rd-gen (crumpet,
MT8167) load chain — **BROM → preloader → LK** — built as a hunting lab
for boot-chain vulnerability research.

Every layer executes **real vendor code**: the MT8167 BROM dump replays
its own boot-read walk, the 2021 preloader segment runs its real
`part_load`/verify gates, and the 2025 `lk.img` runs its real
libtomcrypt RSA unlock path, cert driver and fastboot dispatcher — only
libc / MMIO / platform plumbing is stubbed, with semantics cited from
donor evidence. Around that core sits first-class hunting
instrumentation: checkpoints, fault injection, a differential runner, a
crash-tolerant fuzz loop and AFL-style edge coverage.

```python
from crumpet_emu import resources
from crumpet_emu.lk.battery import run
from crumpet_emu.lk.session import LkSession

lk = LkSession(resources.resolve('lk', '2025').read_bytes(), verbose=False)
run(lk, 'keydump', {})          # real rsa_import against the unlock pubkey
```

## Quickstart

```bash
python3 -m venv venv && venv/bin/pip install -r requirements.txt
venv/bin/python -m pytest                 # Tier 1: green with ZERO vendor bins
venv/bin/python -m crumpet_emu.bins       # what's placed, what's missing
venv/bin/python -m crumpet_emu.bins place /path/to/your/lk.img --as 2025:lk
```

**Tier 1 (always green):** every test that needs no vendor image — core
session/checkpoints, flash models, USB model, hunting instrumentation,
deploy port (against committed own artifacts), plus all smoke surfaces.
Clean `skip`s carry a provenance pointer; nothing fails for want of bins.

**Tier 2 (pinned builds):** closed-loop deploy, real-BROM boot proofs, the
LK unlock battery, fastboot e2e, boot-image auth. These tests pin exact
vendor behavior (UART banners, patch offsets), so they gate on *pinned*
images — files whose sha256 matches `binaries/manifest.json`. **Your own
dumps run everywhere else**: place any image per
[`binaries/README.md`](binaries/README.md) (env var
`CRUMPET_EMU_<GEN>_<NAME>` or drop-in `binaries/vendor/<gen>/`) and every
scenario CLI accepts it — pinned builds run quietly, anything else runs
with a loud `UNPINNED` warning: your bytes, your verdicts. Origins,
hashes and attribution: [`docs/provenance.md`](docs/provenance.md).

With bins placed:

```bash
python3 -m pytest                              # Tier 2 tests join
python3 scenarios/lk_unlock.py keydump         # the signed-unlock audit battery
python3 scenarios/lk_unlock.py --help          # vcode vunlock otu otu-glitch ...
python3 scenarios/boot_brom.py --trace         # classify the stock belt via the REAL BROM
python3 scenarios/lk_fastboot.py --getvar all  # fastboot over the emulated USB seam
```

Without bins you can still exercise the harness plumbing end-to-end:

```bash
python3 scenarios/fuzz_fastboot.py --help      # CLI smoke needs no bins
python3 -m pytest tests/test_hunting.py        # injection/differential/fuzz/coverage
```

## Scenario CLIs

| CLI | what it does | bins? |
|---|---|---|
| `scenarios/preloader_chain.py` | donor emu_chain surface: payload tz / `--calibrate` / `--preflight` / `--from-chip-dump` | yes (2021 set) |
| `scenarios/boot_brom.py` | classify a chip snapshot (default: stock 2021 belt) through the real BROM (`boots_2021_pl` / `brom_usdl_wait` / `invalid`) | yes (`common:brom` + 2021 belt) |
| `scenarios/lk_unlock.py` | donor unlock battery as subcommands: `keydump vcode vunlock otu otu-glitch bootimg certdriver b64 otucode-derive` | yes (2025 `lk.img`) |
| `scenarios/lk_fastboot.py` | one fastboot command over the USB seam (`--cmd 'flash:otucode' --data F`, `--getvar all`) | yes (2025 `lk.img`) |
| `scenarios/differential.py` | variant cross-product + first UART divergence (`--variants 'sbc=on,off'`, `--layer preloader|lk`) | yes (layer-dependent) |
| `scenarios/fuzz_fastboot.py` | checkpoint-restored fastboot fuzzing (`--cp CHECKPOINT --cases N`) | yes (baseline checkpoint) |

All CLIs are thin argparse wrappers over package APIs; binary resolution
is lazy (call time), so `--help` never needs vendor bins and a missing
image prints the provenance pointer instead of a traceback.

## Layout

```
crumpet_emu/            the package
├── core/               Session, device stubs, checkpoint save/restore
├── flash/              NAND chip + NFI register models, GPT, image-backed Flash/ChipDumpFlash
├── brom/               BROM exploit replay (layer 1) + real-BROM boot replay (layer 5)
├── preloader/          validated 2021 preloader segment (constants/Emu/scenarios)
├── lk/                 LK session @0x41E00000, unlock battery, natural-boot walk (M2), seeds
├── usb/                MUSB MAC model, CDC device, transports, FastbootHost
├── deploy/             the closed-loop §7.4 deployment pipeline (backup → slot → verified writes)
└── hunting/            injection, differential, crash-tolerant fuzz loop, edge coverage
scenarios/              thin CLIs (one per layer + differential/fuzz)
tests/                  ported donor suite + core/LK/hunting tests (tier-gated)
binaries/               manifest + committed own artifacts; vendor/ is gitignored (parked)
docs/                   architecture, hunting guide, provenance, porting notes
tools/                  patched-LK patch derivation/verification (IDA-derived patch set)
```

Docs: [`docs/architecture.md`](docs/architecture.md) (layers, entry
points, memory maps, import map) ·
[`docs/hunting.md`](docs/hunting.md) (checkpoints, injection recipes,
differential, fuzzing, coverage, review-focus behaviors) ·
[`docs/provenance.md`](docs/provenance.md) (every binary: origin, hash,
classification, upstream attribution) ·
[`docs/porting-notes.md`](docs/porting-notes.md) (deltas vs donors,
seams, ruling ledger).

## Status and roadmap

- **Done:** BROM exploit replay + real-BROM boot classification;
  preloader segment (38 donor tests ported, tier-gated); LK surgical
  surface — unlock battery, fastboot over the USB seam (e2e OKAY),
  boot-image auth observability (live verdicts AUTHENTICATED /
  FAILED); deploy pipeline; hunting instrumentation.
- **Deferred (M2):** natural LK boot reaching the fastboot loop. The
  walk honestly parks at `wfi`: the scheduler needs the system-timer
  IRQ and unicorn 2.1.4 exposes no interrupt-injection API. The
  prerequisite is a GIC + system-timer IRQ model at register level
  (derivable from LK's own GIC/timer drivers + MT8167 timer registers —
  the same method that produced the NFI register model). Not a
  stub-class task; the honest park and the full blocking chain are
  documented in [`docs/porting-notes.md`](docs/porting-notes.md)
  §platform. Kernel execution beyond the handoff point is out of scope
  by design.

## Responsible use

This is a research lab for boot-chain vulnerability study on the Echo
Dot 3rd-gen. Dump and emulate only devices you own or have lawful access
to; unlock only your own hardware. Vendor images remain Amazon/MediaTek
property and are never distributed from this repository — you supply
your own from your own device. See `docs/provenance.md` for the full
licensing/attribution story.

## License

MIT — see [`LICENSE`](LICENSE). Donor attribution: `kamakiri` (local
work on [R0rt1z2/kamakiri](https://github.com/R0rt1z2/kamakiri)) and
`amonet-koboreru`
([R0rt1z2/amonet-koboreru](https://github.com/R0rt1z2/amonet-koboreru),
MIT); vendor images remain Amazon/MediaTek property and are never
committed — see [`docs/provenance.md`](docs/provenance.md).
