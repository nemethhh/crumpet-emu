# Contributing to crumpet-emu

A research lab for boot-chain vulnerability study on the Amazon Echo Dot
3rd-gen (crumpet, MT8167): BROM → preloader → LK under Unicorn, executing
real vendor code with libc/MMIO stubs cited from donor evidence.

## Dev setup

```bash
python3 -m venv venv
venv/bin/pip install -r requirements.txt   # unicorn>=2.1,<3, capstone>=5, pytest
venv/bin/python -m pytest                  # Tier 1: green with ZERO vendor bins
```

Never install into the system Python.

## The tier discipline

- **Tier 1 must stay green with zero vendor images** — it is the clone-and-run
  promise. Every test that needs a vendor image skips cleanly, with a reason
  that points at placement (`binaries/README.md`), never fails.
- **Tier 2** gates on *pinned* images (sha256 matches
  `binaries/manifest.json`) because those tests assert exact vendor behavior.
  Gate new image-dependent tests on `crumpet_emu.resources.available()`;
  use `present()` only for placement-only checks.
- Operator-local tool-tree crosschecks (IDA/kamakiri/venvs) gate on the
  `CRUMPET_EMU_WS` env var and skip when it is unset.

## Running your own dumps

Place any image at a manifest slot — drop it in `binaries/vendor/<gen>/<file>`
or run `python3 -m crumpet_emu.bins place FILE --as gen:name`. No hash
registration; pinned builds run quietly, anything else runs with an
`UNPINNED` warning. See `binaries/README.md`.

## Adding pinned builds (manifest PRs)

New OTA versions or generations join `binaries/manifest.json` by PR. Each
entry needs: generation key, `file` name, size in bytes, sha256, and
provenance — which device/OTA it came from and how it was extracted
(`docs/provenance.md` carries the full per-file ledger; follow its
format). Vendor images themselves are never committed.

## Code style

- Match the donor-citation header convention: first line names the donor
  file via its `WS/…` placeholder path, plus upstream attribution.
- Scenario CLIs are thin argparse wrappers over package APIs; binary
  resolution is lazy (call time), so `--help` never needs vendor images.
- Every behavior change lands with a test that watched it fail (RED →
  GREEN) and a green full suite before commit.
