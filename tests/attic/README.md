# tests/attic/ — parked donor tests (not collected)

`attic_test_build_reproducible.py` is the donor's
`emu/tests/test_build_reproducible.py` copied verbatim (plus this
provenance header). It is parked, per the design call (§8 C5 / §5.5):

- it drives `build-crumpet.sh` — a reproducibility harness over the
  donor workspace's `brom-payload/` and `tools/amonet-koboreru/` build
  trees, which do not exist in this repo (crumpet-emu pins the build
  products as committed own artifacts under `binaries/own/` instead of
  rebuilding them — no `make` rebuild is a plan ruling);
- it was the donor suite's only failing file at port time (2 of 40
  collected, both here), so it never belonged to the 38-test porting gate.

The `attic_` filename prefix means pytest's default `test_*.py`
collection pattern never imports this file. Do not rename it to
`test_*.py` unless the build harness itself is ported first.
