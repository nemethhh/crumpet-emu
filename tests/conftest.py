# Donor: WS/tools/kamakiri/emu/tests/conftest.py
# Upstream: R0rt1z2/kamakiri
# Copied 2026-10-31: the donor's sys.path bootstrap is intentionally NOT
#   ported — imports work because `python3 -m pytest` from the repo root
#   (the documented invocation) puts the cwd (repo root) on sys.path;
#   pytest's rootdir follows the args' common ancestor (tests/), so this
#   file exists only to anchor rootdir/conftest discovery there.
