# Donor: WS/tools/kamakiri/emu/tests/test_build_reproducible.py
# Upstream: R0rt1z2/kamakiri
# Copied verbatim 2026-10-31 and PARKED (plan call C5 / design §5.5):
#   the donor's build-crumpet.sh reproducibility harness is NOT part of
#   crumpet-emu (its brom-payload + amonet-koboreru build trees stay in
#   the donor workspace; this repo pins build products under
#   binaries/own/ instead), and it was the donor suite's only failing
#   file (2/39) at port time. Kept verbatim below for provenance;
#   the attic_ filename prefix keeps pytest's default `test_*.py`
#   collection pattern from ever picking it up — see attic/README.md.
"""Task 12 — reproducible crumpet artifact set.

test_two_builds_identical
    build-crumpet.sh run twice from scratch into two separate temp
    output dirs must produce a byte-identical artifact set, and the
    generated SHA256SUMS must cover every artifact (the manifest a
    hardware session would verify against before flashing).

The artifact set (the plan's Produces): stage1.bin, stage2.bin,
tz-lka.img, tz-lkb.img, lk-patched.img, preloader/brhgptpl_{0..3}.img,
SHA256SUMS.
"""
import hashlib
import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
WS = REPO.parents[1]
BUILD = REPO / 'build-crumpet.sh'

ARTIFACTS = ('stage1.bin', 'stage2.bin', 'tz-lka.img', 'tz-lkb.img',
             'lk-patched.img',
             'preloader/brhgptpl_0.img', 'preloader/brhgptpl_1.img',
             'preloader/brhgptpl_2.img', 'preloader/brhgptpl_3.img')


def _build(tmp: Path) -> dict[str, str]:
    out = tmp / 'crumpet'
    env = dict(os.environ, SOURCE_DATE_EPOCH='1735689600')
    subprocess.run([str(BUILD), str(out)], check=True, env=env,
                   cwd=REPO, capture_output=True, text=True)
    hashes = {}
    for rel in ARTIFACTS:
        p = out / rel
        assert p.is_file(), f'missing artifact {rel}'
        hashes[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    return hashes


def test_two_builds_identical(tmp_path):
    assert BUILD.is_file(), 'build-crumpet.sh missing'
    a = _build(tmp_path / 'run1')
    b = _build(tmp_path / 'run2')
    assert a == b, (
        'artifact hashes differ between two from-scratch builds: '
        f'{ {k: (a[k], b[k]) for k in a if a[k] != b[k]} }')

    # SHA256SUMS covers every artifact, with the hashes we measured
    sums = (tmp_path / 'run1' / 'crumpet' / 'SHA256SUMS').read_text()
    by_hash = dict(line.split(maxsplit=1) for line in sums.splitlines()
                   if line.strip())          # sha256sum: '<hash>  <file>'
    listed = {name.strip().lstrip('*'): h for h, name in by_hash.items()}
    for rel, h in a.items():
        assert rel in listed, f'SHA256SUMS does not cover {rel}'
        assert listed[rel] == h, f'SHA256SUMS hash mismatch for {rel}'

def test_custom_outdir_build_leaves_tracked_files_clean(tmp_path):
    """A build into a custom OUTDIR (as this test file and any release
    build does) must not rewrite the tracked canonical provenance record
    build/crumpet/lk_patches.json — the patch table lands next to the
    requested output, and only a default-path build refreshes the
    canonical one (final-review fix 1)."""
    canonical = (REPO / 'build' / 'crumpet' / 'lk_patches.json')
    before = canonical.read_bytes()
    out = tmp_path / 'rel' / 'crumpet'
    subprocess.run([str(BUILD), str(out)], check=True,
                   cwd=REPO, capture_output=True, text=True)
    assert canonical.read_bytes() == before, \
        'custom-OUT build rewrote the tracked lk_patches.json'
    assert (out / 'lk_patches.json').is_file(), \
        'the per-build patch table must land in the output dir'
