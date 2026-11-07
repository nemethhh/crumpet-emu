"""Tier-gate regression (plan Review Focus #5): a tier2-marked test must
SKIP cleanly — with the provenance pointer as the reason, never FAIL —
when the parked vendor binaries are absent, and must run (and pass)
when they are placed. The probe runs via pytest.main in a subprocess
with every CRUMPET_EMU_* override cleared from the environment, so the
outcome reflects the parked tree exactly, independent of the outer
suite's state.
"""
import os
import subprocess
import sys

from crumpet_emu import resources

PROBE = """\
import pytest

from crumpet_emu import resources

tier2 = pytest.mark.skipif(
    not resources.available('lk-patched', '2021'),
    reason='tier2: requires parked vendor binaries '
           '- see binaries/README.md')


@tier2
def test_tier2_probe():
    \"\"\"Mirrors what every real tier2 test does first: resolve the
    parked artifact through the manifest gate.\"\"\"
    assert resources.resolve('lk-patched', '2021').is_file()
"""

# pytest.main in the subprocess, args after the runner snippet
RUNNER = 'import sys, pytest; sys.exit(pytest.main(sys.argv[1:]))'


def test_tier2_skips_cleanly(tmp_path):
    probe = tmp_path / 'test_tier2_probe.py'
    probe.write_text(PROBE)

    env = {k: v for k, v in os.environ.items()
           if not k.startswith(resources.ENV_PREFIX)}
    proc = subprocess.run(
        [sys.executable, '-c', RUNNER,
         '-p', 'no:cacheprovider', '-q', str(probe)],
        cwd=resources.REPO_ROOT, env=env, capture_output=True, text=True,
        timeout=300)
    out = (proc.stdout + proc.stderr).strip()
    assert proc.returncode == 0, f'probe run FAILED:\n{out}'

    # exactly one outcome, and it is never a failure: skipped when the
    # parked set is absent, passed when it is placed
    parked = resources.available('lk-patched', '2021')
    expected = '1 skipped' if not parked else '1 passed'
    summary = out.splitlines()[-1] if out else ''
    assert expected in summary, f'expected {expected!r}, got: {summary!r}'
    assert '1 failed' not in summary and 'error' not in summary.lower()
