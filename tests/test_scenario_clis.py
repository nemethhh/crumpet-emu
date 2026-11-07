# Task 16: smoke tests for the scenario CLIs — Tier 1, no vendor bins.
# Each CLI must be importable and exit 0 on --help: binary resolution is
# lazy (inside main()), so argparse parsing never needs the parked set
# (the same clean-missing-binary contract the Review Focus #2 duty pins
# for the package).
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCENARIOS = ('boot_brom', 'lk_unlock', 'differential', 'fuzz_fastboot')


def _load(name):
    spec = importlib.util.spec_from_file_location(
        f'scenarios.{name}', REPO / 'scenarios' / f'{name}.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize('name', SCENARIOS)
def test_cli_importable(name):
    assert callable(_load(name).main)


@pytest.mark.parametrize('name', SCENARIOS)
def test_cli_help_exits_zero(name):
    proc = subprocess.run([sys.executable, f'scenarios/{name}.py', '--help'],
                          cwd=REPO, capture_output=True, text=True,
                          timeout=120)
    assert proc.returncode == 0, f'{name} --help failed:\n{proc.stderr}'
    assert 'usage:' in proc.stdout


def test_lk_unlock_subcommands():
    # the Task-16 brief pins the donor battery surface (flash-e2e is the
    # fastboot e2e covered by lk_fastboot.py / fuzz_fastboot.py)
    assert _load('lk_unlock').SCENARIOS == (
        'keydump', 'vcode', 'vunlock', 'otu', 'otu-glitch', 'bootimg',
        'certdriver', 'b64', 'otucode-derive')
