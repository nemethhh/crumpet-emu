# Donor: WS/tools/amonet-emu/emu_chain.py
# Upstream: in-repo harness (amonet-emu)
# Ported 2026-10-31 (Task 10): pins for the emu_chain module split —
#   constants verbatim (donor lines 44-89) and the scenario-A/A0
#   manifest gate (presets pin historical commit images that are NOT
#   in binaries/manifest.json).
"""Pins for the preloader port (crumpet_emu.preloader).

test_constants_verbatim
    Spot-pins six donor-fact values from the constants module.

test_scenario_a_requires_manifest
    The A/A0 scenario presets pin the donor commit images (3e65ba3 /
    5f5481c), which have no binaries/manifest.json entry:
    run_scenario('A') with the default images raises MissingBinary
    EVEN WITH a sha-valid 2021:brhgptpl_0 placed via the env override —
    proving A/A0 are manifest-gated, never silently served by
    same-named files (documented Tier-2-only behavior).
"""
import shutil

import pytest

from crumpet_emu import resources

# donor bytes come from the placement system itself (pinned builds) —
# nothing reads manifest 'source' paths
needs_pl = pytest.mark.skipif(
    not resources.available('brhgptpl_0', '2021'),
    reason='pinned 2021:brhgptpl_0 not placed — binaries/vendor/2021/ or env var')


def test_constants_verbatim():
    """Six donor-fact spot pins (emu_chain.py lines 45-46, 88, 62-64)."""
    from crumpet_emu.preloader import constants

    assert constants.PART_LOAD == 0x20F4A8
    assert constants.FILE_DELTA == 0x1F8D00
    assert constants.EFUSE_SBC == 0x10009060
    assert constants.LK_LOAD_ADDR == 0x41E00000
    assert constants.TEE_LOAD_ADDR == 0x43001000
    assert constants.GPT['lk_b'] == (640 * 8, 384 * 8)


@needs_pl
def test_scenario_a_requires_manifest(tmp_path, monkeypatch):
    from crumpet_emu.preloader import scenarios

    # make 2021:brhgptpl_0 genuinely resolvable: env override pointing
    # at the real donor bytes, so the manifest sha gate passes
    pl = tmp_path / 'brhgptpl_0.img'
    shutil.copy(resources.resolve('brhgptpl_0', '2021'), pl)
    monkeypatch.setenv('CRUMPET_EMU_2021_BRHGPTPL_0', str(pl))
    assert resources.available('brhgptpl_0', '2021')

    # scenario A still refuses: its preset resolves the 3e65ba3
    # commit-tagged image names, which have no manifest entry
    with pytest.raises(resources.MissingBinary) as exc:
        scenarios.run_scenario('A')
    assert '3e65ba3' in str(exc.value), \
        f'raised on a non-commit-tagged name: {exc.value}'
