"""resources: env-resolved binary paths + generation manifest gate (Task 3).

The env-override and wrong-generation tests read real donor bytes from the
workspace read-only (copies into tmp_path only); the workspace-agnostic tests
monkeypatch VENDOR_DIR/OWN_DIR so they never depend on the operator's
drop-in state.
"""

import shutil

import pytest

from crumpet_emu import resources

def _manifest_entry(key: str) -> dict:
    entry = resources._manifest().get(key)
    assert entry is not None, f'manifest entry missing: {key}'
    return entry


# donor bytes come from the placement system itself (pinned builds — the
# same files a tier-2 run consumes); nothing reads manifest 'source' paths
needs_brom = pytest.mark.skipif(
    not resources.available('brom', 'common'),
    reason='pinned common:brom not placed — binaries/vendor/ or env var')
needs_lk = pytest.mark.skipif(
    not (resources.available('lk', '2021') and resources.available('lk', '2025')),
    reason='pinned 2021/2025 lk not placed')


@needs_brom
def test_env_override_wins(tmp_path, monkeypatch):
    """CRUMPET_EMU_<GEN>_<NAME> beats the vendor default path."""
    vendor = tmp_path / 'vendor'
    (vendor / 'common').mkdir(parents=True)
    donor = resources.resolve('brom', 'common')
    shutil.copy(donor, vendor / 'common' / 'brom_MT8167_MT8516_MT8362_8167.bin')
    env_copy = tmp_path / 'env' / 'brom_MT8167_MT8516_MT8362_8167.bin'
    env_copy.parent.mkdir(parents=True)
    shutil.copy(donor, env_copy)
    monkeypatch.setattr(resources, 'VENDOR_DIR', vendor)
    monkeypatch.setenv('CRUMPET_EMU_COMMON_BROM', str(env_copy))

    assert resources.resolve('brom', 'common') == env_copy
    # byte-identical to the manifest entry, so it passes the sha gate
    assert resources.available('brom', 'common')


def test_missing_binary_pointer(tmp_path, monkeypatch):
    monkeypatch.delenv('CRUMPET_EMU_2025_PL', raising=False)

    if resources.present('pl', '2025'):
        pytest.skip('2025:pl placed on this machine — teaching-message test needs it absent')

    with pytest.raises(resources.MissingBinary) as exc:
        resources.resolve('pl', '2025')

    assert 'provenance' in str(exc.value)
    assert 'binaries/README.md' in str(exc.value)
    assert 'CRUMPET_EMU_2025_PL' in str(exc.value)
    assert 'binaries/vendor/2025/pl2025.bin' in str(exc.value)
    assert not resources.available('pl', '2025')


def test_unpinned_served_with_stderr_warning(tmp_path, monkeypatch, capsys):
    """A placed file whose sha differs from the manifest is SERVED, with a
    loud once-per-slot stderr warning — refusal is over (place-and-run)."""
    vendor = tmp_path / 'vendor'
    (vendor / 'common').mkdir(parents=True)
    rogue = vendor / 'common' / 'brom_MT8167_MT8516_MT8362_8167.bin'
    rogue.write_bytes(b'not-a-brom')          # wrong size AND hash
    monkeypatch.setattr(resources, 'VENDOR_DIR', vendor)
    monkeypatch.delenv('CRUMPET_EMU_COMMON_BROM', raising=False)
    resources._unpinned_warned.clear()

    out = resources.resolve('brom', 'common')   # must NOT raise

    assert out == rogue
    cap = capsys.readouterr()
    assert '[crumpet-emu] UNPINNED common:brom' in cap.err
    assert 'binaries/README.md' in cap.err
    assert 'not-a-brom' not in cap.out          # stdout (UART/trace) clean


def test_unpinned_warning_once_per_slot(tmp_path, monkeypatch, capsys):
    vendor = tmp_path / 'vendor'
    (vendor / 'common').mkdir(parents=True)
    (vendor / 'common' / 'brom_MT8167_MT8516_MT8362_8167.bin').write_bytes(b'x')
    monkeypatch.setattr(resources, 'VENDOR_DIR', vendor)
    monkeypatch.delenv('CRUMPET_EMU_COMMON_BROM', raising=False)
    resources._unpinned_warned.clear()

    resources.resolve('brom', 'common')
    first = capsys.readouterr().err
    assert '[crumpet-emu] UNPINNED common:brom' in first
    resources.resolve('brom', 'common')
    assert capsys.readouterr().err == ''          # second call: silent
    resources._unpinned_warned.clear()            # don't leak into other tests


def test_present_placement_only(tmp_path, monkeypatch):
    monkeypatch.setattr(resources, 'VENDOR_DIR', tmp_path)
    assert resources.present('brom', 'common') is False
    slot = tmp_path / 'common'
    slot.mkdir()
    (slot / 'brom_MT8167_MT8516_MT8362_8167.bin').write_bytes(b'x')
    assert resources.present('brom', 'common') is True   # unpinned still present
    assert resources.present('nope', 'common') is False  # unknown slot: False, never raises


def test_unknown_slot_teaches(tmp_path, monkeypatch):
    monkeypatch.setattr(resources, 'VENDOR_DIR', tmp_path)
    with pytest.raises(resources.MissingBinary) as exc:
        resources.resolve('lk', '2030')
    assert 'no manifest slot' in str(exc.value)
    assert 'manifest PR' in str(exc.value)


@needs_lk
def test_wrong_generation_served_with_warning(tmp_path, monkeypatch, capsys):
    """2021 lk.img bytes placed at the 2025:lk slot now RUN (place-and-run),
    labeled unpinned — the old refusal is retired."""
    wrong_gen = tmp_path / 'lk.img'
    shutil.copy(resources.resolve('lk', '2021'), wrong_gen)
    monkeypatch.setenv('CRUMPET_EMU_2025_LK', str(wrong_gen))
    resources._unpinned_warned.clear()

    out = resources.resolve('lk', '2025')

    assert out == wrong_gen
    assert '[crumpet-emu] UNPINNED 2025:lk' in capsys.readouterr().err
    assert not resources.available('lk', '2025')   # available stays pinned-clean
    resources._unpinned_warned.clear()


def test_hyphenated_name_sanitizes_env_var(tmp_path, monkeypatch):
    """resolve('lk-patched', ...) reads CRUMPET_EMU_2021_LK_PATCHED —
    hyphens sanitize to underscores (the raw spelling produced a var no
    shell could ever export)."""
    entry = _manifest_entry('2021:lk-patched')
    assert resources._env_var('lk-patched', '2021') == \
        'CRUMPET_EMU_2021_LK_PATCHED'

    env_copy = tmp_path / 'lk-patched.img'
    env_copy.write_bytes(b'lk-patched-stand-in')   # bytes immaterial: sha stubbed
    monkeypatch.setattr(resources, 'VENDOR_DIR', tmp_path / 'absent')
    monkeypatch.setattr(resources, '_sha256', lambda path: entry['sha256'])

    # the sanitized (exportable) var wins despite the absent vendor default
    monkeypatch.setenv('CRUMPET_EMU_2021_LK_PATCHED', str(env_copy))
    assert resources.resolve('lk-patched', '2021') == env_copy

    # the old hyphenated spelling is ignored (unusable identifier)
    monkeypatch.delenv('CRUMPET_EMU_2021_LK_PATCHED')
    monkeypatch.setenv('CRUMPET_EMU_2021_LK-PATCHED', str(env_copy))
    with pytest.raises(resources.MissingBinary) as exc:
        resources.resolve('lk-patched', '2021')
    assert 'CRUMPET_EMU_2021_LK_PATCHED' in str(exc.value)
    assert 'CRUMPET_EMU_2021_LK-PATCHED' not in str(exc.value)


def test_own_resolves(tmp_path, monkeypatch):
    """own() resolves committed artifacts under OWN_DIR with no sha gate."""
    monkeypatch.setattr(resources, 'OWN_DIR', tmp_path)
    artifact = tmp_path / 'key_continuity.json'
    artifact.write_text('{}\n')  # deliberately != manifest bytes: no gate

    assert resources.own('key_continuity.json') == artifact
    assert resources.available('key_continuity.json', 'own')

    with pytest.raises(resources.MissingBinary):
        resources.own('not_committed.json')
