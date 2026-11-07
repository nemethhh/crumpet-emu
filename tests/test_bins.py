"""bins CLI: placement status table + drop-in installer (no hash registration)."""

import pytest

from crumpet_emu import resources


def test_status_states(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(resources, 'VENDOR_DIR', tmp_path)
    slot = tmp_path / 'common'
    slot.mkdir()
    (slot / 'brom_MT8167_MT8516_MT8362_8167.bin').write_bytes(b'x')  # unpinned
    from crumpet_emu.bins import main
    assert main(['status']) == 0
    out = capsys.readouterr().out
    assert 'unpinned' in out and 'missing' in out and 'own' in out
    assert 'common:brom' in out


def test_place_malformed_slot(tmp_path, monkeypatch, capsys):
    """A colon-less --as value (likely first-try typo) gets the teaching
    error and exit 2 — never a ValueError traceback."""
    monkeypatch.setattr(resources, 'VENDOR_DIR', tmp_path)
    donor = tmp_path / 'd.bin'
    donor.write_bytes(b'x')
    from crumpet_emu.bins import main
    assert main(['place', str(donor), '--as', 'lk']) == 2
    err = capsys.readouterr().err
    assert 'no manifest slot' in err
    assert 'GEN:NAME' in err


def test_place_pinned_and_unknown_slot(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(resources, 'VENDOR_DIR', tmp_path)
    donor = tmp_path / 'd.bin'
    donor.write_bytes(b'x')
    from crumpet_emu.bins import main
    assert main(['place', str(donor), '--as', 'common:brom']) == 0
    assert (tmp_path / 'common' / 'brom_MT8167_MT8516_MT8362_8167.bin').is_file()
    capsys.readouterr()
    assert main(['place', str(donor), '--as', '2030:lk']) == 2   # unknown slot
    err = capsys.readouterr().err
    assert 'no manifest slot' in err
    assert not (tmp_path / '2030').exists()                      # invented nothing
