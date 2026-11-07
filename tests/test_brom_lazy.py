"""brom lazy-load regression (Task 7): the donor's import-time BROM read
(brom_boot.py:68 module-level ``ROM = (WS / ...).read_bytes()``) and its
workspace-path globals are gone — importing crumpet_emu.brom.boot must not
touch any binary, and the lazy loaders must raise resources.MissingBinary
rather than a bare FileNotFoundError when the blob is absent.
"""

import sys

import pytest

from crumpet_emu import resources


def test_no_import_time_read(tmp_path, monkeypatch):
    absent = tmp_path / 'no-such-brom.bin'
    monkeypatch.setenv('CRUMPET_EMU_COMMON_BROM', str(absent))
    assert not absent.exists()

    # re-execute the module body: an import-time read of the env-pointed
    # (nonexistent) path would raise before the import completes
    sys.modules.pop('crumpet_emu.brom.boot', None)
    import crumpet_emu.brom.boot as boot

    with pytest.raises(resources.MissingBinary):
        boot.load_rom()
