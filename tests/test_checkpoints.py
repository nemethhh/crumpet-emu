"""Checkpoint save/restore tests (real Unicorn, no mocks).

Round-trip identity: a saved session's RAM (sentinel word), code page and
registers come back intact after RAM was dirtied post-save. Transport
state: opaque caller blobs (`extra`) survive the round trip.
"""

import pickle
import struct

import pytest
from unicorn.arm_const import UC_ARM_REG_R0

from crumpet_emu.core.checkpoints import TrackedSession, restore, save

CODE = 0x00100000  # 4 KiB code page, mapped by the test session
SENTINEL = CODE + 0x800  # sentinel word lives inside the code page


def _session():
    s = TrackedSession()
    s.map(CODE, 0x1000)
    s.write(CODE, bytes.fromhex('4018') + bytes.fromhex('7047'))  # adds r0,r0,r1; bx lr
    return s


def test_roundtrip_identity(tmp_path):
    s = _session()
    assert s.call(CODE, [2, 3]) == 5  # mutate regs + stack before saving
    s.write(SENTINEL, struct.pack('<I', 0xDEADBEEF))
    s.uc.reg_write(UC_ARM_REG_R0, 0x1234)   # pin a register across the trip
    path = save(s, tmp_path / 'ckpt.bin')

    s.write(SENTINEL, struct.pack('<I', 0xCAFEBABE))  # dirty RAM post-save
    s.uc.reg_write(UC_ARM_REG_R0, 0x5A5A)             # dirty r0 post-save
    s2, extra = restore(path)

    assert s2.rd32(SENTINEL) == 0xDEADBEEF  # pre-save sentinel restored
    assert s2.uc.reg_read(UC_ARM_REG_R0) == 0x1234  # pre-save register restored
    assert s2.call(CODE, [2, 3]) == 5  # restored session still executes
    assert extra == {}


def test_restore_rejects_non_dict_blob(tmp_path):
    """A pickled non-dict (corrupt/foreign file) must ValueError, not
    crash on .get/.['regions'] access."""
    p = tmp_path / 'notdict.bin'
    with open(p, 'wb') as fh:
        pickle.dump(['v', 1], fh)
    with pytest.raises(ValueError):
        restore(p)


def test_restore_preserves_transport_state(tmp_path):
    s = _session()
    path = save(s, tmp_path / 'ckpt.bin', extra={'usb_rx': b'\x01\x02'})
    s2, extra = restore(path)
    assert extra == {'usb_rx': b'\x01\x02'}
