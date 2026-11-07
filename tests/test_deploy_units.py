# Pins for the verbatim deploy port (crumpet_emu/deploy/, donor
# kamakiri modules/{functions_crumpet,main_crumpet}.py). Brief erratum
# ruled during this task: the brief sketched _dword as little-endian
# '<I', but the donor pins BIG-endian '>I' (functions_crumpet.py:57,
# "big-endian u32 framing" module docstring, and the reviewed stage2
# parser crumpet_emu/usb/transport.py:127 frames the same protocol
# '>I') — the donor semantics win.
"""Unit pins for the deploy port: fail-closed slot detect + framing."""
import struct

import pytest

from crumpet_emu.deploy import functions as fc
from crumpet_emu.deploy.main import SlotUndetermined, detect_active_slot


class _ScriptedTransport:
    """read(n)/write(bytes) recorder over one queued reply stream — the
    plain byte surface functions_crumpet is written against."""

    def __init__(self, reply: bytes = b''):
        self.written = b''
        self._reply = bytes(reply)

    def write(self, data: bytes) -> None:
        self.written += bytes(data)

    def read(self, n: int) -> bytes:
        chunk, self._reply = self._reply[:n], self._reply[n:]
        return chunk


def test_dword_roundtrip():
    # donor functions_crumpet.py:56-58: _dword = struct.pack('>I', ...)
    # — big-endian u32 framing, magic first, then code, then each arg.
    t = _ScriptedTransport(struct.pack('>I', fc.STATUS_OK)
                           + b'\xde\xad\xbe\xef')
    out = fc.command(t, fc.CMD_KICK, 0x11223344, reply_len=4)
    assert out == b'\xde\xad\xbe\xef'
    assert t.written == (struct.pack('>I', fc.MAGIC)
                         + struct.pack('>I', fc.CMD_KICK)
                         + struct.pack('>I', 0x11223344))
    # 0xF00DD00D most-significant-byte first pins the byte order
    assert t.written[:4] == b'\xf0\x0d\xd0\x0d'
    # a status other than STATUS_OK fails the command loudly
    bad = _ScriptedTransport(struct.pack('>I', fc.STATUS_ERR))
    with pytest.raises(fc.FlashError):
        fc.command(bad, fc.CMD_KICK)


def test_detect_active_slot_undetermined():
    # donor main_crumpet.py detect_active_slot: a GPT without misc
    # raises SlotUndetermined BEFORE any page read — the deploy then
    # performs zero writes (misc is never written by this tool).
    assert issubclass(SlotUndetermined, RuntimeError)
    reads = []

    def read_page_fn(page):
        reads.append(page)
        return b'\xff' * fc.PAGE_TOTAL

    gpt_no_misc = {'lk_a': (256, 384), 'lk_b': (640, 384)}
    with pytest.raises(SlotUndetermined):
        detect_active_slot(read_page_fn, gpt_no_misc)
    assert reads == []          # fail-closed: not one page was read
