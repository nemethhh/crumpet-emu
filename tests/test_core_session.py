"""Core Session + device stub tests (real Unicorn, no mocks).

The MMIO writes/reads go through tiny guest-code snippets because Unicorn
memory hooks only fire on emulated CPU accesses, never on host-side
uc.mem_write/uc.mem_read.
"""

import pytest

from crumpet_emu.core.devices import (EFUSE_SBC, TIMER_REG, UART_LSR, UART_THR,
                                      EfuseStub, UartSink, arm_devices)
from crumpet_emu.core.session import Session

CODE = 0x00100000  # 4 KiB code page; Session maps its own stack internally

# Thumb snippets taking their operand address in r1, returning to LR.
STRB_R0_R1 = bytes.fromhex('0870') + bytes.fromhex('7047')  # strb r0,[r1]; bx lr
LDR_R0_R1 = bytes.fromhex('0868') + bytes.fromhex('7047')  # ldr r0,[r1]; bx lr


def _session():
    s = Session()
    s.map(CODE, 0x1000)
    return s


def test_call_runs_thumb_adds_and_returns_r0():
    s = _session()
    s.write(CODE, bytes.fromhex('4018') + bytes.fromhex('7047'))  # adds r0,r0,r1; bx lr
    assert s.call(CODE, [2, 3]) == 5
    assert s.stop_reason == 'magic_ret'


def test_uart_and_timer_stubs_serve_mmio():
    s = _session()
    stubs = arm_devices(s)
    sink = next(st for st in stubs if isinstance(st, UartSink))
    s.write(CODE, STRB_R0_R1)
    s.write(CODE + 8, LDR_R0_R1)
    s.call(CODE, [ord('h'), UART_THR])
    s.call(CODE, [ord('i'), UART_THR])
    assert 'hi' in sink.text
    assert s.call(CODE + 8, [0, UART_LSR]) == 0x20  # LSR: THR always empty
    assert s.call(CODE + 8, [0, TIMER_REG]) == 1  # timer: +1 per read
    assert s.call(CODE + 8, [0, TIMER_REG]) == 2


def test_call_stop_paths_invalid_and_timeout():
    """Fault classification: a call into unmapped memory stops 'invalid';
    an exhausted budget stops 'timeout' (never hangs)."""
    s = _session()
    assert s.call(0x00200000, []) == 0      # unmapped fetch
    assert s.stop_reason == 'invalid'

    s.write(CODE, bytes.fromhex('fee7'))    # b . (halfword e7fe) — never returns
    s.call(CODE, [], timeout=64)
    assert s.stop_reason == 'timeout'


def test_call_rejects_nonpositive_timeout():
    """timeout <= 0 must ValueError: unicorn treats count=0 as unlimited
    and the call would hang instead of stopping."""
    s = _session()
    for bad in (0, -1):
        with pytest.raises(ValueError):
            s.call(CODE, [], timeout=bad)


def test_uart_sink_lines_built_incrementally():
    """Complete lines append on '\n'; .lines always equals
    .text.split('\n'), including the unterminated tail."""
    s = _session()
    stubs = arm_devices(s)
    sink = next(st for st in stubs if isinstance(st, UartSink))
    s.write(CODE, STRB_R0_R1)
    for ch in b'ab\nc':
        s.call(CODE, [ch, UART_THR])
        assert sink.lines == sink.text.split('\n')
    assert sink.text == 'ab\nc'
    assert sink.lines == ['ab', 'c']


def test_efuse_sbc_bit_follows_construction():
    for sbc, expected in ((True, 0b10), (False, 0)):
        s = _session()
        arm_devices(s, uart=False, timer=False, efuse=EfuseStub(sbc=sbc))
        assert s.rd32(EFUSE_SBC) & 0b10 == expected
