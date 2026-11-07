"""MMIO device stubs shared by all layers: UART sink, timer, SBC eFuse.

Register addresses are MT8167 facts carried verbatim from the donor
harnesses; see docs/superpowers/specs/2026-10-31-crumpet-emu-design.md §5.3.
"""

import struct

from unicorn import (UC_ERR_MAP, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE,
                     UcError)

UART_THR = 0x11005000   # transmit holding register: byte writes are output
UART_LSR = 0x11005014   # line status register; bit 5 = THR empty
TIMER_REG = 0x10008048  # 32-bit counter: each read returns previous + 1
WDT_BASE = 0x10007000   # watchdog window base (MODE @ +0, RESTART @ +8)
EFUSE_SBC = 0x10009060  # eFuse word; bit 1 = secure boot (SBC) burned


def _map_page(uc, addr: int) -> None:
    """Map the 4 KiB page containing addr, tolerating an existing mapping."""
    try:
        uc.mem_map(addr & ~0xFFF, 0x1000)
    except UcError as exc:
        if exc.errno != UC_ERR_MAP:  # UC_ERR_MAP = already mapped here
            raise


class UartSink:
    """Collects bytes written to UART_THR; LSR always reports THR empty.

    Lines are built incrementally (a write only touches the chunk since
    the last newline); .lines always equals .text.split('\n')."""

    def __init__(self):
        self.text = ''
        self._lines_done: list[str] = []   # lines terminated by '\n'
        self._partial = ''                 # tail after the last '\n'

    @property
    def lines(self) -> list[str]:
        # identical to .text.split('\n') at every observation point
        return self._lines_done + [self._partial]

    def install(self, uc) -> None:
        _map_page(uc, UART_THR)  # LSR shares THR's page
        uc.mem_write(UART_LSR, struct.pack('<I', 0x20))
        uc.hook_add(UC_HOOK_MEM_WRITE, self._on_thr,
                    begin=UART_THR, end=UART_THR)
        uc.hook_add(UC_HOOK_MEM_READ, self._on_lsr,
                    begin=UART_LSR, end=UART_LSR)

    def _on_thr(self, uc, access, address, size, value, user_data) -> None:
        chunk = value.to_bytes(size, 'little').decode('latin-1')
        self.text += chunk
        pieces = chunk.split('\n')
        if len(pieces) == 1:           # no newline: the unterminated tail grew
            self._partial += chunk
        else:
            self._lines_done.append(self._partial + pieces[0])
            self._lines_done.extend(pieces[1:-1])
            self._partial = pieces[-1]

    def _on_lsr(self, uc, access, address, size, value, user_data) -> None:
        # Read hooks fire before the load commits, so rewriting the word
        # here changes what the guest reads (verified against unicorn 2.1.4).
        uc.mem_write(UART_LSR, struct.pack('<I', 0x20))


class TimerStub:
    """Monotonic timer word: every guest read returns previous value + 1."""

    def __init__(self):
        self.count = 0

    def install(self, uc) -> None:
        _map_page(uc, TIMER_REG)
        uc.mem_write(TIMER_REG, struct.pack('<I', 0))
        uc.hook_add(UC_HOOK_MEM_READ, self._on_read,
                    begin=TIMER_REG, end=TIMER_REG)

    def _on_read(self, uc, access, address, size, value, user_data) -> None:
        self.count += 1
        uc.mem_write(TIMER_REG, struct.pack('<I', self.count))


class EfuseStub:
    """Static eFuse word backed by real memory; bit 1 set iff SBC burned."""

    def __init__(self, sbc: bool):
        self.sbc = sbc

    def install(self, uc) -> None:
        _map_page(uc, EFUSE_SBC)
        uc.mem_write(EFUSE_SBC, struct.pack('<I', 0b10 if self.sbc else 0))


def arm_devices(session, *, uart: bool = True, timer: bool = True,
                efuse: EfuseStub | None = None) -> list:
    """Install the standard device stubs on a Session; returns the stubs."""
    stubs = []
    if uart:
        sink = UartSink()
        sink.install(session.uc)
        stubs.append(sink)
    if timer:
        timer_stub = TimerStub()
        timer_stub.install(session.uc)
        stubs.append(timer_stub)
    if efuse is not None:
        efuse.install(session.uc)
        stubs.append(efuse)
    return stubs
