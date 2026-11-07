"""USB model smoke test (Task 6): the donor-documented CDC cycle.

One enumeration/handshake cycle exactly as the donor's own docs define it:
CdcDevice "Mirrors the pyusb calls modules/load_payload.py makes" and the
donor harness replays the same round (_kamakiri2: "oversized
SET_LINE_CODING (12-byte payload = 8-byte linecode + the 4-byte pointer)
+ GET_DESCRIPTOR kicker, exactly as modules/load_payload.py da_read_write()
does"), with the EP1 command stream and its EP1 IN reply.

The brief's example assert (first device-descriptor byte 0x12) is not
producible by the donor code: usb_model carries no descriptor bytes and an
EP0 IN stage raises KeyError in set_txpktrdy (txcsr has no EP0 key) —
verified against the donor tree before porting. Per the brief ("adjust
test to the value the donor code produces") the test pins the bytes the
donor flow actually produces: the 8-byte setup packets (GET_DESCRIPTOR
kicker: bmRequestType 0x80, wLength 9), the oversized SET_LINE_CODING
data stage delivered unclamped (COUNT0 semantics), and the stage1 reply
pattern the donor's own online check watches for.
"""

import struct

from crumpet_emu.usb.model import (CSR0_DATAEND, CSR0_SERV_RXPKTRDY,
                                   RXCSR_RXPKTRDY, EP0, EP1, CdcDevice,
                                   UsbMac)

GET_DESCRIPTOR = 6
SET_LINE_CODING = 0x20
# 12-byte oversized SET_LINE_CODING payload: 8-byte linecode + the 4-byte
# pointer it smuggles (harness._kamakiri2 / load_payload.py da_read_write)
LINECODE12 = bytes((0x00, 0xC2, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00,
                    0x0D, 0xD0, 0x0D, 0xF0))
MAGIC = 0xF00DD00D            # harness Stage2Session.MAGIC command dword
STAGE1_PATTERN = b'\xA1\xA2\xA3\xA4'   # harness stage1-online EP1 tail


class Mem:
    """The only uc surface usb_model touches: mem_write / mem_read."""

    def __init__(self):
        self.b = {}

    def mem_write(self, addr, data):
        for i, byte in enumerate(data):
            self.b[addr + i] = byte

    def mem_read(self, addr, length):
        return bytes(self.b.get(addr + i, 0) for i in range(length))


def test_cdc_enumeration():
    uc = Mem()
    mac = UsbMac()
    cdc = CdcDevice(mac)

    # host: the da_read_write round — oversized SET_LINE_CODING (ctrl OUT
    # with data stage), then the GET_DESCRIPTOR(CONFIG) kicker, wLength 9
    cdc.ctrl_transfer(0x21, SET_LINE_CODING, 0, 0, LINECODE12)
    cdc.ctrl_transfer(0x80, GET_DESCRIPTOR, 0x0200, 0, bytes(9))

    # ROM side (fcn 0x6d5e poll -> 0x6cbe count -> 0x6b9a FIFO -> 0x6c7c
    # CSR0): the setup packet is waiting on EP0
    assert mac.read_intrtx() == 1 << EP0
    assert mac.ep0_count() == 8
    setup = mac.read_fifo(EP0, mac.ep0_count(), 0x1000, uc)
    assert setup == struct.pack('<BBHHH', 0x21, SET_LINE_CODING, 0, 0, 12)
    # both host transfers are queued before the ROM drains (the model's
    # documented queue-then-consume design)
    assert mac.ctrl_transfers == [(0x21, SET_LINE_CODING, 0, 0),
                                   (0x80, GET_DESCRIPTOR, 0x0200, 0)]

    # ROM services the setup: the data stage becomes the active packet and
    # COUNT0 delivers it unclamped (the donor-documented overflow path)
    mac.ep0_csr_write(CSR0_SERV_RXPKTRDY)
    assert mac.read_intrtx() == 1 << EP0
    assert mac.ep0_count() == 12
    assert mac.read_fifo(EP0, mac.ep0_count(), 0x1000, uc) == LINECODE12
    mac.ep0_csr_write(CSR0_SERV_RXPKTRDY | CSR0_DATAEND)
    # DATAEND does not retire the transfer — retirement happens via the
    # CSR0_SERV_RXPKTRDY bit in this same write (_ep0_advance); the queued
    # kicker setup becomes the active EP0 packet, with a fresh INTRTX bit 0
    assert mac.read_intrtx() == 1 << EP0
    assert mac.ep0_count() == 8
    kicker = mac.read_fifo(EP0, mac.ep0_count(), 0x1000, uc)
    assert kicker == struct.pack('<BBHHH', 0x80, GET_DESCRIPTOR, 0x0200, 0, 9)
    assert mac.ctrl_transfers[-1] == (0x80, GET_DESCRIPTOR, 0x0200, 0)
    mac.ep0_csr_write(CSR0_SERV_RXPKTRDY)
    assert not mac.ep0_rx_ready and mac.ep0_count() == 0

    # host: the command stream goes out on EP1 (cdc.write)
    cmd = struct.pack('<I', MAGIC)
    cdc.write(cmd)
    assert mac.read_intrrx() == 1 << EP1
    assert mac.rx_count(EP1) == len(cmd)
    assert mac.rxcsr[EP1] & RXCSR_RXPKTRDY
    assert mac.read_fifo(EP1, mac.rx_count(EP1), 0x1000, uc) == cmd
    assert not mac.rxcsr[EP1] & RXCSR_RXPKTRDY   # drained: auto-cleared
    mac.clear_rxpktready(EP1)

    # ROM: the stage1-style reply is staged and delivered on EP1 IN
    # (fcn 0x6bc2 write_fifo + 0x6cd0 TXPKTRDY); the host reads replies
    uc.mem_write(0x2000, STAGE1_PATTERN)
    mac.write_fifo(EP1, len(STAGE1_PATTERN), 0x2000, uc)
    mac.set_txpktrdy(EP1)
    assert cdc.replies.endswith(STAGE1_PATTERN)
    assert mac.ep0_stalls == 0
