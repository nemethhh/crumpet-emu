# Donor: WS/tools/kamakiri/emu/usb_model.py
# Upstream: R0rt1z2/kamakiri
# Copied verbatim: 2026-10-31 (no emu imports — header only)

"""USB model for the MT8167 BROM harness.

The BROM drives a MUSB-style USB2.0 MAC at 0x11100000. Every access the ROM
makes to that block goes through the small helper set around fcn 0x6b26..0x6d5c
(verified by disassembly of no-alexa/brom_MT8167_MT8516_MT8362_8167.bin):

    0x6b26  ep FIFO/CSR sizing writes          (config only, no semantics read back)
    0x6b4c  TXCSR + INTRTXE config             (config only)
    0x6b74  RXCSR + INTRRXE config             (config only)
    0x6b9a  read_fifo(ep, len, buf)            (0x6bbe is a tail wrapper)
    0x6bc2  write_fifo(ep, len, buf)
    0x6c58  read CSR0 flags {sendstall, setupend}
    0x6c7c  ep0 CSR write (serv_rxpktready/dataend/serv_setupend/sendstall)
    0x6cbe  EP0 count (RXPKTRDY -> COUNT0)
    0x6cd0  TXPKTRDY set (ep0 or indexed ep)
    0x6d04  RX count for indexed ep
    0x6d26  clear RXPKTRDY for indexed ep
    0x6d44  POWER resume bit read
    0x6d5e  interrupt poll + per-endpoint handler dispatch (kept REAL; see harness)

Register map (offsets from 0x11100000), as used by the ROM:
    0x01 POWER        0x02 INTRTX u16 (W1C)    0x04 INTRRX u16 (W1C)
    0x0A INTRUSB u8 (W1C)                      0x0E INDEX
    indexed window:   0x12 CSR0/TXCSR  0x16 RXCSR  0x18 COUNT0/RXCOUNT
    FIFO ports:       0x20 + 4*ep (byte-wide)

This module keeps the register state Python-side (the harness mirrors the
few bytes the real ROM code touches into mapped memory, and re-syncs them
after every instruction — see BromHarness._apply_fixups). CdcDevice is the
host-side API: it mirrors the pyusb calls modules/load_payload.py makes, so
the exploit sequence can be replayed byte-for-byte.
"""
import struct
from collections import deque

USB_BASE = 0x11100000

# endpoint numbers the BROM CDC-ACM configuration uses
EP0 = 0
EP1 = 1

# CSR0 (indexed window, INDEX=0) bits as the ROM code uses them
CSR0_RXPKTRDY = 0x01      # read: setup/data OUT packet waiting in FIFO0
CSR0_TXPKTRDY = 0x01      # write: FIFO0 content -> host (IN data stage)
CSR0_DATAEND = 0x08
CSR0_SETUPEND = 0x10
CSR0_SENDSTALL = 0x20
CSR0_SERV_RXPKTRDY = 0x40
CSR0_SERV_SETUPEND = 0x80

# RXCSR bits (INDEX>=1)
RXCSR_RXPKTRDY = 0x01
RXCSR_SENTSTALL = 0x40
# TXCSR bits (INDEX>=1)
TXCSR_TXPKTRDY = 0x01
TXCSR_SENTSTALL = 0x20


class UsbMac:
    """Register-level model of the BROM's USB MAC.

    Host->device bytes are queued; the ROM code consumes them via
    read_fifo(). Device->host bytes are staged by write_fifo() and delivered
    when the ROM sets TXPKTRDY (the harness asks for take_*() results).
    """

    def __init__(self):
        self.intrusb = 0
        self.intrtx = 0
        self.intrrx = 0
        self.index = EP0
        # per-ep CSR/count state for the indexed window
        self.txcsr = {EP1: 0}
        self.rxcsr = {EP1: 0}
        self.count = {EP0: 0, EP1: 0}
        # EP0 control transfers are a FIFO of packets (setup, then its data
        # stage, then the next transfer...); exactly one is RXPKTRDY at a
        # time, exactly like the real MAC
        self.ep0_queue = deque()
        self.ep0_active = b''
        self.ep0_rx_ready = False
        # data queues
        self.ep1_rx = b''            # host->device bulk byte stream
        self.tx_staging = {EP0: bytearray(), EP1: bytearray()}
        self.ctrl_in = bytearray()   # delivered to host (EP0 IN data stage)
        self.ep1_in = bytearray()    # delivered to host (bulk IN)
        self.ep0_stalls = 0
        self.ctrl_transfers = []     # (bmRequestType, bRequest, wValue, wIndex)
        self.dirty = False           # host-visible queues changed

    # ---------------- interrupt semantics (W1C, mirrors fcn 0x6d5e) --------
    def read_intrusb(self):
        v = self.intrusb
        self.intrusb = 0
        return v

    def read_intrtx(self):
        v = self.intrtx
        self.intrtx = 0
        return v

    def read_intrrx(self):
        v = self.intrrx
        self.intrrx = 0
        return v

    def set_intrtx(self, bits):
        self.intrtx |= bits

    def set_intrrx(self, bits):
        self.intrrx |= bits

    # ---------------- host side (wired through CdcDevice) ------------------
    def host_setup(self, setup_pkt):
        """Deliver an 8-byte control setup packet on EP0."""
        assert len(setup_pkt) == 8
        bm, req, wval, widx = struct.unpack_from('<BBHH', setup_pkt, 0)
        self.ctrl_transfers.append((bm, req, wval, widx))
        self._ep0_push(bytes(setup_pkt))

    def host_ep0_out(self, data):
        """Deliver a control-OUT data-stage packet on EP0."""
        self._ep0_push(bytes(data))

    def _ep0_push(self, blob):
        self.ep0_queue.append(blob)
        if not self.ep0_rx_ready:
            self._ep0_advance()

    def _ep0_advance(self):
        """Retire the serviced EP0 packet and expose the next one, if any
        (RXPKTRDY + a fresh INTRTX bit 0, like the real MAC)."""
        if self.ep0_queue:
            self.ep0_active = self.ep0_queue.popleft()
            self.ep0_rx_ready = True
            self.count[EP0] = len(self.ep0_active)
            self.intrtx |= 1
            self.dirty = True
        else:
            self.ep0_rx_ready = False
            self.ep0_active = b''
            self.count[EP0] = 0

    def host_ep1_out(self, data):
        """Deliver bulk bytes on EP1 OUT (the BROM command/handshake stream)."""
        self.ep1_rx = self.ep1_rx + bytes(data)
        self.rxcsr[EP1] |= RXCSR_RXPKTRDY
        self.count[EP1] = len(self.ep1_rx)
        self.intrrx |= 1 << EP1
        self.dirty = True

    # ---------------- ROM-side FIFO semantics ------------------------------
    def read_fifo(self, ep, length, dst_addr, uc):
        """fcn 0x6b9a: pull `length` bytes from the ep RX queue into memory.

        NOTE: the BROM's CDC data-stage handler (0x746e) passes COUNT0 here
        unclamped — an oversized SET_LINE_CODING payload overflows the
        destination buffer exactly as on real hardware.
        """
        if ep == EP0:
            take, rest = self.ep0_active[:length], self.ep0_active[length:]
            self.ep0_active = rest
            data = bytes(take)
            self.count[EP0] = len(rest)
        else:
            src = self.ep1_rx
            data = bytes(src[:length])
            self.ep1_rx = src[length:]
            self.count[ep] = len(self.ep1_rx)
            if self.count[ep] == 0:
                self.rxcsr[ep] &= ~RXCSR_RXPKTRDY
        uc.mem_write(dst_addr, data)
        return data

    def write_fifo(self, ep, length, src_addr, uc):
        """fcn 0x6bc2: stage `length` bytes from memory to the ep TX FIFO."""
        data = bytes(uc.mem_read(src_addr, length))
        self.tx_staging[ep] += data

    def set_txpktrdy(self, ep):
        """fcn 0x6cd0: deliver the staged FIFO content to the host."""
        staged = bytes(self.tx_staging[ep])
        self.tx_staging[ep] = bytearray()
        if ep == EP0:
            self.ctrl_in += staged
        else:
            self.ep1_in += staged
        self.txcsr[ep] &= ~TXCSR_TXPKTRDY
        self.intrtx |= 1 << ep
        self.dirty = True

    def ep0_count(self):
        """fcn 0x6cbe: COUNT0 when RXPKTRDY, else 0."""
        return self.count[EP0] if self.ep0_rx_ready else 0

    def ep0_csr_write(self, value):
        """fcn 0x6c7c semantics for the bits the BROM sets."""
        if value & CSR0_TXPKTRDY:
            self.set_txpktrdy(EP0)
        if value & (CSR0_SERV_RXPKTRDY | CSR0_SERV_SETUPEND | CSR0_SENDSTALL):
            # packet serviced (or transfer stalled): expose the next one
            self._ep0_advance()
        if value & CSR0_SENDSTALL:
            self.ep0_stalls += 1

    def rx_count(self, ep):
        """fcn 0x6d04."""
        if self.rxcsr.get(ep, 0) & RXCSR_RXPKTRDY:
            return self.count.get(ep, 0)
        return 0

    def clear_rxpktready(self, ep):
        """fcn 0x6d26."""
        self.rxcsr[ep] &= ~RXCSR_RXPKTRDY


class CdcDevice:
    """Host-side CDC device backed by the UsbMac register model.

    Mirrors the pyusb calls modules/load_payload.py makes:
        ctrl_transfer(bmRequestType, bRequest, wValue, wIndex, data)
        write(data)   -> EP1 OUT (the BROM command stream)
    The emulated ROM consumes queued bytes whenever it polls the USB MAC, so
    the whole amonet sequence can be queued before the emulation runs once;
    device->host replies accumulate in usb.ctrl_in / usb.ep1_in.
    """

    def __init__(self, mac=None):
        self.mac = mac or UsbMac()

    def ctrl_transfer(self, bmRequestType, bRequest, wValue, wIndex, data):
        data = bytes(data) if data is not None else b''
        setup = struct.pack('<BBHHH', bmRequestType, bRequest, wValue,
                            wIndex, len(data))
        self.mac.host_setup(setup)
        if data and not (bmRequestType & 0x80):
            # control OUT data stage (the SET_LINE_CODING payload)
            self.mac.host_ep0_out(data)

    def write(self, data):
        self.mac.host_ep1_out(bytes(data))

    @property
    def replies(self):
        """Everything the device sent on EP1 IN so far."""
        return bytes(self.mac.ep1_in)
