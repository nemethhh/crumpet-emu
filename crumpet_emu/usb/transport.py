# Donor: WS/tools/kamakiri/emu/transport.py
# Upstream: R0rt1z2/kamakiri
# Copied verbatim: 2026-10-31 (import map only)

"""Transport surfaces between the host-side orchestration and a session.

Two pieces live here because both are emulation-side plumbing:

    FakeTransport   the read(n)/write(bytes) byte-stream surface that
                    modules/main_crumpet (and functions_crumpet) are
                    written against — the same shape a real USB CDC
                    device stream offers — wrapped around any
                    cmd()-shaped session (the Unicorn-backed
                    Stage2Session, or ModeledSession below). Written
                    requests are framed into session.cmd() calls and the
                    replies are handed back as a reply byte stream.

    ModeledSession  a fast Stage2Session stand-in that fronts the SAME
                    NandChip model through the SAME command semantics
                    (0x6101/0x6102/0x6103/0x3001/0x3000, statuses,
                    length and program-once checks backed by the chip
                    model) and drives the SAME harness Watchdog model,
                    advancing it by per-op tick costs measured against
                    the real BROM+stage2 harness (task 7): kick ~1.6k,
                    block erase ~2.7k, page write ~256k, page read ~196k
                    ticks per op. It exists because a full §7.4 deploy
                    streams ~13k page ops (~43 MB backup + writes +
                    readback-verify) which costs ~20 min through
                    Unicorn but seconds here; the per-op protocol path
                    itself is pinned by the layer-2 suite and by
    test_transport_framing_against_real_stage2.
"""
import struct

from crumpet_emu.brom.harness import Watchdog
from crumpet_emu.flash.nand import NandChip, PageNotErased

# wire constants — one spelling with emu.harness.Stage2Session's
MAGIC = 0xF00DD00D
STATUS_OK = 0xD0D0D0D0
STATUS_ERR = 0xF0F0F0F0
PAGE_TOTAL = NandChip.PAGE_DATA + NandChip.PAGE_SPARE


class TransportError(RuntimeError):
    """The byte-stream pairing between host and session broke."""


class ModeledReboot(RuntimeError):
    """The modeled watchdog expired mid-session (cadence violation)."""


class FakeTransport:
    """read(n)/write(bytes) surface over a cmd()-shaped session.

    Strictly one request->reply pair at a time, like the wire protocol:
    write() frames complete requests out of the byte stream and executes
    them against the session; read() drains the reply stream and raises
    if the host asks for bytes no reply carries (out of sync).

    Request stream (big-endian u32s): magic, code, args..., then the raw
    payload for payload-carrying commands (declared by the trailing
    length argument). Reply stream: status dword, then the data bytes
    for data-carrying commands — mirroring Stage2Session._reply_data_len
    exactly. Only the command set deploy uses is framed here.
    """

    # code -> (n_args, payload follows the last arg as its length)
    _SHAPE = {
        0x3000: (0, False),   # reboot
        0x3001: (0, False),   # kick watchdog
        0x5000: (2, False),   # mem read {addr, len} -> len bytes
        0x5001: (2, True),    # mem write {addr, len} + len bytes
        0x6101: (2, False),   # page read {page, len} -> 4352 bytes
        0x6102: (2, True),    # page write {page, len} + len bytes
        0x6103: (1, False),   # block erase {block}
    }

    def __init__(self, session):
        self._session = session
        self._tx = bytearray()
        self._rx = bytearray()

    # ------------------------------------------------------------ stream --
    def write(self, data: bytes) -> None:
        self._tx += bytes(data)
        self._pump()

    def read(self, n: int) -> bytes:
        if n < 0:
            raise ValueError('negative read')
        if len(self._rx) < n:
            raise TransportError(
                f'read of {n} bytes with only {len(self._rx)} in the reply '
                'stream — host/session desync')
        out = bytes(self._rx[:n])
        del self._rx[:n]
        return out

    # ------------------------------------------------------------- emu --
    def snapshot(self):
        """A NandChip-style {page: 4352B} dump of the emulated chip.

        Dry-run-only hook consumed by deploy(snapshots=[...]) and the
        Task 10/11 replay tooling; a real-device transport has no chip
        to dump and deploy must be called with snapshots=None there.
        """
        s = self._session
        chip = getattr(s, 'chip', None) or s.h.nfi.chip
        return chip.dump()

    # ------------------------------------------------------------ framing --
    def _pump(self) -> None:
        while True:
            req = self._next_request()
            if req is None:
                return
            code, args, payload = req
            status, data = self._session.cmd(code, *args, payload=payload)
            self._rx += struct.pack('>I', status & 0xFFFFFFFF)
            self._rx += bytes(data)

    def _next_request(self):
        tx = self._tx
        if len(tx) < 8:
            return None
        magic, code = struct.unpack_from('>II', tx, 0)
        if magic != MAGIC:
            raise TransportError(f'bad request magic 0x{magic:08X}')
        shape = self._SHAPE.get(code)
        if shape is None:
            raise TransportError(f'cannot frame unknown command '
                                 f'0x{code:04X}')
        n_args, has_payload = shape
        end = 8 + 4 * n_args
        if len(tx) < end:
            return None
        args = struct.unpack_from(f'>{n_args}I', tx, 8) if n_args else ()
        if has_payload:
            # the trailing argument IS the declared payload length (the
            # same framing Stage2Session.cmd puts on the wire — there is
            # no separate length dword)
            pay_len = args[-1]
            if len(tx) < end + pay_len:
                return None
            payload = bytes(tx[end:end + pay_len])
            end += pay_len
        else:
            payload = None
        del self._tx[:end]
        return code, args, payload


class ModeledSession:
    """cmd()-shaped session over the chip + watchdog models (fast).

    Command semantics mirror the real stage2 driver as pinned by the
    layer-2 suite: exact 4352-byte page lengths, program-once through
    the chip's PageNotErased, bounds through the chip's ValueError —
    every refusal is a 0xF0F0F0F0 status with no data. Every executed
    op advances the modeled device clock by its measured real cost and
    polls the watchdog, so a cadence violation raises ModeledReboot at
    the op where the window closed.
    """

    # measured against the real BROM+stage2 harness, task 7 —
    # re-measure if the stage2 driver changes
    TICKS_KICK = 1_600
    TICKS_ERASE = 2_700
    TICKS_PAGE_WRITE = 256_000
    TICKS_PAGE_READ = 196_000

    def __init__(self, chip, wdt=None, ignore_late_kicks: bool = False):
        self.chip = chip
        self.wdt = wdt if wdt is not None else Watchdog()
        self.now = 0
        # negative-control knob for the WDT-cadence test: the first kick
        # still arms the window, later kicks do not extend it
        self.ignore_late_kicks = ignore_late_kicks
        self._armed = False

    def _advance(self, ticks: int) -> None:
        """Execute `ticks` of device time, then poll the window."""
        self.now += ticks
        if self.wdt.poll(self.now) == 'reboot':
            raise ModeledReboot(f'watchdog window closed at modeled tick '
                                f'{self.wdt.reboots[-1]}')

    def cmd(self, code, *args, payload=None):
        try:
            return self._dispatch(code, args, bytes(payload or b''))
        except ModeledReboot:
            raise
        except (ValueError, PageNotErased):
            return STATUS_ERR, b''

    def _dispatch(self, code, args, payload):
        if code == 0x3001:                                   # kick
            if not self._armed:
                self.wdt.write_mode(Watchdog.MODE_ENABLE, self.now)
                self._armed = True
            if not self.ignore_late_kicks:
                self.wdt.write_restart(Watchdog.RESTART_MAGIC, self.now)
            self._advance(self.TICKS_KICK)
            return STATUS_OK, b''
        if code == 0x3000:                                   # reboot
            self._advance(self.TICKS_KICK)
            return STATUS_OK, b''
        if code == 0x6101:                                   # page read
            page, length = args
            if length != PAGE_TOTAL:
                return STATUS_ERR, b''
            data = self.chip.read_page(page)
            self._advance(self.TICKS_PAGE_READ)
            return STATUS_OK, data
        if code == 0x6102:                                   # page write
            page, length = args
            if length != PAGE_TOTAL or len(payload) != PAGE_TOTAL:
                return STATUS_ERR, b''
            self.chip.program_page(page, payload)
            self._advance(self.TICKS_PAGE_WRITE)
            return STATUS_OK, b''
        if code == 0x6103:                                   # block erase
            self.chip.erase_block(args[0])
            self._advance(self.TICKS_ERASE)
            return STATUS_OK, b''
        return STATUS_ERR, b''
