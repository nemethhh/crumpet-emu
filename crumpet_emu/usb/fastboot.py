"""Fastboot host driver over the LK USB transport seam (Task 12).

Seam (IDA-identified against the donor lk.i64 — full call-chain evidence in
docs/porting-notes.md §seam; seeds.json entries ``usb_read``/``usb_write``):

* ``usb_read``  0x41E1DFA8 — the fastboot rx boundary ``f(buf, maxlen) ->
  total | -1``. Callers: the fastboot command loop 0x41E1E1A2 (command
  lines, maxlen 64, NUL-terminates after rx) and the download handler
  0x41E1F4B8 (raw payload).
* ``usb_write`` 0x41E1E050 — the fastboot tx boundary ``f(buf, len) ->
  len | -1``. Every reply funnels here: fb_ok/fb_fail
  (0x41E1E2F0/0x41E1E144) load the ``OKAY``/``FAIL`` prefix and tail-jump
  the reply formatter 0x41E1E0BC, which snprintf()s prefix+msg (64-byte
  cap) and calls usb_write; the download handler emits ``DATA%08x`` the
  same way; INFO replies go through 0x41E1E108 -> usb_write.

Framing, grounded in that dispatcher behavior:

* host -> device command line: ASCII ``verb:arg`` with no wire terminator
  (the command loop NUL-terminates after rx; 64-byte maxlen).
* device -> host replies: 4-byte status prefix (``OKAY``/``FAIL``/``INFO``/
  ``DATA``) + message, one 64-byte-capped unit per reply call; a ``DATA%08x``
  unit precedes the raw download payload the device then reads.

LkSession serves both seams queue-backed (``lk.usb_rx`` / ``lk.usb_tx``).
Because the surgical-entry session calls per-command handler entries
instead of the ``__noreturn`` command loop (its ``while(1)`` never returns
to MAGIC_RET), FastbootHost dispatches the handler VMAs below directly:
the queued command line stays on the wire queue for any seam-driven
consumer, and replies surface through the donor fb_ok/fb_fail stub channel
(``log_out`` entries ``OKAY: <msg>``/``FAIL: <msg>`` — donor stub semantics
preserved) plus any INFO/DATA bytes captured by the usb_write seam.
"""
from crumpet_emu.lk.session import ARGS

#: 'flash:' handler — the donor battery's flash-e2e entry (HANDLER_CHK
#: 0x41E1F632 lives inside it); takes (name, arg_ptr, arg_len)
FB_FLASH_HANDLER = 0x41E1F5C0
#: 'download:' handler — parses the %08x size, replies DATA%08x via the
#: usb_write seam, reads the payload via the usb_read seam
FB_DOWNLOAD_HANDLER = 0x41E1F4B8
#: 'getvar:' handler — registered by fastboot_init 0x41E1E3B4 at
#: 0x41E1E404 (sub_41E1DF10("getvar:", sub_41E1EA40, 1))
FB_GETVAR_HANDLER = 0x41E1EA40

# staging scratch inside the mapped ARGS region, past battery.py's KEYST
# (ARGS + 0x40000): data buffer and the command-line name/arg string
FB_STAGE_DATA = ARGS + 0x50000
FB_STAGE_CMD = ARGS + 0x58000

_STATUS_TAGS = ('OKAY', 'FAIL', 'INFO', 'DATA')


class FastbootHost:
    """Drives the emulated LK fastboot dispatcher through the USB seam."""

    def __init__(self, lk):
        self.lk = lk
        missing = [n for n in ('usb_read', 'usb_write') if n not in lk.seeds]
        if missing:
            raise ValueError(f'LkSession seeds lack the USB seam: {missing}')

    # ------------------------------------------------------------- helpers
    def _stage(self, addr, blob):
        self.lk.wr(addr, blob + b'\x00')

    def _replies(self, log0, tx0):
        """Parse reply units from the donor stub channel + the tx queue.

        OKAY/FAIL keep log-channel parsing (prefix ``'TAG: '``); tx-queue
        units carry their message after the 4-byte status tag (INFO text,
        DATA%08x size), which becomes the reply message.
        """
        status, message = '', ''
        for entry in self.lk.log_out[log0:]:
            for tag in ('OKAY', 'FAIL'):
                if entry.startswith(f'{tag}: '):
                    status, message = tag, entry[len(tag) + 2:]
        payload = bytes(self.lk.usb_tx[tx0:])
        for tag in _STATUS_TAGS:          # transport units (INFO/DATA bytes)
            if payload.startswith(tag.encode('ascii')) and not status:
                status = tag
                message = payload[len(tag):].decode('latin-1')
        return status, message, payload

    # ---------------------------------------------------------------- api
    def send(self, verb, arg='', data=b''):
        """Send one fastboot command; return (status, message, payload).

        Queues the ``verb:arg`` command line (plus ``data`` bytes for the
        download path) onto the seam's wire queue, dispatches the verb's
        emulated handler entry, and parses the reply units.
        """
        cmd = f'{verb}:{arg}' if arg else verb
        if len(cmd.encode('ascii')) > 64:
            raise ValueError('fastboot command line exceeds the 64-byte '
                             'maxlen of the command loop rx')
        log0, tx0 = len(self.lk.log_out), len(self.lk.usb_tx)
        self.lk.usb_rx += cmd.encode('ascii')

        if verb == 'flash':
            # the command loop dispatches flash handlers as
            # handler(arg_after_prefix, download_ptr, download_len); the
            # download path streams `data` (already payload bytes, e.g. the
            # b64 otucode) through the staging buffer
            self.lk.usb_rx += data
            self._stage(FB_STAGE_DATA, data)
            self._stage(FB_STAGE_CMD, arg.encode('ascii'))
            self.lk.call(FB_FLASH_HANDLER,
                         [FB_STAGE_CMD, FB_STAGE_DATA, len(data)])
        elif verb == 'download':
            # arg is the %08x size. In the cold session the REAL handler
            # faults at its entry — an unmapped fetch at pc=0 (its first
            # indirect callback; the transfer-completion function pointer
            # is boot-time state the noreturn task main initializes) —
            # BEFORE any DATA unit reaches the usb_write seam (verified
            # empirically: usb_tx is empty after the faulted call).
            # send() raises with the session stop_reason (diagnostic, not
            # a fabricated reply)
            self.lk.usb_rx += data
            self._stage(FB_STAGE_CMD, arg.encode('ascii'))
            self.lk.call(FB_DOWNLOAD_HANDLER, [FB_STAGE_CMD, 0, 0])
        elif verb == 'getvar':
            self._stage(FB_STAGE_CMD, arg.encode('ascii'))
            self.lk.call(FB_GETVAR_HANDLER, [FB_STAGE_CMD, 0, 0])
        else:
            raise ValueError(f'no emulated fastboot handler entry wired for '
                             f'verb {verb!r} (surgical entry mode — the '
                             f'command loop is __noreturn)')

        status, message, payload = self._replies(log0, tx0)
        if self.lk.stop_reason:
            # ANY fault in the dispatched call is reported — a partial reply
            # unit (a queued DATA tx, or an OKAY logged before a later
            # fault) must never mask it; surface both in the error
            partial = (f' after partial reply {status}: {message!r}'
                       if status else '')
            raise RuntimeError(f'{verb}:{arg} faulted{partial} — '
                               f'{self.lk.stop_reason}')
        return status, message, payload

    def getvar(self, name):
        """getvar:<name> -> (status, message)."""
        status, message, _ = self.send('getvar', name)
        return status, message
