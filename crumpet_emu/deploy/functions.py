# Donor: WS/tools/kamakiri/modules/functions_crumpet.py
# Upstream: R0rt1z2/kamakiri
# Copied verbatim: 2026-10-31

"""Crumpet flash primitives: page-streaming over the byte transport.

Everything here speaks the crumpet stage2 command protocol through the
plain read(n)/write(bytes) surface (emu.transport.FakeTransport against
the emulation, a USB CDC stream against hardware): big-endian u32
framing, magic 0xf00dd00d, status dword 0xD0D0D0D0/0xF0F0F0F0 first in
every reply (the donut convention pinned by the layer-2 suite).

NAND discipline baked in:
  - program-once: flash_image() erases every block the image covers
    before the first program (partitions are 64-LBA aligned, so whole-
    block erase never crosses into a neighbor);
  - readback-verify: every programmed page is read back and compared
    before the next page is programmed — a mismatch aborts the session
    (FlashError), never continues;
  - the images carry data planes only, so the host pads each page with
    0xFF spare; the bad-block-marker byte (spare byte 0 of pages 0 and
    1 of every block, per emu/nand_model.NandChip) is masked by the
    write path and verified as erased;
  - watchdog: every streaming loop kicks every KICK_EVERY_PAGES pages.
    Worst measured real-harness op pair (write + verify read, task 7)
    is ~452k ticks, so the cadence gap stays under ~29M ticks against
    the 286M-tick (22 s @ 13 MHz) window — a >=10x margin.
"""
import struct

MAGIC = 0xF00DD00D
STATUS_OK = 0xD0D0D0D0
STATUS_ERR = 0xF0F0F0F0

CMD_REBOOT = 0x3000
CMD_KICK = 0x3001
CMD_PAGE_READ = 0x6101
CMD_PAGE_WRITE = 0x6102
CMD_BLOCK_ERASE = 0x6103

PAGE_DATA = 4096
PAGE_SPARE = 256
PAGE_TOTAL = PAGE_DATA + PAGE_SPARE
PAGES_PER_BLOCK = 64

# pages of boot-region flash touched between watchdog kicks (see module
# docstring for the margin math)
KICK_EVERY_PAGES = 64

# bad-block marker layout, one spelling with emu/nand_model.NandChip
BBM_PAGE_OFFSETS = (0, 1)
BBM_SPARE_OFFSET = 0

ERASED = 0xFF


class FlashError(RuntimeError):
    """A flash command failed (status error or readback mismatch)."""


def _dword(value: int) -> bytes:
    return struct.pack('>I', value & 0xFFFFFFFF)


def command(transport, code: int, *args, payload: bytes = b'',
            reply_len: int = 0) -> bytes:
    """One framed request->reply pair; returns the reply data bytes."""
    transport.write(_dword(MAGIC) + _dword(code)
                    + b''.join(_dword(a) for a in args) + bytes(payload))
    reply = transport.read(4 + reply_len)
    status = struct.unpack_from('>I', reply, 0)[0]
    if status != STATUS_OK:
        raise FlashError(f'command 0x{code:04X} failed: status '
                         f'0x{status:08X}')
    data = reply[4:]
    if len(data) != reply_len:
        raise FlashError(f'command 0x{code:04X} reply is {len(data)} bytes, '
                         f'expected {reply_len}')
    return data


def kick(transport) -> None:
    """Kick the device watchdog (arms it on first use, then extends)."""
    command(transport, CMD_KICK)


def read_page(transport, page: int) -> bytes:
    """Read one full 4352-byte page (data + spare)."""
    return command(transport, CMD_PAGE_READ, page, PAGE_TOTAL,
                   reply_len=PAGE_TOTAL)


def read_page_range(transport, first_page: int, n_pages: int) -> list[bytes]:
    """Stream `n_pages` pages from `first_page`, kicking on cadence."""
    pages = []
    for i in range(n_pages):
        pages.append(read_page(transport, first_page + i))
        if (i + 1) % KICK_EVERY_PAGES == 0:
            kick(transport)
    return pages


def _expected_page(chunk: bytes, page: int) -> bytes:
    """The page bytes a correctly programmed page must read back as:
    the (0xFF-padded) data plane + 0xFF spare, with the BBM byte forced
    erased on the marker pages (the write path masks it)."""
    expected = bytearray(chunk.ljust(PAGE_DATA, b'\xff')
                         + b'\xff' * PAGE_SPARE)
    if page % PAGES_PER_BLOCK in BBM_PAGE_OFFSETS:
        expected[PAGE_DATA + BBM_SPARE_OFFSET] = ERASED
    return bytes(expected)


def flash_image(transport, first_page: int, image: bytes,
                part_pages: int | None = None) -> dict[int, bytes]:
    """Erase, program and readback-verify `image` at `first_page`.

    Every block the image covers is erased first (program-once
    discipline); each page is programmed, read back and compared before
    the next page is programmed, so a mismatch aborts immediately with
    at most one page of damage, inside an already-erased region. The
    watchdog is kicked every KICK_EVERY_PAGES pages. `part_pages`, when
    given, bounds the partition so an over-sized image fails before any
    erase. Returns {page: verified 4352-byte page}.
    """
    image = bytes(image)
    n_pages = -(-len(image) // PAGE_DATA)
    if not n_pages:
        raise FlashError('refusing to flash an empty image')
    if part_pages is not None and n_pages > part_pages:
        raise FlashError(f'image of {n_pages} pages exceeds partition of '
                         f'{part_pages} LBAs')
    last = first_page + n_pages                        # exclusive
    for block in range(first_page // PAGES_PER_BLOCK,
                       -(-last // PAGES_PER_BLOCK)):
        command(transport, CMD_BLOCK_ERASE, block)
        kick(transport)          # erases are rare; kick on every one

    verified: dict[int, bytes] = {}
    for i in range(n_pages):
        page = first_page + i
        chunk = image[i * PAGE_DATA:(i + 1) * PAGE_DATA]
        payload = chunk.ljust(PAGE_DATA, b'\xff') + b'\xff' * PAGE_SPARE
        command(transport, CMD_PAGE_WRITE, page, PAGE_TOTAL,
                payload=payload)
        got = read_page(transport, page)
        if got != _expected_page(chunk, page):
            raise FlashError(f'readback mismatch at page {page}: '
                             f'{got[:16].hex()} != '
                             f'{_expected_page(chunk, page)[:16].hex()}')
        verified[page] = got
        if (i + 1) % KICK_EVERY_PAGES == 0:
            kick(transport)
    return verified
