# Donor: WS/tools/kamakiri/emu/gpt.py
# Upstream: R0rt1z2/kamakiri
# Copied verbatim: 2026-10-31

"""GPT parsing for the crumpet NAND layout (4096-byte LBAs).

The 2021 brhgptpl_*.img donors are MTK "BOOTLOADER!" NFI images that embed
the device GPT: GPT LBA l lives at file offset GPT_FILE_BASE + l * 4096,
where GPT_FILE_BASE = 0x2000 (the GPT header, LBA 1, sits at file offset
0x3000, page 3 of the image; LBA 0 at 0x2000 is the zeroed protective MBR
slot). This is the placement already proven in tools/amonet-emu/emu_chain.py,
whose GPT dict holds these LBAs times 8 for the 512-byte boot device:
tee1=(3584*8, 1280*8), lk_a=(256*8, 384*8), tee2=(8768*8, 1280*8).

Header and partition-entry CRC32s are validated, so garbage in place of a
GPT fails loudly instead of returning a bogus table.
"""
import struct
import zlib

LBA_BYTES = 4096           # GPT logical block size on this device
GPT_FILE_BASE = 0x2000     # file offset of GPT LBA 0 inside brhgptpl images
GPT_HEADER_LBA = 1         # header is at GPT_FILE_BASE + 1 * LBA_BYTES

_ENTRY_TYPE_GUID_LEN = 16


def parse_gpt_from_image(brhgptpl0_bytes: bytes) -> dict[str, tuple[int, int]]:
    """Parse a 2021 brhgptpl image into {partition: (start_lba, size_lba)}.

    LBAs are the 4096-byte units the boot ROM uses; size is inclusive
    (end - start + 1). Partition order follows the on-disk entry order.
    """
    d = brhgptpl0_bytes
    hdr = GPT_FILE_BASE + GPT_HEADER_LBA * LBA_BYTES
    if d[hdr:hdr + 8] != b'EFI PART':
        raise ValueError(f'no GPT header at file offset {hdr:#x}')

    hdr_size, hdr_crc = struct.unpack_from('<II', d, hdr + 12)
    body = bytearray(d[hdr:hdr + hdr_size])
    body[16:20] = b'\x00' * 4  # CRC field itself is zeroed for the check
    if zlib.crc32(body) & 0xFFFFFFFF != hdr_crc:
        raise ValueError('GPT header CRC32 mismatch')

    cur_lba, = struct.unpack_from('<Q', d, hdr + 24)
    ents_lba, = struct.unpack_from('<Q', d, hdr + 72)
    n_ents, ent_size, ents_crc = struct.unpack_from('<III', d, hdr + 80)
    base = hdr - cur_lba * LBA_BYTES  # file offset of GPT LBA 0
    ents_off = base + ents_lba * LBA_BYTES
    blob = d[ents_off:ents_off + n_ents * ent_size]
    if len(blob) != n_ents * ent_size or \
            zlib.crc32(blob) & 0xFFFFFFFF != ents_crc:
        raise ValueError('GPT partition-entry CRC32 mismatch')

    parts: dict[str, tuple[int, int]] = {}
    for i in range(n_ents):
        entry = blob[i * ent_size:(i + 1) * ent_size]
        if entry[:_ENTRY_TYPE_GUID_LEN] == b'\x00' * _ENTRY_TYPE_GUID_LEN:
            continue  # unused entry slot
        start, end = struct.unpack_from('<QQ', entry, 32)
        name = entry[56:128].decode('utf-16-le').rstrip('\x00')
        parts[name] = (start, end - start + 1)
    return parts
