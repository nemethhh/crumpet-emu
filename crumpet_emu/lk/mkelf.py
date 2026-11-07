# Verbatim port of: WS/tools/lk-emu/mkelf_lk.py
# Donor header (kept):
#   Wrap raw lk.img in a minimal ELF32 ARM executable at its true load VMA.
#   Mapping (verified): VMA = raw_off + 0x41DFFE00 (GFH 0x200 B; code @ 0x41E00000).
# Port note (Task 13): the donor's hardcoded RAW/OUT workspace paths became
#   wrap(raw, out=None) parameters (no workspace paths in code); every
#   constant and both struct.pack calls are byte-for-byte the donor's.
#   ENTRY 0x41E00000 == donor lk.elf e_entry (readelf-verified, 2025 gen).
"""Wrap raw lk.img in a minimal ELF32 ARM executable at its true load VMA.

Mapping (verified): VMA = raw_off + 0x41DFFE00 (GFH 0x200 B; code @ 0x41E00000).
"""
import struct

BASE, ENTRY = 0x41DFFE00, 0x41E00000


def wrap(raw: bytes, out=None) -> bytes:
    """Return the donor ELF32 wrapping of raw lk.img bytes (optionally write)."""
    ehsize, phentsize, phnum = 52, 32, 1
    data_off = ehsize + phentsize
    eh = struct.pack('<16sHHIIIIIHHHHHH',
        bytes([0x7f]) + b'ELF' + bytes([1, 1, 1, 0, 0]) + b'\x00' * 7,
        2, 40, 1, ENTRY, ehsize, 0, 0x500, ehsize, phentsize, phnum, 0, 0, 0)
    ph = struct.pack('<8I', 1, data_off, BASE, BASE, len(raw), len(raw), 7, 0x1000)
    blob = eh + ph + raw
    if out:
        open(out, 'wb').write(blob)
    return blob
