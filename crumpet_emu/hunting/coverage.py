"""AFL-style edge coverage bitmap over a Unicorn code hook (Task 15).

New code (no donor port). install(uc) registers one UC_HOOK_CODE callback
that folds every executed edge into a 64 KiB map of 1-byte saturating hit
counters (self.bitmap) — the AFL-classic map shape (65536 slots).

Edge index scheme (classic AFL lineage, documented per the brief): with
from = the previously executed PC and to = the current PC,

    index = ((from ^ to) >> 1) & 0xFFFF

The XOR of consecutive PCs keys the slot to the CFG transition (A->B
differs from A->C), and >>1 discards the low carry bit; from starts at 0,
so the first edge encodes the entry PC. A slot saturates at 255 hits —
edges() counts NONZERO slots (distinct edges executed), not hit counts,
which is the coverage signal input scoring wants.

install(uc) accepts either spelling of "register a code hook" in this repo:
a core Session (its hook_code wrapper) or a raw unicorn Uc (hook_add).
"""

from unicorn import UC_HOOK_CODE


class EdgeBitmap:
    MAP_SIZE = 0x10000  # 64 KiB, AFL-classic

    def __init__(self):
        self.bitmap = bytearray(self.MAP_SIZE)
        self._prev_pc = 0  # 0 => the first edge encodes the entry PC

    def install(self, uc) -> None:
        add = getattr(uc, 'hook_code', None)
        if callable(add):                  # core Session idiom
            add(self._on_insn)
        else:                              # raw unicorn Uc
            uc.hook_add(UC_HOOK_CODE, self._on_insn)

    def _on_insn(self, uc, address, size, user_data=None):
        idx = ((self._prev_pc ^ address) >> 1) & 0xFFFF
        if self.bitmap[idx] < 0xFF:
            self.bitmap[idx] += 1
        self._prev_pc = address

    def edges(self) -> int:
        """Number of distinct edges executed (nonzero bitmap slots)."""
        return sum(1 for b in self.bitmap if b)
