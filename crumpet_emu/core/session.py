"""Core emulation session: one ARM/Thumb Unicorn instance per boot run.

Every layer (brom, preloader, lk) drives vendor code through Session: map()
pages, write() code/data, call() a Thumb function and read r0 back. call()
never hangs: it runs under an instruction budget and classifies every stop.
"""

import struct

from unicorn import (UC_ARCH_ARM, UC_ERR_FETCH_PROT, UC_ERR_FETCH_UNMAPPED,
                     UC_ERR_READ_PROT, UC_ERR_READ_UNMAPPED, UC_ERR_WRITE_PROT,
                     UC_ERR_WRITE_UNMAPPED, UC_HOOK_CODE, UC_HOOK_MEM_INVALID,
                     UC_MODE_THUMB, Uc, UcError)
from unicorn.arm_const import (UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0,
                               UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                               UC_ARM_REG_SP)

# Sentinel return address. call() points LR here; the fetch at it faults
# (it is never mapped) and that fault is classified as a normal return,
# with r0 as the function's return value.
MAGIC_RET = 0x0011F000

# Internal call stack (64 KiB), mapped by __init__; call() sets SP to its top.
STACK_BASE = 0x130000
STACK_SIZE = 0x10000

_ARG_REGS = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)

# Memory-access faults that mean "the guest touched memory it may not".
_INVALID_MEM_ERRNOS = frozenset((UC_ERR_READ_UNMAPPED, UC_ERR_WRITE_UNMAPPED,
                                 UC_ERR_FETCH_UNMAPPED, UC_ERR_READ_PROT,
                                 UC_ERR_WRITE_PROT, UC_ERR_FETCH_PROT))


class Session:
    """Thin wrapper around a Thumb-mode ARM Unicorn instance."""

    def __init__(self):
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.uc.mem_map(STACK_BASE, STACK_SIZE)
        self.stack = (STACK_BASE, STACK_SIZE)
        self.trace: list[str] = []
        self.stop_reason = ''

    def map(self, addr: int, size: int) -> None:
        self.uc.mem_map(addr, size)

    def write(self, addr: int, data: bytes) -> None:
        self.uc.mem_write(addr, bytes(data))

    def read(self, addr: int, n: int) -> bytes:
        return bytes(self.uc.mem_read(addr, n))

    def rd32(self, addr: int) -> int:
        return struct.unpack('<I', self.read(addr, 4))[0]

    def hook_code(self, fn) -> None:
        self.uc.hook_add(UC_HOOK_CODE, fn)

    def hook_mem_invalid(self, fn) -> None:
        self.uc.hook_add(UC_HOOK_MEM_INVALID, fn)

    def call(self, addr: int, args: list[int], *,
             timeout: int = 10_000_000) -> int:
        """Run a Thumb function at addr with args in r0-r3; return its r0.

        SP is set to the top of the internal stack and LR to MAGIC_RET.
        `timeout` is the instruction budget (Unicorn count); a call that
        exhausts it stops with stop_reason 'timeout' rather than hanging.
        Faults are classified into stop_reason and swallowed: callers check
        stop_reason ('magic_ret' | 'timeout' | 'invalid' | 'insn').
        """
        if timeout <= 0:
            # unicorn treats count=0 as unlimited: the call would hang
            raise ValueError(f'timeout must be positive, got {timeout!r}')
        if len(args) > 4:
            raise ValueError('at most 4 args fit r0-r3')
        for reg, value in zip(_ARG_REGS, args):
            self.uc.reg_write(reg, value)
        self.uc.reg_write(UC_ARM_REG_SP, self.stack[0] + self.stack[1])
        self.uc.reg_write(UC_ARM_REG_LR, MAGIC_RET)
        self.trace.append('call %#x args=%s' % (addr, args))
        try:
            self.uc.emu_start(addr | 1, 0, count=timeout)
            self.stop_reason = 'timeout'  # budget ran out before returning
        except UcError as exc:
            pc = self.uc.reg_read(UC_ARM_REG_PC)
            if (exc.errno == UC_ERR_FETCH_UNMAPPED and pc == MAGIC_RET):
                self.stop_reason = 'magic_ret'  # normal function return
            elif exc.errno in _INVALID_MEM_ERRNOS:
                self.stop_reason = 'invalid'
                self.trace.append('invalid mem @%#x: %s' % (pc, exc))
            else:
                self.stop_reason = 'insn'
                self.trace.append('insn fault @%#x: %s' % (pc, exc))
        result = self.uc.reg_read(UC_ARM_REG_R0)
        self.trace.append('stop %s r0=%#x' % (self.stop_reason, result))
        return result
