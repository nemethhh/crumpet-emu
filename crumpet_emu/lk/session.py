# Generalized from: WS/tools/lk-emu/lk_emu.py
# Upstream: in-repo audit harness (WS tools/lk-emu)
# Generalized 2026-11-01 (Task 11): donor LKEmu -> session-based LkSession.
#   Generalization seams (everything else is donor-verbatim, per-hunk line
#   citations in the task-11 report):
#   * the donor's hardcoded LK_IMG module path became the build(lk_bytes)
#     parameter (no workspace paths; the caller resolves the image via
#     crumpet_emu.resources);
#   * LKEmu builds on a bare Uc; LkSession subclasses crumpet_emu.core's
#     Session for the repo session idiom (map/write/read/rd32) — __init__
#     deliberately does NOT call Session.__init__ because the donor memory
#     map rules (no core-internal stack region is mapped), and call() is
#     shadowed by the donor call protocol;
#   * MAGIC_RET / UART_THR / UART_LSR / TIMER_REG are shared with
#     crumpet_emu.core (values identical to the donor's own constants);
#   * the donor F table gained a committed data export, seeds.json,
#     parsed by load_seeds() (R10: F below is the code-side authority for
#     the stub table; seeds.json is the extensible data export Task 12+
#     append seam entries to);
#   * Task 12 appended the USB transport seam (usb_read 0x41E1DFA8 /
#     usb_write 0x41E1E050) to seeds.json; _stub resolves them through
#     self.seeds and serves them queue-backed (usb_rx/usb_tx) — the donor F
#     table itself is untouched, and every other stub keeps donor semantics.
#   * the donor scenario mains (main()/scenario dispatch) live in
#     battery.py / the Task-16 CLI, not here.
"""Unicorn session for the crumpet 2025 LK signed-unlock path.

Runs REAL lk.img code (libtomcrypt rsa_import/rsa_verify_hash/PSS/MGF1,
SHA-256, base64, the amzn_* unlock helpers) inside Unicorn; only libc / MMIO
/ platform plumbing is stubbed with faithful semantics. Surgical entry
mode: call() / call_seed() drive single functions directly (the donor
harness's mode); scenario batteries over this session live in battery.py.

Mapping: VMA = raw_off + 0x41DFFE00 (GFH 0x200 B header, code @ 0x41E00000).

Fault model: glitch(mode) arms the donor one-shot single-instruction fault
at the RSA gate 0x41E019F4 ('ret'/'full') and its downstream checks
('stat' @0x41E019F8, 'caller' @0x41E01D3A, 'handler' @0x41E1F632) — see
_stub for the exact semantics.
"""
import json
import struct
import time
from pathlib import Path

from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE,
                     UC_HOOK_MEM_INVALID, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE,
                     UC_HOOK_INSN_INVALID)
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5,
                               UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8,
                               UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
                               UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR,
                               UC_ARM_REG_PC)

from crumpet_emu.core.devices import TIMER_REG, UART_LSR, UART_THR
from crumpet_emu.core.session import MAGIC_RET, Session

# ---- verified VMA map (VMA = raw + 0x41DFFE00) ----------------------------
# donor lk_emu.py:44-53 (BASE/LOAD renamed LK_BASE/LK_LOAD per the task-11
# brief; values unchanged). MAGIC_RET is shared with crumpet_emu.core.session
# (donor lk_emu.py:53 defines the identical 0x0011F000 sentinel).
LK_BASE = 0x41DFFE00
LK_LOAD = 0x41E00000
BSS_END = 0x41E60000          # BSS globals observed up to 0x41E5xxxx
STACK = 0x70000000
STACK_SZ = 0x100000
HEAP = 0x71000000
HEAP_SZ = 0x400000
ARGS = 0x72000000
ARGS_SZ = 0x100000
# UART_THR/UART_LSR/TIMER_REG come from crumpet_emu.core.devices — identical
# to the donor's own UART_THR, UART_LSR = 0x11005000, 0x11005014 /
# TIMER_REG = 0x10008048 (lk_emu.py:55-56).

# ---- audit-pinned function VMAs (donor lk_emu.py:59-96, verbatim) ---------
# seeds.json (next to this module) is the committed data export of this
# table plus the donor IDA seed list; load_seeds() parses it.
F = {
    'rsa_import':        0x41E0C95C,
    'rsa_verify_hash':   0x41E0CDA0,
    'rsa_free':          0x41E0C91C,
    'hash_memory':       0x41E07ECC,
    'verify_code':       0x41E01910,   # amzn_verify_code_internal
    'verify_unlock':     0x41E01A48,   # amzn_verify_unlock (flash:unlock)
    'set_otu_cert':      0x41E01BC8,   # amzn_set_onetime_unlock_cert
    'set_otu_code':      0x41E01C18,   # amzn_set_onetime_unlock_code
    'verify_otu':        0x41E01C84,   # amzn_verify_onetime_unlock_code
    'verify_otu_wrap':   0x41E01C68,
    'boot_auth':         0x41E00F58,   # verify_with_hash wrapper
    'cert_driver':       0x41E0120C,   # monolithic cert-verify driver
    'otu_code_gen':      0x41E1AF8C,   # amzn_get_one_tu_code
    'b64_decode_thunk':  0x41E08CF8,
    'b64_decode':        0x41E08C1C,
    'b64_encode':        0x41E08D0C,
    'get_pubkey':        0x41E1B05C,
    'get_cert_buf':      0x41E01ACC,
    'malloc':            0x41E207F4,
    'calloc':            0x41E20804,
    'free':              0x41E2083A,
    'realloc':           0x41E2083E,
    'memcpy':            0x41E20858,
    'memset':            0x41E20964,
    'log':               0x41E20404,
    'log2':              0x41E1FE0C,
    'sprintf':           0x41E207DA,
    'snprintf':          0x41E207AC,
    'plat_read':         0x41E10B50,   # -> sub_41E2363C(idx)
    'timer_delta':       0x41E12734,
    'fb_ok':             0x41E1E2F0,
    'fb_fail':           0x41E1E144,
    'ltc_argchk':        0x41E08E98,
    'cmd_lock_check':    0x41E0EF18,
    'idme_update':       0x41E00208,
    'fmt_print':         0x41E1E0BC,
    'mutex_lock':        0x41E09090,
}
CERT_BUF = 0x41E3D02C          # 592-byte staged otu cert
OTUCODE_BUF = 0x41E3D27C       # 256-byte staged otu code blob
OTU_CHALLENGE = 0x41E444A8     # 32-byte b64 per-session challenge cache
OTU_CHAL_FLAG = 0x41E444CC     # 'challenge generated' flag
PUBKEY_DER = 0x41E330DC        # 295-byte Amazon unlock RSA-2048 SPKI
GLITCH_ADDR = 0x41E019F4       # cbnz r0 after rsa_verify_hash (fault model)
RSA_GATE = GLITCH_ADDR         # donor name for the same site
RSA_STAT = 0x41E019F8          # cmp r6(stat),#1 - 2nd half of the gate
RSA1_CALLER = 0x41E01D3A       # cbnz r0 in verify_otu after RSA#1 (caller)
HANDLER_CHK = 0x41E1F632       # cbz r0 in flash handler after verify_otu_wrap

# canned platform registers (unit3 getvar unlock_code 0x4a616f429e27cf4b =>
# sprintf("0x%08x%08x", reg13, reg12))
PLAT_REGS = {12: 0x9E27CF4B, 13: 0x4A616F42}
TIMER_TICKS = [0x11223344]

SEEDS_PATH = Path(__file__).with_name('seeds.json')


class LkSession(Session):
    """Surgical-entry Unicorn session over the mapped 2025 LK image.

    Subclass of crumpet_emu.core.Session for the repo session idiom
    (map/write/read/rd32); Session.__init__ is NOT invoked — the donor
    memory map rules (lk_emu.py:117-127), and Session.call is shadowed by
    the donor call protocol below (seconds-based timeout, sp_args,
    signed r0, None on fault).
    """

    def __init__(self, lk_bytes: bytes, verbose: bool = True):
        self.verbose = verbose
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc = self.uc
        # donor LKEmu.__init__ (lk_emu.py:117-127); the donor's
        # `raw = LK_IMG.read_bytes()` became the lk_bytes parameter
        uc.mem_map(LK_BASE & ~0xFFFF, 0x50000)             # image + BSS headroom
        uc.mem_write(LK_BASE, lk_bytes)
        # BSS beyond file end -> zeroed (already zero after map; file is
        # 0x3A000 -> ends 0x41E39E00; extend map to BSS_END)
        uc.mem_map(0x41E40000, BSS_END - 0x41E40000)
        uc.mem_map(STACK, STACK_SZ)
        uc.mem_map(HEAP, HEAP_SZ)
        uc.mem_map(ARGS, ARGS_SZ)
        uc.mem_map(UART_THR & ~0xFFF, 0x1000)              # UART page
        uc.mem_map(TIMER_REG & ~0xFFF, 0x1000)             # timer page
        self.heap_ptr = HEAP
        self.allocs = {}
        self.uart_out = []
        self.log_out = []
        self.usb_rx = bytearray()   # Task 12 USB seam: device rx queue (host->device bytes)
        self.usb_tx = bytearray()   # Task 12 USB seam: device tx queue (device->host bytes)
        self.fault = None          # dict: {'pc': addr, 'mode': 'ret'|'full'}
        self.fault_hits = 0
        self.stop_reason = None
        self.trace = []            # Session attribute parity
        self.seeds = {}            # parsed by load_seeds()
        self._ltc_init()
        self._boot_globals()
        self._install_hooks()
        self.load_seeds()

    @classmethod
    def build(cls, lk_bytes: bytes) -> 'LkSession':
        """Map the image at LK_BASE raw and return the armed session."""
        return cls(lk_bytes)

    def _boot_globals(self):
        """Runtime-initialized globals that early boot fills before fastboot.

        Verified chains:
          sub_41E1AF24 (is_prod): *( *(0x41E38D70) -> 0x41E45E10 ) ->
              device_info ptr; reads byte [di+0x1E2] (prod flag).
        The real writer is boot init (cold image has it NULL). A zeroed
        4KB fake device-info at 0x41E58000 with prod=1 mirrors the live
        unit-3 state (prod: 1).
        """
        self.wr(0x41E58000, b'\x00' * 0x1000)
        self.wr(0x41E58000 + 0x1E2, b'\x01')          # prod flag
        self.wr(0x41E45E10, struct.pack('<I', 0x41E58000))

    def _ltc_init(self):
        """Replicate the runtime crypto init end-state.

        cert_driver 0x41E0120C prologue (memcpy @0x41E01272, 0xD0 bytes)
        fills the ltc_mp math-descriptor struct (BSS 0x41E45B34, reached via
        .data cell 0x41E38D9C) from the rodata LibTommath descriptor
        @0x41E3738C. The runtime context pointer it reads (*(0x41E38C98)) is
        BSS-zero in a cold emulation, so the identical 104-byte copy is done
        directly. Consumers verified: rsa_import 0x41E0C98C, rsa_verify_hash
        0x41E0CDF8 chain both deref cell 0x41E38D9C -> 0x41E45B34.
        """
        self.wr(0x41E45B34, self.rd(0x41E3738C, 104))

    # ------------------------------------------------------------------ mmio
    def _install_hooks(self):
        uc = self.uc

        def on_invalid(uc, access, address, size, value, user):
            self.stop_reason = (f'INVALID access={access} addr={address:#x} '
                                f'size={size} pc={uc.reg_read(UC_ARM_REG_PC):#x}')
            return False

        uc.hook_add(UC_HOOK_MEM_INVALID, on_invalid)

        def on_insn_invalid(uc, user):
            self.stop_reason = (f'INSN_INVALID at pc={uc.reg_read(UC_ARM_REG_PC):#x}')
            return False

        uc.hook_add(UC_HOOK_INSN_INVALID, on_insn_invalid)

        def on_read(uc, access, address, size, value, user):
            if address == TIMER_REG:
                TIMER_TICKS[0] += 1
                uc.mem_write(TIMER_REG, struct.pack('<I', TIMER_TICKS[0]))
            # UART LSR mapped as 0x20 (THR empty) at map time; nothing to do

        uc.hook_add(UC_HOOK_MEM_READ, on_read, begin=0x10000000, end=0x12000000)

        def on_write(uc, access, address, size, value, user):
            if address == UART_THR:
                self.uart_out.append(value & 0xFF)

        uc.hook_add(UC_HOOK_MEM_WRITE, on_write, begin=UART_THR, end=UART_THR + 4)
        uc.mem_write(UART_LSR, b'\x20')

        # ---- code stubs ------------------------------------------------
        uc.hook_add(UC_HOOK_CODE, self._stub, begin=0, end=(1 << 32) - 1)

    # ------------------------------------------------------------- helpers
    # donor rd/wr (lk_emu.py:211-218) over the inherited Session
    # read/write — identical semantics, battery keeps the donor names
    def rd(self, addr, n):
        return self.read(addr, n)

    def wr(self, addr, data):
        self.write(addr, data)

    # rd32 is inherited from Session (== donor lk_emu.py:214-215)

    def cstr(self, addr, maxlen=512):
        out = b''
        while len(out) < maxlen:
            c = self.rd(addr + len(out), 1)[0]
            if c == 0:
                break
            out += bytes([c])
        return out

    def args_at(self, sp, n):
        """Caller-saved args 1..n (r1-r3 already known); stack args 5th+."""
        vals = []
        for i in range(n):
            vals.append(self.rd32(sp + i * 4))
        return vals

    # -------------------------------------------------------------- printf
    def fmt(self, fmt, a1, a2, a3, sp, extra=6):
        args = [a1, a2, a3]
        for i in range(extra):
            args.append(self.rd32(sp + 4 + i * 4))
        out, ai = '', 0
        i = 0
        while i < len(fmt):
            c = fmt[i]
            if c == '%' and i + 1 < len(fmt):
                n = fmt[i + 1]
                if n == 's':
                    out += (self.cstr(args[ai]).decode('latin1')
                            if args[ai] else '(null)')
                    ai += 1
                    i += 2
                    continue
                if n in 'dxu':
                    v = args[ai] & 0xFFFFFFFF
                    out += (str(struct.unpack('<i', struct.pack('<I', v))[0])
                            if n == 'd' else str(v))
                    ai += 1
                    i += 2
                    continue
                if n == 'l' and i + 2 < len(fmt) and fmt[i + 2] in 'dxu':
                    v = args[ai] & 0xFFFFFFFF
                    out += str(struct.unpack('<i', struct.pack('<I', v))[0])
                    ai += 1
                    i += 3
                    continue
                if n in 'pxX':
                    v = args[ai] & 0xFFFFFFFF
                    s = f'{v:08x}' if n == 'x' else f'{v:08X}'
                    out += ('0x' + s) if n == 'p' else s
                    ai += 1
                    i += 2
                    continue
                if n == '0' and i + 3 < len(fmt) and fmt[i + 2] in 'dxu' \
                        and fmt[i + 3].isdigit():
                    w = int(fmt[i + 3])
                    v = args[ai] & 0xFFFFFFFF
                    out += f'{v:0{w}x}'
                    ai += 1
                    i += 4
                    continue
                if n == '%':
                    out += '%'
                    i += 2
                    continue
            out += c
            i += 1
        return out

    # -------------------------------------------------------------- stubs
    def _stub(self, uc, address, size, user):
        pc = address
        r = lambda n: uc.reg_read(n)
        w = lambda n, v: uc.reg_write(n, v)
        lr = r(UC_ARM_REG_LR)
        sp = r(UC_ARM_REG_SP)

        def ret(v=0):
            w(UC_ARM_REG_R0, v & 0xFFFFFFFF)
            w(UC_ARM_REG_PC, lr)

        if pc == F['malloc']:
            n = r(UC_ARM_REG_R0)
            p = self.heap_ptr
            self.heap_ptr = (self.heap_ptr + n + 15) & ~15
            self.allocs[p] = n
            ret(p)
        elif pc == F['calloc']:
            n = r(UC_ARM_REG_R0) * max(r(UC_ARM_REG_R1), 1)
            p = self.heap_ptr
            self.heap_ptr = (self.heap_ptr + n + 15) & ~15
            self.wr(p, b'\x00' * n)
            self.allocs[p] = n
            ret(p)
        elif pc == F['realloc']:
            old, n = r(UC_ARM_REG_R0), r(UC_ARM_REG_R1)
            if old == 0:
                p = self.heap_ptr
                self.heap_ptr = (self.heap_ptr + n + 15) & ~15
                self.wr(p, b'\x00' * n)
                self.allocs[p] = n
                ret(p)
            else:
                oldn = self.allocs.get(old, n)
                p = self.heap_ptr
                self.heap_ptr = (self.heap_ptr + n + 15) & ~15
                self.wr(p, b'\x00' * n)
                self.wr(p, self.rd(old, min(oldn, n)))
                self.allocs[p] = n
                ret(p)
        elif pc == F['free']:
            ret(0)
        elif pc == F['log'] or pc == F['log2']:
            f = self.cstr(r(UC_ARM_REG_R0)).decode('latin1')
            line = self.fmt(f, r(UC_ARM_REG_R1), r(UC_ARM_REG_R2),
                            r(UC_ARM_REG_R3), sp)
            self.log_out.append(line)
            if self.verbose:
                print(f'    [log] {line}')
            ret(0)
        elif pc == F['fmt_print']:
            ret(0)
        elif pc == F['sprintf'] or pc == F['snprintf']:
            dst, f = r(UC_ARM_REG_R0), r(UC_ARM_REG_R1)
            fstr = self.cstr(f).decode('latin1')
            extra = 6
            line = self.fmt(fstr, r(UC_ARM_REG_R2), r(UC_ARM_REG_R3),
                            self.rd32(sp + 4) if extra else 0, sp + 4)
            self.wr(dst, line.encode() + b'\x00')
            ret(len(line))
        elif pc == F['plat_read']:
            idx = r(UC_ARM_REG_R0)
            ret(PLAT_REGS.get(idx, 0xDEAD0000 + idx))
        elif pc == F['timer_delta']:
            ret(0x0BADF00D)
        elif pc == F['fb_ok'] or pc == F['fb_fail']:
            s = self.cstr(r(UC_ARM_REG_R0)).decode('latin1')
            tag = 'OKAY' if pc == F['fb_ok'] else 'FAIL'
            self.log_out.append(f'{tag}: {s}')
            if self.verbose:
                print(f'    [fb] {tag}: {s}')
            ret(0)
        elif pc == F['ltc_argchk']:
            f = self.cstr(r(UC_ARM_REG_R0)).decode('latin1')
            src = self.cstr(r(UC_ARM_REG_R1), 200).decode('latin1')
            line = f'{r(UC_ARM_REG_R2)}' if r(UC_ARM_REG_R2) else ''
            self.log_out.append(f'LTC_ARGCHK: {f} @ {src}:{line} from lr={lr:#x}')
            if self.verbose:
                print(f'    [LTC_ARGCHK] {f} @ ...{src[-40:]}:{line} lr={lr:#x}')
            ret(0)
        elif pc == F['idme_update']:
            name = self.cstr(r(UC_ARM_REG_R0)).decode('latin1')
            val = self.cstr(r(UC_ARM_REG_R1), 64)
            self.log_out.append(f'IDME UPDATE {name} = {val!r}')
            if self.verbose:
                print(f'    [idme] {name} = {val!r}')
            ret(0)
        elif pc == F['mutex_lock']:
            ret(0)
        elif pc == self.seeds.get('usb_read'):
            # Task 12 USB seam: queue-backed fastboot rx boundary
            # 0x41E1DFA8 (buf, maxlen) -> bytes received (0 when the host
            # queue is empty — the real one blocks; see docs/porting-notes
            # §seam). Drains usb_rx into the caller's buffer.
            buf, maxlen = r(UC_ARM_REG_R0), r(UC_ARM_REG_R1)
            n = min(maxlen, len(self.usb_rx))
            if n:
                self.wr(buf, bytes(self.usb_rx[:n]))
                del self.usb_rx[:n]
            ret(n)
        elif pc == self.seeds.get('usb_write'):
            # Task 12 USB seam: queue-backed fastboot tx boundary
            # 0x41E1E050 (buf, len) -> len. Appends the caller's bytes to
            # usb_tx (the host-side reply stream).
            buf, ln = r(UC_ARM_REG_R0), r(UC_ARM_REG_R1)
            self.usb_tx += self.rd(buf, ln)
            ret(ln)
        elif pc == RSA_GATE:
            # Fault model: fires BEFORE the `cbnz r0, fail` at 0x41E019F4
            # executes. Setting r0=0 makes the branch fall through naturally
            # (no PC redirect - unicorn TB quirk); 'full' also forces the
            # libtomcrypt stat word to 1 (r7 = local rsa-result struct).
            if self.fault and self.fault.get('armed') \
                    and self.fault.get('mode') in ('ret', 'full'):
                self.fault_hits += 1
                w(UC_ARM_REG_R0, 0)
                if self.fault.get('mode') == 'full':
                    r7 = r(UC_ARM_REG_R7)
                    self.wr(r7 + 8, struct.pack('<I', 1))
                if self.fault.get('once'):
                    self.fault['armed'] = False
        elif pc == RSA_STAT:
            # Single-instruction fault model: a well-formed PSS sig by any
            # key returns CRYPT_OK (r0=0, cbnz falls through naturally) with
            # stat=0. Corrupting ONLY this `cmp r6,#1` outcome (force r6=1
            # before it executes) models one glitched instruction.
            if self.fault and self.fault.get('armed') \
                    and self.fault.get('mode') == 'stat':
                self.fault_hits += 1
                w(UC_ARM_REG_R6, 1)
                if self.fault.get('once'):
                    self.fault['armed'] = False
        elif pc == RSA1_CALLER:
            # Single-instruction fault model: the CALLER's check of RSA#1's
            # result inside verify_otu (`cbnz r0, fail` @0x41E01D3A).
            # Forcing r0=0 before it executes = one glitched 16-bit insn;
            # everything downstream (RSA#2 w/ cert-embedded key) then runs
            # genuinely against attacker-chosen key material.
            if self.fault and self.fault.get('armed') \
                    and self.fault.get('mode') == 'caller':
                self.fault_hits += 1
                w(UC_ARM_REG_R0, 0)
                if self.fault.get('once'):
                    self.fault['armed'] = False

        elif pc == HANDLER_CHK:
            # Single-instruction fault model at the HANDLER level:
            # `cbz r0, skip-unlock` @0x41E1F632 right after bl verify_otu_wrap.
            # Forcing r0=1 (branch not taken) runs sub_41E1DFA0(unlock_status,
            # true) regardless of the verify result.
            if self.fault and self.fault.get('armed') \
                    and self.fault.get('mode') == 'handler':
                self.fault_hits += 1
                w(UC_ARM_REG_R0, 1)
                if self.fault.get('once'):
                    self.fault['armed'] = False

    # ---------------------------------------------------------------- call
    def call(self, fn, args=(), timeout=120, verbose_name=None,
             sp_args=()):
        """Donor call protocol (lk_emu.py:430-459); shadows Session.call.

        Thumb entry (PC = fn | 1), LR = MAGIC_RET as the emu_start until
        address, timeout in SECONDS (budget = timeout * 1e6 us — not
        Session's instruction count), sp_args written at [sp]..; returns
        SIGNED 32-bit r0, or None on fault with stop_reason set.
        """
        uc = self.uc
        if verbose_name and self.verbose:
            print(f'  -> call {verbose_name} {fn:#x} args={[hex(a) for a in args]}')
        regs = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3]
        for i, a in enumerate(args[:4]):
            uc.reg_write(regs[i], a)
        sp = STACK + STACK_SZ - 0x1000
        # leave room for stack-passed args (scenarios write them explicitly)
        uc.reg_write(UC_ARM_REG_SP, sp)
        for i, v in enumerate(sp_args):
            self.wr(sp + 4 * i, struct.pack('<I', v & 0xFFFFFFFF))
        uc.reg_write(UC_ARM_REG_LR, MAGIC_RET)
        uc.reg_write(UC_ARM_REG_PC, fn | 1)
        self.stop_reason = None
        t0 = time.time()
        try:
            uc.emu_start(fn | 1, MAGIC_RET, timeout=timeout * 1_000_000)
        except Exception as e:
            self.stop_reason = self.stop_reason or f'EXC {e}'
            return None
        dt = time.time() - t0
        if self.verbose:
            print(f'  <- ret r0={uc.reg_read(UC_ARM_REG_R0):#x} '
                  f'({uc.reg_read(UC_ARM_REG_R0) & 0xFFFFFFFF}) [{dt:.2f}s]'
                  + (f' STOP={self.stop_reason}' if self.stop_reason else ''))
        return uc.reg_read(UC_ARM_REG_R0) - (1 << 32) \
            if uc.reg_read(UC_ARM_REG_R0) & 0x80000000 \
            else uc.reg_read(UC_ARM_REG_R0)

    # ------------------------------------------------------------ key dump
    def dump_rsa_key(self, key_addr):
        """rsa_key = {type, *e, *d, *N, *p, *q, *qP, *dP, *dQ}; mp_int =
        {used, alloc, *dp}."""
        def mpi(addr, name):
            used, alloc, sign, dp = struct.unpack('<iiii', self.rd(addr, 16))
            if used <= 0 or used > 4096 or dp == 0:
                return f'{name}: INVALID(used={used},dp={dp:#x})'
            words = struct.unpack(f'<{used}I', self.rd(dp, used * 4))
            v = 0
            for i, wd in enumerate(words):
                v |= wd << (28 * i)   # ltm 28-bit digits (used=74 for N2048)
            return f'{name}: {v:#x} ({v.bit_length()} bits, {used} digs, alloc={alloc}, sign={sign})'

        t, e, d, N, p, q, qP, dP, dQ = struct.unpack('<9i', self.rd(key_addr, 36))
        lines = [f'rsa_key @ {key_addr:#x}: type={t}']
        for ptr, name in ((e, 'e'), (d, 'd'), (N, 'N'), (p, 'p'), (q, 'q')):
            lines.append(f'  {mpi(ptr, name)}' if ptr else f'  {name}: NULL')
        return '\n'.join(lines)

    # ------------------------------------------------------------- seeds
    def load_seeds(self):
        """Parse seeds.json -> self.seeds (name -> VA int).

        seeds.json ("functions" map) is the committed export of the donor F
        table above; later tasks append seam entries there, so this parses
        whatever the file holds (the JSON is the authority for names).
        """
        with open(SEEDS_PATH, encoding='utf-8') as fh:
            data = json.load(fh)
        self.seeds = {name: int(va, 16)
                      for name, va in data['functions'].items()}
        return self.seeds

    def call_seed(self, name, args, *, timeout=120):
        """Call seed function `name` (VA from self.seeds) donor-style.

        Thumb entry (PC = VA | 1); args[:4] in r0-r3, args[4:] at [sp]..
        per AAPCS — the donor battery's call6 shape (battery.py:22-25).
        """
        va = self.seeds[name]
        args = list(args)
        return self.call(va, args[:4], timeout=timeout,
                         sp_args=tuple(args[4:]))

    def glitch(self, mode):
        """Arm the donor one-shot single-instruction fault model.

        Modes (fault sites in _stub, donor lk_emu.py:375-428):
          'ret'|'full' - RSA gate cbnz r0 @0x41E019F4 (GLITCH_ADDR): r0=0,
              'full' also forces the libtomcrypt stat word to 1
          'stat'       - the gate's cmp r6,#1 @0x41E019F8 (force r6=1)
          'caller'     - verify_otu's cbnz r0 @0x41E01D3A (force r0=0)
          'handler'    - flash-handler cbz r0 @0x41E1F632 (force r0=1)
        One-shot: the hook disarms itself after the first hit (the donor
        battery re-arms between calls); fault_hits counts the hits.
        """
        self.fault = {'armed': True, 'mode': mode, 'once': True}
        self.fault_hits = 0
