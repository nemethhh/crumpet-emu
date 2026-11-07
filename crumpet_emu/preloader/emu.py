# Donor: WS/tools/amonet-emu/emu_chain.py
# Upstream: in-repo harness (amonet-emu)
# Split 2026-10-31 (Task 10): donor lines 92-580 verbatim minus the
#   Flash/ChipDumpFlash classes (extracted 2026-10-31, Task 5, as
#   crumpet_emu/flash/image.py — imported by the scenarios/CLI, never
#   duplicated here). Non-verbatim hunks (enumerated in the task-10
#   report): donor module image-path globals (lines 38-42) became the
#   lazy PL_IMG()/LK_IMG()/TEE2_IMG() resolvers below (resources
#   manifest gate, no workspace paths, no import-time reads); the
#   bdev->read trampoline writes flash.image read()'s bytes to dst
#   itself (Task 5's read() returns bytes instead of writing through
#   uc), keeping the donor's unmapped-dst diagnostic + raise.

"""Preloader emulation core: real NS6548 2021 code inside Unicorn.

class Emu maps the REAL preloader text (brhgptpl_0.img content at
TEXT_BASE) plus its DRAM/SRAM/MMIO regions, and hooks only true I/O and
the handful of preloader helpers whose semantics are replicated
faithfully (see the donor docstring in crumpet_emu/preloader/__init__.py):
UART writes, the eFuse SBC word, flash reads (served from any
read(blk, count) -> bytes source, e.g. flash.image.Flash), the RSA
verify oracle, part_get/header-parse/overlap bookkeeping, and the
boot-halting oracles (usbdl handshake hang, assert panic).

The donor builds its own Uc here (verbatim base rule); it does NOT go
through crumpet_emu.core.session.Session — a documented divergence
from the repo's core session layer.
"""
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_HOOK_MEM_WRITE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5,
                               UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8,
                               UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
                               UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR,
                               UC_ARM_REG_PC)

from crumpet_emu import resources
from crumpet_emu.flash.image import GPT
from crumpet_emu.preloader.constants import (ASSERT, BDEV, BDEV_INIT, BDEV_READ,
                                             BLKSZ, BOUNCE, DRAM_BUF, EFUSE_SBC,
                                             FILE_DELTA, HDR_PARSE,
                                             HEAD_CELL, MAGIC_RET, MTEE_VERIFY,
                                             MEMCPY, OVERLAP_CHK, PART_GET,
                                             PART_LOAD, PRINTF, SCRATCH,
                                             SECMEM_REARM, SRAM_DBUF_PTR,
                                             STACK, TEE_SET_ENTRY, TEXT_BASE,
                                             TIMER_GET, TRAMP, UART_LSR,
                                             UART_THR, USB_HANDSHAKE, VERIFY_LK)


def PL_IMG():
    """Default preloader image (donor line 39 module Path -> lazy resolve)."""
    return resources.resolve('brhgptpl_0', '2021')


def LK_IMG():
    """Default stock LK image (donor line 40 module Path -> lazy resolve)."""
    return resources.resolve('lk', '2021')


def TEE2_IMG():
    """Default tee2 image (donor line 41 module Path -> lazy resolve)."""
    return resources.resolve('tee2', '2021')


def rd32(mem, a):
    return struct.unpack_from('<I', mem, a)[0]


def parse_elf_symbols(path):
    """Return {name: value} from .symtab of a 32-bit ELF."""
    d = path.read_bytes()
    e_shoff, = struct.unpack_from('<I', d, 0x20)
    e_shentsize, e_shnum = struct.unpack_from('<HH', d, 0x2E)
    syms = {}
    for i in range(e_shnum):
        sh = e_shoff + i * e_shentsize
        sh_type, = struct.unpack_from('<I', d, sh + 4)
        if sh_type != 2:  # SHT_SYMTAB
            continue
        off, size = struct.unpack_from('<II', d, sh + 16)
        link, = struct.unpack_from('<I', d, sh + 24)
        stro = struct.unpack_from('<I', d, e_shoff + link * e_shentsize + 16)[0]
        for j in range(off, off + size, 16):
            st_name, val, _, _, _, _ = struct.unpack_from('<IIIBBH', d, j)
            end = d.index(b'\x00', stro + st_name)
            name = d[stro + st_name:end].decode()
            if name:
                syms[name] = val
    return syms


def uc_cstr(uc, a, maxlen=64):
    out = b''
    while len(out) < maxlen:
        c = uc.mem_read(a + len(out), 1)[0]
        if c == 0:
            break
        out += bytes([c])
    return out.decode('latin1')


def cstr(mem, a, maxlen=256):
    out = b''
    while len(out) < maxlen:
        c = mem[a + len(out)]
        if c == 0:
            break
        out += bytes([c])
    return out.decode('latin1')


def fmt_stub(uc, r0, r1, r2, r3, sp):
    """Very small printf: %s %d %x %lu %u. Reads strings via uc."""
    def rd(a):
        return struct.unpack('<I', bytes(uc.mem_read(a, 4)))[0]
    f = uc_cstr(uc, r0, 256)
    args = [r1, r2, r3]
    # 5th+ varargs are on the stack above the return address
    for i in range(6):
        try:
            args.append(rd(sp + 4 + i * 4))
        except Exception:
            args.append(0)
    out, ai = '', 0
    i = 0
    while i < len(f):
        c = f[i]
        if c == '%' and i + 1 < len(f):
            n = f[i + 1]
            if n == 's':
                out += uc_cstr(uc, args[ai] & 0xFFFFFFFF, 128) if args[ai] else '(null)'
                ai += 1; i += 2; continue
            if n in 'dxu':
                v = args[ai] & 0xFFFFFFFF
                out += str(struct.unpack('<i', struct.pack('<I', v))[0] if n == 'd' else v)
                ai += 1; i += 2; continue
            if n == 'l' and i + 2 < len(f) and f[i + 2] in 'dxu':
                v = args[ai] & 0xFFFFFFFF
                out += str(struct.unpack('<i', struct.pack('<I', v))[0])
                ai += 1; i += 3; continue
            if n in 'pxX':
                out += hex(args[ai] & 0xFFFFFFFF); ai += 1; i += 2; continue
            if n == '%':
                out += '%'; i += 2; continue
        out += c
        i += 1
    return out


class Emu:
    def __init__(self, flash, sbc=True, log=sys.stdout, payload_syms=None,
                 stock_ok=None):
        self.f, self.sbc, self.log = flash, sbc, log
        self.payload_syms = payload_syms or {}
        self.stock_ok = stock_ok  # genuine stock image bytes: RSA passes for these
        self.timer = 0
        self.events = []          # oracle log
        self.verify_calls = 0
        self.lk_region = (0, 0)   # check_part_overlapped claim state
        self.cur_offset = 0       # sub-image offset of the current part_load call
        self.last_hdr = None      # parsed header of current sub-image
        self.current_part = None  # name of part struct most recently returned
        self.stopped = False
        self.pl_log = []      # decoded preloader prints
        self.faulted = False
        uc = self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

        uc.mem_map(0x0, 0x140000)            # SRAM0 + trampoline/stack block
        uc.mem_map(0x200000, 0x40000)        # preloader text/rodata
        uc.mem_map(0x10000000, 0x10000)      # low MMIO (efuse/wdt/timer)
        uc.mem_map(0x11005000, 0x1000)       # UART
        uc.mem_map(0x41D00000, 0x1000000)    # LK + dram_buf region
        uc.mem_map(0x600000, 0x400000)       # MTEE OS region (donor tee maddr)
        uc.mem_map(0x43000000, 0x100000)     # TEE

        pl = PL_IMG().read_bytes()
        text = pl[TEXT_BASE - FILE_DELTA: TEXT_BASE - FILE_DELTA + 0x3D000]
        uc.mem_write(0x201000, text)
        uc.mem_write(TRAMP, struct.pack('<HH', 0xDEFE, 0xDEFE))  # udf #imm

        # G pointer used by part_load (resolved from its literal pool)
        g_addr = self.resolve_g()
        uc.mem_write(g_addr, struct.pack('<I', DRAM_BUF))

        uc.hook_add(UC_HOOK_CODE, self.hook_code)
        uc.hook_add(UC_HOOK_MEM_INVALID, self.hook_mem_invalid)
        uc.hook_add(UC_HOOK_MEM_WRITE, self.hook_uart_write, begin=UART_THR, end=UART_THR + 3)

        # UART LSR always "THR empty" so payload printf never blocks
        uc.mem_write(UART_LSR, struct.pack('<I', 0x20))
        # SBC eFuse bit (bit 1 of 0x10009060) per scenario
        uc.mem_write(EFUSE_SBC, struct.pack('<I', 2 if sbc else 0))

        # payload-internal timer helpers (polled MMIO would never advance)
        for sym in ('mdelay', 'udelay', 'gpt4_get_current_tick',
                    'gpt4_tick2time_ms'):
            a = self.payload_syms.get(sym)
            if a:
                self.timer_stubs = getattr(self, 'timer_stubs', set()) | {a}

    def hook_uart_write(self, uc, access, address, size, value, user):
        if address == UART_THR:
            self.log.write(chr(value & 0xFF))
            self.log.flush()
        return True

    def resolve_g(self):
        # part_load entry: LDR R7,=lit ; ... find 'LDR.W R7, [R7]' pattern via
        # literal: disassemble-free approach -- the pool value at 0x20F6F4.
        lit = rd32(PL_IMG().read_bytes(), 0x20F6F4 - FILE_DELTA)
        return lit & 0xFFFFFFFF

    # ---------------- hooks ----------------
    def hook_mem_invalid(self, uc, access, address, size, value, user):
        kind = {16: 'FETCH', 17: 'READ', 18: 'WRITE', 19: 'READWRITE',
                20: 'FETCH'}.get(access, str(access))
        self.events.append(f'!! unmapped {kind} at {hex(address)} '
                           f'size={size} pc={hex(uc.reg_read(UC_ARM_REG_PC))}')
        return False  # surface the fault; mapping is pre-configured

    def hook_code(self, uc, address, size, user):
        if address in getattr(self, 'timer_stubs', set()):
            r0 = uc.reg_read(UC_ARM_REG_R0)
            uc.reg_write(UC_ARM_REG_R0, r0)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR) | 1)
            return
        r = uc.reg_read
        regs = {n: r(n) for n in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                                  UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR)}
        mem = None
        def need_mem():
            nonlocal mem
            if mem is None:
                mem = uc.mem_read(0x0, 0x140000)
            return mem

        if address == TRAMP:
            # bdev->read(bdev, blk, count, dst, part)
            bdev, blk, cnt, dst = regs[UC_ARM_REG_R0], regs[UC_ARM_REG_R1], \
                regs[UC_ARM_REG_R2], regs[UC_ARM_REG_R3]
            sp = regs[UC_ARM_REG_SP]
            part = rd32(need_mem(), sp)
            self.events.append(f'READ bdev={hex(bdev)} blk={blk} n={cnt} dst={hex(dst)}')
            if getattr(self, 'reads', None) is not None:
                self.reads.append((dst, blk, cnt))
            # flash.image read() returns the bytes; serve them to dst here
            # (donor Flash wrote through uc itself and printed per-block)
            data = self.f.read(blk, cnt)
            try:
                uc.mem_write(dst, data)
            except Exception:
                print(f'!! {type(self.f).__name__} read to UNMAPPED '
                      f'dst={hex(dst)} blk={blk} n={cnt}')
                raise
            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_PC, regs[UC_ARM_REG_LR] | 1)
            return

        if address == UART_THR:
            ch = regs[UC_ARM_REG_R0] & 0xFF
            self.log.write(chr(ch))
            uc.reg_write(UC_ARM_REG_PC, regs[UC_ARM_REG_LR] | 1)
            return

        if address in (PRINTF,):
            try:
                line = fmt_stub(uc, *[regs[n] for n in
                                  (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                                   UC_ARM_REG_R3)], regs[UC_ARM_REG_SP])
            except Exception as ex:
                line = (f'<printf decode failed: {ex}: r0={hex(regs[UC_ARM_REG_R0])} '
                        f'r1={hex(regs[UC_ARM_REG_R1])} r2={hex(regs[UC_ARM_REG_R2])} '
                        f'r3={hex(regs[UC_ARM_REG_R3])}>')
            self.log.write('[PL@%s] ' % hex(regs[UC_ARM_REG_LR]) + line)
            self.log.flush()
            self.pl_log.append(line)
            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_PC, regs[UC_ARM_REG_LR] | 1)
            return

        if address == VERIFY_LK:
            # RSA oracle: r0 = image address, r1 = size (per gate call site
            # 0x20F6C4: sub_201D70(load_addr, size, 0, ...)). The genuine
            # stock image passes; anything else (patched/custom) fails.
            img, size = regs[UC_ARM_REG_R0], regs[UC_ARM_REG_R1]
            data = bytes(uc.mem_read(img, size)) if size else b''
            # the loaded image is the sub-image DATA (file bytes after the
            # 512-byte partition header)
            if self.stock_ok and data == self.stock_ok[0x200:0x200 + size]:
                self.verify_calls += 1
                self.events.append('RSA_VERIFY: stock image -> PASS (prod key)')
                uc.reg_write(UC_ARM_REG_R0, 0)
            else:
                self.verify_calls += 1
                self.events.append('RSA_VERIFY_CALLED on unsigned image -> FAIL')
                uc.reg_write(UC_ARM_REG_R0, 0xFFFFFFFF)
            uc.reg_write(UC_ARM_REG_PC, regs[UC_ARM_REG_LR] | 1)
            return

        if address == USB_HANDSHAKE:
            self.events.append('!!! ENTERED USBDL HANDSHAKE -> while(1) HANG (brick)')
            self.stopped = True
            uc.emu_stop()
            return

        if address == ASSERT:
            self.events.append(f'!!! ASSERT/panic at caller '
                               f'{hex(regs[UC_ARM_REG_LR])} -> boot halt')
            self.stopped = True
            uc.emu_stop()
            return

        if address == PART_GET:
            name = uc_cstr(uc, regs[UC_ARM_REG_R0], 32)
            self.current_part = name
            if name not in GPT:
                uc.reg_write(UC_ARM_REG_R0, 0)
            else:
                start, nblk = GPT[name]
                idx = list(GPT).index(name)
                p = SCRATCH + 0x100 * (idx + 1)
                namep = SCRATCH + 0x400 + 0x40 * idx
                uc.mem_write(namep, name.encode() + b'\x00')
                blob = struct.pack('<II', start, nblk) + b'\x00' * 8 + \
                    struct.pack('<I', namep) + b'\x00' * 0x2C
                uc.mem_write(p, blob)
                uc.reg_write(UC_ARM_REG_R0, p)
            uc.reg_write(UC_ARM_REG_PC, regs[UC_ARM_REG_LR] | 1)
            return

        if address == BDEV_INIT:
            # re-arm the block device (what the real boot_device_init does to
            # the struct fields we care about)
            uc.mem_write(HEAD_CELL, struct.pack('<I', BDEV))
            uc.mem_write(BDEV + 0x00, struct.pack('<I', 0))          # id
            uc.mem_write(BDEV + 0x04, struct.pack('<I', BLKSZ))     # blksize
            uc.mem_write(BDEV + 0x14, struct.pack('<I', BOUNCE))
            uc.mem_write(BDEV + 0x1C, struct.pack('<I', 0))          # next
            uc.mem_write(BDEV_READ, struct.pack('<I', TRAMP))
            self.events.append('boot_device_init: bdev re-armed')
            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_PC, regs[UC_ARM_REG_LR] | 1)
            return

        if address == PART_LOAD:
            # track (part, sub-image offset) for the header-parse stub
            part = regs[UC_ARM_REG_R1]
            namep = rd32(bytes(uc.mem_read(part + 0x10, 4)), 0)
            name = uc_cstr(uc, namep, 32)
            self.cur_offset = regs[UC_ARM_REG_R3]
            self.reads = []   # reads issued by this part_load invocation
            self.events.append(f'part_load(part={name!r}, off={hex(self.cur_offset)}, '
                               f'addr_cell={hex(regs[UC_ARM_REG_R2])})')
            return

        if address == HDR_PARSE:
            # parse the part_hdr from the buffer the header read landed in
            # (direct dst buffer; sub-image start is 512-aligned on this bdev)
            hdst = self.reads[0][0] if self.reads else BOUNCE
            intra = self.cur_offset & (BLKSZ - 1)
            hdr = bytes(uc.mem_read(hdst + intra, 0x200))
            magic, dsize = struct.unpack_from('<II', hdr, 0)
            name = hdr[8:40].split(b'\x00')[0]
            maddr, mode = struct.unpack_from('<II', hdr, 40)
            self.last_hdr = (magic, dsize, name, maddr, mode)
            maddr_p, size_p = regs[UC_ARM_REG_R1], regs[UC_ARM_REG_R2]
            uc.mem_write(maddr_p, struct.pack('<II', maddr, mode))
            uc.mem_write(size_p, struct.pack('<I', dsize))
            if magic != 0x58881688:
                self.events.append(f'HDR BAD MAGIC {hex(magic)} -> parse error')
                uc.reg_write(UC_ARM_REG_R0, 0xFFFFFFFF)
            else:
                self.events.append(f'HDR name={name!r} dsize={hex(dsize)} '
                                   f'maddr={hex(maddr)} mode={mode}')
                uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_PC, regs[UC_ARM_REG_LR] | 1)
            return

        if address == OVERLAP_CHK:
            # faithful replication of check_part_overlapped (README semantics,
            # name table at 0x224910 == {lk, lk_a, lk_b, uboot})
            load_addr = regs[UC_ARM_REG_R1]
            magic, dsize, name, maddr, mode = self.last_hdr
            NAMES = (b'lk', b'lk_a', b'lk_b', b'uboot')
            if name in NAMES:
                self.lk_region = (load_addr, load_addr + dsize - 1)
                self.events.append(f'  overlap: {name!r} claims '
                                   f'{hex(load_addr)}-{hex(load_addr + dsize - 1)}, '
                                   f'return OK (no overlap check)')
                uc.reg_write(UC_ARM_REG_R0, 0)
            else:
                s, e = load_addr, load_addr + dsize - 1
                rs, re_ = self.lk_region
                if not (e < rs or s > re_):
                    self.events.append(f'  !!! overlap assert (239): range '
                                       f'{hex(s)}-{hex(e)} vs lk_region '
                                       f'{hex(rs)}-{hex(re_)} -> panic')
                    uc.reg_write(UC_ARM_REG_R0, 0xFFFFFFFF)
                else:
                    self.events.append(f'  overlap: {name!r} {hex(s)}-{hex(e)} OK')
                    uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_PC, regs[UC_ARM_REG_LR] | 1)
            return

        if address == 0x20192C:      # ARB fuse-version read (efuse clz decode)
            uc.reg_write(UC_ARM_REG_R0, getattr(self, 'fuse_ver', 1))
            uc.reg_write(UC_ARM_REG_PC, regs[UC_ARM_REG_LR] | 1)
            return
        if address in (0x21A560, 0x201EE8):  # TEE / LK version stamp getters
            uc.reg_write(UC_ARM_REG_R0, 1)   # stock 2021 set is internally 1
            uc.reg_write(UC_ARM_REG_PC, regs[UC_ARM_REG_LR] | 1)
            return
        if address == SECMEM_REARM:
            # identity: returns the load address unchanged; its real body
            # (mblock/secmem bookkeeping) needs live DRAM-layout globals
            uc.reg_write(UC_ARM_REG_R0, regs[UC_ARM_REG_R0])
            uc.reg_write(UC_ARM_REG_PC, regs[UC_ARM_REG_LR] | 1)
            return

        if address == MTEE_VERIFY:
            self.events.append('mtee_verify_decrypt: donor image -> OK')
            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_PC, regs[UC_ARM_REG_LR] | 1)
            return

        if address == TEE_SET_ENTRY:
            self.events.append(f'tee_set_entry({hex(regs[UC_ARM_REG_R0])})')
            uc.reg_write(UC_ARM_REG_PC, regs[UC_ARM_REG_LR] | 1)
            return

        if address == TIMER_GET:
            self.timer += 0x1000000
            uc.reg_write(UC_ARM_REG_R0, self.timer)
            uc.reg_write(UC_ARM_REG_PC, regs[UC_ARM_REG_LR] | 1)
            return

        if address == MEMCPY:
            dst, src, n = regs[UC_ARM_REG_R0], regs[UC_ARM_REG_R1], regs[UC_ARM_REG_R2]
            if n:
                data = uc.mem_read(src, n)
                uc.mem_write(dst, bytes(data))
            uc.reg_write(UC_ARM_REG_R0, dst)
            uc.reg_write(UC_ARM_REG_PC, regs[UC_ARM_REG_LR] | 1)
            return

        if address == MAGIC_RET:
            uc.emu_stop()
            return

    # ---------------- drivers ----------------
    def call(self, addr, args=(), timeout=0, count=0):
        uc = self.uc
        sp = STACK - 0x200
        extra = list(args[4:])
        for i, v in enumerate(reversed(extra)):
            sp -= 4
            uc.mem_write(sp, struct.pack('<I', v))
        uc.reg_write(UC_ARM_REG_SP, sp)
        uc.reg_write(UC_ARM_REG_LR, MAGIC_RET)
        for i, v in enumerate(args[:4]):
            uc.reg_write(UC_ARM_REG_R0 + i, v)
        uc.emu_start(addr | 1, MAGIC_RET, timeout=timeout, count=count)
        return uc.reg_read(UC_ARM_REG_R0)

    def try_call(self, addr, args=(), timeout=0):
        try:
            return self.call(addr, args, timeout=timeout)
        except Exception as ex:
            pc = self.uc.reg_read(UC_ARM_REG_PC)
            self.events.append(f'EMU FAULT: {ex} at pc={hex(pc)} '
                               f'lr={hex(self.uc.reg_read(UC_ARM_REG_LR))}')
            self.faulted = True
            return None


def craft_partition_bytes(tz_img):
    """Extract crafted sub-image (header at 0xe800) as full tee1 content."""
    return tz_img


def arm_device(emu):
    uc = emu.uc
    uc.mem_write(HEAD_CELL, struct.pack('<I', BDEV))
    uc.mem_write(BDEV + 0x00, struct.pack('<I', 0))
    uc.mem_write(BDEV + 0x04, struct.pack('<I', BLKSZ))
    uc.mem_write(BDEV + 0x14, struct.pack('<I', BOUNCE))
    uc.mem_write(BDEV + 0x1C, struct.pack('<I', 0))
    uc.mem_write(BDEV_READ, struct.pack('<I', TRAMP))
    uc.mem_write(SRAM_DBUF_PTR, struct.pack('<I', DRAM_BUF))


def part_struct(emu, name, addr):
    start, nblk = GPT[name]
    namep = SCRATCH + 0x400 + 0x40 * list(GPT).index(name)
    emu.uc.mem_write(namep, name.encode() + b'\x00')
    blob = struct.pack('<II', start, nblk) + b'\x00' * 8 + \
        struct.pack('<I', namep) + b'\x00' * 0x2C  # name is char* at +0x10
    emu.uc.mem_write(addr, blob)
    return addr
