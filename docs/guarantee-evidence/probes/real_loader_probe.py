"""Task 2 probe v3: REAL stock TEE loader sub_20E19C("tee1") against the
CRAFTED tz image — dynamic verification of P3 (*addr=0 for the TEE
sub-image) and the whole first-stage walk. Observation-only seams."""
import sys, struct
sys.path.insert(0, '.')
import crumpet_emu.preloader.emu as emu_mod
from crumpet_emu.preloader.constants import (HDR_PARSE, OVERLAP_CHK, BDEV,
                                             SCRATCH, PAYLOAD_ADDR, TEE_LOAD_ADDR)
from crumpet_emu.flash.image import Flash
from crumpet_emu import resources

class RealSeamsEmu(emu_mod.Emu):
    REAL_NOW = frozenset({HDR_PARSE, OVERLAP_CHK})
    def hook_code(self, uc, address, size, user):
        if address == HDR_PARSE:
            ctx = uc.reg_read(emu_mod.UC_ARM_REG_R0)
            hdr = bytes(uc.mem_read(ctx, 0x30))
            magic, dsize = struct.unpack_from('<II', hdr, 0)
            name = hdr[8:40].split(b'\x00')[0]
            maddr, mode = struct.unpack_from('<II', hdr, 40)
            self.last_hdr = (magic, dsize, name, maddr, mode)
            self.events.append(f'HDR[real] name={name!r} dsize={hex(dsize)} '
                               f'maddr={hex(maddr)} mode={hex(mode)}')
            return
        if address == OVERLAP_CHK:
            hdrp = uc.reg_read(emu_mod.UC_ARM_REG_R0)
            start = uc.reg_read(emu_mod.UC_ARM_REG_R1)
            name = bytes(uc.mem_read(hdrp + 8, 32)).split(b'\x00')[0]
            dsize, = struct.unpack_from('<I', bytes(uc.mem_read(hdrp + 4, 4)))
            self.events.append(f'  overlap[real]: name={name!r} start={hex(start)} '
                               f'end={hex(start + dsize - 1)}')
            return
        return super().hook_code(uc, address, size, user)

tz = resources.own('tz-lka.img').read_bytes()
stock_lk = resources.resolve('lk', '2021').read_bytes()
tee2 = resources.resolve('tee2', '2021').read_bytes()
syms = emu_mod.parse_elf_symbols(resources.own('payload-lka.elf'))
emu = RealSeamsEmu(Flash(tz, stock_lk, tee2), sbc=True, payload_syms=syms, stock_ok=stock_lk)
emu_mod.arm_device(emu)
uc = emu.uc
namep = SCRATCH + 0x90
uc.mem_write(namep, b'tee1\x00')
tee_addr, tee_size = SCRATCH + 0x48, SCRATCH + 0x4C
uc.mem_write(tee_addr, struct.pack('<I', TEE_LOAD_ADDR))
print('=== REAL sub_20E19C("tee1") on CRAFTED image ===')
ret = emu.try_call(0x20E19C, (namep, BDEV, tee_addr, 0, tee_size), timeout=120_000_000)
print(f'sub_20E19C -> {ret} ({hex(ret & 0xFFFFFFFF)}) faulted={emu.faulted} stopped={emu.stopped}')
payload = resources.own('payload-lka.bin').read_bytes()
print('payload staged at 0x101000:', bytes(uc.mem_read(PAYLOAD_ADDR, 4)) == payload[:4])
print('bdev->read now:', hex(struct.unpack('<I', bytes(uc.mem_read(0x10870C, 4)))[0]))
print('*addr cell after:', hex(struct.unpack('<I', bytes(uc.mem_read(tee_addr, 4)))[0]))
for e in emu.events:
    print('  *', e)
