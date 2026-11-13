"""Task 2 probe v2: observation-only hooks at HDR_PARSE/OVERLAP_CHK;
real vendor code executes. Runs calibrate + crafted chain phase 1."""
import io, sys, struct, contextlib
sys.path.insert(0, '.')
import crumpet_emu.preloader.emu as emu_mod
import crumpet_emu.preloader.scenarios as scen
from crumpet_emu.preloader.constants import HDR_PARSE, OVERLAP_CHK
from crumpet_emu.flash.image import Flash
from crumpet_emu import resources

NAME_TABLE = 0x224910
LK_REGION = NAME_TABLE + 0x10

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
            return  # real code runs
        if address == OVERLAP_CHK:
            hdrp = uc.reg_read(emu_mod.UC_ARM_REG_R0)
            start = uc.reg_read(emu_mod.UC_ARM_REG_R1)
            name = bytes(uc.mem_read(hdrp + 8, 32)).split(b'\x00')[0]
            self.events.append(f'  overlap[real]: name={name!r} start={hex(start)} '
                               f'pre_region={[hex(x) for x in self.guest_lk_region()]}')
            return  # real code runs
        return super().hook_code(uc, address, size, user)
    def guest_lk_region(self):
        import struct as s
        return s.unpack('<II', bytes(self.uc.mem_read(LK_REGION, 8)))

emu_mod.Emu = RealSeamsEmu
scen.Emu = RealSeamsEmu

buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    ok = scen.calibrate(sbc=True)
print('calibrate ->', ok)
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    ok = scen.stock_boot(sbc=True)
print('stock_boot ->', ok)

print('== crafted chain (phase 1) ==')
from crumpet_emu.preloader.emu import arm_device, part_struct, parse_elf_symbols
from crumpet_emu.preloader.constants import BDEV, SCRATCH, PAYLOAD_ADDR
tz = resources.own('tz-lka.img').read_bytes()
stock_lk = resources.resolve('lk', '2021').read_bytes()
tee2 = resources.resolve('tee2', '2021').read_bytes()
syms = parse_elf_symbols(resources.own('payload-lka.elf'))
emu = RealSeamsEmu(Flash(tz, stock_lk, tee2), sbc=True, payload_syms=syms, stock_ok=stock_lk)
arm_device(emu)
tee1_part = part_struct(emu, 'tee1', SCRATCH)
addr_cell, size_cell = SCRATCH + 0x40, SCRATCH + 0x44
emu.uc.mem_write(addr_cell, struct.pack('<I', 0))
ret = emu.try_call(emu_mod.PART_LOAD, (BDEV, tee1_part, addr_cell, 0, size_cell), timeout=60_000_000)
print('part_load(tee1 crafted) ->', ret, 'faulted:', emu.faulted, 'stopped:', emu.stopped)
payload = resources.own('payload-lka.bin').read_bytes()
print('payload staged:', bytes(emu.uc.mem_read(PAYLOAD_ADDR, 4)) == payload[:4])
print('bdev->read now:', hex(struct.unpack('<I', bytes(emu.uc.mem_read(0x10870C, 4)))[0]))
print('lk_region after crafted load:', [hex(x) for x in emu.guest_lk_region()])
for e in emu.events:
    if 'real' in e or 'READ' in e or '!!' in e or 'EMU' in e:
        print('  *', e)
