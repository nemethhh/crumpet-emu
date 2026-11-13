"""Task 4 probe v2: full traceback on the first fault inside real
boot_device_init."""
import sys, struct, traceback
sys.path.insert(0, '.')
from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from crumpet_emu import resources
from crumpet_emu.flash.nand import NandChip
from crumpet_emu.flash.nfi import NfiModel, NFI_BASE
from crumpet_emu.flash.image import Flash
from crumpet_emu.preloader.emu import Emu, arm_device
from crumpet_emu.preloader.constants import BDEV, BDEV_INIT, BDEV_READ

donors = {n: resources.resolve(n, '2021')
          for n in ('brhgptpl_0', 'lk', 'tee1', 'tee2')}
chip = NandChip(); chip.load_donors(donors)
nfi = NfiModel(chip)

class ProbeEmu(Emu):
    def hook_code(self, u, address, size, user):
        if address == BDEV_INIT:
            self.events.append('bdev_init[real] entered')
            return
        return super().hook_code(u, address, size, user)

emu = ProbeEmu(Flash(b'x'*0x200, b'y'*0x200, b'z'*0x200), sbc=True)
uc = emu.uc
uc.mem_map(NFI_BASE, 0x1000)
def rd(u, a, ad, s, v, _):
    try:
        u.mem_write(ad, struct.pack({1:'<B',2:'<H',4:'<I'}[s], nfi.read(ad - NFI_BASE, s)))
    except Exception as ex:
        print(f'!! NFI read hook fault @{hex(ad)}: {ex!r}'); raise
    return True
def wr(u, a, ad, s, v, _):
    try:
        nfi.write(ad - NFI_BASE, v, s)
    except Exception as ex:
        print(f'!! NFI write hook fault @{hex(ad)}: {ex!r}'); raise
    return True
uc.hook_add(UC_HOOK_MEM_READ, rd, begin=NFI_BASE, end=NFI_BASE + 0xFFF)
uc.hook_add(UC_HOOK_MEM_WRITE, wr, begin=NFI_BASE, end=NFI_BASE + 0xFFF)
arm_device(emu)
uc.mem_write(0x102188, struct.pack('<I', 0))
try:
    r = emu.call(BDEV_INIT, (), timeout=60_000_000)
    print('boot_device_init ->', hex(r & 0xFFFFFFFF))
except Exception:
    traceback.print_exc()
    print('pc:', hex(uc.reg_read(0x98)) if False else hex(emu.uc.reg_read(Emu and 0) or 0))
ptr = struct.unpack('<I', bytes(uc.mem_read(BDEV_READ, 4)))[0]
print('bdev->read after:', hex(ptr))
