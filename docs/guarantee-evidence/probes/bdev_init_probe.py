"""Task 4 probe: can the REAL boot_device_init (sub_212EFC) run under
the preloader Emu with the NfiModel + a donor-loaded NandChip?"""
import sys, struct
sys.path.insert(0, '.')
from unicorn import (UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_INVALID)
from crumpet_emu import resources
from crumpet_emu.flash.nand import NandChip
from crumpet_emu.flash.nfi import NfiModel, NFI_BASE
from crumpet_emu.flash.image import Flash
from crumpet_emu.preloader.emu import Emu, arm_device
from crumpet_emu.preloader.constants import BDEV, BDEV_INIT, BDEV_READ

# build a donor chip: NandChip.load_donors(dict) like test_layer4
donors = {n: resources.resolve(n, '2021')
          for n in ('brhgptpl_0', 'lk', 'tee1', 'tee2')}
chip = NandChip()
chip.load_donors(donors)

emu = Emu(Flash(resources.resolve('tee2','2021').read_bytes(),
                resources.resolve('lk','2021').read_bytes(),
                resources.resolve('tee2','2021').read_bytes()), sbc=True)
uc = emu.uc
nfi = NfiModel(chip)
uc.mem_map(NFI_BASE, 0x1000)
uc.hook_add(UC_HOOK_MEM_READ, lambda u,a,ad,s,v,_:
            u.mem_write(ad, nfi.read(ad - NFI_BASE, s)) or True,
            begin=NFI_BASE, end=NFI_BASE + 0xFFF)
def w(u, a, ad, s, v, _):
    nfi.write(ad - NFI_BASE, v, s); return True
uc.hook_add(UC_HOOK_MEM_WRITE, w, begin=NFI_BASE, end=NFI_BASE + 0xFFF)

arm_device(emu)
print('bdev->read before:', hex(struct.unpack('<I', bytes(uc.mem_read(BDEV_READ,4)))[0]))
# REAL boot_device_init — no stub interception (BDEV_INIT hook fires first
# in hook_code; bypass by subclass)
class ProbeEmu(Emu): pass
ret = None
import crumpet_emu.preloader.emu as em
orig = Emu.hook_code
def hook_code(self, u, address, size, user):
    if address == BDEV_INIT:
        self.events.append('bdev_init[real] entered — real code runs')
        return
    return orig(self, u, address, size, user)
ProbeEmu.hook_code = hook_code
# rebind method on instance's class won't affect existing emu; emulate via
# direct call with a temporary guard: use try_call on a fresh Emu of subclass
emu2 = ProbeEmu(emu.f, sbc=True, payload_syms={}, stock_ok=None)
nfi2 = NfiModel(chip)
emu2.uc.mem_map(NFI_BASE, 0x1000)
emu2.uc.hook_add(UC_HOOK_MEM_READ, lambda u,a,ad,s,v,_:
            u.mem_write(ad, nfi2.read(ad - NFI_BASE, s)) or True,
            begin=NFI_BASE, end=NFI_BASE + 0xFFF)
emu2.uc.hook_add(UC_HOOK_MEM_WRITE, w, begin=NFI_BASE, end=NFI_BASE + 0xFFF)
arm_device(emu2)
emu2.uc.mem_write(0x102188, struct.pack('<I', 0))   # clear bdev list head
r = emu2.try_call(BDEV_INIT, (), timeout=60_000_000)
print('boot_device_init ->', r, 'faulted:', emu2.faulted, 'stopped:', emu2.stopped)
ptr = struct.unpack('<I', bytes(emu2.uc.mem_read(BDEV_READ, 4)))[0]
print('bdev->read after:', hex(ptr), '(pl text base 0x201000..0x23E000 = real driver fn)')
for e in emu2.events[-10:]:
    print(' *', e)
