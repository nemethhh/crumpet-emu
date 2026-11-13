"""Task 4 probe v3: why does the chip probe (0x213E6A) fail? PL log +
first NFI register traffic."""
import sys, struct
sys.path.insert(0, '.')
from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from crumpet_emu import resources
from crumpet_emu.flash.nand import NandChip
from crumpet_emu.flash.nfi import NfiModel, NFI_BASE
from crumpet_emu.flash.image import Flash
from crumpet_emu.preloader.emu import Emu, arm_device
from crumpet_emu.preloader.constants import BDEV_INIT

donors = {n: resources.resolve(n, '2021')
          for n in ('brhgptpl_0', 'lk', 'tee1', 'tee2')}
chip = NandChip(); chip.load_donors(donors)
nfi = NfiModel(chip)
traffic = []

class ProbeEmu(Emu):
    def hook_code(self, u, address, size, user):
        if address == BDEV_INIT:
            return
        return super().hook_code(u, address, size, user)

emu = ProbeEmu(Flash(b'x'*0x200, b'y'*0x200, b'z'*0x200), sbc=True)
uc = emu.uc
uc.mem_map(NFI_BASE, 0x1000)
def rd(u, a, ad, s, v, _):
    traffic.append(('R', ad - NFI_BASE, s, None))
    u.mem_write(ad, struct.pack({1:'<B',2:'<H',4:'<I'}[s], nfi.read(ad - NFI_BASE, s)))
    traffic[-1] = ('R', ad - NFI_BASE, s, nfi.read(ad - NFI_BASE, s))
    return True
def wr(u, a, ad, s, v, _):
    nfi.write(ad - NFI_BASE, v, s)
    traffic.append(('W', ad - NFI_BASE, s, v))
    return True
uc.hook_add(UC_HOOK_MEM_READ, rd, begin=NFI_BASE, end=NFI_BASE + 0xFFF)
uc.hook_add(UC_HOOK_MEM_WRITE, wr, begin=NFI_BASE, end=NFI_BASE + 0xFFF)
arm_device(emu)
uc.mem_write(0x102188, struct.pack('<I', 0))
r = emu.try_call(BDEV_INIT, (), timeout=60_000_000)
print('boot_device_init ->', r, 'faulted:', emu.faulted)
print('--- PL log:'); [print(' ', l) for l in emu.pl_log]
print(f'--- NFI traffic ({len(traffic)} accesses, first 40):')
for t in traffic[:40]:
    print('  ', t[0], hex(t[1]), 'size', t[2], hex(t[3]) if t[3] is not None else '')
