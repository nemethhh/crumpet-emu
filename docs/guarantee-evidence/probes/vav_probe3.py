import sys, struct
sys.path.insert(0, '.')
from crumpet_emu import resources
from crumpet_emu.lk.session import LkSession
from crumpet_emu.lk.bootimg import BOOT_IMAGE_BASE

patched = resources.resolve('lk-patched', '2021').read_bytes()
stock = resources.resolve('lk', '2025').read_bytes()
# small UNSIGNED custom boot image: 0x1000 data + 0x800 zero sig page
custom = b'CRUMPET-CUSTOM-BOOT' + bytes(0x1000 - 18) + bytes(0x800)

def run(img, label):
    lk = LkSession(img, verbose=False)
    start = BOOT_IMAGE_BASE
    try: lk.uc.mem_read(start, 16)
    except Exception: lk.uc.mem_map(start, 0x4000)
    lk.wr(start, custom)
    from unicorn import UC_HOOK_CODE
    seen = []
    def hk(u, ad, sz, _):
        if 0x41E1158C <= ad <= 0x41E116C0:
            if not seen or seen[-1] != ad: seen.append(ad)
    lk.uc.hook_add(UC_HOOK_CODE, hk)
    m0 = len(lk.log_out)
    r = lk.call(0x41E11548, [start, 0x1000])
    print(f'{label}: ret {r} stop={lk.stop_reason}')
    for l in lk.log_out[m0:]: print('   log:', l[:80])
    # vbstate cell
    pool_addr = (0x41E1154E + 4 + 0x164) & ~3
    pv, = struct.unpack('<I', img[pool_addr-0x41E00000+0x200:pool_addr-0x41E00000+0x204])
    cell = (pv + 0x41E11566) & 0xFFFFFFFF
    vbc, = struct.unpack('<I', bytes(lk.uc.mem_read(cell, 4)))
    print(f'   vbstate={vbc} (cell {hex(cell)})')
    print('  path[8C..]:', ' '.join(hex(a) for a in seen[:20]))
run(stock, 'STOCK  ')
run(patched, 'PATCHED')
