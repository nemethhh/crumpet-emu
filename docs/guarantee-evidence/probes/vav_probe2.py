import sys, struct
sys.path.insert(0, '.')
from crumpet_emu import resources
from crumpet_emu.lk.session import LkSession
from crumpet_emu.lk.bootimg import BOOT_IMAGE_BASE

patched = resources.resolve('lk-patched', '2021').read_bytes()
stock = resources.resolve('lk', '2025').read_bytes()
boot = resources.resolve('boot', '2025').read_bytes()

def run(img, label):
    lk = LkSession(img, verbose=False)
    tampered = bytearray(boot); tampered[0x1000] ^= 0xFF
    start = BOOT_IMAGE_BASE
    try: lk.uc.mem_read(start, 16)
    except Exception: lk.uc.mem_map(start, ((len(boot) + 0xFFF) & ~0xFFF) + 0x1000)
    lk.wr(start, bytes(tampered))
    # trace PCs around 0x41E11548..0x41E11700 to see the taken path
    from unicorn import UC_HOOK_CODE
    seen = []
    def hk(u, ad, sz, _):
        if 0x41E11548 <= ad <= 0x41E11710:
            if not seen or seen[-1] != ad: seen.append(ad)
    lk.uc.hook_add(UC_HOOK_CODE, hk)
    r = lk.call(0x41E11548, [start, len(tampered) - 0x800])
    print(f'{label}: ret {r} (0x{r & 0xFFFFFFFF:x})')
    print('  path:', ' '.join(hex(a) for a in seen[:40]))
    return r
run(stock, 'STOCK  ')
run(patched, 'PATCHED')
