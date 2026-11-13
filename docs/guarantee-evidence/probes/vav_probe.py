import sys, struct
sys.path.insert(0, '.')
from crumpet_emu import resources
from crumpet_emu.lk.session import LkSession
from crumpet_emu.lk.bootimg import BOOT_IMAGE_BASE

patched = resources.resolve('lk-patched', '2021').read_bytes()
stock = resources.resolve('lk', '2025').read_bytes()
boot = resources.resolve('boot', '2025').read_bytes()

def verify_and_vb(img, boot_bytes, label):
    lk = LkSession(img, verbose=False)
    tampered = bytearray(boot_bytes)
    tampered[0x1000] ^= 0xFF          # tamper SIGNED DATA -> hash mismatch
    start = BOOT_IMAGE_BASE
    try: lk.uc.mem_read(start, 16)
    except Exception: lk.uc.mem_map(start, ((len(boot_bytes) + 0xFFF) & ~0xFFF) + 0x1000)
    lk.wr(start, bytes(tampered))
    m0 = len(lk.log_out)
    r = lk.call(0x41E11548, [start, len(tampered) - 0x800])
    print(f'{label}: ret {r} (0x{r & 0xFFFFFFFF:x}) stop={lk.stop_reason}')
    for l in lk.log_out[m0:]:
        print('   log:', l[:90])
    return r

verify_and_vb(stock, boot, 'STOCK  ')
verify_and_vb(patched, boot, 'PATCHED')
