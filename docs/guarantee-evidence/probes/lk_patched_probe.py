import sys, struct
sys.path.insert(0, '.')
from crumpet_emu import resources
from crumpet_emu.lk.session import LkSession
from crumpet_emu.lk.bootimg import BOOT_IMAGE_BASE
from crumpet_emu.usb.fastboot import FastbootHost

patched = resources.resolve('lk-patched', '2021').read_bytes()
stock = resources.resolve('lk', '2025').read_bytes()
boot = resources.resolve('boot', '2025').read_bytes()

def lock_check(img, cmd):
    lk = LkSession(img, verbose=False)
    p = 0x41E40000
    lk.wr(p, cmd + b'\x00')
    r = lk.call(0x41E0EF18, [p])
    print(f'  cmd_lock_check({cmd!r}) -> {r} (0x{r & 0xFFFFFFFF:x}) stop={lk.stop_reason}')
    return r

print('== lock gate differential ==')
lock_check(stock, b'flash:boot'); lock_check(patched, b'flash:boot')
lock_check(stock, b'getvar:version'); lock_check(patched, b'getvar:version')

print('== verify_and_vb on tampered boot ==')
def verify_and_vb(img, boot_bytes):
    lk = LkSession(img, verbose=False)
    tampered = bytearray(boot_bytes)
    tampered[len(boot_bytes)-0x800+0x400] ^= 0xFF
    start = BOOT_IMAGE_BASE
    try: lk.uc.mem_read(start, 16)
    except Exception: lk.uc.mem_map(start, ((len(boot_bytes) + 0xFFF) & ~0xFFF) + 0x1000)
    lk.wr(start, bytes(tampered))
    size = len(tampered) - 0x800
    r = lk.call(0x41E11548, [start, size])
    pool_addr = (0x41E1154E + 4 + 0x164) & ~3
    pv, = struct.unpack('<I', img[pool_addr-0x41E00000+0x200:pool_addr-0x41E00000+0x204])
    cell = (pv + 0x41E11566) & 0xFFFFFFFF
    vbc, = struct.unpack('<I', bytes(lk.uc.mem_read(cell, 4)))
    print(f'  verify_and_vb -> ret {r} (0x{r & 0xFFFFFFFF:x}) vbstate {vbc} stop={lk.stop_reason}')
    return r, vbc
verify_and_vb(stock, boot)
verify_and_vb(patched, boot)

print('== flash:boot e2e on patched ==')
lk = LkSession(patched, verbose=False)
host = FastbootHost(lk)
for verb, arg, data in [('flash', 'boot', boot[:0x1000]), ('getvar', 'version', b'')]:
    try:
        st_, msg, _ = host.send(verb, arg, data=data) if verb == 'flash' else (*host.getvar(arg), b'')
        print(f'  {verb}:{arg} -> {st_} {msg!r}')
    except Exception as ex:
        print(f'  {verb}:{arg} EXC: {ex}')
