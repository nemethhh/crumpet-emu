"""Task 8 probe: real fastboot_init + real command loop entry on the
patched LK. Watch the first fault / reply."""
import sys
sys.path.insert(0, '.')
from crumpet_emu import resources
from crumpet_emu.lk.session import LkSession

patched = resources.resolve('lk-patched', '2021').read_bytes()
lk = LkSession(patched, verbose=False)
print('== fastboot_init (0x41E1E3B4) ==')
try:
    r = lk.call(0x41E1E3B4, [], timeout=10_000_000)
    print('fastboot_init ->', r, 'stop:', lk.stop_reason)
except Exception as ex:
    print('fastboot_init EXC:', ex)
print('  logs:', [l for l in lk.log_out[-6:]])

print('== command loop entry (0x41E1E1A2) with queued getvar:version ==')
lk2 = LkSession(patched, verbose=False)
try:
    lk2.call(0x41E1E3B4, [], timeout=10_000_000)
except Exception as ex:
    print('  init EXC:', ex)
lk2.usb_rx += b'getvar:version\x00'
from unicorn import UC_HOOK_CODE
pcs = []
def hk(u, ad, sz, _):
    if 0x41E1E1A2 <= ad <= 0x41E1E400 and (not pcs or pcs[-1] != ad):
        pcs.append(ad)
lk2.uc.hook_add(UC_HOOK_CODE, hk)
try:
    lk2.call(0x41E1E1A2, [], timeout=60_000_000, count=2_000_000)
    print('loop call returned; stop:', lk2.stop_reason)
except Exception as ex:
    print('loop EXC:', ex)
print('  usb_tx:', bytes(lk2.usb_tx[:80]))
print('  pcs:', ' '.join(hex(a) for a in pcs[:30]))
