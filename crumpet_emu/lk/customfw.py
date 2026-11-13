"""Patched-LK execution legs for the custom-firmware guarantee
(guarantee plan Task 6).

The patched LK (2021:lk-patched = the pinned 2025 stock donor + the
three derive_lk_patches sites) EXECUTES as real code:

- ``lock_gate_differential`` — the real cmd_lock_check (0x41E0EF18) at
  its dispatcher call-site shape (r0 = command line, bl @0x41E1E1FC):
  stock restricts 'flash:…' on a locked device, the patched gate returns
  allowed (0) unconditionally.
- ``verify_and_vb_differential`` — the real boot_image_verify_and_vb
  (0x41E11548(start, size)) on an unsigned custom boot image: stock runs
  the RED block (log 'Image FAILED AUTHENTICATION…', vbstate 3, ret
  -0xD); the patched RED-abort branch (0x41E1158C cbnz -> b) skips to
  the publish path (0x41E115AE+) and never writes RED.
- ``patched_getvar`` — FastbootHost getvar through the real getvar
  handler on patched bytes (dispatcher plumbing).

Known surgical ceilings (documented in docs/guarantee.md): the publish
path deeper than its first stages needs natural-boot state (M2 class),
and the fastboot flash WRITE path needs LK's boot-built partition table
+ mmc stack — the operator's actual flash routes (Linux-root dd, and
mtkclient via the DA-patched preloader USBDL) are covered by the deploy
pipeline against the emulated chip instead.
"""
from crumpet_emu import resources
from crumpet_emu.lk.session import LkSession

LOCK_GATE = 0x41E0EF18          # cmd_lock_check (patch site 1)
VBWARN = 0x41E114B0             # vbstate warning (patch site 2)
RED_ABORT = 0x41E1158C          # RED-abort branch (patch site 3)
RED_BLOCK = 0x41E1158E          # first PC inside the RED block
PUBLISH = 0x41E115AE            # the RED-abort branch target
VERIFY_AND_VB = 0x41E11548      # boot_image_verify_and_vb
# vbstate cell: *(0x41E38D10) -> vbstate ptr (double-deref chain from
# the function's own pc-relative pool: ldr r4,[pc,#0x164] @0x41E1154E,
# add r4,pc @0x41E11562 -> cell 0x41E38D10; ldr r4,[r4] -> vbstate ptr)
VBSTATE_CELL = 0x41E38D10


def _stock():
    return resources.resolve('lk', '2025').read_bytes()


def _patched():
    return resources.resolve('lk-patched', '2021').read_bytes()


def lock_gate_differential(cmd: bytes = b'flash:boot') -> dict:
    """Real cmd_lock_check on stock vs patched bytes."""
    out = {}
    for which, img in (('stock', _stock()), ('patched', _patched())):
        lk = LkSession(img, verbose=False)
        p = 0x41E40000
        lk.wr(p, cmd + b'\x00')
        out[which] = lk.call(LOCK_GATE, [p]) & 0xFFFFFFFF
        # 1 = restricted (locked blocklist), 0 = allowed
    return out


def _vbstate(lk: LkSession, img: bytes) -> int:
    ptr = struct_unpack(lk, VBSTATE_CELL, 4)
    return struct_unpack(lk, ptr, 4)


def struct_unpack(lk: LkSession, addr: int, n: int) -> int:
    import struct
    raw = bytes(lk.uc.mem_read(addr, n))
    return struct.unpack('<I', raw)[0]


def verify_and_vb_differential(custom_boot: bytes, *,
                               trace_hi: int = 0x41E116C0) -> dict:
    """Real verify_and_vb on an unsigned custom boot image, both LKs.

    The image is staged at BOOT_IMAGE_BASE with size = len - 0x800
    (the natural-boot caller's value: the signature page is excluded,
    cert_driver parses the DER at end). A PC trace records the RED/publish
    branch decision; vbstate is read from the guest double-deref cell.
    """
    from crumpet_emu.lk.bootimg import BOOT_IMAGE_BASE
    from unicorn import UC_HOOK_CODE
    size = len(custom_boot) - 0x800
    out = {}
    for which, img in (('stock', _stock()), ('patched', _patched())):
        lk = LkSession(img, verbose=False)
        start = BOOT_IMAGE_BASE
        try:
            lk.uc.mem_read(start, 16)
        except Exception:
            lk.uc.mem_map(start, ((len(custom_boot) + 0xFFF) & ~0xFFF)
                          + 0x1000)
        lk.wr(start, custom_boot)
        pcs: list = []

        def hk(uc, address, s_, user, _pcs=pcs):
            if VERIFY_AND_VB <= address <= trace_hi:
                if not _pcs or _pcs[-1] != address:
                    _pcs.append(address)

        h = lk.uc.hook_add(UC_HOOK_CODE, hk)
        log0 = len(lk.log_out)
        try:
            ret = lk.call(VERIFY_AND_VB, [start, size])
            ret = ret - 0x100000000 if ret and ret >= 0x80000000 else ret
        except Exception:
            ret = None
        finally:
            lk.uc.hook_del(h)
        out[which] = {
            'ret': ret,
            'pcs': pcs,
            'logs': lk.log_out[log0:],
            'vbstate': _vbstate(lk, img),
        }
    return out


def patched_getvar(name: str = 'version'):
    """getvar:<name> through the real getvar handler on patched bytes."""
    from crumpet_emu.usb.fastboot import FastbootHost
    lk = LkSession(_patched(), verbose=False)
    return FastbootHost(lk).getvar(name)
