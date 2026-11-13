# Tier 2: needs the parked 2021 belt + lk-patched + own artifacts +
# common:brom (the BROM leg).
"""Task 7 (guarantee plan): the end-to-end custom-firmware guarantee.

One test, four legs, per active-slot variant (lk_b active -> exploit on
lk_a, and lk_a active -> exploit on lk_b):

1. deploy() really placed the artifacts on the emulated chip (patched
   LK on the INACTIVE slot, the slot-matching crafted tz on tee1);
2. the REAL stock TEE loader boots the crafted tee1 FROM THE DUMP with
   real seams (parsers, overlap, part_get, RSA) — hijack fires, and the
   patched LK is staged at 0x41E00000 byte-identical to lk-patched;
3. those staged bytes are the patched LK the unlock legs execute
   (Task-6 differentials);
4. the REAL BROM classifies the dumped 2021 belt as bootable
   (boots_2021_pl) — the downgrade precondition holds on silicon.
"""
import struct
from types import SimpleNamespace

import pytest

from crumpet_emu.deploy.main import DeployConfig, deploy
from crumpet_emu.flash.gpt import parse_gpt_from_image
from crumpet_emu.flash.image import ChipDumpFlash
from crumpet_emu.flash.nand import NandChip
from crumpet_emu.resources import available, own, resolve
from crumpet_emu.usb.transport import FakeTransport, ModeledSession

DONOR_NAMES = ('brhgptpl_0', 'brhgptpl_1', 'brhgptpl_2', 'brhgptpl_3',
               'lk', 'tee1', 'tee2', 'boot')
BCB_SLOT_OFFSET = 30
TEE_LOADER = 0x20E19C

guarantee_gate = pytest.mark.skipif(
    not (all(available(n, '2021') for n in DONOR_NAMES)
         and available('lk', '2025')
         and available('lk-patched', '2021')
         and available('brom', 'common')),
    reason='tier2: parked 2021 belt + lk-patched + common:brom required')


@pytest.fixture(scope='module', params=['lk_b', 'lk_a'])
def postflash(request, tmp_path_factory):
    """One REAL §7.4 deploy per ACTIVE-slot seeding ('_b' or '_a' in
    misc's BCB): the exploit + patched LK land on the INACTIVE slot."""
    inactive = 'lk_a' if request.param == 'lk_b' else 'lk_b'
    suffix = request.param[-1].encode()
    donors = {name: resolve(name, '2021') for name in DONOR_NAMES}
    donors['lk'] = resolve('lk', '2025')       # key_continuity lk_year
    cfg = DeployConfig(donors=donors,
                       payload_variants={
                           'lk_a': own('tz-lka.img'),
                           'lk_b': own('tz-lkb.img')},
                       patched_lk=resolve('lk-patched', '2021'),
                       backup_dir=tmp_path_factory.mktemp(f'cfw-{suffix}')
                       / 'backup')
    chip = NandChip()
    chip.load_donors(donors)
    gpt = parse_gpt_from_image(donors['brhgptpl_0'].read_bytes())
    bcb = bytearray(b'\xff' * NandChip.PAGE_DATA)
    bcb[BCB_SLOT_OFFSET:BCB_SLOT_OFFSET + 4] = suffix + b'\x00\x00\x00'
    chip.erase_block(gpt['misc'][0] // NandChip.PAGES_PER_BLOCK)
    chip.program_page(gpt['misc'][0],
                      bytes(bcb) + b'\xff' * NandChip.PAGE_SPARE)
    assert deploy(FakeTransport(ModeledSession(chip)), cfg), 'deploy failed'
    return SimpleNamespace(chip=chip, gpt=gpt, dump=chip.dump(),
                           inactive=inactive, suffix=suffix)


@guarantee_gate
def test_customfw_guarantee(postflash):
    # ---- leg 1: the deploy really placed the artifacts (dump provenance)
    patched = resolve('lk-patched', '2021').read_bytes()
    dsize, = struct.unpack_from('<I', patched, 4)
    gpt, dump = postflash.gpt, postflash.dump
    assert dump[gpt[postflash.inactive][0]][:NandChip.PAGE_DATA] \
        == patched[:NandChip.PAGE_DATA], 'patched LK not at inactive slot'
    tz = own(f'tz-lk{postflash.inactive[-1]}.img').read_bytes()
    assert dump[gpt['tee1'][0]][:NandChip.PAGE_DATA] == tz[:NandChip.PAGE_DATA], \
        'crafted tz variant not at tee1'

    # ---- leg 2: REAL stock loader boots the crafted tee1 from the dump
    from crumpet_emu.preloader import constants as pc
    from crumpet_emu.preloader import emu as pe
    flash = ChipDumpFlash(dump)
    syms = pe.parse_elf_symbols(own(f'payload-lk{postflash.inactive[-1]}.elf'))
    emu = pe.Emu(flash, sbc=True, payload_syms=syms)
    pe.arm_device(emu)
    namep = pc.SCRATCH + 0x90
    emu.uc.mem_write(namep, b'tee1\x00')
    tee_addr, tee_size = pc.SCRATCH + 0x48, pc.SCRATCH + 0x4C
    emu.uc.mem_write(tee_addr, struct.pack('<I', pc.TEE_LOAD_ADDR))
    ret = emu.try_call(TEE_LOADER, (namep, pc.BDEV, tee_addr, 0, tee_size),
                       timeout=120_000_000)
    assert not emu.faulted and not emu.stopped
    assert ret == 0xFFFFFFFF, 'tee1 must fail (payload read-abort)'
    payload = own(f'payload-lk{postflash.inactive[-1]}.bin').read_bytes()
    assert bytes(emu.uc.mem_read(pc.PAYLOAD_ADDR, 4)) == payload[:4], \
        'payload not staged from the dump'
    staged = bytes(emu.uc.mem_read(pc.LK_LOAD_ADDR, dsize))
    assert staged == patched[0x200:0x200 + dsize], \
        'patched LK not staged byte-identical at 0x41E00000'
    assert emu.verify_calls == 0, \
        'the LK gate must be skipped by the payload patch (custom LK)'

    # ---- leg 3: the staged bytes are the patched LK the unlock legs run
    from crumpet_emu.lk.customfw import (lock_gate_differential,
                                         verify_and_vb_differential)
    d = lock_gate_differential(b'flash:boot')
    assert d['stock'] == 1 and d['patched'] == 0
    v = verify_and_vb_differential(
        b'CRUMPET-CUSTOM-BOOT' + bytes(0x1000 - 18) + bytes(0x800))
    assert v['stock']['ret'] == -0xD
    assert 0x41E115AE in v['patched']['pcs']

    # ---- leg 4: the REAL BROM boots the dumped 2021 belt
    from crumpet_emu.brom.boot import classify
    assert classify(dump) == 'boots_2021_pl', \
        'the dumped belt must boot through the real BROM (downgrade holds)'
