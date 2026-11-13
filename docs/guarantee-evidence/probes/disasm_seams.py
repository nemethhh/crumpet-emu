import sys
sys.path.insert(0, '.')
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from crumpet_emu import resources
from crumpet_emu.preloader.constants import FILE_DELTA

pl = resources.resolve('brhgptpl_0', '2021').read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
for name, vma, n in [('HDR_PARSE 0x20F2D8', 0x20F2D8, 44),
                     ('OVERLAP_CHK 0x20F398', 0x20F398, 56)]:
    off = vma - FILE_DELTA
    code = pl[off:off + n * 2 + 8]
    print(f'==== {name}')
    for i in md.disasm(code, vma):
        print(f'  {i.address:x}: {i.bytes.hex():<12} {i.mnemonic} {i.op_str}')
        if i.mnemonic in ('pop', 'bx',) and 'pc' in i.op_str:
            break
