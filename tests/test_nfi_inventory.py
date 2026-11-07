# Donor: WS/tools/kamakiri/emu/tests/test_nfi_inventory.py
# Upstream: R0rt1z2/kamakiri
# Copied 2026-10-31: verbatim; paths via manifest sources (see below)
"""Task 4 test: the committed NFI inventory is complete and BROM-crosschecked.

The artifact under test is ``crumpet_emu/flash/nfi_regs.json`` (byte-copy
of the donor ``emu/nfi_regs.json``; schema:
``{"regs": {name: hexaddr}, "ops": {name: hexval}, "funcs": {name: hexvma},
"sequences": {name: [[hexaddr, hexval-or-annotation]...]}}`` — every value a
hex string; sequence values may be ``null`` when the write is a
read-modify-write whose final value is computed at runtime, or an annotation
string ``"or <mask>"`` / ``"and <mask>"``).

This test is cwd-independent and does NOT open the IDA database by default:
the committed ``nfi_regs.json`` is the artifact under test, and
``ida/crosscheck_brom_nfi.py`` disassembles the raw BROM with capstone only.
Set ``KAMAKIRI_EXTRACT_NFI=1`` to re-run ``ida/extract_nfi_inventory.py``
first (under ``tools/ida-venv``; requires the local IDA 9.3 install, no
license-server round trip) and test the freshly extracted JSON instead.
"""
import json
import os
import subprocess
from pathlib import Path

import pytest


# this repo's root; the donor kamakiri repo and workspace root come from
# the CRUMPET_EMU_WS env var (operator-local tool-tree crosschecks; unset
# in a fresh clone → clean skips)
REPO = Path(__file__).resolve().parents[1]
WS = (Path(os.environ['CRUMPET_EMU_WS'])
      if os.environ.get('CRUMPET_EMU_WS') else None)
KAMAKIRI = WS / 'tools' / 'kamakiri' if WS else None
JSON_PATH = REPO / 'crumpet_emu' / 'flash' / 'nfi_regs.json'
CROSSCHECK = KAMAKIRI / 'ida' / 'crosscheck_brom_nfi.py' if KAMAKIRI else None
EXTRACT = KAMAKIRI / 'ida' / 'extract_nfi_inventory.py' if KAMAKIRI else None
EMU_PY = WS / 'tools' / 'emu-venv' / 'bin' / 'python' if WS else None
IDA_PY = WS / 'tools' / 'ida-venv' / 'bin' / 'python' if WS else None

needs_ws = pytest.mark.skipif(
    WS is None,
    reason='set CRUMPET_EMU_WS=<donor workspace root> for tool-tree crosschecks')

# guard follows the approved tests/test_resources.py needs_* skipif pattern:
# the crosscheck subprocess-runs the donor venv python, so a fresh clone
# without the donor workspace must skip, not fail
needs_emu_venv = pytest.mark.skipif(
    WS is None or not (EMU_PY.is_file() and CROSSCHECK.is_file()),
    reason='donor workspace/venv absent (set CRUMPET_EMU_WS)')

REQUIRED_REGS = ('NFI_CON', 'NFI_PAGEFMT', 'NFI_CNFG', 'NFI_CMD', 'NFI_CSN_CON',
                 'NFI_DATAR')
REQUIRED_OPS = ('CMD_READ_1ST', 'CMD_READ_2ND', 'CMD_PROG_1ST', 'CMD_PROG_2ND',
                'CMD_ERASE_1ST', 'CMD_ERASE_2ND', 'CMD_RESET', 'CMD_READ_ID')
REQUIRED_FUNCS = ('nfi_init', 'nfi_read_page', 'nfi_program_page',
                  'nfi_erase_block', 'nand_cmdfunc')
REQUIRED_SEQS = ('nfi_init', 'nfi_read_page', 'nfi_program_page',
                 'nfi_erase_block')
# ONFI command bytes the MX30LF4G28AD must be driven with
OPCODE_VALUES = {'CMD_READ_1ST': 0x00, 'CMD_READ_2ND': 0x30,
                 'CMD_PROG_1ST': 0x80, 'CMD_PROG_2ND': 0x10,
                 'CMD_ERASE_1ST': 0x60, 'CMD_ERASE_2ND': 0xD0,
                 'CMD_RESET': 0xFF, 'CMD_READ_ID': 0x90}
NFI_BASE = 0x11001000
PRELOADER_TEXT = (0x201000, 0x224000)


def hx(v):
    return int(v, 16)


@needs_emu_venv
def test_inventory_complete_and_crosschecked():
    if os.environ.get('KAMAKIRI_EXTRACT_NFI') == '1':
        r = subprocess.run([str(IDA_PY), str(EXTRACT)], capture_output=True,
                           text=True)
        assert r.returncode == 0, 'extract failed:\n' + r.stdout + r.stderr

    data = json.loads(JSON_PATH.read_text())
    for sect in ('regs', 'ops', 'funcs', 'sequences'):
        assert isinstance(data.get(sect), dict) and data[sect], sect

    # --- regs: required names, valid MMIO addresses on the NFI window ---
    addrs = {}
    for name in REQUIRED_REGS:
        assert name in data['regs'], f'reg missing: {name}'
        addrs[name] = hx(data['regs'][name])
    assert len(set(addrs.values())) == len(addrs), 'regs collide'
    for name, a in addrs.items():
        assert NFI_BASE <= a < NFI_BASE + 0x1000, f'{name} not on NFI: {a:#x}'

    # --- ops: ONFI command opcodes, verbatim ---
    for name, want in OPCODE_VALUES.items():
        assert name in data['ops'], f'op missing: {name}'
        assert hx(data['ops'][name]) == want, \
            f'{name}: {data["ops"][name]} != {want:#x}'

    # --- funcs: required driver entry VMAs inside preloader .text ---
    for name in REQUIRED_FUNCS:
        assert name in data['funcs'], f'func missing: {name}'
        vma = hx(data['funcs'][name])
        assert PRELOADER_TEXT[0] <= vma < PRELOADER_TEXT[1], \
            f'{name} vma {vma:#x} outside preloader'
    assert len(set(hx(data['funcs'][n]) for n in REQUIRED_FUNCS)) \
        == len(REQUIRED_FUNCS)

    # --- sequences: non-empty register-write pairs over inventoried regs ---
    regset = {hx(v) for v in data['regs'].values()}
    for name in REQUIRED_SEQS:
        seq = data['sequences'][name]
        assert isinstance(seq, list) and seq, f'sequence missing: {name}'
        for pair in seq:
            assert isinstance(pair, list) and len(pair) == 2, pair
            addr, val = pair
            assert hx(addr) in regset, \
                f'{name}: write to uninventoried reg {addr}'
            if val is not None:
                assert isinstance(val, str), pair  # hex value or annotation
    init_seq = [hx(p[0]) for p in data['sequences']['nfi_init']]
    assert addrs['NFI_CON'] in init_seq, 'init sequence lacks NFI_CON'
    assert addrs['NFI_PAGEFMT'] in init_seq, 'init sequence lacks NFI_PAGEFMT'
    read_seq = [hx(p[0]) for p in data['sequences']['nfi_read_page']]
    assert addrs['NFI_CON'] in read_seq and addrs['NFI_DATAR'] in read_seq, \
        'read sequence lacks CON / FIFO drain (DATAR)'

    # --- command-issue phase: per-op protocol + inlined CMD stores ---
    cmd_addr = hx(data['regs']['NFI_CMD'])
    protocol = data['_meta']['protocol']
    for op in ('read', 'program', 'erase'):
        steps = protocol[op]
        assert steps and isinstance(steps, list), f'protocol.{op} missing'
        for step in steps:
            assert isinstance(step, list) and step[0] in ('call', 'wait', 'seq')
            if step[0] == 'call':
                _, fn, opcode = step
                assert fn in data['funcs'], f'protocol.{op}: {fn} not in funcs'
                assert opcode in data['ops'], f'protocol.{op}: {opcode} not in ops'
            elif step[0] == 'seq':
                assert step[1] in data['sequences'], step
    read_ops = [s[2] for s in protocol['read'] if s[0] == 'call']
    assert read_ops == ['CMD_READ_1ST', 'CMD_READ_2ND'], read_ops
    prog_ops = [s[2] for s in protocol['program'] if s[0] == 'call']
    assert prog_ops == ['CMD_PROG_1ST', 'CMD_PROG_2ND'], prog_ops
    erase_ops = [s[2] for s in protocol['erase'] if s[0] == 'call']
    assert erase_ops == ['CMD_ERASE_1ST', 'CMD_ERASE_2ND'], erase_ops
    # erase/markbad sequences inline cmdfunc->send_command, so the actual
    # NFI_CMD stores with the opcode bytes must be present in them
    erase_cmd_vals = [p[1] for p in data['sequences']['nfi_erase_block']
                      if hx(p[0]) == cmd_addr]
    assert '0x60' in erase_cmd_vals and '0xD0' in erase_cmd_vals, \
        f'erase sequence lacks CMD_ERASE stores: {erase_cmd_vals}'
    mark_cmd_vals = [p[1] for p in data['sequences']['mtk_nfc_markbad']
                     if hx(p[0]) == cmd_addr]
    assert '0x80' in mark_cmd_vals and '0x10' in mark_cmd_vals, \
        f'markbad sequence lacks CMD_PROG stores: {mark_cmd_vals}'

    # --- crosscheck: BROM's own NAND init agrees with the inventory ---
    r = subprocess.run([str(EMU_PY), str(CROSSCHECK)], capture_output=True,
                       text=True)
    assert r.returncode == 0, 'BROM crosscheck failed:\n' + r.stdout + r.stderr
    assert 'CROSSCHECK OK' in r.stdout, r.stdout
