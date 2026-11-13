# Tier 1: the seam ledger is package data — no bins needed.
"""Task 1 (guarantee plan): every amonet-chain seam the preloader Emu
intercepts is inventoried in crumpet_emu.preloader.seams with an honest
classification and a citation, and the inventory tracks the code (VMAs
cross-checked against crumpet_emu.preloader.constants).
"""
import pytest

from crumpet_emu.preloader import seams
from crumpet_emu.preloader import constants as C

# The address set Emu.hook_code intercepts on the amonet chain (plan
# Task 1 list). Keys are seam names; values are the constants-module
# attributes (or literal VMAs for the unnamed inline sites).
INTERCEPTED = {
    'hdr_parse': 'HDR_PARSE',
    'overlap_chk': 'OVERLAP_CHK',
    'part_get': 'PART_GET',
    'bdev_init': 'BDEV_INIT',
    'part_load': 'PART_LOAD',
    'verify_lk': 'VERIFY_LK',
    'mtee_verify': 'MTEE_VERIFY',
    'tee_set_entry': 'TEE_SET_ENTRY',
    'secmem_rearm': 'SECMEM_REARM',
    'assert': 'ASSERT',
    'usb_handshake': 'USB_HANDSHAKE',
    'memcpy': 'MEMCPY',
    'timer_get': 'TIMER_GET',
    'arb_fuse_read': 0x20192C,
    'tee_ver_get': 0x21A560,
    'lk_ver_get': 0x201EE8,
    'tramp': 'TRAMP',
    'uart_thr': 'UART_THR',
    'printf': 'PRINTF',
    'efuse_sbc': 'EFUSE_SBC',
}


def test_every_intercepted_seam_documented():
    for name, attr in INTERCEPTED.items():
        vma = getattr(C, attr) if isinstance(attr, str) else attr
        assert name in seams.SEAMS, f'{name} missing from SEAMS'
        s = seams.SEAMS[name]
        assert s.vma == vma, \
            f'{name} ledger VMA {hex(s.vma)} != code {hex(vma)}'
        assert s.kind in seams.KINDS, f'{name} kind {s.kind!r} not in taxonomy'
        assert s.citation and len(s.citation) > 10, \
            f'{name} citation empty/short: {s.citation!r}'


def test_no_stale_ledger_entries():
    ledger_names = set(seams.SEAMS)
    assert ledger_names == set(INTERCEPTED), (
        f'ledger/code drift: extra={ledger_names - set(INTERCEPTED)} '
        f'missing={set(INTERCEPTED) - ledger_names}')


def test_chain_critical_seams_not_reimplemented():
    """Forcing function (plan Task 1): hdr_parse/overlap_chk/part_get must
    not stay host reimplementations once Tasks 2-3 land."""
    for name in seams.SEAM_CHAIN_CRITICAL:
        assert seams.SEAMS[name].kind not in ('reimplemented',), (
            f'{name} still {seams.SEAMS[name].kind!r}')


def test_mtee_kind_not_conservative():
    """P1 (final review): the mtee hook returns always-OK — that is
    fail-open, NOT conservative per the taxonomy. Its row must say so
    (kind 'stub') and carry the chain-path silicon-equivalence citation;
    the ordering premise (crafted tee1 aborts before any verify) is
    pinned dynamically in test_real_parse_overlap."""
    s = seams.SEAMS['mtee_verify']
    assert s.kind != 'oracle-conservative', (
        'always-OK is optimistic, not conservative — misclassified')
