# Donor: WS/tools/kamakiri/emu/tests/test_layer1_brom.py
# Upstream: R0rt1z2/kamakiri
# Copied 2026-10-31 (Task 9 port; Import Map + ruled path adaptations):
#   ROM/STAGE1 workspace globals -> lazy resources resolve/own; the
#   donor's `make -C brom-payload` stage1 rebuild -> hash assert against
#   the manifest entry own:stage1.bin (no make rebuild in this repo).
"""Layer 1 — real-BROM emulation proof of the amonet stage1 exploit.

The BromHarness maps the real MT8167/MT8516/MT8362 BROM image
(binaries/vendor/common/, manifest key common:brom — Tier 2) at 0x0 and
lets its own Thumb code run: the USBDL handshake loop (fcn 0x5ba8), the
command dispatcher (0xdff6), the 0xDA register-access handler (0xd6f2),
and the CDC class request handler (0x74a8) whose SET_LINE_CODING data
stage (0x746e) copies COUNT0 bytes into the 8-byte line-coding buffer
at 0x1033A8 without a bounds check — the Kamakiri overflow. Only the
hardware is modeled: the MUSB-style USB MAC registers at 0x11100000,
the UART at 0x11005000/0x11005014, the watchdog at 0x10007000 and the
GPT timer at 0x10008048.

The byte math driven by the harness mirrors modules/load_payload.py
(ptr_usbdl 0xd2e4, ptr_da 0xd7ac, stage1 to 0x100A00, ptr_send overwrite).

Tier gating: the two booted-fixture tests need the parked BROM dump
(tier2); the Watchdog-semantics test is pure model (Tier 1).
"""
import hashlib
import json

import pytest

from crumpet_emu.brom.harness import (BromHarness, Watchdog,
                                      HANDSHAKE_PATTERN,
                                      STAGE1_LOAD, PTR_SEND_CELL)
from crumpet_emu.resources import MANIFEST_PATH, available, own, resolve

TIER2 = 'tier2: requires parked vendor binaries — see binaries/README.md'
tier2_rom = pytest.mark.skipif(not available('brom', 'common'), reason=TIER2)


def stage1_bin():
    """The committed own:stage1.bin, hash-checked against its manifest
    entry — the donor built it on demand with `make -C brom-payload`;
    here the artifact is committed and pinned (no make in this repo)."""
    data = own('stage1.bin').read_bytes()
    entry = json.loads(MANIFEST_PATH.read_text())['own:stage1.bin']
    assert hashlib.sha256(data).hexdigest() == entry['sha256'], \
        'own:stage1.bin no longer matches its manifest pin'
    assert len(data) == entry['size']
    return data


@pytest.fixture(scope='module')
def booted():
    image = stage1_bin()
    h = BromHarness(rom_path=resolve('brom', 'common'))
    h.run_cdc_overflow(image)
    assert h.expect_stage1_online(), h.failure_detail()
    h.stage1_image = image
    return h


@tier2_rom
def test_stage1_online_via_real_rom(booted):
    h = booted
    # real handshake: device replied with the complement of every pattern byte
    assert h.device_replies.startswith(
        bytes(b ^ 0xFF for b in HANDSHAKE_PATTERN))
    # stage1 banner went out on the modeled UART
    assert b'Entered 1ST stage payload' in h.uart_out
    # stage1 came online: the 0xA1A2A3A4 handshake dword arrived over USB
    assert h.device_replies.endswith(b'\xA1\xA2\xA3\xA4')
    # and the payload itself landed, byte-exact, at 0x100A00 in SRAM
    assert h.read_mem(STAGE1_LOAD, len(h.stage1_image)) == h.stage1_image
    assert h.stop_reason == 'stage1-online'


@tier2_rom
def test_ptr_send_target(booted):
    h = booted
    # the usbdl struct's ptr_send cell at 0x1029AC was hijacked to the
    # stage1 load address before stage1 restored it (0x5eb3)
    assert 0x00100A00 in h.ptr_send_history
    assert h.ptr_send_history[-1] == 0x00005EB3
    # the overflow really flowed through the real CDC handler: the field at
    # ctrl_struct+0x14 (0x1033B0) received every kamakiri2 pointer value,
    # ending on the >=0x40-branch value ptr_da-5+1 = 0xD7A8
    assert 0x0000D7B3 in h.overflow_field_history
    assert h.overflow_field_history[-1] == 0x0000D7A8


def test_watchdog_hook_semantics():
    w = Watchdog(timeout_ticks=10_000)
    assert not w.enabled
    w.write_mode(0x00000035, now=0)          # MODE write with ENABLE (bit 4)
    assert w.enabled
    d1 = w.deadline
    assert d1 == 10_000
    w.write_restart(0x1971, now=9_999)       # low-level kick
    assert w.kicks == 1
    assert w.deadline == 19_999              # timeout counter was reset
    assert w.poll(now=19_998) is None
    assert w.poll(now=19_999) == 'reboot'    # expiry raises the modeled event
    assert w.reboots == [19_999]
    assert w.poll(now=25_000) is None        # fires exactly once per arming
    w.write_mode(0x22000000, now=25_000)     # amonet's disable write
    assert not w.enabled
