"""Task 12 — lk USB seam: FastbootHost drives the real flash handler to OKAY.

test_flash_okay        (Tier 2) boots LK (Task 11 build), preps the donor
                        run-flash-e2e shape (challenge derive, cert staged
                        through the REAL b64 path, 'caller' glitch armed at
                        the RSA#1 check), drives
                        FastbootHost.send('flash', 'otucode', ...) and
                        asserts the final reply status OKAY plus the donor
                        log's exact marker line pinned from
                        WS/tools/lk-emu/run-flash-e2e.log.
test_send_raises_on_stop_reason_despite_partial_reply  (Tier 1)
                        guard contract (review round-1 fix): send() raises
                        on ANY set stop_reason even when a partial reply
                        unit (queued DATA tx) already surfaced, and the
                        error carries both the stop_reason and the partial
                        status.
"""

import base64

import pytest

from crumpet_emu import resources

TIER2 = 'tier2: requires parked vendor binaries — see binaries/README.md'
tier2_lk = pytest.mark.skipif(not resources.available('lk', '2025'), reason=TIER2)

# Exact marker line from WS/tools/lk-emu/run-flash-e2e.log (scenario_flash_e2e
# renders the fb_ok stub's log_out entry as f'  >> {entry}'; the entry for the
# handler's success reply is 'OKAY: ' — empty message, trailing space).
DONOR_MARKER_LINE = '  >> OKAY: '


@tier2_lk
def test_flash_okay():
    from crumpet_emu.lk.battery import ARG1, derive_challenge, make_cert
    from crumpet_emu.lk.hostcrypto import gen_rsa, rsa_pss_sign, spki_der
    from crumpet_emu.lk.session import LkSession
    from crumpet_emu.usb.fastboot import FastbootHost

    lk = LkSession(resources.resolve('lk', '2025').read_bytes(),
                   verbose=False)
    host = FastbootHost(lk)

    # donor run-flash-e2e prep (battery.scenario_flash_e2e, seed=5)
    chall = derive_challenge(lk)
    mykey = gen_rsa(2048, seed=5)
    cert = bytearray(make_cert(lk, spki_der(*mykey[:2])))
    cert[336:592] = rsa_pss_sign(bytes(cert[:336]), mykey)
    b64cert = base64.b64encode(bytes(cert))
    lk.wr(ARG1, b64cert + b'\x00')
    assert lk.call(lk.seeds['set_otu_cert'], [ARG1, len(b64cert)]) == 0

    lk.glitch('caller')          # one-shot fault at the RSA#1 caller check
    status, message, payload = host.send('flash', 'otucode',
                                         data=base64.b64encode(
                                             rsa_pss_sign(chall, mykey)))
    assert status == 'OKAY'
    # the reply surfaced through the fb_ok stub entry renders to exactly the
    # donor log's marker line
    entries = [e for e in lk.log_out if e.startswith(('OKAY', 'FAIL'))]
    assert entries, 'no fastboot reply entries in log_out'
    assert f'  >> {entries[-1]}' == DONOR_MARKER_LINE


def test_tx_unit_message_surfaces():
    """Transport units (INFO/DATA) contribute their message text: the
    bytes after the 4-byte status tag become the reply message (OKAY/FAIL
    keep log-channel parsing)."""
    from crumpet_emu.lk.session import LkSession
    from crumpet_emu.usb.fastboot import FastbootHost

    lk = LkSession(b'\x00' * 0x200, verbose=False)   # minimal fake GFH: Tier 1
    host = FastbootHost(lk)

    def reply_info(fn, args=(), **kw):
        lk.usb_tx += b'INFOdownload buffer filled'
        return None

    lk.call = reply_info
    status, message, payload = host.send('getvar', 'partitiontype')
    assert (status, message) == ('INFO', 'download buffer filled')
    assert payload == b'INFOdownload buffer filled'

    def reply_data(fn, args=(), **kw):
        lk.usb_tx += b'DATA00000004'
        return None

    lk.call = reply_data
    status, message, _ = host.send('download', '00000004', data=b'ABCD')
    assert (status, message) == ('DATA', '00000004')

    # an OKAY log entry still outranks any queued tx unit (priority kept)
    def reply_ok_then_info(fn, args=(), **kw):
        lk.log_out.append('OKAY: done')
        lk.usb_tx += b'INFOignored'
        return None

    lk.call = reply_ok_then_info
    status, message, _ = host.send('getvar', 'battery-soc-ok')
    assert (status, message) == ('OKAY', 'done')


def test_send_raises_on_stop_reason_despite_partial_reply():
    """Guard contract: a queued tx unit (DATA) must not mask a fault —
    send() raises on ANY set stop_reason and names the partial status."""
    from crumpet_emu.lk.session import LkSession
    from crumpet_emu.usb.fastboot import FastbootHost

    lk = LkSession(b'\x00' * 0x200, verbose=False)   # minimal fake GFH: Tier 1
    host = FastbootHost(lk)

    def fault_after_tx(fn, args=(), **kw):
        # simulate the round-1 scenario: a tx unit went out, THEN the call
        # died with a set stop_reason
        lk.usb_tx += b'DATA00000004'
        lk.stop_reason = 'INVALID access=21 addr=0x0 size=4 pc=0x0'
        return None

    lk.call = fault_after_tx
    with pytest.raises(RuntimeError) as ei:
        host.send('download', '00000004', data=b'ABCD')
    assert 'INVALID access=21 addr=0x0' in str(ei.value)
    assert 'DATA' in str(ei.value)      # partial status surfaced in the error
