# Generalized from: WS/tools/lk-emu/battery.py
# Upstream: in-repo audit harness (WS tools/lk-emu)
# Generalized 2026-11-01 (Task 11): bodies verbatim; the only change is the
#   import surface that moved with the donor split — the lk_emu constants /
#   F table now come from crumpet_emu.lk.session, the pure-python crypto
#   helpers from crumpet_emu.lk.hostcrypto (same functions, extracted
#   verbatim). Every `emu` parameter is an LkSession (same call/rd/wr/rd32/
#   dump_rsa_key surface the donor LKEmu had).
"""Execution battery for the LK signed-unlock audit (see lk_emu.py).

Each scenario prints [EXEC]-backed results. Craft vectors use pure-python
RSA/PSS (hostcrypto.gen_rsa / rsa_pss_sign) so signatures are REAL signatures -
positive controls prove the emulated verifier accepts valid input, then
forged/malformed variants prove rejection or expose edges.
"""
import hashlib
import struct

from crumpet_emu.lk.hostcrypto import (b2i, gen_rsa, i2b, rsa_pss_sign,
                                       spki_der)
from crumpet_emu.lk.session import (ARGS, CERT_BUF, F, OTUCODE_BUF,
                                    OTU_CHAL_FLAG, PUBKEY_DER)

ARG1 = ARGS                 # data buffer
ARG2 = ARGS + 0x10000       # sig buffer
ARG3 = ARGS + 0x20000       # key buffer
ARG4 = ARGS + 0x30000       # scratch
KEYST = ARGS + 0x40000      # rsa_key storage


def call6(emu, fn, a0, a1, a2, a3, a4, a5, **kw):
    """AAPCS: args 5,6 at [sp], [sp+4] on entry."""
    return emu.call(fn, [a0, a1, a2, a3], sp_args=(a4, a5), **kw)


def pk(emu):
    """The 295-byte Amazon unlock SPKI DER from rodata."""
    return emu.rd(PUBKEY_DER, 295)


UNLOCK_MSG = b'0x4a616f429e27cf4b'   # sprintf("0x%08x%08x", reg13, reg12)


def scenario_keydump(emu, opts):
    print('[EXEC] rsa_import(hardcoded unlock pubkey @0x41E330DC, 295)')
    emu.wr(KEYST, b'\x00' * 36)
    r = emu.call(F['rsa_import'], [PUBKEY_DER, 295, KEYST],
                 verbose_name='rsa_import')
    print(f'  ret = {r}')
    print(emu.dump_rsa_key(KEYST))
    print('[EXEC] length edges on rsa_import:')
    for ln in (0, 1, 294, 296, 0x7FFFFFFF):
        emu.wr(KEYST + 0x40, b'\x00' * 36)
        r = emu.call(F['rsa_import'], [PUBKEY_DER, ln, KEYST + 0x40],
                     verbose_name=f'rsa_import len={ln}')
        print(f'  len={ln:#x} -> ret={r} '
              f'{"OOB/STOP: " + str(emu.stop_reason) if emu.stop_reason else ""}')


def scenario_vcode(emu, opts):
    """Direct amzn_verify_code_internal(data, dlen, sig, slen, key, klen)."""
    print('[EXEC] positive control: own-key PSS sig over unlock message')
    MYKEY = gen_rsa(2048, seed=1)
    myder = spki_der(*MYKEY[:2])
    print(f'  own SPKI DER len={len(myder)}')
    MYSIG_SELF = rsa_pss_sign(UNLOCK_MSG, MYKEY)
    emu.wr(ARG1, UNLOCK_MSG + b'\x00' * 32)
    emu.wr(ARG2, MYSIG_SELF)
    emu.wr(ARG3, myder)
    r = call6(emu, F['verify_code'], ARG1, len(UNLOCK_MSG), ARG2, 256,
              ARG3, len(myder), verbose_name='verify_code(self-key)')
    print(f'  ret = {r} (0 == VERIFIED) expect 0')
    print('[EXEC] cross-key: same sig, Amazon key -> expect nonzero')
    emu.wr(ARG2, MYSIG_SELF)
    r = call6(emu, F['verify_code'], ARG1, len(UNLOCK_MSG), ARG2, 256,
              PUBKEY_DER, 295, verbose_name='verify_code(cross-key)')
    print(f'  ret = {r} expect nonzero')
    print('[EXEC] forged sig battery (Amazon key):')
    vecs = {
        'random-256': bytes(range(256)),
        'all-zero': b'\x00' * 256,
        'all-ff': b'\xff' * 256,
        'e3-cube-root-shape': _e3_shape(UNLOCK_MSG),
        'em-leading-zero': b'\x00' * 8 + MYSIG_SELF[8:],
        'sig=1': b'\x01' + b'\x00' * 255,
        'sig=n-1': b'\xff' * 255 + b'\xfe',
    }
    for name, sig in vecs.items():
        emu.wr(ARG2, sig)
        r = call6(emu, F['verify_code'], ARG1, len(UNLOCK_MSG), ARG2, 256,
                  PUBKEY_DER, 295, verbose_name=f'verify_code({name})')
        st = f' STOP={emu.stop_reason}' if emu.stop_reason else ''
        print(f'  {name:<22} -> ret={r}{st} expect nonzero')
    print('[EXEC] sig length edges (Amazon key, random sig):')
    emu.wr(ARG2, bytes(range(256)))
    for sl in (0, 1, 255, 257, 0x8000, 0x7FFFFFFF):
        r = call6(emu, F['verify_code'], ARG1, len(UNLOCK_MSG), ARG2, sl,
                  PUBKEY_DER, 295, verbose_name=f'verify_code siglen={sl:#x}')
        st = f' STOP={emu.stop_reason}' if emu.stop_reason else ''
        print(f'  siglen={sl:#x} -> ret={r}{st}')
    print('[EXEC] data length edges:')
    emu.wr(ARG1, b'A' * 0x8000)
    for dl in (0, 1, 0x8000, 0x7FFFFFFF):
        r = call6(emu, F['verify_code'], ARG1, dl, ARG2, 256,
                  PUBKEY_DER, 295, verbose_name=f'verify_code datalen={dl:#x}')
        st = f' STOP={emu.stop_reason}' if emu.stop_reason else ''
        print(f'  datalen={dl:#x} -> ret={r}{st}')
    # keylen edges
    print('[EXEC] key length edges:')
    for kl in (0, 1, 294, 296, 0x7FFFFFFF):
        r = call6(emu, F['verify_code'], ARG1, 0x100, ARG2, 256,
                  PUBKEY_DER, kl, verbose_name=f'verify_code keylen={kl:#x}')
        st = f' STOP={emu.stop_reason}' if emu.stop_reason else ''
        print(f'  keylen={kl:#x} -> ret={r}{st}')


def _icbrt(n):
    """Integer cube root (Newton)."""
    if n < 0:
        return 0
    x = 1 << ((n.bit_length() + 2) // 3 + 1)
    while True:
        y = (2 * x + n // (x * x)) // 3
        if y >= x:
            return x
        x = y


def _e3_shape(msg):
    """Cube-root shaped 'forgery': EM target for e=3 with zero padding."""
    emlen = 256
    mhash = hashlib.sha256(msg).digest()
    db = b'\x00' * 1 + b'\x01' + b'\xff' * (emlen - 34) + mhash
    em = db + b'\xbc'
    s = i2b(_icbrt(b2i(em)))
    return (b'\x00' * (256 - len(s))) + s


def scenario_vunlock(emu, opts):
    """flash:unlock entry: amzn_verify_unlock(sig, siglen)."""
    print(f'[EXEC] amzn_verify_unlock forged battery (msg={UNLOCK_MSG!r})')
    mykey = gen_rsa(2048, seed=2)
    good = rsa_pss_sign(UNLOCK_MSG, mykey)
    vecs = {
        'random': bytes(range(256)),
        'zero': b'\x00' * 256,
        'ff': b'\xff' * 256,
        'wrong-key-valid-sig': good,
    }
    for name, sig in vecs.items():
        emu.wr(ARG2, sig)
        r = emu.call(F['verify_unlock'], [ARG2, 256],
                     verbose_name=f'amzn_verify_unlock({name})')
        st = f' STOP={emu.stop_reason}' if emu.stop_reason else ''
        print(f'  {name:<22} -> ret={r}{st} expect nonzero (fail)')
    for sl in (0, 1, 255, 257):
        emu.wr(ARG2, bytes(range(256)))
        r = emu.call(F['verify_unlock'], [ARG2, sl],
                     verbose_name=f'amzn_verify_unlock siglen={sl}')
        st = f' STOP={emu.stop_reason}' if emu.stop_reason else ''
        print(f'  siglen={sl:<5} -> ret={r}{st}')


def derive_challenge(emu):
    """Force OTU challenge derivation; return the 32-byte b64 string."""
    buf = ARG4
    emu.wr(buf + 0x40, struct.pack('<I', 64))
    r = emu.call(F['otu_code_gen'], [buf, buf + 0x40],
                 verbose_name='amzn_get_one_tu_code')
    n = emu.rd32(buf + 0x40)
    s = emu.rd(buf, n)
    print(f'  derive ret={r} len={n} otu_code={s!r}')
    return s


def stage_cert(emu, blob):
    assert len(blob) == 592, len(blob)
    emu.wr(CERT_BUF, blob)


def stage_code(emu, blob):
    assert len(blob) == 256
    emu.wr(OTUCODE_BUF, blob)


def make_cert(emu, key_der, header=None):
    """592B = 32B header | 4B keylen@+32 | key DER @+36 (<=300B) | sig@+336."""
    header = (header or b'CRUMPET-OTU-TEST-HDR').ljust(32, b'X')[:32]
    body = bytearray(592)
    body[0:32] = header
    body[32:36] = struct.pack('<I', len(key_der))
    body[36:36 + len(key_der)] = key_der
    return bytes(body)


def scenario_otu(emu, opts):
    print('[EXEC] OTU chain, un-glitched (Amazon RSA#1 gate active):')
    chall = derive_challenge(emu)
    mykey = gen_rsa(2048, seed=3)
    myder = spki_der(*mykey[:2])
    cert = bytearray(make_cert(emu, myder))
    # attacker cannot produce Amazon's sig over cert[0:336]; variants:
    variants = {
        'random-sig': bytes(range(256)),
        'zero-sig': b'\x00' * 256,
        'own-key-sig-over-body': rsa_pss_sign(bytes(cert[:336]), mykey),
    }
    for name, sig in variants.items():
        cert2 = bytearray(cert)
        cert2[336:592] = sig
        stage_cert(emu, bytes(cert2))
        emu.call(F['verify_otu_wrap'], [], verbose_name='verify_otu')
        # wrapper returns BOOL; also call inner for the raw code
        r = emu.call(F['verify_otu'], [OTUCODE_BUF, 256],
                     verbose_name='verify_otu(inner)')
        st = f' STOP={emu.stop_reason}' if emu.stop_reason else ''
        print(f'  cert-sig={name:<22} -> ret={r}{st} expect -5')
    print('[EXEC] cert length tricks (before RSA#1? no: length fields inside):')
    for klen_field in (0, 0xFFFFFFFF, 300, 0x100):
        cert3 = bytearray(make_cert(emu, myder))
        cert3[32:36] = struct.pack('<I', klen_field)
        cert3[336:592] = bytes(range(256))
        stage_cert(emu, bytes(cert3))
        r = emu.call(F['verify_otu'], [OTUCODE_BUF, 256],
                     verbose_name=f'verify_otu keylenfield={klen_field:#x}')
        st = f' STOP={emu.stop_reason}' if emu.stop_reason else ''
        print(f'  cert[32]={klen_field:#x} -> ret={r}{st} expect -5')
    print('[EXEC] replay shape: same random cert twice (state persistence):')
    cert4 = bytearray(make_cert(emu, myder))
    cert4[336:592] = bytes(range(256))
    stage_cert(emu, bytes(cert4))
    for i in (1, 2):
        r = emu.call(F['verify_otu'], [OTUCODE_BUF, 256],
                     verbose_name=f'verify_otu call#{i}')
        print(f'  call#{i} -> ret={r}')


def scenario_otu_glitch(emu, opts):
    """Single-instruction fault model at the RSA#1 gate (0x41E019F4)."""
    print('[EXEC] FI model: glitch cbnz@0x41E019F4 (RSA#1) only:')
    chall = derive_challenge(emu)
    mykey = gen_rsa(2048, seed=4)
    myder = spki_der(*mykey[:2])
    cert = bytearray(make_cert(emu, myder))
    cert[336:592] = rsa_pss_sign(bytes(cert[:336]), mykey)  # own sig (not Amz)
    stage_cert(emu, bytes(cert))
    stage_code(emu, rsa_pss_sign(chall, mykey))             # own-key otucode
    for mode in ('ret', 'full', 'stat', 'caller'):
        emu.fault = {'armed': True, 'mode': mode, 'once': True}
        emu.fault_hits = 0
        # clear the cached challenge so derivation runs inside verify
        emu.wr(OTU_CHAL_FLAG, b'\x00')
        r = emu.call(F['verify_otu'], [OTUCODE_BUF, 256],
                     verbose_name=f'verify_otu glitch-{mode}')
        st = f' STOP={emu.stop_reason}' if emu.stop_reason else ''
        print(f'  glitch-{mode:<5} hits={emu.fault_hits} -> ret={r}{st} '
              f'{"UNLOCK-CHAIN SUCCESS" if r == 0 else "(still gated)"}')
        stage_code(emu, rsa_pss_sign(chall, mykey))


def scenario_bootimg(emu, opts):
    """Boot-image auth wrapper (real call shape: fn(start, end, size, 0))."""
    print('[EXEC] boot-image auth malformed-input battery:')
    img = ARG1
    vecs = {
        'empty': (b'', 0),
        'one-byte': (b'\x00', 1),
        'random-1k': (bytes((i * 7 + 3) & 0xFF for i in range(1024)), 1024),
        'len-oversize': (b'ANDROID!' + b'\x00' * 56, 0x7FFFFFFF),
        'android-hdr-zero': (b'ANDROID!' + b'\x00' * (0x800 - 8), 0x800),
        'android-hdr-ff': (b'ANDROID!' + b'\xff' * (0x800 - 8), 0x800),
    }
    for name, (blob, sz) in vecs.items():
        emu.wr(img, blob)
        r = emu.call(F['boot_auth'], [img, img + len(blob), len(blob), 0],
                     verbose_name=f'boot_auth({name})')
        st = f' STOP={emu.stop_reason}' if emu.stop_reason else ''
        # sub_41E00F58 returns 1 = VERIFIED, 0 = failed (caller logs
        # "Failed to verify image" on !ret -> halt)
        print(f'  {name:<18} -> ret={r}{st}'
              f'{" (VERIFIED!?)" if r == 1 else " (fail-closed)"}')


def scenario_certdriver(emu, opts):
    """Monolithic cert driver 0x41E0120C with malformed DER certs."""
    print('[EXEC] cert-driver malformed DER battery:')
    der_ok = pk(emu)
    vecs = {
        'valid-spki': der_ok,
        'empty': b'',
        'truncated-seq': b'\x30\x82\x01\x22\x30',
        'huge-len': b'\x30\x82\xff\xff' + b'\x00' * 64,
        'indefinite-len': b'\x30\x80' + b'\x00' * 64,
        'tbs-empty': b'\x30\x0c\x30\x00\x03\x02\x00\x01' + b'\x00' * 8,
        'garbage': bytes(range(256)),
    }
    for name, der in vecs.items():
        emu.wr(ARG3, der + b'\x00' * 64)
        emu.wr(ARG4, b'\x11' * 64)
        r = emu.call(F['cert_driver'],
                     [0, ARG4, ARG3, ARG3], verbose_name=f'cert_driver({name})')
        st = f' STOP={emu.stop_reason}' if emu.stop_reason else ''
        print(f'  {name:<15} -> ret={r}{st}')


def scenario_b64(emu, opts):
    """b64 decode wrapper as used by set_otu_cert/set_otu_code."""
    import base64
    print('[EXEC] base64_decode wrapper edge battery:')
    cert592 = bytes((i * 3) & 0xFF for i in range(592))
    code256 = bytes((i * 5) & 0xFF for i in range(256))
    b64cert = base64.b64encode(cert592)
    b64code = base64.b64encode(code256)
    for name, arg, expect in (
            ('cert-b64-792', b64cert, 0),
            ('code-b64-344', b64code, -1),
            ('bad-pad', b64cert[:-1], -1),
            ('wrong-len', base64.b64encode(cert592[:591]), -1),
            ('empty', b'', -1),
            ('dots', b'....', -1)):
        emu.wr(ARG1, arg + b'\x00')
        r = emu.call(F['set_otu_cert'], [ARG1, len(arg)],
                     verbose_name=f'set_otu_cert({name})')
        st = f' STOP={emu.stop_reason}' if emu.stop_reason else ''
        verdict = 'OK' if (r == 0) == (expect == 0) else 'MISMATCH'
        print(f'  {name:<14} -> ret={r} {verdict}{st}')
        if r == 0:
            staged = emu.rd(CERT_BUF, 592)
            print(f'    staged == input: {staged == cert592}')
    # staging via real path then verifying bytes land at CERT_BUF


def scenario_otucode_derive(emu, opts):
    print('[EXEC] otu_code derivation (challenge) semantics:')
    emu.wr(OTU_CHAL_FLAG, b'\x00')
    c1 = derive_challenge(emu)
    c2 = derive_challenge(emu)
    print(f'  cached second call identical: {c1 == c2}')
    print(f'  flag byte now: {emu.rd(OTU_CHAL_FLAG, 1)[0]}')
    emu.wr(OTU_CHAL_FLAG, b'\x00')
    c3 = derive_challenge(emu)
    print(f'  flag-cleared re-derive identical (timer stubbed): {c1 == c3}')
    print(f'  challenge b64 len: {len(c1)}')


def scenario_flash_e2e(emu, opts):
    """End-to-end: the REAL flash handler sub_41E1F5C0('otucode', b64, len)
    with a single-instruction glitch at the caller RSA#1 check (0x41E01D3A).
    Everything else (b64 decode, staging, RSA#2 vs cert-embedded key, idme
    unlock_status update, fastboot OKAY) runs real code."""
    import base64
    print('[EXEC] flash:otucode end-to-end via handler 0x41E1F5C0:')
    chall = derive_challenge(emu)
    mykey = gen_rsa(2048, seed=5)
    myder = spki_der(*mykey[:2])
    cert = bytearray(make_cert(emu, myder))
    cert[336:592] = rsa_pss_sign(bytes(cert[:336]), mykey)
    # stage the cert through the REAL b64 path (set_otu_cert)
    emu.wr(ARG1, base64.b64encode(bytes(cert)) + b'\x00')
    r = emu.call(F['set_otu_cert'], [ARG1, len(base64.b64encode(bytes(cert)))],
                 verbose_name='set_otu_cert(real b64 stage)')
    print(f'  cert staged via real b64 path: ret={r}')
    code = rsa_pss_sign(chall, mykey)
    b64code = base64.b64encode(code)
    namep = ARG4 + 0x100
    emu.wr(namep, b'otucode\x00')
    emu.wr(ARG1, b64code + b'\x00')
    emu.wr(OTU_CHAL_FLAG, b'\x00')
    emu.fault = {'armed': True, 'mode': 'caller', 'once': True}
    emu.fault_hits = 0
    r = emu.call(F['flash_handler'] if 'flash_handler' in F else 0x41E1F5C0,
                 [namep, ARG1, len(b64code)],
                 verbose_name='flash handler (otucode branch)')
    st = f' STOP={emu.stop_reason}' if emu.stop_reason else ''
    print(f'  handler ret={r}{st} fault_hits={emu.fault_hits}')
    idme = [l for l in emu.log_out if 'IDME' in l or l.startswith(('OKAY', 'FAIL'))]
    for l in idme:
        print(f'  >> {l}')

    print('[EXEC] same handler, glitch ONLY the handler-level cbz @0x41E1F632')
    print('       (after bl verify_otu_wrap) - cert/code can even be garbage:')
    emu.wr(CERT_BUF, bytes((i * 7) & 0xFF for i in range(592)))   # garbage cert
    garbage256 = base64.b64encode(bytes((i * 11) & 0xFF for i in range(256)))
    emu.wr(ARG1, garbage256 + b'\x00')                            # valid b64, junk code
    emu.wr(namep, b'otucode\x00')
    emu.fault = {'armed': True, 'mode': 'handler', 'once': True}
    emu.fault_hits = 0
    r = emu.call(0x41E1F5C0, [namep, ARG1, len(garbage256)],
                 verbose_name='flash handler (glitch cbz@0x41E1F632)')
    st = f' STOP={emu.stop_reason}' if emu.stop_reason else ''
    print(f'  handler ret={r}{st} fault_hits={emu.fault_hits}')
    for l in [x for x in emu.log_out if x.startswith(('OKAY', 'FAIL'))][-2:]:
        print(f'  >> {l}')


SCENARIOS = {
    'keydump': scenario_keydump,
    'vcode': scenario_vcode,
    'vunlock': scenario_vunlock,
    'otu': scenario_otu,
    'otu-glitch': scenario_otu_glitch,
    'bootimg': scenario_bootimg,
    'certdriver': scenario_certdriver,
    'b64': scenario_b64,
    'flash-e2e': scenario_flash_e2e,
    'otucode-derive': scenario_otucode_derive,
}


def run(emu, scen, opts):
    if scen in ('help', 'all'):
        order = ['keydump', 'vcode', 'vunlock', 'otucode-derive', 'b64',
                 'otu', 'otu-glitch', 'bootimg', 'certdriver']
        scens = order if scen == 'all' else order
        for s in scens:
            print(f'\n===== {s} =====')
            SCENARIOS[s](emu, opts)
    elif scen in SCENARIOS:
        SCENARIOS[scen](emu, opts)
    else:
        print('scenarios:', ' '.join(SCENARIOS), '| all')
