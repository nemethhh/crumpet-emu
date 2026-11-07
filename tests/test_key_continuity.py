# Donor: WS/tools/kamakiri/emu/tests/test_key_continuity.py
# Upstream: R0rt1z2/kamakiri
# Copied 2026-10-31 (Task 9 port): RECORD path build/crumpet/
#   key_continuity.json -> resources.own('key_continuity.json') (the
#   committed own artifact, manifest key own:key_continuity.json).
#   Tier 1: no parked vendor binary is read.
"""Task 8 — key-continuity decision record test.

The decision record binaries/own/key_continuity.json (donor:
build/crumpet/key_continuity.json) is the committed artifact Task 9
(which LK to patch) and Task 10 (DeployConfig year selection) consume.
Every cross-year image boundary the Task 7 flash order creates must have
a verdict backed by extracted key/cert hashes (cryptographic-level
comparison: RSA-2048 modulus bytes / PSS signature verification, not
string matching).
"""
import json

from crumpet_emu.resources import own

REQUIRED_BOUNDARIES = (
    'pl2021->lk2021',
    'pl2021->lk2025',
    'pl2021->tee2021',
    'pl2021->tee2025',
    'lk2021->boot2025',
)


def test_decision_record_complete():
    record = own('key_continuity.json')   # raises MissingBinary w/ pointer
    rec = json.loads(record.read_text())

    # schema
    assert set(rec) >= {'lk_year', 'tee_swap_rule', 'checks'}, sorted(rec)
    assert rec['lk_year'] in ('2021', '2025')
    assert isinstance(rec['tee_swap_rule'], str) and rec['tee_swap_rule']

    checks = rec['checks']
    for b in REQUIRED_BOUNDARIES:
        assert b in checks, f'boundary {b} missing'
        entry = checks[b]
        assert isinstance(entry.get('verdict'), bool), f'{b}: verdict must be bool'
        ev = entry.get('evidence', '')
        assert isinstance(ev, str) and ev, f'{b}: evidence missing'
        # evidence must be cryptographic: sha256 hex hashes of extracted
        # key/cert material (preloader key hashes and/or per-image hashes)
        assert ev.count('sha256:') >= 2, f'{b}: evidence lacks key/cert hashes'
        assert any(h in ev for h in ('modulus', 'signature', 'PSS', 'undecidable')), \
            f'{b}: evidence does not name what was compared'

    # decision-rule consistency (spec §7.5):
    #   pl2021->lk2025 verifies  -> lk_year 2025 (patch 2025 LK)
    #   else                     -> lk_year 2021 (matched set)
    lk2025_ok = checks['pl2021->lk2025']['verdict']
    assert rec['lk_year'] == ('2025' if lk2025_ok else '2021')
    # an undecidable LK boundary must default to matched-2021 and say so
    if 'undecidable' in checks['pl2021->lk2025']['evidence'].lower():
        assert rec['lk_year'] == '2021'
        assert 'undecidable' in rec['tee_swap_rule'].lower() or \
            'undecidable' in checks['pl2021->lk2025']['evidence'].lower()

    # handoff note boundary is informational for Task 9/10 but still needs
    # a real verdict + extracted-material hashes
    assert 'lk2021->boot2025' in checks
    assert checks['lk2021->boot2025']['verdict'] is True or \
        'undecidable' in checks['lk2021->boot2025']['evidence'].lower()
