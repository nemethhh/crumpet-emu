#!/usr/bin/env python3
# Task 16: thin CLI over crumpet_emu.hunting.fuzz (Task 15); style
# follows scenarios/lk_fastboot.py.

"""Fastboot fuzz harness: restore a checkpoint per case, drive verbs.

FuzzLoop (crumpet_emu.hunting.fuzz) restores --cp before EVERY case, so
a faulting case cannot poison the next one; crashes are recorded not-ok
and the loop continues. mutate(i) is deterministic: the wired fastboot
verbs (getvar/flash/download) over a small argument pool plus a
case-index-derived blob.

Checkpoint duty (Task 15 integration limit): checkpoints.restore()
returns a CORE TrackedSession — mapped regions and registers survive,
LkSession-only state does not (Python hooks cannot ride the unicorn
context). run_case therefore rebuilds that state before each case:
usb_rx/usb_tx queues from the checkpoint's `extra` dict, seeds re-parsed
via load_seeds(), donor stub hooks re-armed (_adopt). Writer recipe for
the baseline checkpoint: docs/hunting.md, section "Checkpoints".
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from crumpet_emu.hunting.fuzz import CaseResult, FuzzLoop
from crumpet_emu.lk.session import HEAP, LkSession
from crumpet_emu.usb.fastboot import FastbootHost

VERBS = ('getvar', 'flash', 'download')
ARGPOOL = ('all', 'version', 'unlocked', 'partition', 'otucode', '')


def _adopt(session, extra):
    """Rebuild LkSession-only state on the restored core TrackedSession:
    queues from `extra`, seeds via load_seeds(), donor stub hooks
    re-armed (Python-side hooks cannot ride the unicorn context).
    __init__ is skipped — the checkpoint already holds the mapped
    memory and staged runtime state."""
    lk = object.__new__(LkSession)
    lk.uc = session.uc
    lk.verbose = False
    lk.heap_ptr = extra.get('heap_ptr', HEAP)
    lk.allocs, lk.trace, lk.stop_reason = {}, [], None
    lk.uart_out, lk.log_out = [], []
    lk.fault, lk.fault_hits = None, 0
    lk.usb_rx = bytearray(extra.get('usb_rx', b''))
    lk.usb_tx = bytearray(extra.get('usb_tx', b''))
    lk.seeds = {}
    lk.load_seeds()
    lk._install_hooks()
    return lk


def mutate(case_index):
    """Deterministic case inputs: same index, same input."""
    verb = VERBS[case_index % len(VERBS)]
    arg = ARGPOOL[(case_index // len(VERBS)) % len(ARGPOOL)]
    blob = bytes(((case_index + j) & 0xFF) for j in range(case_index % 96))
    return {'input_id': case_index, 'verb': verb, 'arg': arg, 'blob': blob}


def run_case(cfg):
    """One case against the restored LK fastboot surface; ok=True on a
    structured OKAY/FAIL reply (the wired verbs' clean endings)."""
    host = FastbootHost(_adopt(cfg['session'], cfg['extra']))
    try:
        status, message, _ = host.send(cfg['verb'], cfg['arg'],
                                       data=cfg['blob'])
    except (RuntimeError, ValueError) as e:
        return CaseResult(cfg['input_id'], False, f'fault: {e}')
    if not status:
        return CaseResult(cfg['input_id'], False, 'no reply')
    return CaseResult(cfg['input_id'], status in ('OKAY', 'FAIL'),
                      f'{status} {message}'.strip())


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cp', required=True, type=Path, metavar='CHECKPOINT',
                   help='checkpoints.save() pickle whose extra dict '
                        'carries usb_rx/usb_tx (writer recipe: '
                        'docs/hunting.md, section "Checkpoints")')
    p.add_argument('--cases', type=int, default=100,
                   help='number of fuzz cases (default 100)')
    a = p.parse_args(argv)
    if not a.cp.is_file():
        print(f'error: checkpoint not found: {a.cp}', file=sys.stderr)
        return 1
    report = FuzzLoop(a.cp, mutate, run_case, max_cases=a.cases)
    print(f'cases={len(report.cases)} crashes={len(report.crashes)}')
    for verdict, count in sorted(report.verdicts.items(),
                                 key=lambda kv: (-kv[1], kv[0])):
        print(f'  {count:4d}  {verdict}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
