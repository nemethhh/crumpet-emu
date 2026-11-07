#!/usr/bin/env python3
# Task 16: thin CLI over crumpet_emu.brom.boot; binaries resolve lazily
# through crumpet_emu.resources, so --help needs no vendor bins.

"""BROM boot replay: classify a chip snapshot through the REAL MT8167 BROM.

Default (no --snapshot): the stock 2021 donor belt — Tier 2, vendor bins.
--snapshot FILE replays a saved NandChip.dump() pickle ({page: 4352B}).
Verdicts: boots_2021_pl / brom_usdl_wait / invalid.
"""

import argparse
import pickle
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from crumpet_emu import resources
from crumpet_emu.brom.boot import classify, last_trace
from crumpet_emu.flash.nand import NandChip

#: the stock-looking 2021 unit (same donor set as the layer-5 fixtures)
BELT = ('brhgptpl_0', 'brhgptpl_1', 'brhgptpl_2', 'brhgptpl_3',
        'lk', 'tee1', 'tee2', 'boot')


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--snapshot', type=Path, metavar='DUMP.pkl',
                   help='classify this NandChip.dump() pickle instead of '
                        'the stock 2021 belt')
    p.add_argument('--final', action='store_true',
                   help='also run the per-page donor-equivalence belt '
                        '(classify(final=True))')
    p.add_argument('--trace', action='store_true',
                   help='print the replay trace (brlyt-walk / pl-loaded / '
                        'verify-pass / jump milestones)')
    a = p.parse_args(argv)

    try:
        if a.snapshot:
            snapshot = pickle.loads(a.snapshot.read_bytes())
        else:
            chip = NandChip()
            chip.load_donors({n: resources.resolve(n, '2021') for n in BELT})
            snapshot = chip.dump()
        verdict = classify(snapshot, final=a.final)
    except (OSError, pickle.PickleError, ValueError,
            resources.MissingBinary, resources.ShaMismatch) as e:
        print(f'error: {e}', file=sys.stderr)
        return 1
    print(f'verdict: {verdict}')
    if a.trace:
        print('\n'.join(last_trace()))
    return 0


if __name__ == '__main__':
    sys.exit(main())
