#!/usr/bin/env python3
# Task 16: thin CLI over crumpet_emu.lk.battery + lk.session (Task 11
# battery port). Style follows scenarios/lk_fastboot.py; the lk image
# resolves lazily through crumpet_emu.resources, so --help needs no bins.

"""LK signed-unlock audit battery: donor scenario names as subcommands.

Each scenario drives the REAL 2025 lk.img unlock path (rsa_import /
verify_code / otu chain / cert driver) inside Unicorn through surgical
function entries — see crumpet_emu/lk/battery.py for the vectors.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from crumpet_emu import resources
from crumpet_emu.lk.battery import run
from crumpet_emu.lk.session import LkSession

#: the donor audit battery surface (flash-e2e lives in lk_fastboot.py /
#: fuzz_fastboot.py; 'all' is battery.run's own keyword)
SCENARIOS = ('keydump', 'vcode', 'vunlock', 'otu', 'otu-glitch',
             'bootimg', 'certdriver', 'b64', 'otucode-derive')


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('scenario', choices=SCENARIOS,
                   help='donor battery scenario to run')
    p.add_argument('--gen', default='2025', choices=('2025',),
                   help='audit target generation (the battery VMAs are '
                        'pinned to the 2025 lk build)')
    a = p.parse_args(argv)

    try:
        lk = LkSession(resources.resolve('lk', a.gen).read_bytes(),
                       verbose=False)
    except (resources.MissingBinary, resources.ShaMismatch) as e:
        print(f'error: {e}', file=sys.stderr)
        return 1
    run(lk, a.scenario, {})
    return 0


if __name__ == '__main__':
    sys.exit(main())
