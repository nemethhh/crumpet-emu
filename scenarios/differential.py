#!/usr/bin/env python3
# Task 16: thin CLI over crumpet_emu.hunting.differential (Task 15);
# style follows scenarios/lk_fastboot.py.

"""Differential runner: same input, varied parameters — first divergence.

--variants 'sbc=on,off' style: whitespace-separated AXIS=V1,V2 terms; the
cross product feeds each variant's override dict to the layer builder —
preloader varies sbc (stock 2021 boot, stdout = trace), lk varies budget
(boot() walk, uart_trace = trace, image picked by --gen).
"""

import argparse
import contextlib
import io
import itertools
import sys
from collections import namedtuple
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from crumpet_emu import resources
from crumpet_emu.hunting.differential import first_divergence, run_variants
from crumpet_emu.lk.boot import boot
from crumpet_emu.preloader.scenarios import stock_boot

#: the axes each layer's builder actually varies
AXES = {'preloader': {'sbc'}, 'lk': {'budget'}}
#: first_divergence's R contract: .uart_text (str or line list), .verdict
Result = namedtuple('Result', 'uart_text verdict')


def parse_variants(spec, layer):
    axes = []
    for term in spec.split():
        name, sep, values = term.partition('=')
        if not sep or not values or name not in AXES[layer]:
            sys.exit(f'error: {term!r} — want AXIS=V1,V2; layer '
                     f'{layer!r} varies {sorted(AXES[layer])}')
        axes.append((name, values.split(',')))
    names = [n for n, _ in axes]
    return {','.join(f'{n}={v}' for n, v in zip(names, c)):
            dict(zip(names, c))
            for c in itertools.product(*(v for _, v in axes))}


def build(args, ov):
    if args.layer == 'preloader':
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ok = stock_boot(sbc=ov.get('sbc', 'on') == 'on')
        return Result(buf.getvalue(), 'ok' if ok else 'fail')
    out = boot(resources.resolve('lk', args.gen).read_bytes(),
               budget=int(ov.get('budget', 3_000_000)))
    return Result(list(out.uart_trace),
                  'fastboot' if out.reached_fastboot else 'unreached')


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--variants', required=True, metavar="'AXIS=V1,V2 ...'")
    p.add_argument('--layer', choices=tuple(AXES), default='preloader')
    p.add_argument('--gen', default='2025', choices=('2021', '2025'),
                   help='lk builder: the LK image generation (the '
                        'preloader layer pins the 2021 validated donors)')
    a = p.parse_args(argv)
    try:
        results = run_variants(lambda ov: build(a, ov),
                               parse_variants(a.variants, a.layer))
    except (resources.MissingBinary, resources.ShaMismatch) as e:
        print(f'error: {e}', file=sys.stderr)
        return 1
    for name, r in results.items():
        print(f'{name}: verdict={r.verdict}')
    div = first_divergence(results)
    print('first divergence:', div if div else 'none (traces aligned)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
