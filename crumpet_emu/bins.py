"""Image placement status + installer: ``python3 -m crumpet_emu.bins``.

``status`` (the default) prints every manifest slot with its placement
state — ``own`` (committed artifact), ``pinned`` (sha matches the
manifest, runs quietly), ``unpinned`` (some other dump at the slot; runs
with a loud warning), ``missing``. ``place FILE --as gen:name`` copies a
dump into the drop-in location. No hash registration: any placed image
runs (unpinned images are labeled at resolve time — binaries/README.md).
"""

import argparse
import shutil
import sys
from pathlib import Path

from . import resources

#: gen prefix -> which scenario CLIs light up when that gen is placed
SCENARIO_HINTS = {
    'common': 'scenarios/boot_brom.py',
    '2021': 'scenarios/preloader_chain.py · boot_brom.py · differential.py',
    '2025': 'scenarios/lk_unlock.py · lk_fastboot.py',
}

_STATES = ('own', 'pinned', 'unpinned', 'missing')


def slot_rows() -> list:
    """One row per manifest slot, in manifest order: key, gen, name, file,
    expected sha256, resolved candidate path, placement state."""
    rows = []
    for key, entry in resources._manifest().items():
        gen, name = key.split(':', 1)
        path = resources._candidate(name, gen, entry)
        if entry['gen'] == 'own':
            state = 'own'
        elif not path.is_file():
            state = 'missing'
        elif resources.available(name, gen):
            state = 'pinned'
        else:
            state = 'unpinned'
        rows.append({'key': key, 'gen': gen, 'name': name,
                     'file': entry['file'],
                     'expected': entry.get('sha256') or '',
                     'path': path, 'state': state})
    return rows


def _cmd_status() -> int:
    rows = slot_rows()
    width = max(len(r['key']) for r in rows)
    print(f"{'slot':<{width}}  state     expected-sha       placed")
    for r in rows:
        placed = r['path'].name if r['state'] not in ('missing', 'own') \
            else ('committed' if r['state'] == 'own' else '—')
        print(f"{r['key']:<{width}}  {r['state']:<9}"
              f"  {r['expected'][:16]:<16}  {placed}")
    counts = {s: sum(1 for r in rows if r['state'] == s) for s in _STATES}
    print(f"\n{counts['pinned']} pinned · {counts['unpinned']} unpinned · "
          f"{counts['missing']} missing · {counts['own']} own (committed)")
    print('place a dump:  python3 -m crumpet_emu.bins place FILE --as gen:name')
    for gen, hint in SCENARIO_HINTS.items():
        print(f'  {gen:<6} unlocks {hint}')
    print(f"unpinned images run with a warning — binaries/README.md")
    return 0


def _cmd_place(args) -> int:
    if ':' not in args.as_slot:
        print(f"{args.as_slot}: no manifest slot — the slot is GEN:NAME "
              f"(e.g. 2021:lk or common:brom); new slots require a "
              f'manifest PR — {resources.PROVENANCE_POINTER}',
              file=sys.stderr)
        return 2
    gen, name = args.as_slot.split(':', 1)
    entry = resources._manifest().get(args.as_slot)
    if entry is None:
        print(f"{args.as_slot}: no manifest slot — place your dump under the "
              f"manifest's file name in binaries/vendor/<gen>/; new slots "
              f"require a manifest PR — {resources.PROVENANCE_POINTER}",
              file=sys.stderr)
        return 2
    src = Path(args.file)
    if not src.is_file():
        print(f'no such file: {src}', file=sys.stderr)
        return 1
    dest_dir = resources.VENDOR_DIR / entry['gen']
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / entry['file']
    shutil.copyfile(src, dest)

    if resources.available(gen, name):
        verdict = 'pinned ✓ (sha matches the manifest — runs quietly)'
    else:
        import hashlib
        digest = hashlib.sha256(dest.read_bytes()).hexdigest()
        verdict = (f'unpinned ⚠ sha256 {digest[:16]}… — scenarios run it; '
                   f'pytest tier-2 wants the pinned build')
    print(f'placed {src} → {dest}')
    print(f'  {args.as_slot}: {verdict}')
    print(f'  (or set {resources._env_var(name, gen)}'
          f'={dest} instead of dropping the file in)')
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog='python3 -m crumpet_emu.bins',
        description='vendor image placement: status + drop-in installer')
    sub = parser.add_subparsers(dest='cmd')
    sub.add_parser('status', help='per-slot placement table (default)')
    p_place = sub.add_parser('place', help='copy an image into its slot')
    p_place.add_argument('file', help='image file to place')
    p_place.add_argument('--as', dest='as_slot', metavar='GEN:NAME',
                         required=True,
                         help='manifest slot, e.g. 2021:lk or common:brom')
    args = parser.parse_args(argv)
    if args.cmd == 'place':
        return _cmd_place(args)
    return _cmd_status()


if __name__ == '__main__':
    raise SystemExit(main())
