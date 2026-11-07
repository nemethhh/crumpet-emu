#!/usr/bin/env python3
# Task 12: thin CLI over crumpet_emu.usb.fastboot.FastbootHost (lk.img via
# resources; no workspace paths).

"""lk fastboot host CLI: --cmd 'flash:otucode' --data FILE | --getvar all."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from crumpet_emu import resources
from crumpet_emu.lk.session import LkSession
from crumpet_emu.usb.fastboot import FastbootHost


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cmd', help="fastboot command, e.g. 'flash:otucode'")
    p.add_argument('--data', help='payload file streamed via the download path')
    p.add_argument('--getvar', metavar='NAME', help="e.g. 'all' or 'version'")
    a = p.parse_args(argv)
    if not (a.cmd or a.getvar):
        p.error('one of --cmd / --getvar required')
    lk = LkSession(resources.resolve('lk', '2025').read_bytes(), verbose=False)
    host = FastbootHost(lk)
    try:
        if a.getvar:
            status, message = host.getvar(a.getvar)
            print(f'{status}: {message}')
            return 0
        verb, _, arg = a.cmd.partition(':')
        data = Path(a.data).read_bytes() if a.data else b''
        status, message, payload = host.send(verb, arg, data=data)
        print(f'{status}: {message}')
        if payload:
            print(f'[{len(payload)} tx bytes via usb_write seam]')
        return 0
    except (RuntimeError, ValueError) as e:
        print(f'error: {e}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
