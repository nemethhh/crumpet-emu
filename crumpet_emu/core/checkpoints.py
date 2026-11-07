"""Checkpoint save/restore for core Session (serialize regions + registers).

Region tracking: Task 1's Session maps its internal stack directly in
__init__ and keeps no region list, so checkpoints carry their own
registry — `TrackedSession` records every (addr, size) passed to map()
plus the internal stack (saved SP/LR and call frames live there), and
save() serializes each recorded region's current bytes. Tests and
consumers build sessions with TrackedSession; restore() returns a
TrackedSession so a restored session is itself checkpointable again.

On-disk format: pickle of the versioned dict
    {'v': 1,
     'regions': [[addr, bytes], ...],
     'context': blob,   # pickle.dumps(uc.context_save())
     'extra': {...}}    # opaque caller blobs (e.g. transport queues)

Context blob: unicorn 2.1.4 python bindings expose only
context_save()/context_restore(UcContext) — there is no context_write,
and a raw bytes(context) cannot be turned back into a usable context —
so the blob is pickle.dumps(context_save()) and restore() unpickles it
and passes it to uc.context_restore(). Verified to preserve all
registers across instances and processes. pickle.load must never see an
untrusted checkpoint file.
"""

import pickle
from pathlib import Path

from crumpet_emu.core.session import STACK_BASE, STACK_SIZE, Session


class TrackedSession(Session):
    """Session that remembers its mapped regions for checkpointing."""

    def __init__(self):
        super().__init__()
        self._regions: list[tuple[int, int]] = [(STACK_BASE, STACK_SIZE)]

    def map(self, addr: int, size: int) -> None:
        super().map(addr, size)
        self._regions.append((addr, size))


def save(session: Session, path: Path,
         extra: dict[str, bytes] | None = None) -> Path:
    """Write session state (regions, registers, extra) to path; return it."""
    regions = getattr(session, '_regions', None)
    if regions is None:
        raise TypeError('save() needs a TrackedSession (region tracking), '
                        'got %s' % type(session).__name__)
    blob = {
        'v': 1,
        'regions': [[addr, session.read(addr, size)] for addr, size in regions],
        'context': pickle.dumps(session.uc.context_save()),
        'extra': dict(extra or {}),
    }
    path = Path(path)
    with open(path, 'wb') as fh:
        pickle.dump(blob, fh)
    return path


def restore(path: Path) -> tuple[Session, dict[str, bytes]]:
    """Load a checkpoint; return (session, extra) with all regs restored."""
    with open(Path(path), 'rb') as fh:
        blob = pickle.load(fh)
    if not isinstance(blob, dict):
        raise ValueError('not a checkpoint dict: %s' % type(blob).__name__)
    if blob.get('v') != 1:
        raise ValueError('unsupported checkpoint version: %r' % (blob.get('v'),))
    session = TrackedSession()
    for addr, data in blob['regions']:
        if (addr, len(data)) not in session._regions:
            session.map(addr, len(data))  # fresh stack already tracked
        session.write(addr, data)
    session.uc.context_restore(pickle.loads(blob['context']))
    return session, dict(blob['extra'])
