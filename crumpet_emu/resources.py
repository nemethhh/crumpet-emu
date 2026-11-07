"""Vendor/own binary resolution: env overrides, generation manifest, place-and-run.

Vendor-proprietary blobs are never committed: ``binaries/vendor/`` is
gitignored, and every vendor image resolves at runtime via the
``CRUMPET_EMU_<GEN>_<NAME>`` environment variable, else the repo-local
default ``binaries/vendor/<gen>/<file>``. Any placed image RUNS: a file
whose sha256 matches ``binaries/manifest.json`` is served quietly
(pinned); any other bytes are served with a loud one-time-per-slot
UNPINNED warning on stderr — wrong-generation images are labeled, not
refused (a stranger's own dump must run; see binaries/README.md).
Own-source artifacts are committed under ``binaries/own/`` and resolve
without a sha gate. ``available`` keeps pinned-clean semantics for the
tier-2 test battery; ``present`` reports placement-only existence.
"""

import hashlib
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BINARIES_DIR = REPO_ROOT / 'binaries'
VENDOR_DIR = BINARIES_DIR / 'vendor'
OWN_DIR = BINARIES_DIR / 'own'
MANIFEST_PATH = BINARIES_DIR / 'manifest.json'

#: appended to every resolve failure so operators land on the placement docs
PROVENANCE_POINTER = 'see binaries/README.md + docs/provenance.md'

ENV_PREFIX = 'CRUMPET_EMU'

_READ_CHUNK = 1 << 20


class MissingBinary(RuntimeError):
    """A required binary was not found (env var and default path checked)."""


class ShaMismatch(RuntimeError):
    """A vendor file's sha256 differs from the manifest entry.

    Kept for API compat; ``resolve`` no longer raises it — placed images
    run with an UNPINNED warning instead of being refused.
    """

_manifest_cache = None

#: slots whose UNPINNED warning was already emitted this process
_unpinned_warned: set = set()


def _manifest() -> dict:
    global _manifest_cache
    if _manifest_cache is None:
        with open(MANIFEST_PATH, encoding='utf-8') as fh:
            _manifest_cache = json.load(fh)
    return _manifest_cache


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as fh:
        for block in iter(lambda: fh.read(_READ_CHUNK), b''):
            digest.update(block)
    return digest.hexdigest()


def _env_var(name: str, gen: str) -> str:
    # hyphenated manifest names (lk-patched) sanitize to underscores: a
    # hyphen is not a legal shell identifier, so the raw spelling produced
    # an env var that could never be exported
    return f'{ENV_PREFIX}_{gen.upper()}_{name.upper().replace("-", "_")}'


def _entry(name: str, gen: str) -> dict:
    key = f'{gen}:{name}'
    entry = _manifest().get(key)
    if entry is None:
        raise MissingBinary(
            f"{key}: no manifest slot — place your dump under the manifest's "
            f'file name in binaries/vendor/<gen>/; new slots require a '
            f'manifest PR — {PROVENANCE_POINTER}')
    return entry


def _candidate(name: str, gen: str, entry: dict) -> Path:
    override = os.environ.get(_env_var(name, gen))
    if override:
        return Path(override)
    if entry['gen'] == 'own':
        return OWN_DIR / entry['file']
    return VENDOR_DIR / gen / entry['file']


def _warn_unpinned(key: str, path: Path, expected, actual: str) -> None:
    if key in _unpinned_warned:
        return
    _unpinned_warned.add(key)
    print(f'[crumpet-emu] UNPINNED {key} at {path}: sha256 {actual[:16]}… '
          f'!= manifest {(expected or "?")[:16]}… — running your bytes; '
          f'verdicts not comparable to pinned builds (binaries/README.md)',
          file=sys.stderr)


def resolve(name: str, gen: str = '2021') -> Path:
    """Return the checked path for manifest key ``f'{gen}:{name}'``.

    Resolution order: ``CRUMPET_EMU_<GEN>_<NAME>`` env var, else the
    repo-local default (``binaries/vendor/<gen>/<file>``; own artifacts:
    ``binaries/own/<file>``, no sha gate). Place-and-run: a placed vendor
    file is served whether pinned or not — pinned (sha256 matches the
    manifest) quietly; unpinned with a loud once-per-slot stderr warning.
    Absent files raise MissingBinary with a placement-teaching message.
    """
    entry = _entry(name, gen)
    path = _candidate(name, gen, entry)
    if not path.is_file():
        raise MissingBinary(
            f'{gen}:{name}: not placed — drop your image at {path} or set '
            f'{_env_var(name, gen)}; any dump runs once placed (unpinned '
            f'images get a warning) — {PROVENANCE_POINTER}')
    if entry['gen'] != 'own':
        actual = _sha256(path)
        if actual != entry.get('sha256'):
            _warn_unpinned(f'{gen}:{name}', path, entry.get('sha256'), actual)
    return path


def own(name: str) -> Path:
    """Return the path of a committed own-source artifact (no sha gate)."""
    path = OWN_DIR / name
    if not path.is_file():
        raise MissingBinary(
            f'own:{name}: not committed at {path} — {PROVENANCE_POINTER}')
    return path


def present(name: str, gen: str = '2021') -> bool:
    """True iff a file exists at the resolved candidate path (pinned or
    not). Placement-only: never raises, unknown slot → False. Scenarios
    and the bins CLI use this; tier-2 gating uses ``available`` (pinned
    -clean) instead.
    """
    entry = _manifest().get(f'{gen}:{name}')
    if entry is None:
        return False
    return _candidate(name, gen, entry).is_file()


def available(name: str, gen: str = '2021') -> bool:
    """True iff resolvable now as a PINNED build: committed own artifact
    present, or vendor file present with a matching manifest sha256.
    Never raises. Tier-2 test gating uses this; placement-only checks use
    ``present``.

    Best-effort check: a TOCTOU window remains on concurrently-removed
    files (acceptable — single-user tool).
    """
    entry = _manifest().get(f'{gen}:{name}')
    if entry is None:
        return False
    path = _candidate(name, gen, entry)
    if not path.is_file():
        return False
    if entry['gen'] == 'own':
        return True
    return _sha256(path) == entry.get('sha256')
