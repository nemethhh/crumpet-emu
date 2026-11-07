# Donor: WS/tools/kamakiri/modules/main_crumpet.py
# Upstream: R0rt1z2/kamakiri
# Copied verbatim: 2026-10-31 (import map only: emu/emu.gpt -> relative
#   ..flash imports; modules.functions_crumpet -> relative .functions;
#   donor sys.path bootstrap dropped with it)

"""Crumpet deployment orchestration — spec §7.4 order, fail-closed gates.

This is the host-side deploy driver. It consumes an established session
through the plain read(n)/write(bytes) transport surface (emu/transport
FakeTransport against the emulation; the same shape a USB CDC device
stream offers on hardware) and performs the deployment sequence whose
safety properties ARE the product:

  2. read the GPT from flash, parse the 18 partitions, sanity-assert
     names/geometry — and require the on-flash table to be identical to
     the donor brhgptpl_0 table (placement authority: emu/gpt.py);
  3. BACKUP before the first write: read back and sha256 every
     partition this session writes, plus the full boot region (LBA 0
     through the end of tee2 — every boot-critical partition lies in
     that span), as raw files + manifest.json in cfg.backup_dir;
  4. detect the active slot READ-ONLY from the AOSP boot_control/BCB
     slot suffix inside misc (see detect_active_slot); anything
     unrecognized raises SlotUndetermined and the deploy performs ZERO
     writes — misc is never written by this tool;
  5. stock tee -> tee2;
  6. stock LK (the key-continuity-selected year, expressed by which
     donor cfg.donors['lk'] points at) -> the ACTIVE slot;
  7. 2021 preloader -> brhgptpl_0..3 in order, each copy fully written
     and readback-verified before the next (a stall mid-region always
     leaves the already-written copies complete; the per-copy index
     bytes flow naturally from flashing the donor brhgptpl_k images);
  8. patched LK -> the INACTIVE slot;
  9. crafted tz.img (the variant keyed by the INACTIVE slot — it embeds
     LK_PART_NAME and must load the patched LK) -> tee1, LAST: every
     fallback for it is already resident at that point.

Every write is readback-verified before the next step (inside
functions_crumpet.flash_image). NEVER-written partitions (misc,
idme_nand, persist, reserve0..3) are enforced by an explicit allowlist:
a step whose target is not in WRITABLE_PARTITIONS refuses to erase or
program anything.

`snapshots` (dry-run only): when a list is passed, a NandChip-style
{page: 4352B} dump is appended after the baseline (post slot-detect)
and after every write step above — including each preloader copy — so
Task 10/11 can replay every intermediate state through the bootable-
or-BROM checker. It requires the transport to expose snapshot() (the
FakeTransport does; a hardware stream does not — pass None there).
"""
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from ..flash import gpt
from ..flash.gpt import parse_gpt_from_image

from . import functions as fc

# The 18 partitions of the crumpet GPT (verified against the 2021
# brhgptpl_0 donor, task 1): the exact expected name set.
EXPECTED_PARTITIONS = frozenset({
    'brhgptpl_0', 'brhgptpl_1', 'brhgptpl_2', 'brhgptpl_3',
    'reserve0', 'lk_a', 'lk_b', 'reserve1', 'idme_nand', 'reserve2',
    'misc', 'reserve3', 'tee1', 'boot_a', 'tee2', 'boot_b',
    'persist', 'userdata',
})

# NEVER write these (spec §7.4): BCB/misc stays untouched, and the
# factory/reserve regions are not this tool's to reflash.
NEVER_PARTITIONS = frozenset({'misc', 'idme_nand', 'persist',
                              'reserve0', 'reserve1', 'reserve2',
                              'reserve3'})

# The explicit allowlist: the only partitions deploy may erase/program.
WRITABLE_PARTITIONS = frozenset({'tee2', 'lk_a', 'lk_b', 'tee1',
                                 'brhgptpl_0', 'brhgptpl_1',
                                 'brhgptpl_2', 'brhgptpl_3'})

# the boot region ends at the end of tee2: every boot-critical
# partition (GPT/preloader copies, both LK slots, both TEEs, misc,
# idme_nand, reserves, boot_a/b) lies inside LBA 0 .. this end
BOOT_REGION_END_PART = 'tee2'

# AOSP boot_control/BCB slot suffix inside the 2048-byte
# bootloader_message that begins misc's first page: 4 bytes at
# data-plane offset 30 (task-7 ruling; see detect_active_slot).
BCB_SLOT_OFFSET = 30

# one 4096-byte LBA per page on this geometry (emu/nand_model)
LBA_BYTES = fc.PAGE_DATA


class SlotUndetermined(RuntimeError):
    """misc carries no recognizable active-slot suffix; zero writes."""


@dataclass
class DeployConfig:
    """One deployment's inputs.

    donors maps the stock images to flash: 'lk' is the key-continuity-
    selected year's stock LK (the dry run uses the 2021 matched set;
    Task 8's key_continuity.json / Task 10 wire the choice), 'tee2' the
    stock TEE fallback, 'brhgptpl_0..3' the 2021 preloader copies
    (brhgptpl_0 doubles as the GPT authority for the sanity check).
    payload_variants holds the crafted tz.img builds keyed by the LK
    partition name they embed (lk_a|lk_b); the deploy flashes the
    variant keyed by the INACTIVE slot. patched_lk is the patched stock
    LK for the inactive slot.
    """
    donors: dict[str, Path]
    payload_variants: dict[str, Path]
    patched_lk: Path
    backup_dir: Path


# ------------------------------------------------------------- gates --

def detect_active_slot(read_page_fn, gpt: dict) -> str:
    """Return the active slot's LK partition name ('lk_a'/'lk_b').

    READ-ONLY: reads misc's first page through `read_page_fn` (a
    page -> 4352-byte-page callable) and parses the AOSP boot_control
    HAL slot suffix — the 4 bytes at offset 30 of the 2048-byte
    bootloader_message (b'_a\\x00\\x00' or b'a\\x00\\x00' style: an
    optional leading underscore, the slot letter, trailing NULs).
    Erased (0xFF), zeroed, or any unrecognized bytes raise
    SlotUndetermined: the caller must perform zero writes.
    """
    if 'misc' not in gpt:
        raise SlotUndetermined('no misc partition in the GPT')
    page = read_page_fn(gpt['misc'][0])        # LBA -> page is identity
    raw = bytes(page[BCB_SLOT_OFFSET:BCB_SLOT_OFFSET + 4])
    suffix = raw.rstrip(b'\x00')
    if suffix.startswith(b'_'):
        suffix = suffix[1:]
    if suffix == b'a':
        return 'lk_a'
    if suffix == b'b':
        return 'lk_b'
    raise SlotUndetermined(
        f'misc bootloader_message slot suffix at offset '
        f'{BCB_SLOT_OFFSET} is {raw!r} — not a recognizable active slot; '
        'refusing to write anything')


def read_gpt_from_flash(transport) -> dict[str, tuple[int, int]]:
    """Read the on-flash GPT and parse it with the donor parser.

    GPT LBA0 sits at partition-relative page GPT_FILE_BASE//4096 == 2 of
    brhgptpl_0 (chip page 2): the first two pages carry the MTK
    preloader header/BRLYT. LBAs 0..33 cover header + entries for this
    table (128 entries x 128 B in 4 LBAs).
    """
    first = gpt.GPT_FILE_BASE // LBA_BYTES
    pages = fc.read_page_range(transport, first, 34)
    blob = b'\x00' * gpt.GPT_FILE_BASE \
        + b''.join(p[:fc.PAGE_DATA] for p in pages)
    return parse_gpt_from_image(blob)


def sanity_check_gpt(gpt: dict, donor_gpt: dict) -> None:
    """Fail-closed GPT gate: the exact 18-partition name set, 64-LBA
    (block) alignment, non-overlapping extents, and a table identical
    to the donor brhgptpl_0 placement."""
    names = set(gpt)
    if names != set(EXPECTED_PARTITIONS):
        missing = sorted(EXPECTED_PARTITIONS - names)
        extra = sorted(names - EXPECTED_PARTITIONS)
        raise RuntimeError(f'unexpected GPT partition set (missing '
                           f'{missing}, extra {extra})')
    intervals = []
    for name, (start, size) in gpt.items():
        if start % fc.PAGES_PER_BLOCK:
            raise RuntimeError(f'partition {name} starts at LBA {start}, '
                               'not block-aligned')
        if size <= 0:
            raise RuntimeError(f'partition {name} has size {size}')
        intervals.append((start, start + size, name))
    intervals.sort()
    for (_, end_a, name_a), (start_b, _, name_b) in zip(intervals,
                                                        intervals[1:]):
        if start_b < end_a:
            raise RuntimeError(f'partitions {name_a} and {name_b} overlap')
    if gpt != donor_gpt:
        raise RuntimeError('on-flash GPT differs from the donor '
                           'brhgptpl_0 table — refusing to deploy')


# ------------------------------------------------------------- backup --

def backup_partitions(transport, gpt: dict, partitions, backup_dir: Path
                      ) -> dict[str, str]:
    """Read back and sha256 every partition in `partitions` plus the
    full boot region, BEFORE the first write.

    The boot region is the superset read (LBA 0 .. end of tee2); each
    partition's image is sliced out of it, so nothing is read twice.
    Raw bytes land in backup_dir as <part>.img / boot_region.bin, and
    manifest.json maps name -> sha256 hex of the partition's full
    on-flash content (data planes over size_lba LBAs, erased pages
    reading 0xFF). Returns the manifest dict.
    """
    backup_dir = Path(backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)
    boot_end = (gpt[BOOT_REGION_END_PART][0]
                + gpt[BOOT_REGION_END_PART][1])
    pages = fc.read_page_range(transport, 0, boot_end)
    planes = b''.join(p[:fc.PAGE_DATA] for p in pages)
    (backup_dir / 'boot_region.bin').write_bytes(planes)

    manifest = {'boot_region': hashlib.sha256(planes).hexdigest()}
    for part in partitions:
        if part not in gpt:
            raise RuntimeError(f'cannot back up unknown partition '
                               f'{part!r}')
        start, size = gpt[part]
        blob = planes[start * LBA_BYTES:(start + size) * LBA_BYTES]
        (backup_dir / f'{part}.img').write_bytes(blob)
        manifest[part] = hashlib.sha256(blob).hexdigest()
    (backup_dir / 'manifest.json').write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    return manifest


# ------------------------------------------------------------- deploy --

def deploy(transport, cfg: DeployConfig, snapshots: list | None = None
           ) -> dict[int, bytes]:
    """Run the §7.4 deployment; return {page: verified 4352B} for every
    page this session wrote and readback-verified."""
    def snap() -> None:
        if snapshots is not None:
            snapshot = getattr(transport, 'snapshot', None)
            if snapshot is None:
                raise RuntimeError('snapshots require a transport with '
                                   'snapshot() (dry-run only)')
            snapshots.append(snapshot())

    # ---- step 2: GPT from flash, sanity-asserted against the donor ----
    gpt = read_gpt_from_flash(transport)
    donor_gpt = parse_gpt_from_image(
        Path(cfg.donors['brhgptpl_0']).read_bytes())
    sanity_check_gpt(gpt, donor_gpt)
    fc.kick(transport)

    # ---- step 3: backup every written partition + boot region --------
    backup_partitions(transport, gpt, sorted(WRITABLE_PARTITIONS),
                      cfg.backup_dir)

    # ---- step 4: active slot, READ-ONLY, fail-closed ------------------
    def read_page_fn(page: int) -> bytes:
        return fc.read_page(transport, page)

    active = detect_active_slot(read_page_fn, gpt)
    inactive = 'lk_b' if active == 'lk_a' else 'lk_a'
    snap()                                   # baseline: zero writes yet

    written: dict[int, bytes] = {}

    def flash_part(part: str, path) -> None:
        """Allowlist-gated erase+program+verify of one partition."""
        if part not in WRITABLE_PARTITIONS:
            raise RuntimeError(f'{part!r} is not in the writable '
                               'allowlist — refusing to flash')
        if part in NEVER_PARTITIONS or part not in gpt:
            raise RuntimeError(f'{part!r} is a NEVER partition or absent '
                               'from the GPT — refusing to flash')
        image = Path(path).read_bytes()
        start, size = gpt[part]
        written.update(fc.flash_image(transport, start, image,
                                      part_pages=size))

    # ---- step 5: stock tee -> tee2 (the fallback TEE) ------------------
    flash_part('tee2', cfg.donors['tee2'])
    snap()

    # ---- step 6: stock LK -> ACTIVE slot --------------------------------
    flash_part(active, cfg.donors['lk'])
    snap()

    # ---- step 7: 2021 preloader -> brhgptpl_0..3, in order -------------
    for k in range(4):
        flash_part(f'brhgptpl_{k}', cfg.donors[f'brhgptpl_{k}'])
        snap()

    # ---- step 8: patched LK -> INACTIVE slot ----------------------------
    flash_part(inactive, cfg.patched_lk)
    snap()

    # ---- step 9: crafted tz.img -> tee1, LAST ---------------------------
    flash_part('tee1', cfg.payload_variants[inactive])
    snap()

    return written
