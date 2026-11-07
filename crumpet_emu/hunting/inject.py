"""Fault-injection recipes against flash models and session memory (Task 15).

New code (no donor port). A recipe is one dict with two forms:

  {'target': 'lk_a'|'lk_b'|'tee1'|'tee2', 'offset': int, 'patch': bytes}
      overwrite `patch` at byte offset `offset` inside the named partition
  {'target': ..., 'fill': int, 'start': int, 'end': int}
      fill the byte range [start, end) inside the named partition with the
      byte value `fill` (0..255)

Offsets are partition-relative; the GPT map in crumpet_emu.flash.image is
the single owner of partition placement (Flash and ChipDumpFlash serve
identical bdev block numbering — ChipDumpFlash is a drop-in replacement).
Unknown target -> ValueError; writes that would run past the partition end
are refused with ValueError too, so a recipe can never silently corrupt the
neighbouring partition.

apply_flash() mutates the flash model's backing store directly (Flash:
512-B bdev block map, ChipDumpFlash: page map — the data plane is patched,
the 256-B spare plane preserved). Both models serve erase-fill (0xFF) for
absent blocks/pages, so patching an absent region materializes the erased
bytes first, matching exactly what read() would have served.

apply_mem(session, recipe) applies the same two forms against memory: here
'target' is the base ADDRESS (int, not a partition name) — `offset`/`patch`
or `start`/`end` are relative byte positions from that base. A non-int
target is refused with ValueError (mirrors the flash unknown-target rule);
writing unmapped memory faults loudly through unicorn.
"""

from crumpet_emu.flash.image import GPT, ChipDumpFlash, Flash

BLK = 512  # bdev block size (the GPT map's unit)
_TARGETS = frozenset(GPT)


def _fill_byte(recipe):
    fill = recipe['fill']
    if not isinstance(fill, int) or isinstance(fill, bool) \
            or not 0 <= fill <= 0xFF:
        raise ValueError(f'fill must be a byte value 0..255, got {fill!r}')
    return fill


def _range_span(recipe):
    """[start, end) span of a fill recipe, validated int/non-negative/ordered."""
    start, end = recipe['start'], recipe['end']
    for name, value in (('start', start), ('end', end)):
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f'fill {name} must be an int byte offset, '
                             f'got {value!r}')
    if start < 0 or end < start:
        raise ValueError(f'fill range needs 0 <= start <= end, '
                         f'got start={start!r} end={end!r}')
    return start, end


def _flash_write(flash, pos: int, data: bytes) -> None:
    """Write data at absolute bdev byte position pos into the backing store.

    Walks 512-B block straddling correctly: a patch crossing a block
    boundary splices into each touched block/page separately. A write must
    never silently move: the target bytearray is materialized to CANONICAL
    size before splicing (512-B block / 4096-B data plane) with 0xFF, so a
    splice always lands at the recipe's offset instead of clamping to a
    stored slice's end.

    One deliberate donor deviation: a PATCHED short trailing block becomes
    a full 512-B block (donor put() stores trailing short slices and
    read() serves them short; unpatched short blocks keep serving short —
    the canonicalization happens only where a recipe touches the block).
    """
    i = 0
    while i < len(data):
        blk = (pos + i) // BLK
        intra = (pos + i) % BLK
        n = min(BLK - intra, len(data) - i)
        chunk = data[i:i + n]
        if isinstance(flash, ChipDumpFlash):
            page_i = blk // ChipDumpFlash.SECTORS_PER_PAGE
            off = (blk % ChipDumpFlash.SECTORS_PER_PAGE) * BLK
            page = bytearray(flash.pages.get(page_i, b''))
            if len(page) < ChipDumpFlash.SECTORS_PER_PAGE * BLK:
                # absent/short page: materialize the FULL 4096-B data plane
                # as erase-fill (never just the touched 512-B slice — the
                # page's other blocks must keep serving 0xFF, not b''); the
                # 256-B spare plane beyond the data plane is never touched
                page.extend(b'\xFF' * (ChipDumpFlash.SECTORS_PER_PAGE * BLK
                                       - len(page)))
            page[off + intra:off + intra + n] = chunk
            flash.pages[page_i] = bytes(page)
        elif isinstance(flash, Flash):
            block = bytearray(flash.read(blk, 1))  # read() erase-fills absent
            if len(block) < BLK:
                # short trailing slice: canonicalize to the 512-B block with
                # erase-fill so the splice lands at its true offset (donor
                # deviation, see docstring)
                block.extend(b'\xFF' * (BLK - len(block)))
            block[intra:intra + n] = chunk
            flash.blocks[blk] = bytes(block)
        else:
            raise TypeError('apply_flash needs a Flash/ChipDumpFlash, '
                            f'got {type(flash).__name__}')
        i += n


def apply_flash(flash, recipe: dict) -> None:
    """Apply one flash recipe; mutates the flash model's backing bytes."""
    target = recipe.get('target')
    if target not in _TARGETS:
        raise ValueError(f'unknown inject target {target!r} — '
                         f'one of {sorted(_TARGETS)}')
    start_blk, size_blk = GPT[target]
    base = start_blk * BLK
    limit = size_blk * BLK
    if 'patch' in recipe:
        offset = recipe['offset']
        patch = bytes(recipe['patch'])
        if not isinstance(offset, int) or isinstance(offset, bool):
            raise ValueError(f'patch offset must be an int byte offset, '
                             f'got {offset!r}')
        if offset < 0 or offset + len(patch) > limit:
            raise ValueError(f'patch [{offset:#x}, {offset + len(patch):#x}) '
                             f'runs outside partition {target!r} '
                             f'({limit:#x} bytes)')
        if len(patch) == 0 and offset == limit:
            raise ValueError(f'no-op patch at partition end ({target!r} '
                             f'offset {offset:#x} == partition size)')
        _flash_write(flash, base + offset, patch)
    else:
        fill = _fill_byte(recipe)
        start, end = _range_span(recipe)
        if end > limit:
            raise ValueError(f'fill [{start:#x}, {end:#x}) runs outside '
                             f'partition {target!r} ({limit:#x} bytes)')
        _flash_write(flash, base + start, bytes([fill]) * (end - start))


def apply_mem(session, recipe: dict) -> None:
    """Apply one memory recipe against session addresses (base = target)."""
    target = recipe.get('target')
    if not isinstance(target, int) or isinstance(target, bool):
        raise ValueError(f'apply_mem target must be a memory address int, '
                         f'got {target!r}')
    if 'patch' in recipe:
        offset = recipe['offset']
        patch = bytes(recipe['patch'])
        if offset < 0:
            raise ValueError(f'offset must be non-negative, got {offset!r}')
        session.write(target + offset, patch)
    else:
        fill = _fill_byte(recipe)
        start, end = _range_span(recipe)
        session.write(target + start, bytes([fill]) * (end - start))
