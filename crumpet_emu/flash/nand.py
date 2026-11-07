# Donor: WS/tools/kamakiri/emu/nand_model.py
# Upstream: R0rt1z2/kamakiri
# Copied verbatim: 2026-10-31 (relative gpt import works as-is)

"""NAND chip model for the crumpet board (MT8167 + Macronix MX30LF4G28AD).

Geometry: 2048 blocks x 64 pages/block x (4096 data + 256 spare) bytes per
page; the data plane is 2048 * 64 * 4096 = 512 MiB. LBA mapping is one
4096-byte LBA per page -- the spare area carries ECC and is never addressed
by LBAs -- so page_of_lba(lba4096) == lba4096.

Bad-block markers (assumed layout; no datasheet exists in this repo and the
2021 donor images carry no spare bytes): as is standard for this geometry
class (MX30LF4G28AD first-/second-page BBM), the BBM occupies spare byte 0
of page 0 and page 1 of every block. program_page() masks those positions
so programmed spare bytes never clobber a BBM; erase_block() restores them
to 0xFF.

Programming is one-shot per erase, like real SLC NAND: a page accepts a
single program_page() after its block is erased, then only erase_block()
can reset it. PageNotErased is raised otherwise.

Donor placement: load_donors() parses the GPT out of the brhgptpl_0 donor
(emu.gpt.parse_gpt_from_image) and flashes each donor file's data plane at
its partition start page, with all-0xFF spare (donor files carry no spare
bytes).
"""
from pathlib import Path

from . import gpt

ERASED = 0xFF


class PageNotErased(Exception):
    """Programming was attempted on a page that is not fully erased."""

    def __init__(self, page: int):
        self.page = page
        super().__init__(f'page {page} is not erased')


class NandChip:
    PAGE_DATA = 4096
    PAGE_SPARE = 256
    PAGES_PER_BLOCK = 64
    BLOCKS = 2048

    # BBM layout assumption documented in the module docstring: spare byte 0
    # of the first two pages of every block.
    BBM_PAGE_OFFSETS = (0, 1)      # page index within block
    BBM_SPARE_OFFSET = 0           # byte offset within the spare area

    # donor file name -> GPT partition carrying it (A-slot for two-slot parts)
    DONOR_PART = {'lk': 'lk_a', 'boot': 'boot_a'}
    GPT_DONOR = 'brhgptpl_0'       # the donor the GPT is parsed from

    def __init__(self):
        self._erased_page = bytes([ERASED]) * (self.PAGE_DATA + self.PAGE_SPARE)
        self._pages: dict[int, bytes] = {}  # programmed pages only

    # ---- addressing ----

    @property
    def _total_pages(self) -> int:
        return self.BLOCKS * self.PAGES_PER_BLOCK

    def page_of_lba(self, lba4096: int) -> int:
        """Map a 4096-byte LBA to its page: identity on this geometry."""
        if not 0 <= lba4096 < self._total_pages:
            raise ValueError(f'LBA {lba4096} outside 0..{self._total_pages - 1}')
        return lba4096

    def _check_page(self, page: int) -> None:
        if not 0 <= page < self._total_pages:
            raise ValueError(f'page {page} outside 0..{self._total_pages - 1}')

    # ---- erase / program / read ----

    def erase_block(self, block: int) -> None:
        if not 0 <= block < self.BLOCKS:
            raise ValueError(f'block {block} outside 0..{self.BLOCKS - 1}')
        first = block * self.PAGES_PER_BLOCK
        for page in range(first, first + self.PAGES_PER_BLOCK):
            self._pages.pop(page, None)

    def program_page(self, page: int, data_spare: bytes) -> None:
        """Program one page from a full 4352-byte data+spare payload."""
        self._check_page(page)
        if len(data_spare) != self.PAGE_DATA + self.PAGE_SPARE:
            raise ValueError(
                f'page payload must be {self.PAGE_DATA + self.PAGE_SPARE} '
                f'bytes, got {len(data_spare)}')
        if self._pages.get(page, self._erased_page) != self._erased_page:
            raise PageNotErased(page)
        payload = bytearray(data_spare)
        if page % self.PAGES_PER_BLOCK in self.BBM_PAGE_OFFSETS:
            payload[self.PAGE_DATA + self.BBM_SPARE_OFFSET] = ERASED
        self._pages[page] = bytes(payload)

    def read_page(self, page: int) -> bytes:
        """Return the full 4352-byte page (erased pages read as 0xFF)."""
        self._check_page(page)
        return self._pages.get(page, self._erased_page)

    def dump(self) -> dict[int, bytes]:
        """Return {page: 4352-byte page} for every programmed page."""
        return dict(self._pages)

    def load_dump(self, dump: dict[int, bytes]) -> None:
        """Restore a chip state produced by dump() (layer-5 replay:
        intermediate snapshots classify without re-deploying)."""
        self._pages = {}
        for page, payload in dump.items():
            self._check_page(page)
            if len(payload) != self.PAGE_DATA + self.PAGE_SPARE:
                raise ValueError(
                    f'dump page {page} is {len(payload)} bytes, want '
                    f'{self.PAGE_DATA + self.PAGE_SPARE}')
            self._pages[page] = bytes(payload)

    # ---- donor loading ----

    def load_donors(self, donors: dict[str, Path]) -> None:
        """Flash donor images at their GPT partition start pages.

        The GPT is parsed from the brhgptpl_0 donor, which must be present.
        Each file's data plane is programmed page by page with all-0xFF
        spare; covered blocks are erased first, so loading is repeatable.
        """
        if self.GPT_DONOR not in donors:
            raise ValueError(f'{self.GPT_DONOR!r} donor is required '
                             '(the GPT is parsed from it)')
        table = gpt.parse_gpt_from_image(
            Path(donors[self.GPT_DONOR]).read_bytes())
        for name, path in donors.items():
            part = self.DONOR_PART.get(name, name)
            if part not in table:
                raise ValueError(f'no GPT partition for donor {name!r}')
            self._flash_image(self.page_of_lba(table[part][0]),
                              table[part][1], Path(path).read_bytes())

    def _flash_image(self, first_page: int, part_lbas: int, data: bytes) -> None:
        n_pages = -(-len(data) // self.PAGE_DATA)  # ceil; tail pads with 0xFF
        if n_pages > part_lbas:
            raise ValueError(f'image of {n_pages} pages exceeds partition '
                             f'of {part_lbas} LBAs')
        last_page = first_page + n_pages  # exclusive
        for block in range(first_page // self.PAGES_PER_BLOCK,
                           -(-last_page // self.PAGES_PER_BLOCK)):
            self.erase_block(block)
        spare = bytes([ERASED]) * self.PAGE_SPARE
        for i in range(n_pages):
            chunk = data[i * self.PAGE_DATA:(i + 1) * self.PAGE_DATA]
            self.program_page(first_page + i,
                              chunk.ljust(self.PAGE_DATA, b'\xff') + spare)
