# binaries/ — image placement for crumpet-emu

Vendor-proprietary blobs are **never committed** to this repository:
`binaries/vendor/` is gitignored. Every vendor image the emulator loads is
resolved at runtime by `crumpet_emu.resources`, in this order:

1. `CRUMPET_EMU_<GEN>_<NAME>` environment variable (absolute path), else
2. the repo-local default `binaries/vendor/<gen>/<file>` — drop the file
   there using the `file` name from `manifest.json`.

**Place-and-run:** any image placed at a manifest slot runs — no hash
registration, no manifest editing. Two states, announced per slot:

- **pinned** — the file's sha256 matches [`manifest.json`](manifest.json):
  it runs quietly and its verdicts are comparable across machines. This is
  what the tier-2 pytest battery requires (it pins exact vendor behavior).
- **unpinned** — any other bytes at the slot (your own OTA version, your
  chip-off dump): they run too, with a loud one-time-per-slot `UNPINNED`
  warning on stderr naming the slot and both sha prefixes. Your bytes,
  your verdicts.

An absent file raises `resources.MissingBinary` with a message that
teaches this placement; an unknown slot name (`gen:name` not in the
manifest) is refused with a pointer to the manifest's `file` names — new
slots require a manifest PR. Check or install placements with:

```bash
python3 -m crumpet_emu.bins                                   # status table
python3 -m crumpet_emu.bins place /path/to/lk.img --as 2025:lk
```

Full origins, extraction steps, and licensing/attribution for every
pinned file live in `docs/provenance.md`.

### Donor tool-tree crosschecks (operator-local)

A few pytest files crosscheck own artifacts against the donor tool trees
(kamakiri IDA workspaces, donor venvs). They locate that workspace via
the `CRUMPET_EMU_WS` env var (absolute workspace root). Unset — as in
any fresh clone — those tests skip cleanly; nothing else depends on it.

`binaries/own/` holds **committed** own-source artifacts (built from this
project's MIT-licensable sources). They resolve via `resources.own(name)`
on the committed path, with no sha gate at resolve time; the manifest lists
them under `own:` keys for documentation. `resources.available(name, gen)`
reports whether an artifact is resolvable right now (own artifact present,
or vendor file present **and** sha-clean) — it never raises.

Generations:

- `common` — generation-neutral boot-rom artifacts (BROM dump, SRAM snapshot)
- `2021` — 2021 OTA images + kamakiri `lk-patched.img`
- `2025` — 2025 OTA images + `pl2025.bin`
- `own` — own-built artifacts (committed)

## Vendor placement table

Default drop-in dir is `binaries/vendor/<gen>/<file>`, or set the env var.

| manifest key | file | env var | size (B) |
|---|---|---|---|
| `common:brom` | `brom_MT8167_MT8516_MT8362_8167.bin` | `CRUMPET_EMU_COMMON_BROM` | 131,072 |
| `common:sram` | `sram_MT8167_MT8516_MT8362_8167.bin` | `CRUMPET_EMU_COMMON_SRAM` | 2,097,152 |
| `2021:brhgptpl_0` | `brhgptpl_0.img` | `CRUMPET_EMU_2021_BRHGPTPL_0` | 184,320 |
| `2021:brhgptpl_1` | `brhgptpl_1.img` | `CRUMPET_EMU_2021_BRHGPTPL_1` | 184,320 |
| `2021:brhgptpl_2` | `brhgptpl_2.img` | `CRUMPET_EMU_2021_BRHGPTPL_2` | 184,320 |
| `2021:brhgptpl_3` | `brhgptpl_3.img` | `CRUMPET_EMU_2021_BRHGPTPL_3` | 184,320 |
| `2021:lk` | `lk.img` | `CRUMPET_EMU_2021_LK` | 233,472 |
| `2021:tee1` | `tee1.img` | `CRUMPET_EMU_2021_TEE1` | 2,367,488 |
| `2021:tee2` | `tee2.img` | `CRUMPET_EMU_2021_TEE2` | 2,367,488 |
| `2021:boot` | `boot.img` | `CRUMPET_EMU_2021_BOOT` | 10,354,688 |
| `2021:lk-patched` | `lk-patched.img` | `CRUMPET_EMU_2021_LK_PATCHED` | 237,568 |
| `2025:brhgptpl_0` | `brhgptpl_0.img` | `CRUMPET_EMU_2025_BRHGPTPL_0` | 184,320 |
| `2025:brhgptpl_1` | `brhgptpl_1.img` | `CRUMPET_EMU_2025_BRHGPTPL_1` | 184,320 |
| `2025:brhgptpl_2` | `brhgptpl_2.img` | `CRUMPET_EMU_2025_BRHGPTPL_2` | 184,320 |
| `2025:brhgptpl_3` | `brhgptpl_3.img` | `CRUMPET_EMU_2025_BRHGPTPL_3` | 184,320 |
| `2025:lk` | `lk.img` | `CRUMPET_EMU_2025_LK` | 237,568 |
| `2025:tee1` | `tee1.img` | `CRUMPET_EMU_2025_TEE1` | 2,367,488 |
| `2025:tee2` | `tee2.img` | `CRUMPET_EMU_2025_TEE2` | 2,367,488 |
| `2025:boot` | `boot.img` | `CRUMPET_EMU_2025_BOOT` | 9,908,224 |
| `2025:pl` | `pl2025.bin` | `CRUMPET_EMU_2025_PL` | 149,088 |

## Own artifacts (committed under `binaries/own/`)

| manifest key | file | size (B) |
|---|---|---|
| `own:stage1.bin` | `stage1.bin` | 624 |
| `own:stage1.elf` | `stage1.elf` | 4,168 |
| `own:stage2.bin` | `stage2.bin` | 4,044 |
| `own:payload.elf` | `payload.elf` | 10,660 |
| `own:payload.bin` | `payload.bin` | 2,484 |
| `own:payload-lka.elf` | `payload-lka.elf` | 10,660 |
| `own:payload-lka.bin` | `payload-lka.bin` | 2,484 |
| `own:payload-lkb.elf` | `payload-lkb.elf` | 10,660 |
| `own:payload-lkb.bin` | `payload-lkb.bin` | 2,484 |
| `own:tz-lka.img` | `tz-lka.img` | 1,143,312 |
| `own:tz-lkb.img` | `tz-lkb.img` | 1,143,312 |
| `own:key_continuity.json` | `key_continuity.json` | 6,116 |

## See also

- [`docs/provenance.md`](../docs/provenance.md) — every manifest entry
  with source path, sha256, park/own classification, upstream
  attribution, own-artifact build instructions, and the seeds.json
  restructured-export + stage2-hash notes.
- [`docs/architecture.md`](../docs/architecture.md) — what each layer
  loads and from where.
- The `scenarios/` CLIs resolve everything through this mechanism and
  print this file + provenance pointer on a missing binary; a placed
  binary whose sha differs from the manifest runs with an `UNPINNED`
  warning instead.
