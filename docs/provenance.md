# Provenance — every binary, its origin, and its classification

This repository never commits vendor-proprietary blobs. Everything the
emulator loads resolves at runtime through `crumpet_emu.resources`
(`CRUMPET_EMU_<GEN>_<NAME>` env override, else
`binaries/vendor/<gen>/<file>`; sha256 checked against
[`binaries/manifest.json`](../binaries/manifest.json) — see
[`binaries/README.md`](../binaries/README.md) for placement). Own-source
artifacts ARE committed under `binaries/own/`. This document lists every
manifest entry with origin and classification, the upstream attribution,
the own-artifact build instructions, and the spec/audit errata that
surfaced during the 2026-10-31 port.

## Licensing and upstream attribution

- This repo: MIT (`LICENSE`, Copyright (c) 2026 Oleksandr Martynenko
  (nemethhh)).
- `kamakiri` (`WS/tools/kamakiri`): local work on
  [R0rt1z2/kamakiri](https://github.com/R0rt1z2/kamakiri) — donor of the
  emu harness (`crumpet_emu/{flash,brom,deploy,usb.transport,usb.model}`),
  the BROM payloads (`binaries/own/stage1*`, `stage2.bin`) and the patch
  tooling ported to `tools/`.
- `amonet-koboreru` (`WS/tools/amonet-koboreru`):
  [R0rt1z2/amonet-koboreru](https://github.com/R0rt1z2/amonet-koboreru),
  MIT — source of the payload/TEE build trees behind the committed
  `binaries/own/payload*` / `tz-*` artifacts and the preloader-segment
  donor (`crumpet_emu/preloader`).
- `lk-emu` (`WS/tools/lk-emu`): in-repo audit harness (same author,
  same workspace) — donor of the LK session/battery surface
  (`crumpet_emu/lk`).

Vendor images themselves remain Amazon/MediaTek proprietary property;
they are **parked** — listed here so an operator with lawful access to
their own device's images can place them, and so every emulated verdict
is reproducible against pinned hashes.

## Parked vendor set (not committed)

Resolution: env var `CRUMPET_EMU_<GEN>_<NAME>` →
`binaries/vendor/<gen>/<file>`; the manifest `source` fields are `WS/…`
placeholders — documentation only, never parsed. Since the place-and-run
change, `resources.resolve` serves any placed image at a manifest slot:
pinned builds quietly, anything else with a loud UNPINNED warning (see
[`binaries/README.md`](../binaries/README.md)); `sha256` in the manifest
defines what counts as pinned and gates the tier-2 test battery.
`WS` = the operator workspace the artifacts were extracted from.

| manifest key | file | size (B) | sha256 (prefix) | source | class |
|---|---|---|---|---|---|
| `common:brom` | `brom_MT8167_MT8516_MT8362_8167.bin` | 131,072 | `df00ca7d871fc90e…` | `WS/no-alexa/brom_MT8167_MT8516_MT8362_8167.bin` | vendor, gen-neutral BROM dump |
| `common:sram` | `sram_MT8167_MT8516_MT8362_8167.bin` | 2,097,152 | `e1a4a759ba65ff71…` | `WS/no-alexa/sram_MT8167_MT8516_MT8362_8167.bin` | vendor, gen-neutral SRAM snapshot |

| manifest key | file | size (B) | sha256 (prefix) | source | class |
|---|---|---|---|---|---|
| `2021:boot` | `boot.img` | 10,354,688 | `63ce3d68d7319d33…` | `WS/ota-crumpet/2021/ota_out/boot.img` | vendor (2021 OTA) |
| `2021:brhgptpl_0` | `brhgptpl_0.img` | 184,320 | `a5b30bff5dc20e7f…` | `WS/ota-crumpet/2021/ota_out/brhgptpl_0.img` | vendor (2021 OTA) |
| `2021:brhgptpl_1` | `brhgptpl_1.img` | 184,320 | `3b7f004526084905…` | `WS/ota-crumpet/2021/ota_out/brhgptpl_1.img` | vendor (2021 OTA) |
| `2021:brhgptpl_2` | `brhgptpl_2.img` | 184,320 | `ed242bf5dcce75a4…` | `WS/ota-crumpet/2021/ota_out/brhgptpl_2.img` | vendor (2021 OTA) |
| `2021:brhgptpl_3` | `brhgptpl_3.img` | 184,320 | `063e6e09078b494d…` | `WS/ota-crumpet/2021/ota_out/brhgptpl_3.img` | vendor (2021 OTA) |
| `2021:lk` | `lk.img` | 233,472 | `82794651a7f977dc…` | `WS/ota-crumpet/2021/ota_out/lk.img` | vendor (2021 OTA) |
| `2021:lk-patched` | `lk-patched.img` | 237,568 | `157a2deddb909b53…` | `WS/tools/kamakiri/build/crumpet/lk-patched.img` | vendor-derived (patch tooling output; 99.99% vendor bytes) |
| `2021:tee1` | `tee1.img` | 2,367,488 | `68f9cbefa012b7aa…` | `WS/ota-crumpet/2021/ota_out/tee1.img` | vendor (2021 OTA) |
| `2021:tee2` | `tee2.img` | 2,367,488 | `68f9cbefa012b7aa…` | `WS/ota-crumpet/2021/ota_out/tee2.img` | vendor (2021 OTA) |

| manifest key | file | size (B) | sha256 (prefix) | source | class |
|---|---|---|---|---|---|
| `2025:boot` | `boot.img` | 9,908,224 | `ee998730e81966a6…` | `WS/img/boot.img` | vendor (2025 OTA) |
| `2025:brhgptpl_0` | `brhgptpl_0.img` | 184,320 | `d090914376da5cc6…` | `WS/img/brhgptpl_0.img` | vendor (2025 OTA) |
| `2025:brhgptpl_1` | `brhgptpl_1.img` | 184,320 | `89cb4b7cee4feeb0…` | `WS/img/brhgptpl_1.img` | vendor (2025 OTA) |
| `2025:brhgptpl_2` | `brhgptpl_2.img` | 184,320 | `7488fa09d5fef6a9…` | `WS/img/brhgptpl_2.img` | vendor (2025 OTA) |
| `2025:brhgptpl_3` | `brhgptpl_3.img` | 184,320 | `1fc4f90b133d67c5…` | `WS/img/brhgptpl_3.img` | vendor (2025 OTA) |
| `2025:lk` | `lk.img` | 237,568 | `c4e87b94b1fb0a39…` | `WS/img/lk.img` | vendor (2025 OTA) |
| `2025:pl` | `pl2025.bin` | 149,088 | `17bedde9f3bfae3a…` | `WS/extracted/pl2025.bin` | vendor (2025 preloader extract) |
| `2025:tee1` | `tee1.img` | 2,367,488 | `8b0dfbc020ec108d…` | `WS/img/tee1.img` | vendor (2025 OTA) |
| `2025:tee2` | `tee2.img` | 2,367,488 | `8b0dfbc020ec108d…` | `WS/img/tee2.img` | vendor (2025 OTA) |

Notes:
- Within each generation the `tee1` and `tee2` images are byte-identical
  (same sha256) — an observed property of the donor OTAs, recorded so the
  identical hashes in the table don't look like a transcription error.
- **Spec erratum (ruled R3)**: the design/audit prose said "2025
  `lk.img` 237,056 B". The real file is **237,568 B** and its sha256
  (`c4e87b94…`) matches the audit-recorded hash — the prose number was a
  transcription typo; the manifest records the real bytes (file + hash
  is the authority, not prose).

## Committed own artifacts (`binaries/own/`)

Built from this project's MIT-licensable sources; resolved via
`resources.own(name)` with **no sha gate at resolve time** (the manifest
`own:` entries are documentation).

| manifest key | file | size (B) | sha256 (prefix) | built from |
|---|---|---|---|---|
| `own:stage1.bin` | `stage1.bin` | 624 | `174bad4e3bbd0d9e…` | `kamakiri/brom-payload/stage1/` (`make`) |
| `own:stage1.elf` | `stage1.elf` | 4,168 | `9ee9a9df8f9f05b3…` | same build |
| `own:stage2.bin` | `stage2.bin` | 4,044 | `76e314e633b13e73…` | `kamakiri/brom-payload/stage2/` (`make`) |
| `own:payload.bin` | `payload.bin` | 2,484 | `0a0eb7819add538d…` | `amonet-koboreru` build `crumpet2021` |
| `own:payload.elf` | `payload.elf` | 10,660 | `1441d6b1198d516e…` | same build |
| `own:payload-lka.bin` | `payload-lka.bin` | 2,484 | `57bf3d344765bb89…` | `amonet-koboreru` build `crumpet2021-lka` |
| `own:payload-lka.elf` | `payload-lka.elf` | 10,660 | `1bbf1bd996430808…` | same build |
| `own:payload-lkb.bin` | `payload-lkb.bin` | 2,484 | `b114078a28a7120a…` | `amonet-koboreru` build `crumpet2021-lkb` |
| `own:payload-lkb.elf` | `payload-lkb.elf` | 10,660 | `903f2c77748c0e7b…` | same build |
| `own:tz-lka.img` | `tz-lka.img` | 1,143,312 | `306a1c54867ee97d…` | `amonet-koboreru` build `crumpet2021-lka` (`tz.img`) |
| `own:tz-lkb.img` | `tz-lkb.img` | 1,143,312 | `e7c213e6c706256b…` | `amonet-koboreru` build `crumpet2021-lkb` (`tz.img`) |
| `own:key_continuity.json` | `key_continuity.json` | 6,116 | `b18c40d6212ecc5a…` | IDA modulus audit (see below) |

### Build instructions (own artifacts)

- **stage1 / stage2** — from the kamakiri BROM payload tree
  (`WS/tools/kamakiri/brom-payload/`, arm-none-eabi toolchain,
  per-stage `make`; linker scripts `stage1.ld`/`stage2.ld` in-tree).
  stage1 is the payload the layer-1 CDC overflow plants
  (`crumpet_emu.brom.harness` loads it at 0x100A00, the amonet
  load_payload address); stage2 is the second stage the emulated CDC
  transport then delivers.
- **payload / tz variants** — from the amonet-koboreru tree
  (`WS/tools/amonet-koboreru/`, `build.sh crumpet2021[-lka|-lkb]`):
  the `-lka`/`-lkb` variants embed the patched-LK partition name
  (`lk_a`/`lk_b`) and are the crafted TEE images the deploy writes to
  `tee1` keyed by the INACTIVE slot; `crumpet2021` is the plain
  variant.
- **key_continuity.json** — derived (not built): an IDA cross-check of
  the preloader/LK/TEE verify moduli across both generations
  (`pl2021→lk2021/lk2025/tee2021/tee2025` verdicts + evidence hashes,
  `lk_year: 2025` selection). The committed ported tooling
  (`tools/verify_lk_patches.py` + `tools/derive_lk_patches.py`) reads it
  to select the stock LK the patch set applies to and to assert the
  donor sha matches the recorded one.

### seeds.json is a restructured export (ruled R10)

`crumpet_emu/lk/seeds.json` is **not a donor copy**: the donor
`ida_seeds.json` is a bare 839-int list (no names), and the design spec
§5.3 conflated it with `lk_emu.py`'s named F dict. The committed export
restructures both: `{"functions": {<name>: "<VMA hex>"}}` — the donor F
table's 37 named entries plus the later append-seam entries
(`usb_read`, `usb_write`, `fastboot_main`) — and `"ida"`: the donor's
839-int list **byte-exact/verbatim**. The code-side stub authority stays
the F table in `crumpet_emu/lk/session.py` (donor-verbatim);
`load_seeds()` parses the JSON, and `call_seed()` resolves through it.

### stage2 sha: manifest-recorded, not test-enforced

`own:stage2.bin` carries a manifest sha256 for provenance, but no test
enforces it (`resources.own()` performs no sha gate) — the recorded hash
documents what was committed, it does not police the working tree. If
you rebuild stage2, update the manifest entry to match.
