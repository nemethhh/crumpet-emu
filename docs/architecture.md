# Architecture — crumpet-emu

crumpet-emu is a layered Unicorn emulator for the Amazon Echo Dot 3rd-gen
(crumpet, MT8167) load chain — BROM → preloader → LK → kernel-handoff —
built as a hunting lab for boot-chain vulnerability research. Every layer
executes **real vendor code** (the parked BROM dump, the 2021 preloader
segment, the 2025 `lk.img`); only libc / MMIO / platform plumbing is
stubbed, with semantics cited from the donor evidence. This document
describes the code as landed (Tasks 1–16); nothing here is aspirational —
the one deferred capability (natural boot reaching fastboot) is called out
plainly in [Entry points](#entry-points).

## Layers

| layer | package | ported from | role |
|-------|---------|-------------|------|
| core | `crumpet_emu.core` | new (donor-shaped) | `Session` (Thumb ARM Unicorn + `call()` with stop classification), device stubs (UART/GPT-timer/eFuse), checkpoint save/restore |
| flash | `crumpet_emu.flash` | `kamakiri/emu/{gpt,nand_model,nfi_model}` + `amonet-emu` image Flash | NAND chip model, NFI register model, GPT parse, image-backed `Flash` + closed-loop `ChipDumpFlash` |
| brom | `crumpet_emu.brom` | `kamakiri/emu/{harness,brom_boot}` | layer-1 BROM exploit replay (CDC SET_LINE_CODING overflow) + layer-5 real-BROM boot replay with `classify()` verdicts |
| preloader | `crumpet_emu.preloader` | `amonet-emu/emu_chain.py` | the validated 2021 preloader segment: constants, `Emu`, scenarios A/A0/B/C, calibrate/preflight |
| lk | `crumpet_emu.lk` | `lk-emu/{lk_emu,battery}.py` (generalized) + new boot path | surgical LK execution at 0x41E00000, unlock battery, natural boot walk (M2, see below), boot-image auth observability, seeds |
| usb | `crumpet_emu.usb` | `kamakiri/emu/{usb_model,transport}` + new fastboot host | MUSB MAC model, CDC device, fake/modelled transports, `FastbootHost` over the LK USB seam |
| deploy | `crumpet_emu.deploy` | `kamakiri/modules/{functions,main}_crumpet.py` | the closed-loop §7.4 deployment pipeline (backup → slot detect → staged writes with readback verify) |
| hunting | `crumpet_emu.hunting` | new | checkpoints consumer API, fault injection, differential runner, crash-tolerant fuzz loop, AFL-style edge coverage — see [docs/hunting.md](hunting.md) |

## Entry points

Two entry modes exist, per the ruled C4 phasing (surgical v1, boot-path as
milestone M2):

- **Surgical** (all layers, default): map real code, call one function at
  its verified VMA with donor call conventions, read r0 / traces. This is
  the donor-harness mode: the LK unlock battery (`crumpet_emu.lk.battery`,
  `scenarios/lk_unlock.py`), the fastboot verbs at the handler boundary
  (`FastbootHost`, `scenarios/lk_fastboot.py`), the preloader scenarios
  (`scenarios/preloader_chain.py`), the BROM exploit replay
  (`crumpet_emu.brom.harness`).
- **Boot-path** (M2): run the reset entry and let init code execute.
  *Layer 5 is done*: `crumpet_emu.brom.boot.classify()` replays the REAL
  BROM boot-read walk over a chip snapshot
  (`scenarios/boot_brom.py`). *The LK natural boot is honest but parked*:
  `crumpet_emu.lk.boot.boot()` walks the 2025 reset entry (ARM vector →
  thread_init_early → idle) and truthfully reports
  `reached_fastboot=False` / `stop_reason='PARKED last-pc=0x41e1a550'` —
  the scheduler needs the system-timer IRQ and unicorn 2.1.4 exposes no
  interrupt-injection API (full blocking chain:
  [docs/porting-notes.md](porting-notes.md) §platform item 5c). The
  `xfail` test stays; fastboot reach today is the surgical surface above.

## Memory maps

Each layer owns its map; values are donor-verbatim facts (spec §5.3).

### core

| region | value | note |
|---|---|---|
| internal call stack | 0x130000 + 64 KiB | mapped by `Session.__init__`; `call()` sets SP to its top |
| MAGIC_RET | 0x0011F000 | sentinel LR; the fetch fault classifies as a normal return |
| UART_THR / UART_LSR | 0x11005000 / 0x11005014 | LSR reads 0x20 (THR empty) |
| TIMER_REG | 0x10008048 | GPT timer, +1 per read |
| EFUSE_SBC | 0x10009060 | SBC eFuse word, bit 1 = SBC burned (preloader reads it) |

### flash

NAND geometry (MX30LF4G28AD class): 2048 blocks × 64 pages × (4096 data +
256 spare) B. One 4096-B LBA per page (`page_of_lba(lba) == lba`); the
bdev the boot layers read is 512-B blocks — 8 per page. The GPT map in
`crumpet_emu.flash.image` is the single placement authority (2021
`brhgptpl_0` donor table, 512-B start blocks): `tee1` 28672, `lk_a` 2048,
`lk_b` 5120, `tee2` 70144, plus the full 18-partition donor table the
deploy layer asserts against.

### brom (boot replay)

BROM mapped at 0x0 (128 KiB dump, boot main sub_C634); SRAM window at
0x100000 (+0x21000); preloader load window at 0x200000 (+0x80000) — the
loaded image lands at 0x200D00..0x226000, entry 0x201000; WDT 0x10007000,
GPT timer 0x10008048, eFuse 0x10009000, strap latch 0x1000A000,
DRAM-cal 0x10209000, clk/cfg 0x10200000, infra cfg 0x10005000, NFI
0x11001000, ECC 0x11002000, UART 0x11005000. The layer-1 exploit harness
(`brom.harness`) adds the MUSB MAC at 0x11100000 and the SRAM seed cells
(line-coding buffer 0x1033A8 — the overflow target).

### preloader

2021 preloader segment at TEXT_BASE 0x201000 (file delta 0x1F8D00);
surgical entries: `part_load` 0x20F4A8, `part_get` 0x20F250, TEE loader
0x20E19C, `VERIFY_LK` 0x201D70, `USB_HANDSHAKE` 0x20D7DC; unicorn-placed:
bdev→read shim vector 0x120000, stack 0x12F000, payload 0x101000,
scratch part-structs 0x42070000 (DRAM), DRAM buffer 0x42000000; load
targets: LK 0x41E00000, TEE 0x43001000.

### lk

VMA = raw offset + 0x41DFFE00 (0x200-B GFH header, code at LK_LOAD
0x41E00000). Image + BSS headroom 0x41DF0000..0x41E60000 (BSS_END
0x41E60000); stack 0x70000000 (1 MiB); heap 0x71000000 (4 MiB); args
0x72000000 (1 MiB). Fastboot top level (seed `fastboot_main`)
0x41E1DAEC; USB seam `usb_read` 0x41E1DFA8 / `usb_write` 0x41E1E050
(queue-backed via `lk.usb_rx`/`lk.usb_tx`); RSA unlock gate 0x41E019F4
(the glitch model's target). The function-seed authority is
`crumpet_emu/lk/seeds.json` — see [docs/provenance.md](provenance.md)
for its restructured-export note.

### usb

MUSB MAC registers at 0x11100000 (`usb.model`); the two FIFO pump
helpers are emulated at the function boundary (a FIFO port cannot live
in flat memory). Transports: `FakeTransport` (in-memory, snapshots for
the deploy tests) and `ModeledSession` (register-level against the MAC
model). `FastbootHost` drives the LK seam, not the MAC: framing is
command line `verb:arg` (64-B maxlen) in, one 64-B-capped reply unit
(`OKAY`/`FAIL`/`INFO`/`DATA`) out.

### deploy / hunting

No memory of their own: deploy orchestrates over a plain
`read(n)/write(bytes)` transport with bdev block numbering (the flash
layer owns placement); hunting instruments flash models and sessions
([docs/hunting.md](hunting.md)).

## Import map

Donor module → `crumpet_emu` module (the porting rule; one owner per
concept):

| donor import | new import |
|---|---|
| `emu.gpt` | `crumpet_emu.flash.gpt` |
| `emu.nand_model` | `crumpet_emu.flash.nand` |
| `emu.nfi_model` | `crumpet_emu.flash.nfi` |
| `emu.harness` | `crumpet_emu.brom.harness` |
| `emu.brom_boot` | `crumpet_emu.brom.boot` |
| `emu.transport` | `crumpet_emu.usb.transport` |
| `emu.usb_model` | `crumpet_emu.usb.model` |
| `emu_chain.py` (amonet-emu main) | `crumpet_emu.preloader.{constants,emu,scenarios}` |
| `lk_emu.py` (lk-emu) | `crumpet_emu.lk.session` (+ `platform`, `boot`) |
| `battery.py` (lk-emu) | `crumpet_emu.lk.battery` |
| `modules.functions_crumpet` | `crumpet_emu.deploy.functions` |
| `modules.main_crumpet` | `crumpet_emu.deploy.main` |

## Scenario CLIs

| CLI | layer | what it does |
|---|---|---|
| `scenarios/preloader_chain.py` | preloader | donor `emu_chain` argparse surface (payload tz / --calibrate / --preflight / --from-chip-dump) |
| `scenarios/boot_brom.py` | brom | classify a chip snapshot (default: stock 2021 belt) through the real BROM |
| `scenarios/lk_unlock.py` | lk | the donor unlock battery as subcommands (keydump / vcode / vunlock / otu / otu-glitch / bootimg / certdriver / b64 / otucode-derive) |
| `scenarios/lk_fastboot.py` | lk+usb | one fastboot command over the USB seam (`--cmd flash:otucode --data F`, `--getvar all`) |
| `scenarios/differential.py` | hunting | variant cross-product over preloader (`sbc=`) / lk (`budget=`) builds + first UART divergence |
| `scenarios/fuzz_fastboot.py` | hunting | checkpoint-restored fastboot fuzzing (`--cp CHECKPOINT --cases N`) |

## Roadmap (M2)

Natural LK boot reaching the fastboot loop is **deferred** (ruling R13):
the prerequisite is a GIC + system-timer IRQ model at register level,
derivable from LK's own GIC/timer drivers and the MT8167 timer registers
(precedent: the NFI register model built from `nfi_regs.json`). unicorn
2.1.4 cannot inject interrupts — that is the wall; it is NOT a stub-class
task. Downstream work (boot-image auth natural upgrade, kernel-handoff
observation) proceeds on the surgical path meanwhile. See
[docs/porting-notes.md](porting-notes.md) §platform.
