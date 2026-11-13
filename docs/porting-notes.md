# Porting notes — crumpet-emu

Per-task porting evidence: donor provenance, seams, and rulings that the
source headers do not carry. Tasks append sections here.

## §seam — LK USB transport boundary (Task 12)

Route taken: **IDA headless** (idalib via the donor `tools/ida-venv`
python; a COPY of the donor `lk.i64` at `/tmp/lk_seam.i64`, never saved).
No fallback needed.

Seam entries appended to `crumpet_emu/lk/seeds.json` → `functions`
(R10: `"ida"` untouched):

| seed       | VMA        | role |
|------------|------------|------|
| `usb_read` | `0x41E1DFA8` | fastboot rx boundary `f(buf, maxlen) -> total \| -1` |
| `usb_write`| `0x41E1E050` | fastboot tx boundary `f(buf, len) -> len \| -1` |

No init-thunk seed: the per-command handler path (the surgical-entry mode
the donor harness and `FastbootHost` use) reads/writes the transport
directly; boot-time usb init happens inside the `__noreturn` fastboot task
main, outside this model.

### Call-chain evidence (donor lk.i64, VMAs are function entries)

rx (`usb_read` 0x41E1DFA8) — posted-transfer wrapper: stores
`{buf, min(len,0x4000), cb}` into a descriptor and waits on the event
queue (`sub_41E14050`); returns the accumulated byte count, `-1` on the
error path (state cell → 3):

* `sub_41E1E1A2` (fastboot command loop, loop head 0x41E1E1A2 per
  recovery-notes `lk-fastboot-dispatcher-table.md`): `memset(buf,0,4096)`
  then `bl 0x41E1DFA8(buf, 64)` at 0x41E1E1C2 — command lines, 64-byte
  maxlen, `*(buf+n)=0` after rx.
* `sub_41E1F4B8` (the registered `download:` handler):
  `bl 0x41E1DFA8(download_buf, size)` at 0x41E1F566 — the raw payload rx
  of the download phase.

tx (`usb_write` 0x41E1E050) — mirror wrapper: descriptor `{buf,len,cb}` +
event-queue wait; returns `len` or `-1`:

* `sub_41E1E0BC` (reply formatter, donor F `fmt_print`):
  `snprintf(buf,64,fmt,prefix,msg)` → `strlen` → `bl 0x41E1E050(buf,len)`
  at 0x41E1E0F4. `fb_ok` 0x41E1E2F0 / `fb_fail` 0x41E1E144 are 10-byte
  thunks that load `"OKAY"`/`"FAIL"` into r0, move msg to r1, and
  `b.w 0x41E1E0BC` — so every OKAY/FAIL reply funnels through
  usb_write.
* `sub_41E1F4B8` (download handler): `snprintf(buf,64,"DATA%08x",sz)` →
  `strlen` → `bl 0x41E1E050` at 0x41E1F544 — the DATA reply unit.
* `sub_41E1E108` (`INFO%s` replies, string 0x41E3482E): `bl 0x41E1E050`
  at 0x41E1E132.

Supporting registrations (not seam entries): `sub_41E1E3B4` =
`fastboot_init()` — logs `"fastboot_init()\n"`, registers
`"getvar:"` → `sub_41E1EA40` at 0x41E1E40A (`sub_41E1DF10` = register),
`"download:"` and `"flash:"` likewise; the flash handler the donor battery
drives is `0x41E1F5C0` (`HANDLER_CHK` 0x41E1F632 is inside it), dispatched
by the loop as `handler(arg_after_prefix, download_ptr, download_len)` —
the argument shape `FastbootHost.send('flash', ...)` reproduces.

### Seam wiring (crumpet_emu/lk/session.py)

`_stub` resolves the seam VMAs through `self.seeds` (the donor F table is
untouched; donor semantics for every other stub unchanged):

* `usb_read`: drains `self.usb_rx` into the caller's buffer,
  `r0 = min(maxlen, len(queue))` — 0 on an empty queue (the real one
  blocks; the queue model has no blocking read).
* `usb_write`: appends the caller's bytes to `self.usb_tx`, `r0 = len`.

Known limitation (honest failure, not fabricated replies): in the cold
session the REAL `download:` handler faults at its ENTRY — an unmapped
fetch at pc=0 (its first indirect callback; the transfer-completion
function pointer is boot-time state the `__noreturn` task main
initializes) — BEFORE any `DATA%08x` unit reaches the usb_write seam
(verified empirically: `usb_tx` is empty after the faulted call — the
static DATA@0x41E1F544 path above is real wiring, just not reached cold).
`FastbootHost.send('download', ...)` therefore raises with the session
`stop_reason`, on ANY set stop_reason — a partial reply unit can never
mask a fault; `flash`/`getvar` are the fully wired verbs.

## §platform — LK boot-path stubs (Task 13, M2 WIP)

Cite by function name; line numbers verified against donor as of commit
d750d8b.

Route taken: **probe-driven stub iteration** (ARM-entry natural boot under
Unicorn with an on-demand page mapper logging every unmapped access; ring
hook on the image range for PC evidence). Donor baseline: `session.py`
already ports the donor's surgical stub table (lk_emu.py F table +
`_stub`), and `platform.py` adds the boot path the donor never exercised.
`stub_pts` removed (donor-verbatim dead code: the sorted stub-VMA list was
computed but never consumed — `_stub` arms the full-range code hook).

### What `install_platform(lk)` arms (crumpet_emu/lk/platform.py)

MMIO pages mapped plain-RAM (donor maps the UART/timer pages the same
way, lk_emu.py:128-129 `mem_map(UART_THR...`/`mem_map(TIMER_REG...)`) —
the union of pages the boot walk touched before the
current blocker: `0x10200000, 0x10310000, 0x10320000, 0x10001000,
0x10003000, 0x10005000, 0x10011000, 0x11007000, 0x10006000, 0x10007000`.

Function stubs:

| function | VMA | stub behavior | citation |
|----------|-----|---------------|----------|
| sw sram repair driver | `0x41E143EC` | `ret 0` (skip) | live unit: `[3] SKIP sw sram repair` (uart_fastboot_w_usb.txt); emu MBIST reads `0x267x600c` result registers absent from the MMIO model → fake failure `Sram repair failed 1` then deliberate hang @0x41E1066E |
| memset | `0x41E20964` (F-table `memset`, lk_emu.py:83) | semantic: host `mem_fill(dst, c&0xFF, n)`, `r0=dst` (AAPCS) | donor F-table entry, NEVER stubbed and never executed by the donor (its one needed copy is pre-staged, `_ltc_init` lk_emu.py:158-166) → real memset semantics are the ground truth. Body is an ARM builtin cluster (capstone ARM: `cmp r2,#0; bxeq lr; mov ip,r0; cmp r2,#0x30 ...`); thumb callers reach it via interworking `blx` (e.g. `blx 0x41E20964` @0x41E1B4B2) or plain `bl`, and unicorn's ARM decode of the deep body raises UC_ERR_EXCEPTION (errno 21, original blocker pc=0x41E209A0) |
| memcpy | `0x41E20858` (F-table `memcpy`, lk_emu.py:82) | semantic: host `mem_copy(dst, src, n)`, `r0=dst` (AAPCS) | same donor treatment (F-table entry, never stubbed/run); body verified ARM builtin cluster (capstone ARM: `cmp r2,#0; cmpne r1,r0; bxeq lr; push {r0,r4,r5,lr} ...`) |
| SCTLR write accessor | `0x41E1A560` | mask bit0 (M) out of the value the real `mcr p15,0,r0,c1,c0,0` writes | environment fidelity (same class as the MMIO page map, not a donor function stub): natural boot's arch init enables the page-table MMU here (observed write 0x00C5007B via mrc@0x41E1A558), but the ATF-built page tables do not exist in the flat-memory emu — after the real mcr EVERY CPU-mode data store raises EXCP_DATA_ABORT (UC_HOOK_INTR intno 4; first victim `str r3,[r0],#0x44` @0x41E1B4BE writing the malloc'd heap). Donor never enables the MMU (surgical entries over flat memory), so flat stays the emu contract. Everything else in the written SCTLR value (caches A/C/I bits) is preserved and the mcr executes as real code |

Boot-time state staged (the Task-12 "transfer-completion fn ptr is
boot-time state" class — cold sessions miss state an earlier boot stage
writes; donor pattern `_boot_globals` lk_emu.py:141-153):

| state | cells | content | citation |
|-------|-------|---------|----------|
| device-info boot-stage table | `*(0x41E00020)` → `0x72010000` | 0x200 bytes: magic `0x504C504C` @+0, BOOT_REASON 4 @+0x8, BOOT_MODE 0 @+0xC, MEM_NUM 1 @+0x18 (checked 1..4), mblock0 size `0xF9C0000` @+0x1C (u32-per-mblock, start implied `0x40000000`, validator 0x41E104EC), prod flag 1 @+0x1E2 | live unit bootargs: `[14] BOOT_REASON: 4` / `[14] BOOT_MODE: 0` / `[16] MEM_NUM: 1` / `[17] mblock start: 0x40000000` / `mblock size: 0xf9c0000` (uart_fastboot_w_usb.txt); consumer chain 0x41E102D4 (stamp check + `memcpy(di_mirror, src, 0x200)`, mirror ptr `*(0x41E38D18)`=`0x41E45C10`) and MEM_NUM check 0x41E104CC–0x41E104DA |

The slot `0x41E00020` is itself 4-byte BSS (LK's startup clear zeroes it
after `install_platform` runs), so the pointer write happens lazily via a
hook at the consumer's entry `0x41E102D4`. The device-info copy, field
checks, bootargs dump and `prod` consumption all stay REAL code (the
surgical-path `_boot_globals` staging in session.py remains; natural boot
overwrites the same cells through the real copy).

### Blocking chain for the M2 finisher (probe evidence, in boot order)

1. **Entry mode** — thumb entry faults (`INVALID access=20 addr=0x4
   pc=0x41E00024`); the reset entry 0x41E00000 is an ARM vector table
   (`b` vectors → stacks → BSS clear → `blx 0x41E1B2B0` C entry).
   `boot()` starts ARM (emu_start with bit0 clear) — solved.
2. **device-info boot-stage chain** — cold NULL deref `access=19 addr=0x0
   pc=0x41E102EC` (double deref *(0x41E38E0C)→slot→magic). Staged —
   solved (above).
3. **DRAM bank check hang** — `kernel_boot_opt=0` / `64Bit Kernel` /
   `[LK ERROR] DRAM bank number is not correct!!!` then deliberate `b .`
   at **0x41E1064A** (flag `0x41E3F2A0` set -1 by the validator at
   0x41E104E6 because MEM_NUM read 0). Staged MEM_NUM — solved.
4. **MBIST/sram-repair failure hang** — `repair_sram START` + `MBIST
   before sram repair --- failed` + `Sram repair failed 1`, hang at
   **0x41E1066E**; page cluster `0x20120000/0x20000000/0x12000000/
   0x24000000/0x20110000/0x26700000-0x26750000` (MBIST result reads,
   on-demand-mapped in the probe only). Stubbed SRAM_REPAIR — solved.
5. **libc memset/memcpy ARM builtin cluster — SOLVED** (Task 13b). The
   original characterization ("entered as thumb") was half-right: thumb
   callers reach both functions via interworking `blx` (ARM mode, e.g.
   0x41E1B4B2) OR plain `bl` (thumb, garbage decode); either way unicorn's
   decode of the deep ARM builtin body raises UC_ERR_EXCEPTION at
   pc=0x41E209A0. Both encodings re-verified with capstone in ARM and thumb
   modes (Task 13b). Donor treatment: F-table entries (lk_emu.py:82-83) with
   NO `_stub` branch — the donor stages around the one memcpy it needs
   (`_ltc_init`), so host-true memset/memcpy semantics at the entry (the
   `_boot_stub` surface in platform.py) are the donor-faithful answer.
5b. **arch-init MMU enable — SOLVED** (Task 13b). After the libc fix, every
   CPU-mode data store raised EXCP_DATA_ABORT (UC_HOOK_INTR intno 4; first
   at 0x41E1B4BE to the 0x71000000 heap, probed: ALL regions abort — image,
   DRAM, ARGS, stack). Root cause traced live: LK's arch init writes SCTLR
   0x00C5007B (bit0 M=1) through the generic accessor at 0x41E1A560
   (full mrc/mcr trace in the 13b report); with M=1 and no ATF page tables,
   QEMU faults every data store. Neutralized by masking M at that accessor
   (platform.py `_boot_stub`; see stub table above) — aborts dropped to 0
   and the walk advanced ~500k insns further.
5c. **CURRENT BLOCKER — scheduler needs the system-timer IRQ; unicorn 2.1.4
   cannot inject interrupts.** With 5/5b solved, natural boot runs: vector
   head → arch/cache init (D-cache set/way loop 0x41E1A3xx) → BSS clear →
   `blx 0x41E1B2B0` = thread_init_early (NOT kmain — the 32×8 run-queue
   init loop at 0x41E1B7C0 confirms; porting-notes previously called it
   "C entry") → thread setup → `thread_become_idle` tail (enable IRQs
   0x41E1A4DC → 0x41E1B870 idle entry: name/priority set, then the park
   `blx wfi(0x41E1A550); b .` @0x41E1B890/94). Evidence: NO context-switch
   primitive (`mov sp,r1; bx r0` @0x41E1A598) ever executed — the
   bootstrap thread directly became idle; the created main thread can only
   preempt via the timer IRQ (live capture: ticks [19]→[1790] span the
   `ISSI_ESOL: end anim` delay, then `[1790] Key Uber: Pressed`, then
   `[1824] fastboot_init()`). `wfi` halts unicorn `emu_start` (boot parks,
   budget unused); masking M left the emu flat so the park is honest.
   Options checked: unicorn 2.1.4 exposes NO interrupt-injection API
   (UC_CTL/ctl surface inspected — only cpu-model/tlb/tb/exits controls).
   Delivering the tick faithfully needs an emulated IRQ entry (banked
   CPSR/SPSR switch + vector fetch @0x41E00018) PLUS a GIC-ack model whose
   semantics have NO donor citation (the donor never ran this path) —
   fabricated-platform territory, out of stub class. This is where Task 13b
   stopped (DONE_WITH_CONCERNS): boot() honestly returns
   reached_fastboot=False with stop_reason `PARKED last-pc=0x41e1a550`
   (wfi) and the last-50-PC ring in `lk.pc_ring`.
6. **Downstream, expected** — the Task-12 cold `download:` fault (unmapped
   fetch at pc=0, access=21 UC_MEM_FETCH_UNMAPPED: the USB
   transfer-completion fn ptr is boot-time state the `__noreturn` fastboot
   task main initializes, §seam above) must resolve NATURALLY once the
   boot walk reaches the usb/fastboot init — do not stub around it.
   Key-detect/PMIC path decides fastboot entry (`[1790] Key Uber: Pressed`
   live; `plat_read` stub semantics may need the key index answer there).
   Still unreached — parked upstream at 5c.

### Checkpoint duty (Task 15)

On reaching `FASTBOOT_MAIN` 0x41E1DAEC, `boot()` snapshots the
fastboot-loop-entry state onto the session as `lk.fastboot_checkpoint`
(pc, sp, heap_ptr, uart_bytes, usb_rx, usb_tx) — `crumpet_emu/lk/boot.py`.

## §bootimg — boot-image auth observability (Task 14, v1 surgical)

v1 = surgical entry per plan §5.3: `observe_auth(lk, boot_bytes)`
(crumpet_emu/lk/bootimg.py) stages the image and invokes the wrapper
`verify_with_hash` 0x41E00F58 (dual-attempt eng+prod → cert driver
0x41E0120C) exactly like donor battery.py `scenario_bootimg`
(fn(start, end, size, 0)), hooks the surroundings, and reports an
`AuthReport(verdict, cmdline, rollback, handoff)`. Kernel execution is a
non-goal: the handoff hook records-if-observed but the surgical path
returns handoff=None; the natural-boot upgrade (running boot-image auth
fn 0x41E11548 for real cmdline construction + kernel jump) is milestone
M2 (R13) and is NOT attempted here.

### Hook points (crumpet_emu/lk/bootimg.py)

| hook | address | source |
|---|---|---|
| verify_with_hash call capture | 0x41E00F58 | donor F table `boot_auth` (lk_emu.py:70; seeds.json `functions`) |
| image-hash host-assist (R14) | 0x41E01170 | wrapper call site `sub_41E01170(a1, a3, v10)` (decomp_cluster.c:376 — hash helper inside verify_with_hash) |
| anti-rollback u16 reads | deviceinfo(0x41E58000)+0x1E4/0x1E6/0x1E8 | donor decomp sub_41E11548 (decomp_helpers3.c:484-508: `*(unsigned __int16 *)(*(_DWORD *)v10 + 484/486/488)` feeding `androidboot.pl_version/tee_version/lk_version`) — report keys pinned in `ROLLBACK_READS` |
| kernel-jump handoff | code leave of [LK_BASE, BSS_END] | spec §5.3 "final handoff (jump to kernel entry)"; same shape as Task 13 boot() on_leave |
| cmdline capture | log/UART stub deltas | androidboot.* strings surface through the session log stub (`log2` 0x41E1FE0C) / UART_THR; empty on the surgical path (cmdline lives in 0x41E11548) |

### Call-shape refinement: the signature page

battery.scenario_bootimg's vectors (≤0x800 B, no footer) fail closed
before any layout matters, so the donor log pins no image shape. The
real 2025:boot forced one: cert_driver 0x41E0120C parses the cert DER
AT the passed end pointer (ASN.1 flexi helper 0x41E0A960 reads the DER
at `end` directly — prologue disasm: `mov r0, sl(=end); bl 0x41e0a960`).
boot.img = signed_data || one 0x800 signature page (cert DER at
end-0x800; file tail beyond the DER is zero padding). Calling with the
raw file end reads zeros → `'tbsCertificate is empty'` → fail-closed;
excluding the signature page (`end = start + size - 0x800`,
`SIGNATURE_PAGE`) live-verified: ret=1 AUTHENTICATED in 14.5 s.

### R14 host-assisted hashing (v1 boundary)

Donor ground truth: lk_emu.py/battery.py have NO sha treatment at all
(the donor log's fast run-bootimg times reflect the emulated hash chain
bailing early, not emulated-SHA throughput — §errata T14 below). The
emulated libtomcrypt SHA-256 transform manages <16.5 KB/s (probe: the
9.9 MB 2025:boot hash did not complete in a 600 s budget), so
observe_auth hooks the wrapper's hash helper sub_41E01170 and, for
messages > 0x10000, computes the byte-identical digest host-side
(hashlib.sha256 — deterministic, same function contract) and returns
CRYPT_OK, letting the emulated cert driver + RSA-PSS verify (small
digests — untouched) continue from the correct state. Precedent:
Task 7 _emu_dma_memcpy and the NFI register models (expensive
primitives host-side). Small images stay fully emulated.

### Verdict literals (rodata provenance, byte-for-byte)

`strings -t x` on lk.img, VMA = raw + 0x41DFFE00; paths per the wrapper
disasm 0x41E00F58 (decomp_cluster.c:365 + resolved branches):
- `'Image AUTHENTICATED with PRODUCTION certificate'` (raw 0x24a06) —
  first verify attempt returns ok → log → ret 1;
- `'Image FAILED AUTHENTICATION on PRODUCTION device'` (eng-cert image
  on prod device — the session boots prod=1, the differential
  tamper case) / `'...on ENGINEERING device'` / `'Authentication failed
  on engineering device with production certificate'` /
  `'ERROR: Unable to allocate image hash'` — fail-closed ret 0;
- `'Failed to verify image'` (raw 0x2f06e) is the CALLER's (0x41E11548)
  line on wrapper ret 0 — natural-boot path only, not observable in v1.

Live with-bins results (2025:lk + 2025:boot): verdict AUTHENTICATED
(ret 1, 14.5 s; metadata lines `product:crumpet` / `signer:CodeSigner`
also surface), manual byte-flip tamper → FAILED AUTHENTICATION on
PRODUCTION device (ret 0). handoff/cmdline/rollback stay None/[]/{} on
the surgical path — populated only by the M2 upgrade (R13).

## §errata — accumulated review rulings and doc fixes (Task 16 ledger)

Errata the run's reviews accumulated, kept so the plan/spec prose and
the code can be reconciled. Where a ruling contradicted plan text, the
code followed the donor (verbatim rule) and the plan text is corrected
here, not silently.

### R5 — `_dword` is big-endian (Task 8 brief erratum)

The Task-8 brief pinned `_dword` framing as little-endian (`'<I'`);
the donor `functions_crumpet.py:57` is **big-endian** (`'>I'`, module
docstring "big-endian u32 framing") and matches the reviewed transport
framing. Verbatim rule wins: the port (`crumpet_emu/deploy/functions.py`
`_dword`) and `tests/test_deploy_units.py::test_dword_roundtrip` pin
`'>I'` — magic bytes assert MSB-first (`b'\xf0\x0d\xd0\x0d'`). The
brief sketch was wrong; the plan's `<I` should not be reintroduced.

### R10 — `seeds.json` is a restructured export, not a donor copy (Task 11)

Donor `ida_seeds.json` is a bare 839-int list (no names); the spec §5.3
prose conflated it with `lk_emu.py`'s F dict (37 named entries). The
committed `crumpet_emu/lk/seeds.json` restructures both:
`{"functions": {<37 donor-F names>: <VA hex>}}` plus `"ida"`: the donor
839-int list **byte-exact**. Tasks 12/13 appended seam/entry names
(`usb_read`, `usb_write`, `fastboot_main`); the code-side stub
authority stays the donor-verbatim F table in `lk/session.py`.
Provenance note: docs/provenance.md, "seeds.json is a restructured
export".

### R11 — dispatcher-table 0x37400 is libtomcrypt descriptors (Task 12)

The plan/spec claimed a "dispatcher table 0x37400..0x37654 (22 Thumb
handlers)"; the donor recovery-note contradicts it — that range is
**libtomcrypt descriptor blocks**. Authority for the fastboot dispatch
structure is the donor session VMAs (§seam call-chain evidence above):
fastboot top level `0x41E1DAEC`, command loop `0x41E1E1A2`, flash
handler `0x41E1F5C0`, download handler `0x41E1F4B8`, getvar handler
`0x41E1EA40`.

### T4 — filename/interface errata (plan text)

- Task 4's Files list named `tests/test_flash_ports.py`; the steps (and
  the donor suite) name `tests/test_nand_model.py` +
  `tests/test_nfi_inventory.py`. The port followed the steps.
- Task 4's interface line said `NfiModel` "loads `nfi_regs.json` via
  importlib.resources / Path(__file__).parent". The donor
  `nfi_model.py` does **not** load the JSON at all — only the test reads
  the package copy; the JSON references in the module are
  documentation. Donor code is the spec: no loader was added.

### T14 — donor-log wording fix (§bootimg above)

The §bootimg sentence "run-bootimg.log is fast only because every vector
is ≤0x800 B" is imprecise: the len-oversize vector (size=0x7FFFFFFF,
64-byte blob) also returns fast and cleanly, which blob size cannot
explain — the emulated hash chain bails early in the donor harness
(`verify_with_hash` ignores the helper return, so a fast hash failure
yields fail-closed ret=0). Consequence: **the donor log does not
independently corroborate emulated-SHA throughput**; that justification
rests on the R14 probe itself (the 9.9 MB 2025:boot hash did not
complete in a 600 s budget — <16.5 KB/s). The R14 host-assist design
stands; this note is honest bookkeeping, no code change.

### run_scenario stock_ok self-reference (Task 10 — parked, escalated)

`run_scenario`'s RSA pass-oracle takes `stock_ok = ` the belt's own
stock lk — any coherent manifested belt passes the gate by
construction. A manifested scenario A/A0 belt would therefore return
ok=True where the donor docstring labels A a brick. Unreachable by
default (presets are documented but inactive: no manifest entries →
MissingBinary, pinned by test; brick repros remain CLI-driven via the
historical images) and scope-honest in the detail string ("boot gate
passed"). Escalated to the owner per the Task-10 report: letter-faithful
A/A0 semantics need crafted tz/payload fields in ImageSet or preset
manifest entries. Owner decision pending — do not "fix" silently.

### Stale donor-era docstring references (inventory, verbatim-kept)

Donor fidelity keeps several stale references in inherited
strings/comments, intentionally unmodified:

- Task 5: `ChipDumpFlash` docstring "(closed loop, Task 10)" refers to
  the **donor's** task 10, not this repo's.
- Task 6: stale module spellings in donor docstrings/comments
  (`emu.gpt`-era names; the ported imports are the mapping, per the
  import map in docs/architecture.md).
- Task 8: stale donor-era docstring refs in the deploy port.
- Task 11: battery docstring "(see lk_emu.py)" kept verbatim.

### M2 ROADMAP — natural-boot reach deferred (R13)

Natural LK boot reaching the fastboot loop is deferred, with the wall
documented (§platform item 5c): the bootstrap thread becomes idle and
the main thread preempts only via the system-timer IRQ; unicorn 2.1.4
exposes **no interrupt-injection API** (ctl surface inspected), so
`boot()` parks at `wfi` (0x41E1A550) and honestly reports
`reached_fastboot=False`. Completion prerequisite: a **GIC +
system-timer IRQ model** at register level, derivable from LK's own
GIC/timer drivers and the MT8167 timer registers (precedent: the NFI
register model built from `nfi_regs.json`). NOT a stub-class task — a
GIC-ack model would have no donor citation (fabricated-platform
territory). Downstream work proceeds on the surgical path (Task 14
auth observability landed there).

## §guarantee — amonet custom-firmware guarantee effort (2026-11-08)

Charter: make the emu a bounded pre-flight oracle for the amonet-koboreru
crumpet2021 chain + patched-LK custom-firmware path (plan:
`docs/superpowers/plans/2026-11-08-amonet-customfw-guarantee.md`,
deliverable: `docs/guarantee.md`). This effort intentionally DEVIATES from
the donor-verbatim rule for four preloader seams (hdr_parse 0x20F2D8,
overlap_chk 0x20F398, part_get 0x20F250, bdev_init 0x212EFC): the donor
shipped host reimplementations, and the guarantee requires REAL vendor
code there. Rulings for each upgrade are appended in this section by the
landing task; the reimplementations stay reachable via
`Emu(..., legacy_seams=True)` for differential comparison.

### Task-2 ruling (guarantee plan): real hdr-parse + overlap, legacy mode

The donor's HDR_PARSE/OVERLAP_CHK reimplementations are demoted to
`Emu(..., legacy_seams=True)` (default False). Default path: the REAL
sub_20F2D8 and sub_20F398 execute; hooks observe only (last_hdr mirror;
`overlap[real]` event lines; claim state = guest cells at 0x224920,
in-file init {0,0}, name ptrs in-file pre-relocated — probe-verified).

Probe finding recorded for the guarantee: the donor CLI's phase-1 drive
(`part_load` at offset 0xE800 with a fabricated `*addr == 0`) models only
the loader's SECOND sub-image call. Driving offset 0 with `*addr == 0`
under the real parsers panics on the atf sub-image — correct real
behavior for that wrong shape. The REAL stock loader sub_20E19C walks
atf first at TEE_LOAD_ADDR (0x43001000) and passes its own zero cell for
the crafted sub-image — dynamically proving port-doc premise P3 (the
exploit's load-bearing fallback). The CLI keeps its donor-verbatim drive
(the shape matches the second call); the guarantee tests
(test_real_parse_overlap.py) and the Task-7 e2e drive the real loader.

### Task-3 ruling (guarantee plan): real part_get on a staged real-GPT table

The donor's PART_GET synthesized-struct stub is demoted to
`legacy_seams=True`. Default: REAL sub_20F250 (name memcpy to
0x102A70) + the sub_20F1F8 walk execute against a table staged at
`*(*(0x22518C)) + 0x69244` — the double deref resolves via SRAM_DBUF_PTR
(0x102994) to DRAM_BUF+0x69244, matching the walk disasm (entries 0x14 B:
start@0, nblk@4 (0 terminates), name*@0x10; match copied to the global
struct 0x102A5C with the name copied to 0x102A0C/0x102A70 .bss buffers).
Entry values come from flash.gpt.parse_gpt_from_image on the pinned
2021:brhgptpl_0 (LBA4096 -> 512-block x8, the donor GPT-dict rule) — the
boot-time part_init build is the staged state (LK-platform.py
boot-state precedent). Hook observes only (part_get[real] event).

### Task-4 ruling (guarantee plan): bdev_init stays staged; NFI-model
### extension deferred

Probe result (probes/bdev_init_probe3.py): the REAL sub_212EFC runs
under the preloader Emu with the NfiModel + donor NandChip mapped, but
takes its error branch — the pl2021 NAND probe handshake (11 NFI
accesses; polls at NFI+0x14/0x220 the model answers 0) is not covered
by NfiModel, which was built for the BROM-payload stage2 driver traffic.
Full decode recovered instead (pool-literal math in the probe):
- real init targets the SAME struct 0x1086EC (memset 0x2C B);
- fields from the probe ctx: id @+0, blksize ctx+0x9C @+4, ctx+0xA4
  @+8, ctx+0x94 @+0xC;
- read method @+0x20 = **0x212AA1** (real mtk_nfc read; |1 Thumb),
  +0x24 = 0x2127B3.

Decision: keep the re-arm stub (kind 'staged', citation above) — after
the payload hijack, the only chain consumer of the struct is the
+0x20 indirection part_load calls per block; the stub restores exactly
that mechanism with observed stock values. Real-init upgrade path:
extend NfiModel to answer the pl2021 driver register traffic, then the
whole read path (0x212AA1) becomes real code — deferred as
high-value-later (ledger minor).
