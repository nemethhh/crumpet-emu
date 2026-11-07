# Task 14 (plan §5.3 kernel-load observability, v1 surgical entry).
# Donor facts: WS/tools/lk-emu/{lk_emu.py,battery.py}
# (scenario_bootimg staging) + lk.img rodata (verdict literals, VMA = raw +
# 0x41DFFE00). v1 invokes the boot-image auth wrapper verify_with_hash
# (0x41E00F58, dual-attempt eng+prod -> cert driver 0x41E0120C) on a staged
# boot.img inside LkSession and observes everything around the verdict.
# The natural-boot upgrade (boot-image auth fn 0x41E11548: androidboot
# cmdline construction + kernel handoff) is milestone M2 (R13) — NOT
# attempted here: kernel execution is a non-goal, so handoff stays None and
# cmdline/rollback carry only what the hooks actually observed (empty on
# the surgical path, because 0x41E11548 never runs — see AuthReport).
"""Boot-image auth observability: verify_with_hash on a staged boot.img.

observe_auth(lk, boot_bytes) reuses battery.scenario_bootimg's staging
pattern (stage blob at a flat VMA, call F['boot_auth'] as fn(start, end,
size, 0)) with the natural-call refinement the real image forced: end/size
cover the signed data ONLY — the trailing 0x800-byte signature page (cert
DER) is excluded, because cert_driver (0x41E0120C) parses the ASN.1 flexi
tree AT the end pointer (helper 0x41E0A960 reads the DER at end directly;
live-verified 2025:boot: ret=1 AUTHENTICATED in 14.5 s). Hooks installed
around the call:

  * verify_with_hash (0x41E00F58) call capture — staged args r0-r3;
  * androidboot.* cmdline strings surfacing on the log/UART stubs;
  * anti-rollback reads at deviceinfo+0x1E4/+0x1E6/+0x1E8 (u16 reads
    feeding androidboot.pl_version/tee_version/lk_version in the
    boot-image auth fn 0x41E11548 — donor decomp sub_41E11548);
  * kernel-jump handoff (execution leaving the LK image region) —
    record-if-observed; None on the surgical path (no kernel execution);
  * R14 host-assisted hashing (see below).

Verdict: derived from the donor literal strings the wrapper prints
through the log stub (lk.log_out), pinned byte-for-byte from lk.img
rodata (raw offsets +0x41DFFE00 = VMA; donor lk_emu.py pool math):
authenticated 'Image AUTHENTICATED with PRODUCTION certificate' vs the
failure paths 'Image FAILED AUTHENTICATION on PRODUCTION device',
'Image FAILED AUTHENTICATION on ENGINEERING device', 'Authentication
failed on engineering device with production certificate', 'ERROR:
Unable to allocate image hash'. When no line fires, the wrapper's return
decides (battery.py: sub_41E00F58 returns 1 = VERIFIED, 0 = failed).

R14 host-assisted hashing: the wrapper hashes the staged image via its
helper sub_41E01170(start, size, out32). The emulated libtomcrypt
SHA-256 transform manages <16.5 KB/s (probe: 9.9 MB did not finish in
600 s), so a real 9.9 MB boot.img is prohibitive in-emulation. For
images above SHA_HOST_ASSIST_MIN observe_auth hooks sub_41E01170,
computes the byte-identical digest host-side (hashlib.sha256 —
deterministic, same function contract) and returns success, letting the
emulated cert driver 0x41E0120C + RSA-PSS verify continue from the
correct state; images <= the threshold stay fully emulated. Donor ground
truth: lk_emu.py/battery.py have NO sha treatment at all — their
run-bootimg.log is fast only because the vectors are <=0x800 bytes; the
full-image case is new in Task 14. (Precedent: Task 7 _emu_dma_memcpy
and the NFI register models — expensive primitives computed host-side.)
"""
import hashlib
from dataclasses import dataclass, field

from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ
from unicorn.arm_const import (UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0,
                               UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)

from crumpet_emu.lk.session import BSS_END, F, LK_BASE, LkSession

#: staging VMA for the boot image — clear of the donor LkSession map
#: (image/BSS through 0x41E60000, stack/heap/args at 0x7xxxxxxx, TEE
#: staging 0x43001000).
BOOT_IMAGE_BASE = 0x60000000

#: the Amazon signature page: the boot image is signed_data || one 0x800
#: page holding the cert DER; verify_with_hash covers only the signed data
#: and cert_driver (0x41E0120C) parses the ASN.1 flexi tree AT the passed
#: end pointer (0x41E0A960 reads the DER at end directly — live-verified:
#: end = start + size - 0x800 gives ret=1 AUTHENTICATED in 14.5s; end at
#: the raw file end reads zeros -> 'tbsCertificate is empty').
SIGNATURE_PAGE = 0x800

#: the wrapper's image-hash helper (verify_with_hash -> sub_41E01170 ->
#: hash_memory); host-assist hook point (R14).
IMAGE_HASH = 0x41E01170

#: LkSession._boot_globals fake device-info (session.py: a zeroed 4KB page
#: at 0x41E58000, prod flag +0x1E2, pointer cell 0x41E45E10).
DEVICEINFO = 0x41E58000

#: anti-rollback/version u16 reads the boot-image auth fn makes at
#: deviceinfo+0x1E4/+0x1E6/+0x1E8 (donor sub_41E11548: androidboot.
#: pl_version/tee_version/lk_version). The dict keys are the pinned
#: rollback-report keys, the values the pinned offsets.
ROLLBACK_READS = {
    'pl_version': 0x1E4,
    'tee_version': 0x1E6,
    'lk_version': 0x1E8,
}

#: images above this many bytes hash host-side inside observe_auth (R14);
#: smaller ones stay fully emulated.
SHA_HOST_ASSIST_MIN = 0x10000

# ---- verdict literals (lk.img rodata, byte-for-byte; trailing \n
# stripped as they surface through the log stub) -------------------------
#: wrapper success line (rodata raw 0x24a06 -> 0x41E24806; donor lk_emu.py
#: wrapper path: first verify attempt returns ok -> log -> ret 1)
VERDICT_AUTHENTICATED = 'Image AUTHENTICATED with PRODUCTION certificate'
#: eng-cert image on a prod device (fail-closed; the session boots prod=1)
VERDICT_FAILED_PROD = 'Image FAILED AUTHENTICATION on PRODUCTION device'
#: both attempts rejected on an engineering device
VERDICT_FAILED_ENG = 'Image FAILED AUTHENTICATION on ENGINEERING device'
#: eng-device intermediate line before the second attempt
VERDICT_FAILED_ENG_CERT = ('Authentication failed on engineering device '
                           'with production certificate')
#: malloc failure path (ret 0)
VERDICT_HASH_ALLOC = 'ERROR: Unable to allocate image hash'
_FAILURE_LITERALS = (VERDICT_FAILED_PROD, VERDICT_FAILED_ENG,
                     VERDICT_FAILED_ENG_CERT, VERDICT_HASH_ALLOC)


@dataclass
class AuthReport:
    """What the hooks saw around one verify_with_hash verdict.

    verdict  -- the pinned donor literal for the observed path;
    cmdline  -- androidboot.* strings the hooks captured (surgical mode
                runs only the wrapper, and cmdline construction lives in
                the boot-image auth fn 0x41E11548 — empty here; the M2
                upgrade (R13) populates it);
    rollback -- observed deviceinfo+0x1E4/1E6/1E8 reads as
                {ROLLBACK_READS key: u16 value} (empty on the surgical
                path for the same reason);
    handoff  -- kernel-jump address if execution left the LK image;
                None in surgical mode (kernel execution is a non-goal).
    """
    verdict: str
    cmdline: list[str] = field(default_factory=list)
    rollback: dict[str, int] = field(default_factory=dict)
    handoff: int | None = None


def verdict_from_logs(lines, ret=None):
    """Derive the AuthReport verdict from log-stub lines + wrapper return.

    The wrapper's log line is authoritative; with no line, battery.py's
    pinned return semantics decide (1 = VERIFIED, else failed).
    """
    for line in lines:
        if VERDICT_AUTHENTICATED in line:
            return VERDICT_AUTHENTICATED
    for line in lines:
        for lit in _FAILURE_LITERALS:
            if lit in line:
                return lit
    if ret == 1:
        return VERDICT_AUTHENTICATED
    return VERDICT_FAILED_PROD


def _staged_extent(uc, img: int, upper: int) -> int:
    """Readable byte extent of the staging region at img (0 = unmapped).

    Unicorn's Python bindings expose no mapping query, so the extent is
    a binary-searched probe of [img, img + upper): mem_read faults past
    the region end. upper bounds the search (the staged image size).
    """
    lo, hi = 0, upper
    while lo < hi:
        mid = (lo + hi + 1) // 2
        try:
            uc.mem_read(img, mid)
            lo = mid
        except Exception:                       # noqa: BLE001 - unmapped tail
            hi = mid - 1
    return lo


def observe_auth(lk: LkSession, boot_bytes: bytes, *,
                 timeout: int = 120) -> AuthReport:
    """Stage boot_bytes, run verify_with_hash, and report the verdict.

    Surgical entry (donor battery.scenario_bootimg shape): stage the
    image and call F['boot_auth'] as fn(start, end, size, 0) with
    end/size covering the signed data only (the trailing SIGNATURE_PAGE
    is excluded — cert_driver parses the cert DER at end). Observation
    hooks are installed before and removed after the call, so the session
    stays reusable for differential runs.
    """
    uc = lk.uc
    img = BOOT_IMAGE_BASE
    size = max(len(boot_bytes) - SIGNATURE_PAGE, 0)
    try:                                 # probe: reuse a previous staging
        uc.mem_read(img, len(boot_bytes))
    except Exception:
        extent = _staged_extent(uc, img, len(boot_bytes))
        if extent:
            # region exists but cannot hold this image (a previous
            # observe_auth staged a smaller one): refuse, never truncate
            raise ValueError(
                f'staging region at {img:#x} holds {extent:#x} bytes, '
                f'too small for this {len(boot_bytes):#x}-byte image '
                f'(use a fresh LkSession)') from None
        # page-aligned file + one guard page: the donor's staging
        # (battery.scenario_bootimg -> ARG1 in the 1MB zeroed ARGS region)
        # never faults on footer walks past the data; mirror that slack.
        uc.mem_map(img, max((len(boot_bytes) + 0xFFF & ~0xFFF) + 0x1000,
                            0x2000))
    lk.wr(img, boot_bytes)

    log_mark = len(lk.log_out)
    uart_mark = len(lk.uart_out)
    report = AuthReport(verdict=VERDICT_FAILED_PROD)

    # verify_with_hash call capture (staged args)
    vh = {'args': None}

    def on_verify(uc, address, size, user):
        if vh['args'] is None:
            vh['args'] = [uc.reg_read(r) for r in
                          (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                           UC_ARM_REG_R3)]

    hooks = [uc.hook_add(UC_HOOK_CODE, on_verify,
                         begin=F['boot_auth'], end=F['boot_auth'])]

    # R14 host-assisted hashing at the wrapper's image-hash helper
    def on_image_hash(uc, address, size, user):
        start = uc.reg_read(UC_ARM_REG_R0)
        length = uc.reg_read(UC_ARM_REG_R1)
        out = uc.reg_read(UC_ARM_REG_R2)
        if length > SHA_HOST_ASSIST_MIN:
            digest = hashlib.sha256(lk.rd(start, length)).digest()
            lk.wr(out, digest)
            uc.reg_write(UC_ARM_REG_R0, 0)          # CRYPT_OK
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    hooks.append(uc.hook_add(UC_HOOK_CODE, on_image_hash,
                             begin=IMAGE_HASH, end=IMAGE_HASH))

    # anti-rollback reads at deviceinfo+0x1E4/0x1E6/0x1E8 (u16)
    offsets = {DEVICEINFO + off: key for key, off in ROLLBACK_READS.items()}

    def on_di_read(uc, access, address, size, value, user):
        key = offsets.get(address)
        if key is not None and size == 2 and key not in report.rollback:
            report.rollback[key] = int.from_bytes(lk.rd(address, 2), 'little')

    hooks.append(uc.hook_add(UC_HOOK_MEM_READ, on_di_read,
                             begin=DEVICEINFO, end=DEVICEINFO + 0x1FF))

    # kernel-jump handoff: record-if-observed, then stop (non-goal guard)
    hit = {'handoff': None}

    def on_leave(uc, address, size, user):
        if hit['handoff'] is None:
            hit['handoff'] = address
            report.handoff = address
        uc.emu_stop()

    hooks.append(uc.hook_add(UC_HOOK_CODE, on_leave,
                             begin=0, end=LK_BASE - 1))
    hooks.append(uc.hook_add(UC_HOOK_CODE, on_leave,
                             begin=BSS_END + 1, end=(1 << 32) - 1))

    try:
        ret = lk.call(F['boot_auth'], [img, img + size, size, 0],
                      timeout=timeout, verbose_name='boot_auth(observe)')
    finally:
        for h in hooks:
            uc.hook_del(h)

    new_logs = list(lk.log_out[log_mark:])
    uart_text = bytes(lk.uart_out[uart_mark:]).decode('latin1')
    new_logs += uart_text.splitlines()          # UART cmdline strings
    report.verdict = verdict_from_logs(new_logs, ret)
    report.cmdline = [s.strip() for s in new_logs
                      if s.strip().startswith('androidboot.')]
    return report
