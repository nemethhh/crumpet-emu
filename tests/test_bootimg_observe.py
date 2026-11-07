# Task 14 — lk boot-image auth observability (kernel-load layer, v1 surgical).
#
# test_authreport_shape          (Tier 1) AuthReport is the ruled dataclass
#                                (verdict/cmdline/rollback/handoff=None) and
#                                observe_auth accepts a duck-typed session.
# test_rollback_keys_pinned      (Tier 1) the rollback report keys are pinned
#                                to the donor's deviceinfo offsets 0x1E4/
#                                0x1E6/0x1E8 (sub_41E11548 u16 reads feeding
#                                androidboot.pl_version/tee_version/
#                                lk_version).
# test_verdict_from_logs         (Tier 1) verdict derivation maps the pinned
#                                donor literals (rodata provenance) and falls
#                                back to battery.py's return semantics
#                                (1 = VERIFIED, 0 = failed).
# test_observe_auth_surgical_shape (Tier 1) with a fake duck-typed session:
#                                the staged call keeps donor
#                                battery.scenario_bootimg's shape
#                                fn(start, end, size, 0), the verdict/report
#                                are assembled from what the hooks saw, and
#                                every installed hook is removed afterwards
#                                (session stays reusable for differential
#                                runs).
# test_observe_auth_reports      (Tier 2) real 2025:boot on 2025:lk —
#                                verdict matches the donor authenticated
#                                literal, handoff None (surgical), rollback
#                                keys within the pinned map; differential:
#                                a manually tampered copy yields the
#                                failure-path literal.
"""Boot-image auth observability (Task 14): AuthReport + observe_auth."""
import pytest

from crumpet_emu import resources
from crumpet_emu.lk.bootimg import (BOOT_IMAGE_BASE, DEVICEINFO,
                                    ROLLBACK_READS, SIGNATURE_PAGE,
                                    AuthReport, VERDICT_AUTHENTICATED,
                                    VERDICT_FAILED_ENG,
                                    VERDICT_FAILED_PROD, observe_auth,
                                    verdict_from_logs)
from crumpet_emu.lk.session import F

TIER2 = 'tier2: requires parked vendor binaries — see binaries/README.md'


# ---------------------------------------------------------------- tier 1
def test_authreport_shape():
    rep = AuthReport(verdict=VERDICT_AUTHENTICATED)
    assert rep.verdict == VERDICT_AUTHENTICATED
    assert rep.cmdline == []
    assert rep.rollback == {}
    assert rep.handoff is None
    # ruled shape: exactly the four fields, donor-typed
    import dataclasses
    assert [f.name for f in dataclasses.fields(AuthReport)] == \
        ['verdict', 'cmdline', 'rollback', 'handoff']


def test_rollback_keys_pinned():
    # donor decomp sub_41E11548: u16 reads at deviceinfo+484/486/488
    # (0x1E4/0x1E6/0x1E8) feeding androidboot.pl_version/tee_version/
    # lk_version — the report keys are pinned to exactly those offsets.
    assert ROLLBACK_READS == {'pl_version': 0x1E4, 'tee_version': 0x1E6,
                              'lk_version': 0x1E8}


def test_verdict_from_logs():
    assert verdict_from_logs(['Image AUTHENTICATED with PRODUCTION '
                              'certificate']) == VERDICT_AUTHENTICATED
    assert verdict_from_logs(['Image FAILED AUTHENTICATION on PRODUCTION '
                              'device']) == VERDICT_FAILED_PROD
    assert verdict_from_logs(['Image FAILED AUTHENTICATION on ENGINEERING '
                              'device']) == VERDICT_FAILED_ENG
    # no line fired -> battery.py return semantics (1 = VERIFIED)
    assert verdict_from_logs([], ret=1) == VERDICT_AUTHENTICATED
    assert verdict_from_logs([], ret=0) == VERDICT_FAILED_PROD


class _FakeHook:
    def __init__(self, name):
        self.name = name
        self.removed = False


class _FakeUc:
    """Minimal unicorn surface observe_auth uses on the surgical path."""

    def __init__(self, mapped=()):
        self.mapped = set(mapped)
        self.mem = {}
        self.installed = []
        self.regs = {}

    def mem_map(self, addr, size):
        self.mapped.add(addr)
        self.mem[addr] = bytearray(size)

    def mem_read(self, addr, n):
        for base, buf in self.mem.items():
            if base <= addr < base + len(buf):
                if addr + n > base + len(buf):
                    raise RuntimeError('unmapped')   # real unicorn faults
                return bytes(buf[addr - base:addr - base + n])
        raise RuntimeError('unmapped')

    def mem_write(self, addr, data):
        for base, buf in self.mem.items():
            if base <= addr < base + len(buf):
                buf[addr - base:addr - base + len(data)] = bytes(data)
                return
        raise RuntimeError('unmapped')

    def hook_add(self, typ, fn, begin=0, end=(1 << 32) - 1):
        h = _FakeHook(fn.__name__)
        self.installed.append(h)
        return h

    def hook_del(self, h):
        h.removed = True
        if h in self.installed:
            self.installed.remove(h)

    def reg_read(self, reg):
        return self.regs.get(reg, 0)


class _FakeLk:
    """Duck-typed LkSession: records the staged call, emits a verdict line."""

    def __init__(self, ret, log_lines):
        self.uc = _FakeUc()
        self.log_out = []
        self.uart_out = []
        self._ret = ret
        self._log_lines = log_lines
        self.calls = []

    def rd(self, addr, n):
        return self.uc.mem_read(addr, n)

    def wr(self, addr, data):
        self.uc.mem_write(addr, bytes(data))

    def call(self, fn, args, timeout=120, verbose_name=None):
        self.calls.append((fn, tuple(args)))
        self.log_out.extend(self._log_lines)
        return self._ret


def test_observe_auth_surgical_shape():
    fake = _FakeLk(ret=1, log_lines=[VERDICT_AUTHENTICATED])
    fake.uc.mem_map(BOOT_IMAGE_BASE, 0x3000)     # pre-staged probe target
    boot = b'\x00' * 0x1000                      # data page + signature page
    rep = observe_auth(fake, boot, timeout=30)
    fn, args = fake.calls[0]
    # donor battery.scenario_bootimg staging: fn(start, end, size, 0) with
    # end/size covering the signed data (signature page excluded)
    assert fn == F['boot_auth']
    data_len = len(boot) - SIGNATURE_PAGE
    assert args == (BOOT_IMAGE_BASE, BOOT_IMAGE_BASE + data_len,
                    data_len, 0)
    assert fake.uc.mem_read(BOOT_IMAGE_BASE, len(boot)) == boot
    assert rep.verdict == VERDICT_AUTHENTICATED
    assert rep.cmdline == [] and rep.rollback == {} and rep.handoff is None
    # every installed hook was removed: the session stays reusable
    assert fake.uc.installed == []


def test_staging_region_too_small_raises():
    """The 1-byte readability probe could not see the region extent: a
    second observe_auth with a bigger image on a reused session silently
    overran (or died in UC_ERR_MAP). The full-extent probe now refuses
    with the region size vs image size."""
    fake = _FakeLk(ret=0, log_lines=[])
    fake.uc.mem_map(BOOT_IMAGE_BASE, 0x2000)   # a previous, smaller staging
    with pytest.raises(ValueError) as ei:
        observe_auth(fake, b'\x00' * 0x8000)
    assert 'staging region' in str(ei.value)
    assert hex(0x2000)[2:] in str(ei.value)    # region extent named
    assert hex(0x8000)[2:] in str(ei.value)    # image size named
    assert fake.calls == []                    # refused before the call

    # a fresh (unmapped) staging region still maps and proceeds
    fresh = _FakeLk(ret=1, log_lines=[VERDICT_AUTHENTICATED])
    rep = observe_auth(fresh, b'\x00' * 0x8000)
    assert rep.verdict == VERDICT_AUTHENTICATED


# ---------------------------------------------------------------- tier 2
tier2_boot = pytest.mark.skipif(
    not (resources.available('lk', '2025')
         and resources.available('boot', '2025')),
    reason=TIER2)


@tier2_boot
def test_observe_auth_reports():
    from crumpet_emu.lk.session import LkSession

    lk = LkSession.build(resources.resolve('lk', '2025').read_bytes())
    boot = resources.resolve('boot', '2025').read_bytes()

    rep = observe_auth(lk, boot, timeout=120)
    assert rep.verdict == VERDICT_AUTHENTICATED
    assert set(rep.rollback) <= set(ROLLBACK_READS)
    assert rep.handoff is None                    # surgical: no kernel run

    # differential: manual byte flip near the image start -> failure literal
    tampered = bytearray(boot)
    tampered[0x1000] ^= 0xFF
    tampered[0x1001] ^= 0xA5
    rep2 = observe_auth(lk, bytes(tampered), timeout=120)
    assert rep2.verdict == VERDICT_FAILED_PROD
    assert rep2.handoff is None
