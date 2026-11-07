"""Crash-tolerant fuzz loop over checkpointed sessions (Task 15).

New code (no donor port). FuzzLoop() restores the checkpoint before EVERY
case, so a faulting case can never poison the next one; a UcError (invalid
memory/fetch — the Session stop classes) or any other exception inside
run_case() is recorded as a not-ok case and the loop CONTINUES. That
crash-tolerance contract is pinned by tests/test_hunting.py
(test_fuzz_survives_crash): a UcError at input 7 of 10 yields a report with
9 ok + 1 crash and the loop completing.

Harness contract (spec §5.4: fastboot verb/blob inputs, DER/cert blobs into
the verify path, crafted GPT/part headers):

* mutate(case_index) -> dict of case inputs (deterministic: same index,
  same input);
* run_case(cfg) -> CaseResult(input_id, ok, verdict) drives the case
  against the emulated target.

Plumbing: the pinned run_case signature receives only the dict, so FuzzLoop
injects the per-case restored checkpoint into the dict it hands run_case
under two reserved keys — 'session' (the restored TrackedSession) and
'extra' (the checkpoint's opaque caller blobs, e.g. transport queues). The
dict passed to run_case is a shallow copy; mutate()'s dict is never
mutated. Note the checkpoint integration limit: checkpoints.restore()
returns a core TrackedSession, so an LK harness that needs LkSession-only
attributes (seeds, usb queues) rebuilds them from `extra` — see
docs/porting-notes.md section "Checkpoint duty".
"""

from collections import namedtuple
from pathlib import Path

from crumpet_emu.core.checkpoints import restore

CaseResult = namedtuple('CaseResult', 'input_id ok verdict')
FuzzReport = namedtuple('FuzzReport', 'cases crashes verdicts')


def FuzzLoop(cp_path, mutate, run_case, *, max_cases=1000) -> FuzzReport:
    """Run up to max_cases checkpoint-restored fuzz cases -> FuzzReport.

    FuzzReport.cases   — every CaseResult in run order;
    FuzzReport.crashes — the not-ok cases: any case that ended ok=False,
                         whether run_case reported it or an exception was
                         absorbed (exception verdicts carry the class name,
                         e.g. 'UcError');
    FuzzReport.verdicts— histogram {verdict string: count} over all cases.
    """
    cp_path = Path(cp_path)
    cases = []
    for input_id in range(max_cases):
        session, extra = restore(cp_path)  # per case: dirt cannot leak
        cfg = dict(mutate(input_id))
        cfg['session'] = session
        cfg['extra'] = extra
        try:
            result = run_case(cfg)
        except Exception as exc:  # noqa: BLE001 — absorbing is the contract
            result = CaseResult(input_id, False, type(exc).__name__)
        cases.append(result)
    crashes = [r for r in cases if not r.ok]
    verdicts: dict[str, int] = {}
    for r in cases:
        verdicts[r.verdict] = verdicts.get(r.verdict, 0) + 1
    return FuzzReport(cases, crashes, verdicts)
