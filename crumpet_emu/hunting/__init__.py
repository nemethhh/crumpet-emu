"""Hunting instrumentation layer (Task 15 — new code, no donor port).

Cross-cutting instruments over the emulated load chain (spec §5.4):
- inject       fault recipes against flash models / session memory
- differential same input, varied parameters; UART-trace divergence
- fuzz         checkpoint-restored deterministic case loop (crash-tolerant)
- coverage     AFL-style edge bitmap over a UC_HOOK_CODE hook
"""

from .inject import apply_flash, apply_mem
from .differential import first_divergence, run_variants
from .fuzz import CaseResult, FuzzLoop, FuzzReport
from .coverage import EdgeBitmap

__all__ = ['apply_flash', 'apply_mem', 'run_variants', 'first_divergence',
           'FuzzLoop', 'FuzzReport', 'CaseResult', 'EdgeBitmap']
