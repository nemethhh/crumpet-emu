"""Differential runner: same input, varied parameters (Task 15).

New code (no donor port). run_variants() feeds each variant's override dict
to the caller's build_fn (SBC state, slot, locked flags, firmware profile —
whatever the builder varies) and returns per-variant results; every result
R exposes .uart_text and .verdict — boot()'s BootOutcome (fields
uart_trace/reached_fastboot) does NOT qualify as-is; scenarios/
differential.py wraps each build in its own Result(uart_text, verdict).
first_divergence() aligns the UART traces pairwise and reports the first
differing line, so a hunt starts exactly where the variants split.
"""

from itertools import combinations


def run_variants(build_fn, variants):
    """Build every variant -> {name: R}.

    build_fn receives a shallow copy of each variant's override dict, so a
    builder that mutates its input cannot leak state between variants.
    """
    return {name: build_fn(dict(overrides))
            for name, overrides in variants.items()}


def _lines(uart_text):
    """Normalize a result's UART trace to a list of lines.

    Both trace shapes in this repo qualify: a plain text blob (str, e.g. a
    decoded UART capture) or a list/tuple of lines (boot()'s uart_trace).
    """
    if isinstance(uart_text, str):
        return uart_text.splitlines()
    return [str(line) for line in uart_text]


def first_divergence(results):
    """(pair, line) for the first UART divergence across variants, else None.

    Pair naming: '<first> vs <second>' with the pair taken in results
    insertion order (itertools.combinations over the variant names), so the
    output is deterministic for a given variant dict.

    Line: the first variant of the pair's line at the first differing index
    — a line present in one trace only also counts as a difference; if the
    first trace ran out, the second variant's line at that index is
    reported instead.

    Verdict differences are intentionally NOT reported here: verdicts are
    plain values the caller can compare directly; the UART alignment is the
    part that needs tooling.
    """
    names = list(results)
    for a, b in combinations(names, 2):
        la, lb = _lines(results[a].uart_text), _lines(results[b].uart_text)
        for i in range(max(len(la), len(lb))):
            da = la[i] if i < len(la) else None
            db = lb[i] if i < len(lb) else None
            if da != db:
                return (f'{a} vs {b}', da if da is not None else db)
    return None
