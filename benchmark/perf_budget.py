"""Performance budgets for the official benchmark slices (Phase 387).

Until now ``benchmark.runner`` measured ``total_time_s`` and recorded it in
the JSON artifact, but nothing ever looked at it: a scanner that drifted to
10x slower would still pass every gate as long as FP0/FN0/ERROR0 held.  This
module pins a *hard* wall-clock budget per fixed slice composition so the
official strict-gate run fails loudly on order-of-magnitude slowdowns, the
same way ``tests/test_architecture_scale.py`` pins line budgets.

Rules this module follows (same discipline as the line budgets):

- **Measured, not aspirational.**  Every ``baseline_s`` comes from an actual
  strict-gate run on this machine (the file name / date is recorded).  The
  baseline JSON lives in ``benchmark/results/perf_baseline_*_<date>.json``.
- **Ceilings are derived, not hand-written.**  ``ceiling_s`` is
  ``round_up_to_5(baseline_s * MARGIN)`` and nothing else; a guard test
  recomputes it, so editing a ceiling without re-measuring turns the gate
  red.
- **Machine-anchored.**  The budgets are calibrated on THIS box (loopback
  profile, CPU, TEMP integrity label) and enforced on local official runs.
  CI hosted runners have different absolute speeds and their own noise
  profile; pinning CI budgets requires CI-run baselines and is explicitly
  NOT done here (an unbudgeted run is stated, never implied green).
- **Fixed compositions only.**  A budget names the exact slice it measured
  (mode + engine + case count + quick offset 0 + concurrency 1).  The CI push
  gate runs a weekly-rotated slice whose member costs differ per family, and a
  non-default ``--concurrency`` changes the wall clock without changing the
  cases; neither was measured, so ``budget_for`` returns ``None`` for any
  composition the table did not measure, and the runner says so instead of
  silently skipping.
- **Skip counts are reported separately** by the strict quality gate; the
  perf budget judges wall clock only.  A degraded day that SKIPs work is a
  quality-gate conversation, not a perf-gate green.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

# Ceiling = baseline * MARGIN, rounded up to a multiple of 5s.  The factor is
# deliberately generous: the point of this gate is to catch order-of-magnitude
# drift (the "an order of magnitude slower than nuclei" failure shape), not to
# flag every noisy day -- the project has a long history of attributing
# degraded-loopback reds as environment form, and a tight gate would manufacture
# exactly those.  2x absorbs documented loopback degradation episodes while
# still failing anything that doubled and stayed there.  Tightening below 2x
# requires evidence that the noise band allows it; widening it requires a
# measured reason in a dated record, same as any budget raise.
MARGIN = 2.0


def round_up_to_5(seconds: float) -> int:
    """Smallest multiple of 5 that is >= ``seconds``."""
    return int(5 * math.ceil(seconds / 5.0))


@dataclass(frozen=True)
class PerfBudget:
    """A measured wall-clock budget for one fixed slice composition."""

    mode: str           # "quick" (offset-0 stratified slice) | "full" (whole manifest)
    engine: str         # "sync" | "async"
    cases: int          # slice size the baseline actually measured
    quick_offset: int   # the slice rotation the baseline measured (0 = historical)
    baseline_s: float   # measured total_time_s, strict-gate run, this machine
    measured: str       # ISO date of the baseline run
    evidence: str       # artifact file in benchmark/results/ holding the run
    ceiling_s: int      # derived: round_up_to_5(baseline_s * MARGIN)
    concurrency: int = 1  # scanner parallelism the baseline was measured at


# Baselines: the four fixed strict-gate compositions.  Each entry is filled
# ONLY from its own artifact in benchmark/results/ (a guard re-reads every
# number); an unfilled entry (baseline_s == 0) is NOT a budget -- budget_for
# returns None for it, so a half-filled table can never judge a run against
# ceiling 0.  The async quick slice historically SKIPs 1 manifest-declared
# sync-only case; that SKIP reduces its work slightly and is part of the
# measured composition, and skip counts remain a quality-gate concern.
PERFORMANCE_BUDGETS: dict[tuple[str, str], PerfBudget] = {
    ("quick", "sync"): PerfBudget(
        mode="quick", engine="sync", cases=64, quick_offset=0,
        baseline_s=163.69, measured="2026-11-13",
        evidence="perf_baseline_quick_sync_20261113.json",
        ceiling_s=330,
    ),
    ("quick", "async"): PerfBudget(
        mode="quick", engine="async", cases=64, quick_offset=0,
        baseline_s=173.24, measured="2026-11-13",
        evidence="perf_baseline_quick_async_20261113.json",
        ceiling_s=350,
    ),
    ("full", "sync"): PerfBudget(
        mode="full", engine="sync", cases=194, quick_offset=0,
        baseline_s=397.09, measured="2026-11-13",
        evidence="perf_baseline_full_sync_20261113.json",
        ceiling_s=795,
    ),
    ("full", "async"): PerfBudget(
        mode="full", engine="async", cases=194, quick_offset=0,
        baseline_s=418.03, measured="2026-11-13",
        evidence="perf_baseline_full_async_20261113.json",
        ceiling_s=840,
    ),
}


def budget_for(mode: str, engine: str, total_cases: int,
               quick_offset: int, concurrency: int = 1) -> PerfBudget | None:
    """The budget governing this run's exact composition, or ``None``.

    ``None`` is a *statement*, not a gap: the composition was never measured
    as a whole (rotated CI slices, ad-hoc ``--quick-offset`` reproductions,
    case counts no baseline covers, non-default parallelism), and the caller
    must say so instead of claiming an unmeasured budget.
    """
    entry = PERFORMANCE_BUDGETS.get((mode, engine))
    if entry is None:
        return None
    # "Zero is not a pass" applies to budgets too: an entry with no measured
    # baseline is a placeholder, not a ceiling.  Without this rule a table
    # that is only half filled would fail every run for a reason that has
    # nothing to do with wall-clock drift.
    if entry.baseline_s <= 0 or entry.ceiling_s <= 0:
        return None
    if entry.cases != total_cases or entry.quick_offset != quick_offset:
        return None
    if entry.concurrency != concurrency:
        return None
    return entry


def evaluate_perf_budget(budget: PerfBudget, total_time_s: float) -> tuple[bool, str]:
    """Judge one measured wall clock against one budget.

    Returns ``(passed, detail)``; ``detail`` is a single human-readable line
    that carries the measurement, the ceiling, and the provenance, so a red
    is attributable without opening the JSON.
    """
    detail = (f"{total_time_s:.1f}s vs ceiling {budget.ceiling_s}s "
              f"(baseline {budget.baseline_s:.1f}s @{budget.measured}, "
              f"margin {MARGIN:.1f}x, {budget.mode}/{budget.engine})")
    return total_time_s <= budget.ceiling_s, detail
