#!/usr/bin/env python3
"""Phase 387: prove the strict gate's perf arm through the REAL ``main()``.

Two arms replay a MEASURED result through ``benchmark.runner.main``: at the
baseline wall clock the gate returns 0, one second over the ceiling it returns
1, and the quality verdict is still printed in both.  No scanner is launched:
``run_benchmark`` is replaced by the measured artifact itself, so this checks
the gate's wiring (call site + exit code), not detection.  The four real
strict-gate arms in ``phase387_measure.py`` are the wall-clock evidence; this
is the enforcement evidence.

Usage: .venv/Scripts/python.exe dev/phase387_enforcement_check.py
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
from dataclasses import fields
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmark import perf_budget as PB  # noqa: E402
from benchmark import runner as R  # noqa: E402

ARTIFACT = (ROOT / "benchmark" / "results" /
            "perf_baseline_quick_sync_20261113.json")
# Keep the replay output inside the workspace's gitignored archive: this is a
# two-write smoke, not a gate run, so the safe-delete cap is irrelevant.
OUT = (ROOT / "benchmark" / "results" / "_local_archive" /
       "phase387_enforcement.json")


def _result(total_time_s: float) -> R.BenchmarkResult:
    data = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    names = {f.name for f in fields(R.BenchmarkResult)}
    kwargs = {k: v for k, v in data.items() if k in names}
    kwargs["total_time_s"] = total_time_s
    return R.BenchmarkResult(**kwargs)


def _arm(total_time_s: float) -> tuple[int, str]:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    argv = ["runner.py", "--quick", "--strict-gate", "--engine", "sync",
            "-o", str(OUT)]
    buf = io.StringIO()
    with mock.patch.object(sys, "argv", argv), \
            mock.patch.object(R, "run_benchmark",
                              return_value=_result(total_time_s)), \
            contextlib.redirect_stdout(buf):
        rc = R.main()
    return rc, buf.getvalue()


def main() -> int:
    b = PB.PERFORMANCE_BUDGETS[("quick", "sync")]
    ok, at_baseline = _arm(b.baseline_s)
    bad, over = _arm(float(b.ceiling_s) + 1)
    checks = [
        ("baseline wall clock passes",
         ok == 0 and "Performance budget PASSED" in at_baseline),
        ("one second over the ceiling returns 1",
         bad == 1 and "Performance budget FAILED" in over),
        ("quality verdict is still printed in both arms",
         "Strict quality gate PASSED" in at_baseline
         and "Strict quality gate PASSED" in over),
        ("the two gates print separate verdicts",
         at_baseline.count("Performance budget") == 1
         and at_baseline.count("Strict quality gate") == 1),
    ]
    for label, passed in checks:
        print(f"[{'PASS' if passed else 'FAIL'}] {label}")
    print(f"baseline rc={ok}, over-ceiling rc={bad}, "
          f"ceiling={b.ceiling_s}s")
    if not all(p for _, p in checks):
        print(f"--- baseline stdout tail ---\n{at_baseline[-600:]}")
        print(f"--- over-ceiling stdout tail ---\n{over[-600:]}")
    return 0 if all(p for _, p in checks) else 1


if __name__ == "__main__":
    sys.exit(main())
