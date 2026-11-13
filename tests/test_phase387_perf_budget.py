# -*- coding: utf-8 -*-
"""Phase 387: the strict gate's wall-clock budget is measured, derived and enforced.

Why this guard exists (the failure shapes it locks out):

* a ceiling typed by hand instead of derived from a real run;
* a baseline number that no longer matches its artifact (a "latest file is
  my file" mistake), or an artifact that was never a clean strict-gate run;
* a rotated/unmeasured composition silently treated as a perf pass;
* a half-filled table judging real runs against ``ceiling 0``;
* the runner growing its own hand-rolled verdict instead of calling the
  shared helper -- the "same contract handwritten twice" family.  The
  function body does not rot; its CALL SITE does, so the call site is
  asserted from source, not just exercised.

The quality gate (FP/FN/ERROR/SKIP) and the perf gate stay separate: this
file only pins the wall-clock dimension.
"""
from __future__ import annotations

import ast
import json
import sys
from dataclasses import replace
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from benchmark import perf_budget as PB  # noqa: E402
from benchmark import runner as R  # noqa: E402

_RESULTS = _ROOT / "benchmark" / "results"
_RUNNER_SRC = _ROOT / "benchmark" / "runner.py"
_MEASURE_SRC = _ROOT / "dev" / "phase387_measure.py"
_OPT = _ROOT / "docs" / "OPTIMIZATION.md"
_EXPECTED_ARMS = {("quick", "sync"), ("quick", "async"),
                  ("full", "sync"), ("full", "async")}


def _artifact(budget) -> dict:
    path = _RESULTS / budget.evidence
    assert path.is_file(), f"missing baseline artifact: {path}"
    return json.loads(path.read_text(encoding="utf-8"))


def test_every_budget_ceiling_is_derived_not_handwritten():
    assert set(PB.PERFORMANCE_BUDGETS) == _EXPECTED_ARMS
    for key, b in PB.PERFORMANCE_BUDGETS.items():
        assert (b.mode, b.engine) == key
        assert b.baseline_s > 0 and b.cases > 0, b
        assert b.concurrency == 1, b  # all four arms measured serially
        assert len(b.measured) == 10 and b.measured[4] == "-", b
        assert b.evidence.endswith(".json"), b
        assert b.ceiling_s == PB.round_up_to_5(b.baseline_s * PB.MARGIN), b
        assert b.ceiling_s > b.baseline_s, b


def test_every_budget_matches_its_own_clean_artifact():
    for b in PB.PERFORMANCE_BUDGETS.values():
        assert b.mode in b.evidence and b.engine in b.evidence, b
        assert b.measured.replace("-", "") in b.evidence, b
        data = _artifact(b)
        assert data["total_time_s"] == b.baseline_s, (b, data["total_time_s"])
        assert data["total_cases"] == b.cases, b
        assert data["engine"] == b.engine, b
        assert data["timestamp"][:10] == b.measured, b
        assert (data["fp"], data["fn"], data["errors"]) == (0, 0, 0), b
        assert data["tp"] + data["tn"] > 0, b  # "zero is not a pass"


def test_budget_for_exact_composition_only():
    for (mode, engine), b in PB.PERFORMANCE_BUDGETS.items():
        assert PB.budget_for(mode, engine, b.cases, b.quick_offset) is b
        assert PB.budget_for(mode, engine, b.cases + 1,
                             b.quick_offset) is None
        if mode == "quick":
            assert PB.budget_for(mode, engine, b.cases,
                                 b.quick_offset + 1) is None
        assert PB.budget_for(mode, engine, b.cases,
                             b.quick_offset, 2) is None
        assert PB.budget_for(mode, "other", b.cases, b.quick_offset) is None
    assert PB.budget_for("rotated", "sync", 64, 0) is None


def test_unmeasured_entry_is_never_a_budget(monkeypatch):
    """A half-filled table must say UNBUDGETED, not fail on ceiling 0."""
    b = PB.PERFORMANCE_BUDGETS[("quick", "sync")]
    monkeypatch.setitem(PB.PERFORMANCE_BUDGETS, ("quick", "sync"),
                        replace(b, baseline_s=0.0, ceiling_s=0))
    assert PB.budget_for("quick", "sync", b.cases, b.quick_offset) is None
    ok, line = R._perf_gate_line(
        R.BenchmarkResult(engine="sync", total_cases=b.cases,
                          total_time_s=b.baseline_s), True, 0)
    assert ok and "UNBUDGETED" in line and "PASSED" not in line


def test_evaluate_boundary_carries_provenance():
    b = PB.PERFORMANCE_BUDGETS[("quick", "sync")]
    ok, detail = PB.evaluate_perf_budget(b, float(b.ceiling_s))
    assert ok is True
    for token in (str(b.ceiling_s), b.measured, b.mode, b.engine,
                  f"{b.baseline_s:.1f}s"):
        assert token in detail, (token, detail)
    ok2, detail2 = PB.evaluate_perf_budget(b, float(b.ceiling_s) + 0.01)
    assert ok2 is False and str(b.ceiling_s) in detail2


def test_margin_is_conservative_not_hollow():
    # 2x absorbs documented loopback degradation; 10x would be a gate that
    # can never fail.  Tightening or widening needs a dated measured reason.
    assert 2.0 <= PB.MARGIN < 10.0


def test_runner_real_entry_point_states_all_three_outcomes():
    """Probe the REAL helper, not a copy of its logic."""
    b = PB.PERFORMANCE_BUDGETS[("quick", "sync")]
    ok, line = R._perf_gate_line(
        R.BenchmarkResult(engine="sync", total_cases=b.cases,
                          total_time_s=b.baseline_s), True, 0)
    assert ok and "PASSED" in line and str(b.ceiling_s) in line, line
    ok2, line2 = R._perf_gate_line(
        R.BenchmarkResult(engine="sync", total_cases=b.cases,
                          total_time_s=float(b.ceiling_s) + 1), True, 0)
    assert not ok2 and "FAILED" in line2, line2
    ok3, line3 = R._perf_gate_line(
        R.BenchmarkResult(engine="sync", total_cases=b.cases + 1,
                          total_time_s=1.0), True, 0)
    assert ok3 and "UNBUDGETED" in line3 and "PASSED" not in line3, line3
    assert "NO performance claim" in line3


def test_nondefault_concurrency_is_unbudgeted():
    """Parallelism changes wall clock without changing the case list."""
    b = PB.PERFORMANCE_BUDGETS[("quick", "sync")]
    ok, line = R._perf_gate_line(
        R.BenchmarkResult(engine="sync", total_cases=b.cases,
                          total_time_s=b.baseline_s), True, 0, 4)
    assert ok and "UNBUDGETED" in line and "concurrency 4" in line, line


def test_runner_calls_shared_helper_and_enforces_failure():
    """Source assertion: the CALL SITE is what rots, not the helper body."""
    src = _RUNNER_SRC.read_text(encoding="utf-8")
    tree = ast.parse(src)
    main_node = next(n for n in tree.body
                     if isinstance(n, ast.FunctionDef) and n.name == "main")
    called = {n.func.id for n in ast.walk(main_node)
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert "_perf_gate_line" in called, called
    arms = [n for n in ast.walk(main_node)
            if isinstance(n, ast.If)
            and isinstance(n.test, ast.UnaryOp)
            and isinstance(n.test.op, ast.Not)
            and isinstance(n.test.operand, ast.Name)
            and n.test.operand.id == "perf_ok"]
    assert len(arms) == 1, arms
    assert any(isinstance(s, ast.Return)
               and isinstance(s.value, ast.Constant)
               and s.value.value == 1 for s in arms[0].body)
    assert "ceiling_s=" not in src            # no handwritten ceiling
    assert "PERFORMANCE_BUDGETS[" not in src  # no bypass of budget_for
    helper = next(n for n in tree.body
                  if isinstance(n, ast.FunctionDef)
                  and n.name == "_perf_gate_line")
    attrs = {f"{n.value.id}.{n.attr}" for n in ast.walk(helper)
             if isinstance(n, ast.Attribute)
             and isinstance(n.value, ast.Name)
             and n.value.id == "perf_budget"}
    assert {"perf_budget.budget_for",
            "perf_budget.evaluate_perf_budget"} <= attrs, attrs


def test_measure_script_only_accepts_clean_artifacts():
    src = _MEASURE_SRC.read_text(encoding="utf-8")
    fn = next(n for n in ast.parse(src).body
              if isinstance(n, ast.FunctionDef)
              and n.name == "_clean_artifact")
    seg = ast.get_source_segment(src, fn) or ""
    for token in ('data.get("fp")', 'data.get("fn")', 'data.get("errors")',
                  'data.get("tp", 0) + data.get("tn", 0)',
                  'data.get("total_cases") != len(data.get("cases", []))'):
        assert token in seg, (token, seg[:200])
    assert "subprocess.run" in src and "ThreadPoolExecutor" not in src


def test_optimization_records_the_same_measured_numbers():
    """Document parity: no second copy of the numbers may rot unnoticed."""
    text = _OPT.read_text(encoding="utf-8")
    assert "### 8.18" in text
    section = text.split("### 8.18", 1)[1].split("\n### ", 1)[0]
    for b in PB.PERFORMANCE_BUDGETS.values():
        assert f"{b.baseline_s:.2f}s" in section, b
        assert f"{b.ceiling_s}s" in section, b
