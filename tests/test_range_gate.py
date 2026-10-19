# -*- coding: utf-8 -*-
"""Guards for range_gate.py -- the one definition both range runners call.

Phase 267.  range4 and range5 printed `browser-confirmed=N` and then let
the gate ignore it.  Measured on range4 with a Chromium-less environment:

    r4-pos-react-dsi  TP  top: reflected/high/script_string_sq/errored
                          browser-confirmed=0
    [*] Range4 gate: every case scored as ground truth requires
    EXIT=0

Every case "scored as ground truth requires" while the range measured
zero browser execution -- which is the only thing the range exists to
measure.  The rules now live in range_gate.py so the three runners cannot
each keep their own copy (Phase 259: hand-kept duplicates are how
contracts drift).

These are pure-function tests plus a call-site check.  The call-site check
is deliberate: a function body stays correct forever, the question is
whether main() still calls it (Phase 176u's lesson).
"""
from __future__ import annotations

import ast
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from range_gate import evidence_gaps, failing_rows  # noqa: E402


# ---------------------------------------------------------------------------
# failing_rows
# ---------------------------------------------------------------------------

def test_failing_rows_keeps_fn_fp_error_and_drops_skip():
    rows = [{"verdict": "TP"}, {"verdict": "TN"}, {"verdict": "SKIP"},
            {"verdict": "FN"}, {"verdict": "FP"}, {"verdict": "ERROR"}]
    assert [r["verdict"] for r in failing_rows(rows)] == ["FN", "FP", "ERROR"]


# ---------------------------------------------------------------------------
# evidence_gaps
# ---------------------------------------------------------------------------

HEADLESS_POS = {"id": "p", "gt": "vulnerable", "headless": True}
STATIC_POS = {"id": "p", "gt": "vulnerable", "headless": False}
HEADLESS_NEG = {"id": "n", "gt": "safe", "headless": True}


@pytest.mark.parametrize("case,row,expect_gap", [
    # the measured shape: TP, nothing fired
    (HEADLESS_POS, {"verdict": "TP", "confirmed": 0}, True),
    # no recorded evidence is not evidence
    (HEADLESS_POS, {"verdict": "TP"}, True),
    # at least one fired outcome is the claim
    (HEADLESS_POS, {"verdict": "TP", "confirmed": 2}, False),
    # a negative has nothing to fire
    (HEADLESS_NEG, {"verdict": "TN", "confirmed": 0}, False),
    # statically scored ranges (range6's sanitizer pair) are exempt
    (STATIC_POS, {"verdict": "TP", "confirmed": 0}, False),
    # an FN is already a verdict failure; do not report it twice
    (HEADLESS_POS, {"verdict": "FN", "confirmed": 0}, False),
    # a row whose case vanished from the manifest is not silently an FP
    (None, {"verdict": "TP", "confirmed": 0}, False),
])
def test_evidence_gap_rules(case, row, expect_gap):
    row = dict(row, engine="sync", case_id="p")
    cases = {} if case is None else {case["id"]: case}
    assert bool(evidence_gaps([row], cases)) is expect_gap


# ---------------------------------------------------------------------------
# the call sites (function bodies do not rot, call sites do)
# ---------------------------------------------------------------------------

def _calls_in_main(rel_path: str) -> set[str]:
    path = os.path.join(ROOT, rel_path)
    tree = ast.parse(open(path, encoding="utf-8").read())
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "main":
            names |= {c.func.id for c in ast.walk(node)
                      if isinstance(c, ast.Call)
                      and isinstance(c.func, ast.Name)}
    return names


@pytest.mark.parametrize("runner", ["range3/runner.py",
                                    "range4/runner.py",
                                    "range5/runner.py"])
def test_every_runner_calls_the_shared_verdict_rule(runner):
    assert "failing_rows" in _calls_in_main(runner), (
        f"{runner} went back to hand-rolling its FN/FP/ERROR filter")


@pytest.mark.parametrize("runner", ["range4/runner.py", "range5/runner.py"])
def test_browser_ranges_require_browser_evidence(runner):
    assert "evidence_gaps" in _calls_in_main(runner), (
        f"{runner} claims browser execution but its gate no longer checks it")
