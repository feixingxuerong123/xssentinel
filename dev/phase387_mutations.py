#!/usr/bin/env python3
"""Phase 387 mutation checks: baseline GREEN -> mutated RED -> restored GREEN.

Each mutation runs ONE named test node, so "another assertion turned red"
cannot impersonate a load-bearing guard.  Anchors are read from the real
source wherever a measured number is involved (the budget table is filled
from artifacts, so a hardcoded baseline here would rot on the next re-measure).

Usage: .venv/Scripts/python.exe dev/phase387_mutations.py
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmark import perf_budget as PB  # noqa: E402

PY = sys.executable
GUARD = "tests/test_phase387_perf_budget.py"
BUDGET_SRC = ROOT / "benchmark" / "perf_budget.py"
RUNNER_SRC = ROOT / "benchmark" / "runner.py"
MEASURE_SRC = ROOT / "dev" / "phase387_measure.py"

_B = PB.PERFORMANCE_BUDGETS[("quick", "sync")]
# The four ceilings are rounded to multiples of 5 and can legitimately repeat,
# so "ceiling_s=330," is NOT a unique anchor.  Anchor on the quick/sync
# entry's own evidence file name instead: it is unique by construction.
_E = _B.evidence
_BASE_LINE = (f'baseline_s={_B.baseline_s}, measured="{_B.measured}",'
              f'\n        evidence="{_E}",')
_CEIL_LINE = f'evidence="{_E}",\n        ceiling_s={_B.ceiling_s},'


def _node(name: str) -> str:
    return f"{GUARD}::{name}"


CASES = [
    ("a baseline must come from its artifact, not from a typed number",
     BUDGET_SRC,
     _BASE_LINE,
     _BASE_LINE.replace(f"baseline_s={_B.baseline_s},",
                        f"baseline_s={_B.baseline_s + 10},"),
     _node("test_every_budget_matches_its_own_clean_artifact")),
    ("a ceiling must be derived, not widened by hand",
     BUDGET_SRC,
     _CEIL_LINE,
     _CEIL_LINE.replace(f"ceiling_s={_B.ceiling_s},",
                        f"ceiling_s={_B.ceiling_s + 5},"),
     _node("test_every_budget_ceiling_is_derived_not_handwritten")),
    ("an unmeasured entry must never become a ceiling-0 budget",
     BUDGET_SRC,
     "if entry.baseline_s <= 0 or entry.ceiling_s <= 0:",
     "if False:",
     _node("test_unmeasured_entry_is_never_a_budget")),
    ("unmeasured compositions must stay unbudgeted",
     BUDGET_SRC,
     "if entry.cases != total_cases or entry.quick_offset != quick_offset:",
     "if False:",
     _node("test_budget_for_exact_composition_only")),
    ("the runner must return non-zero when the perf arm is red",
     RUNNER_SRC,
     "        if not perf_ok:\n            return 1",
     "        if False:\n            return 1",
     _node("test_runner_calls_shared_helper_and_enforces_failure")),
    ("the runner must call the shared helper, not hand-roll a verdict",
     RUNNER_SRC,
     "        perf_ok, perf_line = _perf_gate_line(\n"
     "            result, args.quick, args.quick_offset, args.concurrency)",
     '        perf_ok, perf_line = True, "handrolled"',
     _node("test_runner_calls_shared_helper_and_enforces_failure")),
    ("a red artifact must never be promoted into a baseline",
     MEASURE_SRC,
     '    if (data.get("fp") or data.get("fn") or data.get("errors")):',
     "    if False:",
     _node("test_measure_script_only_accepts_clean_artifacts")),
]


def _run(node: str) -> tuple[int, str]:
    env = dict(os.environ,
               PYTHONDONTWRITEBYTECODE="1",
               NO_PROXY="127.0.0.1,localhost",
               no_proxy="127.0.0.1,localhost")
    proc = subprocess.run(
        [PY, "-m", "pytest", "-q", "--no-header", node],
        cwd=str(ROOT), capture_output=True, text=True, timeout=300,
        env=env)
    return proc.returncode, (proc.stdout + proc.stderr)[-400:]


def main() -> int:
    all_ok = True
    for label, src, anchor, mutated, node in CASES:
        original = src.read_bytes()
        text = original.decode("utf-8")
        # runner.py predates this phase and is CRLF; the new files are LF.
        # Bytes-decoding does NOT apply universal-newline translation, so a
        # multi-line anchor must use the file's own separator or it silently
        # matches zero times -- the "anchor found 0 times" ABORT is the guard
        # working, not a missing mutation.
        nl = "\r\n" if "\r\n" in text else "\n"
        anchor_n = anchor.replace("\n", nl)
        mutated_n = mutated.replace("\n", nl)
        count = text.count(anchor_n)
        if count != 1:
            print(f"ABORT [{label}]: anchor found {count} times, expected 1")
            return 2
        base_rc, base_out = _run(node)
        if base_rc != 0:
            print(f"ABORT [{label}]: baseline is not green\n{base_out}")
            return 2
        try:
            src.write_bytes(text.replace(anchor_n, mutated_n, 1)
                            .encode("utf-8"))
            mut_rc, mut_out = _run(node)
        finally:
            src.write_bytes(original)
        rest_rc, rest_out = _run(node)
        restored = src.read_bytes() == original
        ok = mut_rc != 0 and rest_rc == 0 and restored
        all_ok = all_ok and ok
        print(f"[{'PASS' if ok else 'FAIL'}] {label}: "
              f"baseline rc={base_rc}, mutated rc={mut_rc}, "
              f"restored rc={rest_rc}, bytes_restored={restored}")
        if not ok:
            print(f"  mutated tail: {mut_out[-280:]}")
            print(f"  restored tail: {rest_out[-280:]}")
    print(f"\nPhase 387 mutations: {len(CASES)} cases, "
          f"{'ALL PASS' if all_ok else 'FAILURES PRESENT'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
