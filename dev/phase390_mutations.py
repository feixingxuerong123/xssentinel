#!/usr/bin/env python3
"""Phase 390 mutation checks: baseline GREEN -> mutated RED -> restored GREEN.

One named test node per mutation.  Anchors use each file's own newline
convention (this repo mixes CRLF sources with LF artifacts), same as
dev/phase389_mutations.py.

Usage: python dev/phase390_mutations.py
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
GUARD = "tests/test_phase390_parity_harness_shape.py"

GATE = ROOT / "tests" / "test_parity_full_matrix.py"
ART = ROOT / "benchmark" / "results" / "phase390_parity_probe_20261114.json"
OPT = ROOT / "docs" / "OPTIMIZATION.md"
CHANGELOG = ROOT / "CHANGELOG.md"


def _node(name: str) -> str:
    return f"{GUARD}::{name}"


CASES = [
    ("param-less cases must not get a synthetic param",
     GATE,
     '    if not param:\n        return {}\n    return {param: "probe"}',
     '    if not param:\n        return {"q": "probe"}\n'
     '    return {param: "probe"}',
     _node("test_param_less_cases_get_no_synthetic_param")),
    ("the sync runner must not inline a probe dict again",
     GATE,
     "sc.scan_target(url, method, _gate_params(c), data,",
     'sc.scan_target(url, method, {"q": "probe"}, data,',
     _node("test_both_runners_use_the_same_params_source")),
    ("the BEFORE arm must still show the fake divergence",
     ART,
     '        "sync": [],',
     '        "sync": [\n'
     '          [\n'
     '            "reflected",\n'
     '            "high",\n'
     '            "high"\n'
     '          ]\n'
     '        ],',
     _node("test_fact_table_pins_the_harness_verdict")),
    ("the BEFORE arm's disagreement bit must stay false",
     ART,
     '        "agree": false,',
     '        "agree": true,',
     _node("test_fact_table_pins_the_harness_verdict")),
    ("the artifact's measured budgets must not drift",
     ART,
     '    "max_payloads": 14,',
     '    "max_payloads": 12,',
     _node("test_fact_table_pins_the_harness_verdict")),
    ("the changelog must record the correction",
     CHANGELOG,
     "### \u52d8\u8bef\u4e0e\u5904\u7f6e(2026-11-14,Phase 390)",
     "### \u52d8\u8bef\u4e0e\u5904\u7f6e(2026-11-14,Phase 39X)",
     _node("test_documents_record_the_correction")),
    ("the optimization log must name 8.21",
     OPT,
     "### 8.21 \u5904\u7f6e\u8bb0\u5f55",
     "### 8.2X \u5904\u7f6e\u8bb0\u5f55",
     _node("test_documents_record_the_correction")),
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
    print(f"\nPhase 390 mutations: {len(CASES)} cases, "
          f"{'ALL PASS' if all_ok else 'FAILURES PRESENT'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
