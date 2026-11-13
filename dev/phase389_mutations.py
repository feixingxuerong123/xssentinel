#!/usr/bin/env python3
"""Phase 389 mutation checks: baseline GREEN -> mutated RED -> restored GREEN.

One named test node per mutation.  Anchors use each file's own newline
convention (this repo mixes CRLF sources with LF artifacts).

Usage: .venv/Scripts/python.exe dev/phase389_mutations.py
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
GUARD = "tests/test_phase389_marquee_inert.py"

SANDBOX = ROOT / "xssentinel" / "core" / "sandbox.py"
ART389 = (ROOT / "benchmark" / "results" /
          "phase389_primitive_matrix_20261113.json")
CHANGELOG = ROOT / "CHANGELOG.md"


def _node(name: str) -> str:
    return f"{GUARD}::{name}"


CASES = [
    ("the inert set must name the measured pair",
     SANDBOX,
     'INERT_HANDLER_PAIRS = frozenset({("marquee", "onstart")})',
     "INERT_HANDLER_PAIRS = frozenset()",
     _node("test_rule_is_a_pair_and_lives_in_handler_state")),
    ("the pair check must really be in _handler_state",
     SANDBOX,
     "if (name, ev) in INERT_HANDLER_PAIRS:",
     "if False:",
     _node("test_rule_is_a_pair_and_lives_in_handler_state")),
    ("returning inert is what lets the veto fire",
     SANDBOX,
     'return "inert", (f"{name}.{ev} is measured no-exec in Chromium: "',
     'return "activation", (f"{name}.{ev} is measured no-exec in Chromium: "',
     _node("test_marquee_onstart_is_refused_with_sandbox_attribution")),
    ("after-fix matrix must have zero verifier-only shapes",
     ART389,
     '"verifier_only": []',
     '"verifier_only": ["<svg/onload=alert(\'{msg}\')>"]',
     _node("test_before_after_fact_tables_differ_only_in_the_verifier_bit")),
    ("after-fix matrix controls must still be valid",
     ART389,
     '"shapes": 9,\n    "arms": 72,\n    "controls_valid": true,',
     '"shapes": 9,\n    "arms": 72,\n    "controls_valid": false,',
     _node("test_before_after_fact_tables_differ_only_in_the_verifier_bit")),
    ("the changelog must record the narrow fix",
     CHANGELOG,
     "**Phase 389 /",
     "**Phase 38X /",
     _node("test_documents_record_the_narrow_fix")),
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
    print(f"\nPhase 389 mutations: {len(CASES)} cases, "
          f"{'ALL PASS' if all_ok else 'FAILURES PRESENT'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
