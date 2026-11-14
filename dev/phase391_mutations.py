#!/usr/bin/env python3
"""Phase 391 mutation checks: baseline GREEN -> mutated RED -> restored GREEN.

Covers the fact table, its summary sets, the probe's own shape corpus, the
product-boundary decision, and the documents' OPEN-conflict wording.

Usage: python dev/phase391_mutations.py
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
GUARD = "tests/test_phase391_onstart_fact_table.py"

ART = ROOT / "benchmark" / "results" / "phase391_onstart_shapes_20261114.json"
PROBE = ROOT / "dev" / "phase391_onstart_shapes.py"
SANDBOX = ROOT / "xssentinel" / "core" / "sandbox.py"
OPT = ROOT / "docs" / "OPTIMIZATION.md"
CHANGELOG = ROOT / "CHANGELOG.md"


def _node(name: str) -> str:
    return f"{GUARD}::{name}"


CASES = [
    ("the positive control must have fired in the browser",
     ART,
     '      "browser_dialog": true,',
     '      "browser_dialog": false,',
     _node("test_controls_and_baseline_are_measured")),
    ("no measured onstart shape may be called live",
     ART,
     '    "live": []',
     '    "live": ["<div onstart>"]',
     _node("test_controls_and_baseline_are_measured")),
    ("the arm count must describe the rows",
     ART,
     '    "arms": 15,',
     '    "arms": 14,',
     _node("test_controls_and_baseline_are_measured")),
    ("the verifier_only set must match the rows",
     ART,
     '      "<a onstart>",',
     '      "<a onstart> (edited)",',
     _node("test_every_measured_onstart_shape_is_verifier_only")),
    ("shapes must come from the probe's own ELEMENTS corpus",
     PROBE,
     'ELEMENTS = ("marquee", "div", "span",',
     'ELEMENTS = ("marquee", "div", "EM",',
     _node("test_shapes_come_from_the_probe_scripts_own_corpus")),
    ("the inert pair must not expand from this fact table alone",
     SANDBOX,
     'INERT_HANDLER_PAIRS = frozenset({("marquee", "onstart")})',
     'INERT_HANDLER_PAIRS = frozenset({("marquee", "onstart"), '
     '("div", "onstart")})',
     _node("test_this_round_did_not_change_the_product_verdict")),
    ("the documents must leave the conflict OPEN",
     OPT,
     "证据冲突未定谳",
     "证据冲突已定谳",
     _node("test_documents_record_the_open_conflict")),
    ("the changelog must name Phase 391",
     CHANGELOG,
     "**Phase 391 /",
     "**Phase 39X /",
     _node("test_documents_record_the_open_conflict")),
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
    print(f"\nPhase 391 mutations: {len(CASES)} cases, "
          f"{'ALL PASS' if all_ok else 'FAILURES PRESENT'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
