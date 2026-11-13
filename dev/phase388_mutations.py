#!/usr/bin/env python3
"""Phase 388 mutation checks: baseline GREEN -> mutated RED -> restored GREEN.

One named test node per mutation, so a different assertion turning red cannot
impersonate a load-bearing guard.  Anchors are normalized to each file's own
newline convention (runner-style CRLF files coexist with LF artifacts here).

Usage: .venv/Scripts/python.exe dev/phase388_mutations.py
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
GUARD = "tests/test_phase388_primitive_matrix.py"

ART = ROOT / "benchmark" / "results" / "phase388_primitive_matrix_20261113.json"
MATRIX = ROOT / "dev" / "phase388_primitive_matrix.py"
ADJUDICATOR = ROOT / "dev" / "fn_net_adjudicate.py"
CHANGELOG = ROOT / "CHANGELOG.md"


def _node(name: str) -> str:
    return f"{GUARD}::{name}"


CASES = [
    ("summary verdicts must be recomputed from rows, not typed",
     ART,
     '"verifier_only": [\n      "<marquee onstart=alert(\'{msg}\')>"\n    ]',
     '"verifier_only": []',
     _node("test_summary_is_recomputed_from_rows")),
    ("controls_valid must come from the measured control arms",
     ART,
     '"shapes": 9,\n    "arms": 72,\n    "controls_valid": true,',
     '"shapes": 9,\n    "arms": 72,\n    "controls_valid": false,',
     _node("test_controls_are_load_bearing")),
    ("the browser oracle must actually listen for dialogs",
     MATRIX,
     'page.on("dialog"',
     'page.on("console"',
     _node("test_matrix_script_uses_product_corpus_and_real_fixture")),
    ("the matrix must render each escaping, not a hardcoded one",
     MATRIX,
     "esc={esc}",
     "esc=raw",
     _node("test_matrix_script_uses_product_corpus_and_real_fixture")),
    ("the engine verifier must be consulted, not assumed",
     MATRIX,
     "V.verify_semantic(html, MSG, headers)",
     "{'confirmed': True}",
     _node("test_matrix_script_uses_product_corpus_and_real_fixture")),
    ("the adjudicator must mark the finding's own payload",
     ADJUDICATOR,
     "marked = V.mark(payload, TOKEN)",
     "marked = payload",
     _node("test_adjudicator_uses_the_findings_own_payload")),
    ("the erratum must state the corrected verdict",
     CHANGELOG,
     "**8/9 形状 verifier 与浏览器一致确认(真阳性)**",
     "**8/9 形状 verifier 与浏览器一致确认**",
     _node("test_documents_carry_the_correction_and_keep_history")),
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
    print(f"\nPhase 388 mutations: {len(CASES)} cases, "
          f"{'ALL PASS' if all_ok else 'FAILURES PRESENT'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
