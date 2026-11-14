#!/usr/bin/env python3
"""Phase 393 mutation checks: green -> RED -> green on the sandbox fixes.

Four anchored mutations, one per judgment change this round, each verified
with three real pytest subprocess runs (baseline / mutated / restored) against
ONE named test node.  All touched bytes are restored in a ``finally`` block
and compared afterwards.

Usage: .venv/Scripts/python.exe dev/phase393_mutations.py
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable

GUARD = "tests/test_phase393_sandbox_attribution.py"
RUNNER = ROOT / "xssentinel" / "core" / "sandbox.py"

CASES = [
    ("token-less script may not over-claim again",
     "test_tokenless_script_defers_instead_of_overclaiming",
     '        return {"node": "script[no-token]", "state": "unknown",',
     '        return {"node": "script[no-token]", "state": "live",'),
    ("empty-src onerror may not be vetoed again",
     "test_empty_src_onerror_is_live",
     '            return "live", (f"{name}.{ev} fires: an empty {src_attr} still "',
     '            return "inert", (f"{name}.{ev} fires: an empty {src_attr} still "'),
    ("a <source> child may not be ignored again",
     "test_media_loadstart_with_source_child_is_live",
     '                                   and c.name.lower() == "source"',
     '                                   and False'),
    ("declarative shadow roots may not be inert again",
     "test_declarative_shadow_root_is_not_an_inert_host",
     '            if p.has_attr("shadowrootmode"):',
     '            if False:'),
    ("contenteditable focusability may not be dropped again",
     "test_contenteditable_is_focusable_and_attr_names_fold_case",
     '        focusable = (name in FOCUSABLE_CONTROLS or "tabindex" in attrs\n'
     '                     or "contenteditable" in attrs)',
     '        focusable = (name in FOCUSABLE_CONTROLS or "tabindex" in attrs)'),
]


def _run(node: str):
    env = dict(os.environ,
               PYTHONDONTWRITEBYTECODE="1",
               NO_PROXY="127.0.0.1,localhost",
               no_proxy="127.0.0.1,localhost")
    proc = subprocess.run(
        [PY, "-m", "pytest", "-q", "--no-header", f"{GUARD}::{node}"],
        cwd=str(ROOT), capture_output=True, text=True, timeout=300, env=env)
    return proc.returncode, (proc.stdout + proc.stderr)[-400:]


def _apply(anchor: str, replacement: str):
    text = RUNNER.read_text(encoding="utf-8")
    if text.count(anchor) != 1:
        raise AssertionError(f"ABORT: anchor not unique (count="
                             f"{text.count(anchor)}): {anchor[:60]!r}")
    RUNNER.write_text(text.replace(anchor, replacement, 1), encoding="utf-8")


def main() -> int:
    original = RUNNER.read_text(encoding="utf-8")
    all_ok = True
    for label, node, anchor, replacement in CASES:
        base_rc, base_out = _run(node)
        if base_rc != 0:
            print(f"ABORT [{label}]: baseline is not green\n{base_out}")
            return 2
        try:
            _apply(anchor, replacement)
            mut_rc, mut_out = _run(node)
        except AssertionError as exc:
            print(f"ABORT [{label}]: {exc}")
            return 2
        finally:
            RUNNER.write_text(original, encoding="utf-8")
        rest_rc, rest_out = _run(node)
        ok = mut_rc != 0 and rest_rc == 0
        all_ok = all_ok and ok
        print(f"[{'PASS' if ok else 'FAIL'}] {label}: "
              f"baseline rc={base_rc}, mutated rc={mut_rc}, "
              f"restored rc={rest_rc}")
        if not ok:
            print(f"  mutated tail: {mut_out[-300:]}")
            print(f"  restored tail: {rest_out[-300:]}")

    if RUNNER.read_text(encoding="utf-8") != original:
        print("ABORT: sandbox.py was not restored byte-for-byte")
        return 2
    print(f"\nPhase 393 mutations: {len(CASES)} cases, "
          f"{'ALL PASS' if all_ok else 'FAILURES PRESENT'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
