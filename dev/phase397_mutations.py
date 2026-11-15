#!/usr/bin/env python3
"""Phase 397 mutation check: the `off` branch stays on BOTH resolvers.

Two anchored mutations (remove the off branch from sync / from async), each
verified with baseline / mutated / restored pytest runs against its own
behavioural test node. Bytes restored byte-for-byte.

Usage: .venv/Scripts/python.exe dev/phase397_mutations.py
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
CORE = ROOT / "xssentinel" / "core"

ANCHOR = '        if de == "off":\n            return None\n'
MUTATIONS = (
    ("sync", CORE / "scanner.py",
     "tests/test_phase397_dom_engine_off.py::test_sync_off_disables_browser_engine"),
    ("async", CORE / "async_scanner_layers.py",
     "tests/test_phase397_dom_engine_off.py::test_async_off_disables_browser_engine"),
)
GUARD = "tests/test_phase397_dom_engine_off.py"


def _run(node: str):
    env = dict(os.environ,
               PYTHONDONTWRITEBYTECODE="1",
               NO_PROXY="127.0.0.1,localhost",
               no_proxy="127.0.0.1,localhost")
    p = subprocess.run([PY, "-m", "pytest", "-q", "--no-header", node],
                       cwd=str(ROOT), capture_output=True, text=True,
                       timeout=300, env=env)
    return p.returncode, (p.stdout + p.stderr)[-400:]


def main() -> int:
    ok_all = True
    for label, path, node in MUTATIONS:
        original = path.read_text(encoding="utf-8")
        if original.count(ANCHOR) != 1:
            print(f"ABORT: {label} anchor count="
                  f"{original.count(ANCHOR)} (expected 1)")
            return 2
        base_rc, base_out = _run(node)
        if base_rc != 0:
            print(f"ABORT: {label} baseline is not green\n{base_out}")
            return 2
        mut_rc = None
        try:
            path.write_text(original.replace(ANCHOR, "", 1), encoding="utf-8")
            mut_rc, mut_out = _run(node)
        finally:
            path.write_text(original, encoding="utf-8")
        rest_rc, rest_out = _run(GUARD)
        ok = mut_rc != 0 and rest_rc == 0
        ok_all = ok_all and ok
        print(f"[{'PASS' if ok else 'FAIL'}] {label} off branch removed -> red: "
              f"baseline rc={base_rc}, mutated rc={mut_rc}, "
              f"restored (whole guard) rc={rest_rc}")
        if not ok:
            print(f"  mutated tail: {(mut_out or '')[-300:]}")
            print(f"  restored tail: {rest_out[-300:]}")
        if path.read_text(encoding="utf-8") != original:
            print(f"ABORT: {path.name} not restored byte-for-byte")
            return 2
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
