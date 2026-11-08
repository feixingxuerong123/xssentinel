#!/usr/bin/env python3
"""Phase 375 mutation check: green -> RED -> green on the FINAL tree.

Anchored mutation (project rule): remove the ``total`` supplied by the
scoped emitter; test_phase375_mcp_progress_total.py must go RED, and the
restored source must be green again.  Source bytes are restored in a finally
block and each run is a real pytest subprocess.

Usage: .venv/Scripts/python.exe dev/phase375_mutation.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "xssentinel" / "api" / "mcp_server.py"
GUARD = "tests/test_phase375_mcp_progress_total.py"
ANCHOR = "total if total is not None else estimated_total"
MUTATED = "None"
PY = sys.executable


def _run():
    proc = subprocess.run(
        [PY, "-m", "pytest", "-q", "--no-header", GUARD],
        cwd=str(ROOT), capture_output=True, text=True, timeout=300)
    return proc.returncode, (proc.stdout + proc.stderr)[-400:]


def main() -> int:
    original = SRC.read_bytes()
    text = original.decode("utf-8")
    if text.count(ANCHOR) != 1:
        print(f"ABORT: anchor found {text.count(ANCHOR)} times, expected 1")
        return 2
    base_rc, base_out = _run()
    if base_rc != 0:
        print(f"ABORT: baseline is not green\n{base_out}")
        return 2
    try:
        SRC.write_bytes(text.replace(ANCHOR, MUTATED, 1).encode("utf-8"))
        mut_rc, mut_out = _run()
    finally:
        SRC.write_bytes(original)
    rest_rc, rest_out = _run()
    ok = base_rc == 0 and mut_rc != 0 and rest_rc == 0
    print(f"[{'PASS' if ok else 'FAIL'}] Phase 375 progress total: "
          f"baseline rc={base_rc}, mutated rc={mut_rc}, "
          f"restored rc={rest_rc}")
    if not ok:
        print(f"  mutated tail: {mut_out[-300:]}")
        print(f"  restored tail: {rest_out[-300:]}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
