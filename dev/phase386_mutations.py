#!/usr/bin/env python3
"""Phase 386 mutation check: the xlink:href classifier arm is load-bearing.

One anchored mutation (revert the classifier to the pre-386 URL set) run
as baseline / mutated / restored with real pytest subprocesses; source
bytes restored in a finally block; a missing or duplicated anchor ABORTS.

Usage: .venv/Scripts/python.exe dev/phase386_mutations.py
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "xssentinel" / "core" / "context.py"
GUARD = "tests/test_phase386_svg_link_context.py"
PY = sys.executable

ANCHOR = 'if name in ("href", "src") or name == "xlink:href":'
MUTATED = 'if name in ("href", "src"):'


def _run() -> tuple[int, str]:
    env = dict(os.environ,
               PYTHONDONTWRITEBYTECODE="1",
               NO_PROXY="127.0.0.1,localhost",
               no_proxy="127.0.0.1,localhost")
    proc = subprocess.run(
        [PY, "-m", "pytest", "-q", "--no-header", GUARD],
        cwd=str(ROOT), capture_output=True, text=True, timeout=300,
        env=env)
    return proc.returncode, (proc.stdout + proc.stderr)[-300:]


def main() -> int:
    original = SRC.read_bytes()
    text = original.decode("utf-8")
    count = text.count(ANCHOR)
    if count != 1:
        print(f"ABORT: anchor found {count} times, expected 1")
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
    rest_rc, _ = _run()
    ok = mut_rc != 0 and rest_rc == 0 and SRC.read_bytes() == original
    print(f"[{'PASS' if ok else 'FAIL'}] xlink arm is load-bearing: "
          f"baseline rc={base_rc}, mutated rc={mut_rc}, restored rc={rest_rc}, "
          f"bytes_restored={SRC.read_bytes() == original}")
    if not ok:
        print(f"  mutated tail: {mut_out[-250:]}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
