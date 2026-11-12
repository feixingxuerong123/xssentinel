#!/usr/bin/env python3
"""Phase 384 mutation checks: green -> RED -> green on the REAL source.

Two anchored mutations, each proving the credential-echo guard is not
vacuously green: the audit's negative assertions must turn red the moment
a tool channel actually starts carrying caller credentials.

Usage: .venv/Scripts/python.exe dev/phase384_mutations.py
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "xssentinel" / "api" / "mcp_server.py"
GUARD = "tests/test_phase384_credential_echo.py"
PY = sys.executable

CASES = [
    ("the pre-flight error sentence must not echo caller credentials",
     'f"{budget_s:.0f}s, so no probe storm was sent)")',
     'f"{budget_s:.0f}s, so no probe storm was sent) {args.get(\'cookies\')}")'),
    ("result metadata must not echo caller credentials",
     '"waf": getattr(scanner, "waf_name", None),',
     '"waf": str(args.get("cookies")),'),
]


def _run() -> tuple[int, str]:
    env = dict(os.environ,
               PYTHONDONTWRITEBYTECODE="1",
               NO_PROXY="127.0.0.1,localhost",
               no_proxy="127.0.0.1,localhost")
    proc = subprocess.run(
        [PY, "-m", "pytest", "-q", "--no-header", GUARD],
        cwd=str(ROOT), capture_output=True, text=True, timeout=600,
        env=env)
    return proc.returncode, (proc.stdout + proc.stderr)[-400:]


def main() -> int:
    all_ok = True
    original = SRC.read_bytes()
    text = original.decode("utf-8")
    for label, anchor, mutated in CASES:
        count = text.count(anchor)
        if count != 1:
            print(f"ABORT [{label}]: anchor found {count} times, expected 1")
            return 2
        base_rc, base_out = _run()
        if base_rc != 0:
            print(f"ABORT [{label}]: baseline is not green\n{base_out}")
            return 2
        try:
            SRC.write_bytes(text.replace(anchor, mutated, 1).encode("utf-8"))
            mut_rc, mut_out = _run()
        finally:
            SRC.write_bytes(original)
        rest_rc, rest_out = _run()
        ok = mut_rc != 0 and rest_rc == 0
        all_ok = all_ok and ok
        print(f"[{'PASS' if ok else 'FAIL'}] {label}: "
              f"baseline rc={base_rc}, mutated rc={mut_rc}, "
              f"restored rc={rest_rc}")
        if not ok:
            print(f"  mutated tail: {mut_out[-300:]}")
            print(f"  restored tail: {rest_out[-300:]}")
    restored_now = SRC.read_bytes() == original
    print(f"\nsource bytes restored: {restored_now}")
    print(f"Phase 384 mutations: {len(CASES)} cases, "
          f"{'ALL PASS' if all_ok else 'FAILURES PRESENT'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
