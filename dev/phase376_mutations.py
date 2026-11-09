#!/usr/bin/env python3
"""Phase 376 mutation checks: green -> RED -> green on the FINAL tree.

Four anchored mutations, each on the REAL source file, each verified with
three real pytest subprocess runs (baseline / mutated / restored).  Source
bytes are restored in a ``finally`` block.  An anchor that is missing or
duplicated ABORTS -- never "run it and see" (project rule).

Covers both failure shapes Phase 376 protects against:
  * a helper that silently stops negotiating (min -> max, modern -> False);
  * a caller that stops wiring the helper (no cancel_event, no discover key).

Usage: .venv/Scripts/python.exe dev/phase376_mutations.py
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MCP = ROOT / "xssentinel" / "api" / "mcp_server.py"
HTTP = ROOT / "xssentinel" / "api" / "server.py"
GUARD = "tests/test_phase376_mcp_timeout_contract.py"
PY = sys.executable

CASES = [
    ("client budget can shorten but never lengthen a scan", MCP,
     'out["max_seconds"] = min(server_s, int(budget_s))',
     'out["max_seconds"] = max(server_s, int(budget_s))'),
    ("modern era must reach the one negotiation point", MCP,
     "modern=modern)", "modern=False)"),
    ("discover must advertise the platform timeout", MCP,
     '"recommendedTimeoutMs": _RECOMMENDED_TIMEOUT_MS,',
     '"recommendedTimeoutMsDISABLED": _RECOMMENDED_TIMEOUT_MS,'),
    ("HTTP watcher must be wired into dispatch", HTTP,
     "resp = dispatch_message(msg, cancel_event=cancel)",
     "resp = dispatch_message(msg)"),
]


def _run():
    env = dict(os.environ,
               PYTHONDONTWRITEBYTECODE="1",
               NO_PROXY="127.0.0.1,localhost",
               no_proxy="127.0.0.1,localhost")
    proc = subprocess.run(
        [PY, "-m", "pytest", "-q", "--no-header", GUARD],
        cwd=str(ROOT), capture_output=True, text=True, timeout=300,
        env=env)
    return proc.returncode, (proc.stdout + proc.stderr)[-400:]


def main() -> int:
    all_ok = True
    for label, path, anchor, mutated in CASES:
        original = path.read_bytes()
        text = original.decode("utf-8")
        count = text.count(anchor)
        if count != 1:
            print(f"ABORT [{label}]: anchor found {count} times, expected 1")
            return 2
        base_rc, base_out = _run()
        if base_rc != 0:
            print(f"ABORT [{label}]: baseline is not green\n{base_out}")
            return 2
        try:
            path.write_bytes(text.replace(anchor, mutated, 1).encode("utf-8"))
            mut_rc, mut_out = _run()
        finally:
            path.write_bytes(original)
        rest_rc, rest_out = _run()
        ok = mut_rc != 0 and rest_rc == 0
        all_ok = all_ok and ok
        print(f"[{'PASS' if ok else 'FAIL'}] {label}: "
              f"baseline rc={base_rc}, mutated rc={mut_rc}, "
              f"restored rc={rest_rc}")
        if not ok:
            print(f"  mutated tail: {mut_out[-300:]}")
            print(f"  restored tail: {rest_out[-300:]}")
    print(f"\nPhase 376 mutations: {len(CASES)} cases, "
          f"{'ALL PASS' if all_ok else 'FAILURES PRESENT'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
