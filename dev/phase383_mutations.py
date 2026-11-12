#!/usr/bin/env python3
"""Phase 383 mutation checks: green -> RED -> green on the REAL source.

Six anchored mutations on api/mcp_server.py, each verified with three real
pytest subprocess runs (baseline / mutated / restored); source bytes are
restored in a ``finally`` block, and a missing or duplicated anchor ABORTS
rather than "running it to see" (project rule).

The mutations target the ways an authorization boundary can silently
stop being one: the per-call check disabled outright, pins burned by
failed calls, an allowlist that matches nothing (i.e. everything), the
redirect boundary unwired, the open-mode disclosure deleted, and the
TOFU refusal turned off.

Usage: .venv/Scripts/python.exe dev/phase383_mutations.py
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "xssentinel" / "api" / "mcp_server.py"
GUARD = "tests/test_phase383_mcp_scope.py"
PY = sys.executable

CASES = [
    ("the per-call scope check must actually run",
     'if (schema.get("properties") or {}).get("url") and normalized.get("url"):',
     'if False and (schema.get("properties") or {}).get("url") and normalized.get("url"):'),
    ("a failed call must not burn the TOFU pin",
     'if not result.get("isError") and \\\n                (schema.get("properties") or {}).get("url"):',
     'if True or not result.get("isError") and \\\n                (schema.get("properties") or {}).get("url"):'),
    ("an allowlist pattern must actually be matched",
     "if _host_matches_pattern(org[1], _scope_patterns):",
     "if True:"),
    ("the redirect boundary must be wired into MCP requesters",
     'options["stop_at_cross_origin"] = True',
     'options["stop_at_cross_origin"] = False'),
    ("open mode must disclose the missing boundary",
     '" NO authorization boundary is configured (--allow-any-host): "',
     '" "'),
    ("the TOFU refusal must refuse",
     "if not _scope_pins or org in _scope_pins:",
     "if True or not _scope_pins or org in _scope_pins:"),
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
    print(f"Phase 383 mutations: {len(CASES)} cases, "
          f"{'ALL PASS' if all_ok else 'FAILURES PRESENT'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
