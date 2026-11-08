#!/usr/bin/env python3
"""Phase 372-374 mutation check: green -> RED -> green on the FINAL tree.

Project rule (AGENTS.md): assert the anchor exists first (ABORT if not),
then run baseline / mutated / restored.  Only "mutated RED and restored
green" counts.  Each run is a real pytest subprocess; source bytes are
restored in a finally block, and no pytest temp dirs are created inside
this process (the safe-delete quota lesson from Phase 358/360).

Usage: .venv/Scripts/python.exe dev/phase372_374_mutations.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "xssentinel" / "api" / "mcp_server.py"
PY = sys.executable

MUTATIONS = (
    ("372 modern structured errors",
     'if modern and result.get("isError"):\n'
     '                result = _attach_structured_error(result)',
     'if False and result.get("isError"):\n'
     '                result = _attach_structured_error(result)',
     "tests/test_phase372_mcp_structured_errors.py"),
    ("373 truncation flag",
     "truncated = total_findings > len(findings)",
     "truncated = False",
     "tests/test_phase373_mcp_truncation.py"),
    ("374 modern-only annotations",
     "if modern:\n"
     "                catalogue = _modernize_tools(TOOL_DEFINITIONS)",
     "if False:\n"
     "                catalogue = _modernize_tools(TOOL_DEFINITIONS)",
     "tests/test_phase374_mcp_annotations.py"),
)


def _guard(path: str):
    proc = subprocess.run(
        [PY, "-m", "pytest", "-q", "--no-header", path],
        cwd=str(ROOT), capture_output=True, text=True, timeout=300)
    return proc.returncode, (proc.stdout + proc.stderr)[-500:]


def main() -> int:
    results = []
    original = SRC.read_bytes()
    text = original.decode("utf-8")
    for label, anchor, mutated_anchor, guard in MUTATIONS:
        count = text.count(anchor)
        if count != 1:
            print(f"ABORT [{label}]: anchor found {count} times, expected 1")
            return 2
        base_rc, base_out = _guard(guard)
        if base_rc != 0:
            print(f"ABORT [{label}]: baseline is not green\n{base_out}")
            return 2
        try:
            SRC.write_bytes(text.replace(anchor, mutated_anchor, 1)
                            .encode("utf-8"))
            mut_rc, mut_out = _guard(guard)
        finally:
            SRC.write_bytes(original)
        rest_rc, rest_out = _guard(guard)
        ok = base_rc == 0 and mut_rc != 0 and rest_rc == 0
        results.append(ok)
        print(f"[{'PASS' if ok else 'FAIL'}] {label}: "
              f"baseline rc={base_rc}, mutated rc={mut_rc}, "
              f"restored rc={rest_rc}")
        if not ok:
            print(f"  mutated tail: {mut_out[-300:]}")
            print(f"  restored tail: {rest_out[-300:]}")
    print(f"\nVERDICT: {sum(results)}/{len(results)} mutations proved "
          f"the guards have teeth")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
