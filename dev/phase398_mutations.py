#!/usr/bin/env python3
"""Phase 398 mutation check: the four-value contract is really pinned.

Three anchored mutations (drop 'off' from CLI choices / MCP enum / README
brace list).  Each is verified baseline-green -> mutated-red ->
restored-whole-guard-green, with byte-for-byte restoration.  Anchors are
asserted unique BEFORE any byte is changed (Phase 201 rule).

Usage: .venv/Scripts/python.exe dev/phase398_mutations.py
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
GUARD = "tests/test_phase398_dom_engine_contract.py"

MUTATIONS = (
    ("cli_choices", ROOT / "xssentinel" / "__main__.py",
     'choices=["auto", "playwright", "static", "off"],',
     'choices=["auto", "playwright", "static"],'),
    ("mcp_enum", ROOT / "xssentinel" / "api" / "mcp_server.py",
     '"enum": ["auto", "playwright", "static", "off"],',
     '"enum": ["auto", "playwright", "static"],'),
    ("zh_readme", ROOT / "README.md",
     "{auto,playwright,static,off}",
     "{auto,playwright,static}"),
    ("en_readme", ROOT / "README.en.md",
     "--dom-engine off",
     ""),
)


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
    for label, path, anchor, replacement in MUTATIONS:
        original = path.read_text(encoding="utf-8")
        if original.count(anchor) != 1:
            print(f"ABORT: {label} anchor count="
                  f"{original.count(anchor)} (expected 1)")
            return 2
        base_rc, base_out = _run(GUARD)
        if base_rc != 0:
            print(f"ABORT: {label} baseline is not green\n{base_out}")
            return 2
        mut_rc = None
        try:
            path.write_text(original.replace(anchor, replacement, 1),
                            encoding="utf-8")
            mut_rc, mut_out = _run(GUARD)
        finally:
            path.write_text(original, encoding="utf-8")
        rest_rc, rest_out = _run(GUARD)
        ok = mut_rc != 0 and rest_rc == 0
        ok_all = ok_all and ok
        print(f"[{'PASS' if ok else 'FAIL'}] {label} 'off' removed -> red: "
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
