#!/usr/bin/env python3
"""Phase 396 mutation check: the stored-auto fresh fetch stays fixed.

One anchored mutation (``cache_get=False`` removed -> the old LRU read
returns, so the cached login page hides the write face again), verified with
three real pytest subprocess runs against ONE behavioural test node. Bytes
restored byte-for-byte.

Usage: .venv/Scripts/python.exe dev/phase396_mutations.py
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable

MIXIN = ROOT / "xssentinel" / "core" / "scanner_stored_auto.py"

ANCHOR = "                resp = self.req.get(page_url, cache_get=False)\n"
REPLACEMENT = "                resp = self.req.get(page_url)\n"


def _run(node: str):
    env = dict(os.environ,
               PYTHONDONTWRITEBYTECODE="1",
               NO_PROXY="127.0.0.1,localhost",
               no_proxy="127.0.0.1,localhost")
    proc = subprocess.run(
        [PY, "-m", "pytest", "-q", "--no-header",
         f"tests/test_phase396_stored_auto_fresh_fetch.py::{node}"],
        cwd=str(ROOT), capture_output=True, text=True, timeout=300, env=env)
    return proc.returncode, (proc.stdout + proc.stderr)[-400:]


def main() -> int:
    original = MIXIN.read_text(encoding="utf-8")
    node = "test_poisoned_cache_does_not_hide_write_face"
    base_rc, base_out = _run(node)
    if base_rc != 0:
        print(f"ABORT: baseline is not green\n{base_out}")
        return 2
    mut_rc = mut_out = None
    try:
        text = original
        if text.count(ANCHOR) != 1:
            raise AssertionError(f"anchor not unique (count={text.count(ANCHOR)})")
        MIXIN.write_text(text.replace(ANCHOR, REPLACEMENT, 1), encoding="utf-8")
        mut_rc, mut_out = _run(node)
    except AssertionError as exc:
        print(f"ABORT: {exc}")
        return 2
    finally:
        MIXIN.write_text(original, encoding="utf-8")
    rest_rc, rest_out = _run(node)
    ok = mut_rc != 0 and rest_rc == 0
    print(f"[{'PASS' if ok else 'FAIL'}] auto fetch falls back to LRU -> red: "
          f"baseline rc={base_rc}, mutated rc={mut_rc}, restored rc={rest_rc}")
    if not ok:
        print(f"  mutated tail: {(mut_out or '')[-300:]}")
        print(f"  restored tail: {rest_out[-300:]}")
    if MIXIN.read_text(encoding="utf-8") != original:
        print("ABORT: scanner_stored_auto.py was not restored byte-for-byte")
        return 2
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
