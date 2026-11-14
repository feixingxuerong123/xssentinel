#!/usr/bin/env python3
"""Phase 395 mutation check: the empty-comment fix stays fixed.

One anchored mutation (`<!-->` / `<!--->` branches removed -> the old
unterminated-comment swallow returns), verified with three real pytest
subprocess runs against ONE named test node.  Bytes restored byte-for-byte.

Usage: .venv/Scripts/python.exe dev/phase395_mutations.py
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable

PARSER = ROOT / "xssentinel" / "core" / "sandbox_parser.py"

ANCHOR = """                    if s[self.i + 4:self.i + 5] == ">":
                        self.current().append(_comment(""))
                        self.i += 5
                        continue
                    if s[self.i + 4:self.i + 6] == "->":
                        self.current().append(_comment(""))
                        self.i += 6
                        continue
"""
REPLACEMENT = ""


def _run(node: str):
    env = dict(os.environ,
               PYTHONDONTWRITEBYTECODE="1",
               NO_PROXY="127.0.0.1,localhost",
               no_proxy="127.0.0.1,localhost")
    proc = subprocess.run(
        [PY, "-m", "pytest", "-q", "--no-header",
         f"tests/test_phase395_empty_comment.py::{node}"],
        cwd=str(ROOT), capture_output=True, text=True, timeout=300, env=env)
    return proc.returncode, (proc.stdout + proc.stderr)[-400:]


def main() -> int:
    original = PARSER.read_text(encoding="utf-8")
    node = "test_empty_comment_closes_and_releases_following_markup"
    base_rc, base_out = _run(node)
    if base_rc != 0:
        print(f"ABORT: baseline is not green\n{base_out}")
        return 2
    try:
        text = original
        if text.count(ANCHOR) != 1:
            raise AssertionError(f"anchor not unique (count={text.count(ANCHOR)})")
        PARSER.write_text(text.replace(ANCHOR, REPLACEMENT, 1), encoding="utf-8")
        mut_rc, mut_out = _run(node)
    except AssertionError as exc:
        print(f"ABORT: {exc}")
        return 2
    finally:
        PARSER.write_text(original, encoding="utf-8")
    rest_rc, rest_out = _run(node)
    ok = mut_rc != 0 and rest_rc == 0
    print(f"[{'PASS' if ok else 'FAIL'}] empty-comment branches removed -> red: "
          f"baseline rc={base_rc}, mutated rc={mut_rc}, restored rc={rest_rc}")
    if not ok:
        print(f"  mutated tail: {mut_out[-300:]}")
    if PARSER.read_text(encoding="utf-8") != original:
        print("ABORT: sandbox_parser.py was not restored byte-for-byte")
        return 2
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
