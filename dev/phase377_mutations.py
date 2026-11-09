#!/usr/bin/env python3
"""Phase 377 mutation checks: green -> RED -> green on the FINAL tree.

Six anchored mutations on the REAL source, each verified with three real
pytest subprocess runs (baseline / mutated / restored).  Source bytes are
restored in a ``finally`` block.  A missing or duplicated anchor ABORTS
rather than "running it to see" (project rule).

Two failure shapes are covered: a helper that stops honouring a contract
(no settle, no args, no truncation truth, no pending-cancel check), and a
CALLER that stops wiring the helper (modern catalogue, modern dispatch gate).
The latter matters most here: the helpers cannot rot, the two modern-only
call sites can.

Usage: .venv/Scripts/python.exe dev/phase377_mutations.py
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "xssentinel" / "api" / "mcp_server.py"
GUARD = "tests/test_phase377_mcp_async_tools.py"
PY = sys.executable

CASES = [
    ("modern tools/list must append the two async tools",
     "for tool in list(tools) + _ASYNC_TOOL_DEFINITIONS]",
     "for tool in tools]"),
    ("legacy frames must not reach the async dispatch",
     "if entry is None and modern:",
     "if entry is None:"),
    ("a job cancelled while PENDING must never scan",
     "if mgr.is_cancel_requested(job.scan_id):",
     "if False:"),
    ("an aborted worker must still settle the job",
     '        mgr.mark_failed(\n'
     '            job.scan_id,\n'
     '            "scan aborted before completion (cancelled or client "\n'
     '            "disconnected); no verdict was produced")',
     "        pass"),
    ("the full normalized args must reach the worker",
     'options={"async_args": dict(args)})',
     "options={})"),
    ("status must carry the truncation truth",
     '    "target", "total_findings", "truncated", "truncation_hint",',
     '    "target", "truncated", "truncation_hint",'),
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
    print(f"\nPhase 377 mutations: {len(CASES)} cases, "
          f"{'ALL PASS' if all_ok else 'FAILURES PRESENT'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
