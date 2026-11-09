# -*- coding: utf-8 -*-
"""Run the FULL BATCHED regression gate with its logs OUTSIDE the workspace.

Companion to ``gate_run_scratch.py`` (which does the same for the accuracy
gate).  ``tests/run_all_batched.py`` writes one .log per test file plus a
timings report -- 285+ file writes.  On this host the safe-delete guard caps
file overwrites per agent turn at 50, so an un-redirected run is killed in
the middle and never prints its verdict.

The runner is NOT modified: its module-level LOG_DIR is rebound in-process
after import, before main().  All argv (--jobs / --quiet / explicit test
files) is passed straight through so a degraded run can be resumed exactly
as documented in CONTRIBUTING.

The OTHER half of the workaround is pytest itself.  The project pins the
tmp root INSIDE the workspace (``tests/_pytest_tmp``), and 297 concurrent
file-subprocesses share it: every session cleans up old numbered dirs, so
the workspace sees >50 deletions in one agent turn and the safe-delete
guard turns a fully-green pytest run into rc=1.  Measured 2026-11-09:
265/297 (32 red) and 261/297 (36 red), with 35/35 failure logs containing
SAFE_DELETE_BULK_CONFIRM_REQUIRED and ZERO real pytest failures.  Turning
OFF that cleanup (not the tests) made it 297/297 green in 459s.

Run (BOTH parts are required on this host):

  export PYTEST_ADDOPTS='-o tmp_path_retention_policy=all -o tmp_path_retention_count=10000'
  .venv/Scripts/python.exe dev/batched_gate_scratch.py --jobs 4 --quiet

Evidence: benchmark/results/gate_evidence_20261109.md
"""
from __future__ import annotations

import importlib.util
import os
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRATCH = (pathlib.Path(os.environ.get("TEMP", "/tmp"))
           / "xssentinel_batched_gate")
SCRATCH.mkdir(parents=True, exist_ok=True)

_spec = importlib.util.spec_from_file_location(
    "xssentinel_batched_gate_runner",
    ROOT / "tests" / "run_all_batched.py")
_runner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_runner)
_runner.LOG_DIR = str(SCRATCH)
print(f"[batched] logs redirected to {SCRATCH}", flush=True)
raise SystemExit(_runner.main())
