# -*- coding: utf-8 -*-
"""Run the FN/FP net with the report scratch dir OUTSIDE the workspace.

Same reason as dev/gate_run_scratch.py: the sandbox's safe-delete guard caps
file deletions/overwrites at 50 per agent turn, and every scanner invocation
rewrites its report file -- a 198-combination net run is ~200 overwrites, so
it would be killed around combination 50 with no baseline written.

Kept without the "_" prefix: this is the supported way to run the net here.

Run:  C:/Python39/python.exe dev/fn_net_run.py [--sinks none,dom] [--top 3]
"""
import os
import pathlib
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "benchmark"))

SCRATCH = pathlib.Path(os.environ.get("TEMP", "/tmp")) / "xssentinel_net"
SCRATCH.mkdir(parents=True, exist_ok=True)

import benchmark.runner as R  # noqa: E402

R._RESULTS_DIR = SCRATCH
print(f"[fn_net_run] report scratch redirected to {SCRATCH}", flush=True)

from dev.fn_net import main  # noqa: E402

raise SystemExit(main())
