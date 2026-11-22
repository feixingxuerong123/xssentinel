"""Competitor-authored test assets -> our classifier (reproducible runner).

Why this exists
---------------
Phase 404 (2026-11-20) fed payload catalogues published by OTHER scanner
projects (XSStrike / XSSer / dalfox / nuclei-templates) through two
measurements.  This runner is the committed, re-runnable entry point.  The
guard tests (tests/test_phase404_competitor_corpus.py,
tests/test_phase405_onload_scheme.py) read the committed fact tables; this
script regenerates them.

Three layers, deliberately separated by cost -- do NOT run the oracle arm in
the default CI job:

  * extract : parse competitor SOURCE TREES into flat payload files.  Sources
    live in gitignored dev/_competitors_*/ (third-party assets, pinned by URL
    + sha256 in the manifest).  Offline after first fetch.
  * m1      : real-Chromium load-time oracle vs sandbox.judge, reusing the
    Phase 392 harness (benchmark/run_external_corpus.py).  ~13 min for the
    full 157-vector x 12-context matrix; `--smoke` cuts it to 3 per family.
    Opt-in: the committed evidence is the artifact; re-run to investigate a
    suspected judgement change, not on every push.
  * e2e     : inject the catalogues via --custom-payloads into the real scanner
    on a stratified reflection slice, baseline arm included.  ~1 min.

The two Phase 404 fact tables are NOT a scorecard: they use no TP/FP/F1 on the
M1 arm, and the E2E arm is a targeted slice, separate from the 194 matrix and
XSSMaze.  ground_truth always comes from benchmark/manifest.json.

Usage::
    # one-time: fetch competitor sources into dev/_competitors_20261120/,
    #   then extract vectors (writes gitignored dev/_external_corpus/)
    python -m benchmark.run_competitor_corpus extract

    # smoke both measurements (control pages + a few vectors/cases)
    python -m benchmark.run_competitor_corpus m1 --smoke --tree <sha>
    python -m benchmark.run_competitor_corpus e2e --tree <sha>

    # regenerate committed evidence (opt-in, slow)
    python -m benchmark.run_competitor_corpus m1 --tree <sha>
    python -m benchmark.run_competitor_corpus e2e --tree <sha>

Environment: export TEMP/TMP to a writable dir (SPLIT exports, never
`export TEMP=TMP=...`) and NO_PROXY=127.0.0.1,localhost before any browser or
local-server arm.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)

# The scratch implementation modules are gitignored (dev/_*).  This wrapper
# loads them by path when present so the committed entry point has ONE command
# surface, while the measurement logic stays in one place (no copy).  If they
# are absent (fresh checkout), the command prints the fetch/extract recipe.
_SCRATCH = os.path.join(_ROOT, "dev")
_MODULES = {
    "extract": os.path.join(_SCRATCH, "_p_comp_extract.py"),
    "m1": os.path.join(_SCRATCH, "_p_comp_m1.py"),
    "e2e": os.path.join(_SCRATCH, "_p_comp_e2e.py"),
}


def _load(name: str):
    path = _MODULES[name]
    if not os.path.isfile(path):
        print(f"[abort] measurement module missing: {path}\n"
              "These are third-party-source adapters kept gitignored under "
              "dev/_* (Phase 404). On a fresh checkout, re-fetch the 6 "
              "competitor trees into dev/_competitors_20261120/ and restore "
              "the adapters, or use the committed fact tables in "
              "benchmark/results/ (the guards read those, not this script).",
              file=sys.stderr)
        raise SystemExit(2)
    spec = importlib.util.spec_from_file_location(f"_comp_{name}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("arm", choices=("extract", "m1", "e2e"))
    ap.add_argument("--tree", default="", help="git sha for evidence ownership")
    ap.add_argument("--smoke", action="store_true",
                    help="m1 only: 3 vectors per family (control pages still "
                         "assert); do NOT publish as a conclusion")
    ap.add_argument("--port", type=int, default=0)
    args = ap.parse_args()

    if args.arm == "extract":
        return _load("extract").main()
    if args.arm == "m1":
        tree = args.tree or "UNOWNED"
        if not args.tree:
            print("[warn] no --tree given; evidence will record UNOWNED "
                  "(Phase 381 rule says don't fabricate ownership)",
                  file=sys.stderr)
        mod = _load("m1")
        argv = ["m1", "--tree", tree]
        if args.smoke:
            argv.append("--smoke")
        if args.port:
            argv += ["--port", str(args.port)]
        old = sys.argv
        sys.argv = argv
        try:
            return mod.main()
        finally:
            sys.argv = old
    if args.arm == "e2e":
        tree = args.tree or "UNOWNED"
        mod = _load("e2e")
        argv = ["e2e", "--tree", tree]
        if args.port:
            argv += ["--port", str(args.port)]
        old = sys.argv
        sys.argv = argv
        try:
            return mod.main()
        finally:
            sys.argv = old
    return 2


if __name__ == "__main__":
    sys.exit(main())
