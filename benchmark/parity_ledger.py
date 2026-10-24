#!/usr/bin/env python
"""Full-parity one-shot ledger (Phase 313): every DIRECT manifest case
through BOTH engines, verdict shapes recorded, divergences listed.

The parity GATE (tests/test_engine_parity_gate.py) stays a 17-endpoint
slice -- incident-driven, cheap enough for every run.  This ledger is the
one-shot measurement behind it: all manifest cases that are scannable
over plain HTTP by both engines (GET, no stored/upload/crawl extras, no
DOM-browser family) are scanned twice from the raw reports, and the
(type, severity, confidence) multiset of each engine is recorded per
case.  Divergences are REPORTED, not failed: some are legitimate (the
gate's documented exclusions -- which payload confirms first is
ladder-order-dependent), and the ledger's job is to make the residual
population visible instead of discovering it one incident at a time.

Artifacts: benchmark/results/phase313_parity_ledger.json
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)

from benchmark.runner import (  # noqa: E402
    _build_target_url, _case_extra_args, _invoke_scanner)
from benchmark.server import run_server  # noqa: E402


def _direct(case: dict) -> bool:
    """Scannable by both engines over plain HTTP: GET, no extras, no DOM
    browser family, declared for the async engine (or engine-agnostic)."""
    if case.get("method", "GET").upper() != "GET":
        return False
    if case.get("extra_args"):
        return False
    if case.get("upload_field") or case.get("stored_dom") \
            or case.get("stored_extra") or case.get("stored_archive_entry"):
        return False
    if case.get("param", "") == "":
        return False  # DOM/fragment family: needs the browser
    eng = case.get("engines")
    if eng and "async" not in eng:
        return False
    return True


def _shapes(base: str, case: dict, engine: str) -> list:
    """(type, severity, confidence) rows from the RAW report, one retry
    on a dead scan (a transport artifact must not read as divergence)."""
    url = _build_target_url(base, case)
    extra = _case_extra_args(base, case)
    rep, _elapsed, _err = _invoke_scanner(
        url, timeout=90, max_payloads=10, max_transforms=6,
        engine=engine, extra_args=extra)
    if rep is None:
        rep, _elapsed, _err = _invoke_scanner(
            url, timeout=90, max_payloads=10, max_transforms=6,
            engine=engine, extra_args=extra)
    return sorted((f.get("type"), f.get("severity"), f.get("confidence"))
                  for f in (rep or {}).get("findings", [])
                  if f.get("type") != "fuzzer_triage")


def main() -> int:
    man_path = os.path.join(_HERE, "manifest.json")
    with open(man_path, encoding="utf-8") as fh:
        cases = json.load(fh)["cases"]
    direct = [c for c in cases if _direct(c)]
    skipped = len(cases) - len(direct)
    print(f"manifest {len(cases)} cases -> {len(direct)} direct (both-engine "
          f"HTTP), {skipped} skipped families recorded below")

    holder = {}

    def on_ready(srv):
        holder["port"] = srv.server_address[1]
        holder["ready"].set()

    holder["ready"] = threading.Event()
    t = threading.Thread(target=run_server, args=(0,),
                         kwargs={"ready_callback": on_ready}, daemon=True)
    t.start()
    assert holder["ready"].wait(15), "benchmark server did not start"
    base = f"http://127.0.0.1:{holder['port']}"
    time.sleep(0.2)

    rows = []
    t0 = time.time()
    for i, case in enumerate(direct):
        cid = case["id"]
        s_set = _shapes(base, case, "sync")
        a_set = _shapes(base, case, "async")
        divergent = s_set != a_set
        rows.append({
            "case": cid, "path": case["path"], "context": case.get("context"),
            "ground_truth": case["ground_truth"],
            "sync_shapes": s_set, "async_shapes": a_set,
            "divergent": divergent,
        })
        print(f"  [{i+1}/{len(direct)}] {cid}: "
              f"{'DIVERGENT' if divergent else 'ok'}", flush=True)

    divergences = [r for r in rows if r["divergent"]]
    doc = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "cases_total": len(cases), "cases_direct": len(direct),
        "cases_skipped": skipped,
        "runtime_s": round(time.time() - t0, 1),
        "divergences": len(divergences),
        "rows": rows,
    }
    out = os.path.join(_ROOT, "benchmark", "results",
                       "phase313_parity_ledger.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=1)
    print(f"ledger: {out} ({len(direct)} cases, "
          f"{len(divergences)} divergent, {time.time()-t0:.0f}s)")
    for r in divergences[:20]:
        print(f"  {r['case']}: sync={r['sync_shapes']} "
              f"async={r['async_shapes']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
