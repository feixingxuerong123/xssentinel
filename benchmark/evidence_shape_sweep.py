#!/usr/bin/env python
"""Evidence-shape sweep: measure the 1.5-① invariant across both engines.

The contract (Phase 218's rule, stated as a finding-level invariant):
every HIGH/CRITICAL finding must carry a checkable basis --

    browser-executed evidence, an OOB callback, a confirmed headless
    replay, a proof payload, or a response excerpt (``evidence``).

``cap_unverified_severity`` enforces this at both engines' choke points
(async ``scan()`` final yield, sync ``_record``); this sweep MEASURES it
over a real server population instead of trusting the wiring, which is
what OPTIMIZATION 3.6's "仍然待做 ①" asked for: a gate that crosses all
the static layers, not one guard per incident.

Artifacts: benchmark/results/phase312_evidence_shapes.json

Usage:
  python benchmark/evidence_shape_sweep.py            # full sweep, all routes
  python -c "from benchmark.evidence_shape_sweep import run_sweep, \
      invariant_violations"                           # resident gate import
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

from xssentinel.core.findings import (  # noqa: E402
    EVIDENCE_BROWSER_EXECUTED, EVIDENCE_OOB)

# The routes the RESIDENT gate sweeps: every family the cap was measured
# to bite on (trusted-types static hints, prototype pollution) plus the
# reflected/safe twins, so the gate cannot pass on a population that
# contains no high findings at all.
RESIDENT_ROUTES = [
    "/dom/tt-innerhtml#/route",
    "/dom/tt-innerhtml-safe#/route",
    "/r/prt01",
    "/s/prt01",
    "/echo",
    "/safe",
    "/s/jsonct01",
    "/s/flt05",
]

_BUDGETS = dict(max_payloads=10, max_transforms=6)


def finding_row(f) -> dict:
    """The evidence shape of one finding, engine-agnostic."""
    d = f.data if hasattr(f, "data") else dict(f)
    return {
        "url": d.get("url"),
        "type": d.get("type"),
        "severity": d.get("severity"),
        "confidence": d.get("confidence"),
        "evidence_class": d.get("evidence_class"),
        "has_proof": bool(d.get("proof")),
        "has_evidence": bool(d.get("evidence")),
        "headless_confirmed": bool((d.get("headless") or {}).get("confirmed")),
    }


def invariant_violations(rows: list[dict]) -> list[str]:
    """Rows whose high/critical claim carries no checkable basis."""
    out = []
    for r in rows:
        if r.get("severity") not in ("high", "critical"):
            continue
        if (r.get("evidence_class") in (EVIDENCE_BROWSER_EXECUTED, EVIDENCE_OOB)
                or r.get("headless_confirmed")
                or r.get("has_proof") or r.get("has_evidence")):
            continue
        out.append(f"{r.get('type')} at {r.get('url')}: high claim with "
                   f"evidence_class={r.get('evidence_class')!r}, no proof, "
                   "no evidence, no browser/OOB/headless basis")
    return out


def _sweep_sync(base: str, routes: list[str]) -> list[dict]:
    from xssentinel.core.requester import Requester
    from xssentinel.core.scanner import Scanner

    rows: list[dict] = []
    for path in routes:
        sc = Scanner(requester=Requester(timeout=8), dom_engine="static",
                     verbose=False, **_BUDGETS)
        sc.scan_endpoint(base + path, "GET", {"q": "probe"}, {})
        rows.extend(finding_row(f) for f in sc.findings)
    return rows


def _sweep_async(base: str, routes: list[str]) -> list[dict]:
    import asyncio
    from xssentinel.core.async_scanner import AsyncScanner

    async def _all():
        rows: list[dict] = []
        for path in routes:
            asc = AsyncScanner(max_concurrent=2, per_host_delay=0, jitter=0,
                               timeout=8, dom_engine="static",
                               advanced_layers=True, **_BUDGETS)
            async for f in asc.scan(base + path, method="GET",
                                    params={"q": "probe"}):
                rows.append(finding_row(f))
        return rows

    # Phase 203: fresh thread -- the sync pass may hold a loop binding.
    out: dict = {}
    t = threading.Thread(target=lambda: out.update(
        res=asyncio.run(_all())))
    t.start()
    t.join(1200)
    return out.get("res", [])


def run_sweep(base: str, routes: list[str] | None = None,
              engines=("sync", "async")) -> tuple[list[dict], list[str]]:
    """Sweep the routes through the given engines; return (rows, violations)."""
    routes = routes if routes is not None else RESIDENT_ROUTES
    rows: list[dict] = []
    if "sync" in engines:
        rows.extend(_sweep_sync(base, routes))
    if "async" in engines:
        rows.extend(_sweep_async(base, routes))
    return rows, invariant_violations(rows)


def main() -> int:
    from server import load_routes, run_server  # benchmark/server.py

    routes = sorted(load_routes().keys())
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

    t0 = time.time()
    rows, violations = run_sweep(base, routes)
    highs = [r for r in rows if r["severity"] in ("high", "critical")]
    doc = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "routes": len(routes),
        "findings": len(rows),
        "high_findings": len(highs),
        "violations": violations,
        "rows": rows,
    }
    out = os.path.join(_ROOT, "benchmark", "results",
                       "phase312_evidence_shapes.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=1)
    print(f"swept {len(routes)} routes: {len(rows)} findings "
          f"({len(highs)} high/critical), "
          f"{len(violations)} invariant violations, {time.time()-t0:.0f}s")
    print(f"ledger: {out}")
    for v in violations[:20]:
        print("  VIOLATION:", v)
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
