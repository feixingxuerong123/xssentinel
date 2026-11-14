# -*- coding: utf-8 -*-
"""Phase 390: adjudicate the two parity-full divergences on the 2.1.0 tree.

The 2026-11-13 note recorded `pos-sri-01` and `pos-pmmine-01` as 2/194
divergences of ``XSSENTINEL_PARITY_FULL=1`` and called them "behavioural /
a sync-side potential mining FN".  This probe does not assume that verdict.
It re-measures both cases at more than one harness shape, because Phase 222
already established the rule: a harness that hands the two engines different
inputs measures the *harness*, not the engines.

Arms (URL and budgets identical in every arm; only the "known params" dict
and one documented env escape hatch change):

  A gate_shape   -- exactly what tests/test_parity_full_matrix.py passes:
                    params={'q': 'probe'} on both sides.
  B runner_shape -- what benchmark/runner.py actually supplies for a case
                    whose manifest param is empty: no known params at all.
  C adaptive_off -- gate_shape + XSS_ADAPTIVE_MINING=0, the documented
                    escape hatch for Phase 353's mining gate in sync.
  D budget_v2_off -- gate_shape + XSS_BUDGET_V2=0, the other documented
                     escape hatch; sync's _scan_dom _browser_pointless gate
                     is disabled while async has no such gate.

Usage:  python dev/phase390_parity_probe.py
Output: benchmark/results/phase390_parity_probe_20261114.json
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "benchmark"))

from runner import _build_target_url  # noqa: E402
from server import run_server as bench_run_server  # noqa: E402

BUDGETS = dict(max_payloads=14, max_transforms=12)
CASE_IDS = ("pos-sri-01", "pos-pmmine-01")
ARMS = ("gate_shape", "runner_shape", "adaptive_off", "budget_v2_off")
ENV_KEYS = ("XSS_ADAPTIVE_MINING", "XSS_BUDGET_V2")
OUT = os.path.join(ROOT, "benchmark", "results",
                   "phase390_parity_probe_20261114.json")


def _load_cases() -> dict:
    with open(os.path.join(ROOT, "benchmark", "manifest.json"),
              encoding="utf-8") as f:
        rows = json.load(f)["cases"]
    return {c["id"]: c for c in rows if c["id"] in CASE_IDS}


def _norm(findings) -> list:
    """Byte-identical to tests/test_parity_full_matrix.py::_norm."""
    rows = []
    for f in findings:
        d = f.data if hasattr(f, "data") else dict(f)
        rows.append([d.get("type"), d.get("severity"), d.get("confidence")])
    return sorted(r for r in rows if r[0] != "fuzzer_triage")


def _target(base: str, case: dict) -> tuple:
    """The gate's own URL builder (which is the benchmark runner's)."""
    return _build_target_url(base, case), case.get("method", "GET").upper()


def _run_sync(base: str, case: dict, params: dict) -> list:
    from xssentinel.core.requester import Requester
    from xssentinel.core.scanner import Scanner

    url, method = _target(base, case)
    sc = Scanner(requester=Requester(timeout=8), dom_engine="off",
                 verbose=False, **BUDGETS)
    try:
        sc.scan_target(url, method, params, {}, oob_collect=False)
        return _norm(sc.findings)
    except Exception as e:  # a crash is a fact, not an empty verdict
        return [f"ERROR:{type(e).__name__}"]


def _run_async(base: str, case: dict, params: dict) -> list:
    from xssentinel.core.async_scanner import AsyncScanner

    url, method = _target(base, case)

    async def _one():
        asc = AsyncScanner(max_concurrent=4, per_host_delay=0, jitter=0,
                           timeout=8, dom_engine="off", advanced_layers=True,
                           **BUDGETS)
        got = []
        try:
            async for f in asc.scan(url, method=method, params=params,
                                    data=None):
                got.append(f.data if hasattr(f, "data") else dict(f))
            return _norm(got)
        except Exception as e:
            return [f"ERROR:{type(e).__name__}"]

    holder: dict = {}
    t = threading.Thread(target=lambda: holder.update(res=asyncio.run(_one())))
    t.start()
    t.join()
    return holder["res"]


def _start_server() -> str:
    holder = {"ready": threading.Event()}

    def on_ready(srv):
        holder["port"] = srv.server_address[1]
        holder["ready"].set()

    threading.Thread(target=bench_run_server, args=(0,),
                     kwargs={"ready_callback": on_ready},
                     daemon=True).start()
    assert holder["ready"].wait(20), "benchmark server did not start"
    time.sleep(0.2)
    return f"http://127.0.0.1:{holder['port']}"


def main() -> None:
    cases = _load_cases()
    assert set(cases) == set(CASE_IDS), "manifest no longer has both cases"
    base = _start_server()
    report = {
        "tree": "2.1.0 final tree (44403a3)",
        "date": "2026-11-14",
        "budgets": BUDGETS,
        "arms": {},
    }
    original = {k: os.environ.get(k) for k in ENV_KEYS}
    try:
        for arm in ARMS:
            params = {} if arm == "runner_shape" else {"q": "probe"}
            for key in ENV_KEYS:
                os.environ.pop(key, None)
            if arm == "adaptive_off":
                os.environ["XSS_ADAPTIVE_MINING"] = "0"
            if arm == "budget_v2_off":
                os.environ["XSS_BUDGET_V2"] = "0"
            arm_out = {}
            for cid, case in cases.items():
                t0 = time.monotonic()
                sync_out = _run_sync(base, case, params)
                t1 = time.monotonic()
                async_out = _run_async(base, case, params)
                t2 = time.monotonic()
                arm_out[cid] = {
                    "url": _build_target_url(base, case),
                    "params": params,
                    "sync": sync_out,
                    "async": async_out,
                    "agree": sync_out == async_out,
                    "sync_s": round(t1 - t0, 2),
                    "async_s": round(t2 - t1, 2),
                }
                print(f"[{arm}] {cid}: sync={sync_out} async={async_out} "
                      f"agree={sync_out == async_out}", flush=True)
            report["arms"][arm] = arm_out
    finally:
        for key, value in original.items():
            os.environ.pop(key, None)
            if value is not None:
                os.environ[key] = value

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
