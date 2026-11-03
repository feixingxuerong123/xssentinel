# -*- coding: utf-8 -*-
"""One-off Phase 355 diagnostic (explicit-path pytest, never collected by
the batched runner): dump full finding dicts for one DOM endpoint, both
engines, to attribute the async-side duplicated dom_dynamic."""
from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))), "benchmark"))

os.environ["XSS_DOM_TRACE"] = "1"


def test_dump_one_dom_endpoint_both_engines():
    from server import run_server as bench_run_server

    holder = {}

    def on_ready(srv):
        holder["port"] = srv.server_address[1]
        holder["ready"].set()

    holder["ready"] = threading.Event()
    t = threading.Thread(target=bench_run_server, args=(0,),
                         kwargs={"ready_callback": on_ready}, daemon=True)
    t.start()
    assert holder["ready"].wait(15), "benchmark server did not start"
    time.sleep(0.2)
    base = f"http://127.0.0.1:{holder['port']}"
    case = "/dom/hash-settimeout"
    try:
        from xssentinel.core.requester import Requester
        from xssentinel.core.scanner import Scanner
        sc = Scanner(requester=Requester(timeout=8), dom_engine="auto",
                     verbose=False, max_payloads=6, max_transforms=4)
        sc.scan_endpoint(base + case, "GET", {"q": "probe"}, {})
        print("\n=== sync ===", flush=True)
        for f in sc.findings:
            print(json.dumps(f.data, ensure_ascii=False, default=str)[:700],
                  flush=True)

        from xssentinel.core.async_scanner import AsyncScanner

        async def _one():
            asc = AsyncScanner(max_concurrent=4, per_host_delay=0, jitter=0,
                               timeout=8, dom_engine="auto",
                               advanced_layers=True, max_payloads=6,
                               max_transforms=4)
            got = []
            async for f in asc.scan(base + case, method="GET",
                                    params={"q": "probe"}):
                got.append(f.data if hasattr(f, "data") else dict(f))
            return got

        out = {}
        t2 = threading.Thread(target=lambda: out.update(
            res=asyncio.run(_one())))
        t2.start()
        t2.join(timeout=180)
        print("=== async ===", flush=True)
        for f in out.get("res", []):
            print(json.dumps(f, ensure_ascii=False, default=str)[:700],
                  flush=True)
        assert True
    finally:
        pass  # server thread is daemon; process exit reaps it
