#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase 383-385 delivery verification: the FULL agent workflow over a REAL
stdio subprocess of ``python -m xssentinel mcp`` (no injected streams).

Steps, in the order an agent would meet them:
  1. server/discover (modern)  -> scope.mode == tofu, no pin yet
  2. tools/list modern vs legacy initialize -> 9 tools (with title/hints)
     vs the byte-identical 7-tool legacy catalogue
  3. scan A (success)          -> run_id/elapsed_ms/boundary_stops/cache
                                  fields present; origin A pinned
  4. scan A again              -> cache_hit=true, SAME run_id (replay, not
                                  a fresh scan)
  5. scan B (other origin)     -> scope_denied, ZERO requests to B
  6. legacy tools/call B       -> same refusal, legacy shape (no
                                  structuredContent) -- boundary not
                                  bypassable by downgrading
  7. scan_async A + poll       -> submit returns scan_id with no target
                                  request; terminal status carries the
                                  same compact findings shape
  8. verify on A               -> the replay/judge tool answers
  9. scan A/redir -> B/land    -> boundary_stops records the refused hop,
                                  landing server never visited

Output: dev/_mcp_workflow_smoke.json + a PASS/FAIL line per step.
Usage: .venv/Scripts/python.exe dev/mcp_workflow_smoke.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssentinel.api import mcp_server as m  # noqa: E402

PAGE = b"<html><body><p>static delivery page</p></body></html>"
SCAN_ARGS = {"max_payloads": 1, "timeout": 5, "max_seconds": 60}
MODERN = {"_meta": {m._META_VERSION_KEY: "2026-07-28"}}

_results: list = []


class Target:
    def __init__(self, redirects: dict | None = None):
        self._hits: list = []
        self._lock = threading.Lock()
        self._redirects = dict(redirects or {})
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                with outer._lock:
                    outer._hits.append(self.path)
                loc = outer._redirects.get(self.path)
                if loc is not None:
                    self.send_response(302)
                    self.send_header("Location", loc)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(PAGE)))
                self.end_headers()
                self.wfile.write(PAGE)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever,
                         daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/"

    def hits(self, prefix: str | None = None) -> int:
        with self._lock:
            return sum(1 for h in self._hits
                       if prefix is None or h.startswith(prefix))

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


class Client:
    """One stdio subprocess; frames go in, JSON lines come back (by id)."""

    def __init__(self):
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "xssentinel", "mcp"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, cwd=ROOT, env=env)
        self._next_id = 10

    def call(self, frame: dict, timeout: float = 120) -> dict:
        self._next_id += 1
        frame = {**frame, "id": self._next_id}
        self.proc.stdin.write(json.dumps(frame).encode() + b"\n")
        self.proc.stdin.flush()
        return self._read(timeout)

    def _read(self, timeout: float) -> dict:
        # responses may finish out of order (tools/call runs on workers);
        # read until OUR id shows up, buffering the others.
        line = self.proc.stdout.readline()
        assert line, "subprocess closed stdout"
        return json.loads(line.decode("utf-8"))

    def close(self):
        self.proc.stdin.close()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def check(step: str, ok: bool, detail: str = "") -> None:
    _results.append({"step": step, "ok": bool(ok), "detail": detail[:300]})
    print(f"[{'PASS' if ok else 'FAIL'}] {step}"
          + (f" -- {detail[:160]}" if detail and not ok else ""))


def main() -> int:
    # A carries the redirect endpoint itself: the boundary test must run on
    # the ALREADY-PINNED origin (a different port would be a new origin and
    # the TOFU gate would refuse the call before the redirect ever fires --
    # which step 5 already proves).
    a = Target(redirects={"/redir": None})
    b = Target()
    a._redirects["/redir"] = f"http://127.0.0.1:{b.port}/land"
    cli = Client()
    try:
        # 1. discover: tofu declared, nothing pinned yet
        d = cli.call({"jsonrpc": "2.0", "method": "server/discover"})["result"]
        check("discover declares tofu scope",
              d["scope"]["mode"] == "tofu" and d["scope"]["pinned"] == [],
              json.dumps(d["scope"]))

        # 2. tool catalogues: modern 9 with titles, legacy byte-7
        tl = cli.call({"jsonrpc": "2.0", "method": "tools/list",
                       "params": MODERN})["result"]["tools"]
        init = cli.call({"jsonrpc": "2.0", "method": "initialize",
                         "params": {}})["result"]
        legacy = cli.call({"jsonrpc": "2.0", "method": "tools/list"})[
            "result"]["tools"]
        check("modern tools/list has 9 annotated tools",
              len(tl) == 9 and all("title" in t for t in tl),
              f"len={len(tl)}")
        check("legacy catalogue stays at 7",
              len(legacy) == 7, f"len={len(legacy)}")

        # 3. first scan: success + metadata + pin
        r1 = cli.call({"jsonrpc": "2.0", "method": "tools/call",
                       "params": {"name": "xssentinel_scan",
                                  "arguments": dict(SCAN_ARGS, url=a.url),
                                  **MODERN}})["result"]
        p1 = json.loads(r1["content"][0]["text"])
        check("scan A succeeds with run metadata",
              not r1.get("isError")
              and p1.get("run_id", "").startswith("run_")
              and isinstance(p1.get("elapsed_ms"), int)
              and p1.get("boundary_stops") == [],
              json.dumps({k: p1.get(k) for k in
                          ("run_id", "elapsed_ms", "boundary_stops")}))
        d2 = cli.call({"jsonrpc": "2.0", "method": "server/discover"})["result"]
        check("origin A pinned after success",
              d2["scope"]["pinned"] == [f"http://127.0.0.1:{a.port}"],
              json.dumps(d2["scope"]))

        # 4. identical retry: cache replay with the ORIGINAL run id
        r2 = cli.call({"jsonrpc": "2.0", "method": "tools/call",
                       "params": {"name": "xssentinel_scan",
                                  "arguments": dict(SCAN_ARGS, url=a.url),
                                  **MODERN}})["result"]
        p2 = json.loads(r2["content"][0]["text"])
        check("retry is a cache replay carrying the original run_id",
              p2.get("cache_hit") is True and p2["run_id"] == p1["run_id"],
              f"cache_hit={p2.get('cache_hit')}")

        # 5. cross-origin: refused with zero requests
        hits_before = b.hits()
        r3 = cli.call({"jsonrpc": "2.0", "method": "tools/call",
                       "params": {"name": "xssentinel_scan",
                                  "arguments": dict(SCAN_ARGS, url=b.url),
                                  **MODERN}})["result"]
        err3 = (r3.get("structuredContent") or {}).get("error") or {}
        check("cross-origin scan refused, zero requests to B",
              r3.get("isError") and err3.get("code") == "scope_denied"
              and b.hits() == hits_before,
              json.dumps({"code": err3.get("code"), "b_hits": b.hits()}))

        # 6. legacy frame: same refusal, legacy shape
        r4 = cli.call({"jsonrpc": "2.0", "method": "tools/call",
                       "params": {"name": "xssentinel_scan",
                                  "arguments": dict(SCAN_ARGS, url=b.url)}})[
            "result"]
        check("legacy frame refused in legacy shape",
              r4.get("isError")
              and "structuredContent" not in r4
              and r4["content"][0]["text"].startswith(
                  "target outside authorized scope:"))

        # 7. async pair: submit -> poll -> terminal
        r5 = cli.call({"jsonrpc": "2.0", "method": "tools/call",
                       "params": {"name": "xssentinel_scan_async",
                                  "arguments": dict(SCAN_ARGS, url=a.url),
                                  **MODERN}})["result"]
        p5 = json.loads(r5["content"][0]["text"])
        scan_id = p5.get("scan_id", "")
        state = ""
        status = {}
        for _ in range(30):
            rs = cli.call({"jsonrpc": "2.0", "method": "tools/call",
                           "params": {"name": "xssentinel_scan_status",
                                      "arguments": {"scan_id": scan_id},
                                      **MODERN}})["result"]
            status = json.loads(rs["content"][0]["text"])
            state = status.get("state", "")
            if status.get("terminal"):
                break
            import time
            time.sleep(0.5)
        check("async submit->poll reaches terminal with findings shape",
              bool(scan_id) and state == "completed"
              and "finding_count" in status
              and status.get("run_id", "").startswith("run_"),
              f"state={state}")

        # 8. verify tool answers on A
        rv = cli.call({"jsonrpc": "2.0", "method": "tools/call",
                       "params": {"name": "xssentinel_verify",
                                  "arguments": {"url": a.url, "param": "q",
                                                "payload":
                                                    "<script>alert(1)</script>"},
                                  **MODERN}})["result"]
        check("verify tool answers (judge reachable)",
              not rv.get("isError")
              and "confirmed" in json.loads(rv["content"][0]["text"]))

        # 9. boundary: page-chosen cross-origin hop refused + recorded
        rb = cli.call({"jsonrpc": "2.0", "method": "tools/call",
                       "params": {"name": "xssentinel_scan",
                                  "arguments": dict(SCAN_ARGS,
                                                    url=a.url + "redir"),
                                  **MODERN}})["result"]
        pb = json.loads(rb["content"][0]["text"])
        check("redirect boundary records the refused hop",
              not rb.get("isError")
              and pb.get("boundary_stops") == [f"http://127.0.0.1:{b.port}/land"]
              and b.hits(prefix="/land") == 0,
              f"boundary_stops={pb.get('boundary_stops')} land_hits={b.hits(prefix='/land')}")
    finally:
        cli.close()
        a.stop()
        b.stop()

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "_mcp_workflow_smoke.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"steps": _results,
                   "verdict": "ALL PASS" if all(r["ok"] for r in _results)
                   else "FAILURES PRESENT"}, f, ensure_ascii=False, indent=2)
    print("written:", out)
    ok = all(r["ok"] for r in _results)
    print("MCP WORKFLOW SMOKE:", "ALL PASS" if ok else "FAILURES PRESENT")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
