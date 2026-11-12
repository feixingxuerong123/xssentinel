#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Delivery verification: the TWO faces of one ``xssentinel serve`` process.

The REST face (``POST /api/v1/scans``) is operator-driven by contract: the
operator POSTs the target themselves, so the MCP scope does not gate it.
The MCP face (``POST /mcp``) shares the stdio scope contract (same flags,
first-use pinning default).  This smoke proves BOTH statements on a REAL
server subprocess:

  1. REST scan A            -> job completes (operator-driven, as always)
  2. /mcp discover          -> scope.mode == tofu (serve wired the scope)
  3. /mcp scan A            -> success; origin A pinned (shared module state)
  4. /mcp scan B            -> scope_denied, ZERO requests to B
  5. REST scan B            -> completes anyway (operator-driven contract,
                               deliberately NOT gated -- recorded decision)
  6. /mcp scan B again      -> still refused (pin state survived the REST run)

Output: dev/_rest_mcp_face_smoke.json + PASS/FAIL lines.
Usage: .venv/Scripts/python.exe dev/rest_mcp_face_smoke.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssentinel.api import mcp_server as m  # noqa: E402

PORT = 18960
PAGE = b"<html><body><p>static page</p></body></html>"
MODERN = {"_meta": {m._META_VERSION_KEY: "2026-07-28"}}
_results: list = []


class Target:
    def __init__(self):
        self._hits: list = []
        self._lock = threading.Lock()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                with self.server.outer._lock:
                    self.server.outer._hits.append(self.path)
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(PAGE)))
                self.end_headers()
                self.wfile.write(PAGE)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.outer = self
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever,
                         daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/"

    def hits(self) -> int:
        with self._lock:
            return len(self._hits)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


def _http(method: str, path: str, body: dict | None = None) -> tuple:
    req = urllib.request.Request(
        f"http://127.0.0.1:{PORT}{path}",
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8") or "{}")


def _mcp(frame: dict) -> dict:
    status, resp = _http("POST", "/mcp", frame)
    return resp


def check(step: str, ok: bool, detail: str = "") -> None:
    _results.append({"step": step, "ok": bool(ok), "detail": detail[:300]})
    print(f"[{'PASS' if ok else 'FAIL'}] {step}"
          + (f" -- {detail[:160]}" if detail and not ok else ""))


def main() -> int:
    a, b = Target(), Target()
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    proc = subprocess.Popen(
        [sys.executable, "-m", "xssentinel", "serve",
         "--host", "127.0.0.1", "--port", str(PORT)],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        # wait for the REST face to accept
        for _ in range(40):
            try:
                status, _root = _http("GET", "/")
                break
            except Exception:
                time.sleep(0.5)
        else:
            raise SystemExit("serve never came up")

        # 1. REST scan A: operator-driven, completes
        status, job = _http("POST", "/api/v1/scans",
                            {"url": a.url, "max_payloads": 1})
        scan_id = job.get("id") or job.get("scan_id")
        state = job.get("state") or job.get("status")
        for _ in range(60):
            if state in ("completed", "failed"):
                break
            time.sleep(0.5)
            _s, jd = _http("GET", f"/api/v1/scans/{scan_id}")
            state = jd.get("state") or jd.get("status")
        check("REST scan A completes (operator-driven face ungated)",
              state == "completed", f"state={state}")

        # 2. /mcp discover on the same process: scope wired by serve
        d = _mcp({"jsonrpc": "2.0", "id": 1, "method": "server/discover",
                  "params": MODERN})
        check("serve's /mcp face declares tofu scope",
              d.get("result", {}).get("scope", {}).get("mode") == "tofu",
              json.dumps(d)[:200])

        # 3. /mcp scan A: success, pins A
        r = _mcp({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                  "params": {"name": "xssentinel_scan",
                             "arguments": {"url": a.url, "max_payloads": 1,
                                           "timeout": 5, "max_seconds": 60},
                             **MODERN}})
        p = json.loads(r["result"]["content"][0]["text"])
        check("/mcp scan A succeeds (same origin as the REST scan)",
              not r["result"].get("isError"), json.dumps(r)[:200])

        # 4. /mcp scan B: refused, zero requests
        hb = b.hits()
        r2 = _mcp({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                   "params": {"name": "xssentinel_scan",
                              "arguments": {"url": b.url, "max_payloads": 1,
                                            "timeout": 5, "max_seconds": 60},
                              **MODERN}})
        err = (r2["result"].get("structuredContent") or {}).get("error") or {}
        check("/mcp scan B refused with zero requests",
              r2["result"].get("isError") and err.get("code") == "scope_denied"
              and b.hits() == hb,
              json.dumps({"code": err.get("code"), "hits": b.hits()}))

        # 5. REST scan B: the operator-driven contract is deliberately NOT
        #    gated by the MCP scope (recorded decision, Phase 383) -- prove
        #    the documented asymmetry is real.
        status, job2 = _http("POST", "/api/v1/scans",
                             {"url": b.url, "max_payloads": 1})
        scan_id2 = job2.get("id") or job2.get("scan_id")
        state2 = ""
        for _ in range(60):
            _s, jd2 = _http("GET", f"/api/v1/scans/{scan_id2}")
            state2 = jd2.get("state") or jd2.get("status")
            if state2 in ("completed", "failed"):
                break
            time.sleep(0.5)
        check("REST scan B completes (operator-driven contract, ungated)",
              state2 == "completed", f"state={state2}")

        # 6. pin state survived the REST runs (baseline = AFTER step 5:
        #    the REST scan legitimately hit B; this call must add nothing)
        hb2 = b.hits()
        r3 = _mcp({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                   "params": {"name": "xssentinel_scan",
                              "arguments": {"url": b.url, "max_payloads": 1,
                                            "timeout": 5, "max_seconds": 60},
                              **MODERN}})
        check("/mcp scan B still refused after REST runs",
              r3["result"].get("isError") and b.hits() == hb2
              and (r3["result"].get("structuredContent") or {})
              .get("error", {}).get("code") == "scope_denied",
              json.dumps({"hits": b.hits(), "hb2": hb2}))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        a.stop()
        b.stop()

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "_rest_mcp_face_smoke.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"steps": _results,
                   "verdict": "ALL PASS" if all(r["ok"] for r in _results)
                   else "FAILURES PRESENT"}, f, ensure_ascii=False, indent=2)
    print("written:", out)
    ok = all(r["ok"] for r in _results)
    print("REST/MCP FACE SMOKE:", "ALL PASS" if ok else "FAILURES PRESENT")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
