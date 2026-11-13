#!/usr/bin/env python3
"""Phase 388: deterministic shape matrix for the fn_net FP candidates.

Why this exists: ``build_multi_stage_polyglot`` picks its executor from
``_EXEC_PRIMITIVES`` by ``sum(ord(c) for c in token) % len(...)`` -- so a
single scan reports a DIFFERENT payload every run.  Adjudicating "the two
FP candidates" from one scan is a lottery.  This matrix removes the lottery:
it enumerates the product's OWN primitive corpus, asks the product's OWN
builder for each payload, renders each through the REAL /fuzz/render fixture,
and records both the engine verifier and a real Chromium dialog.

No hand-written "nearby" shapes: the break-out prefix also comes from
``build_multi_stage_polyglot``.  §8.17's false FP verdict came from exactly
such a reconstruction (entity-escaped closing tag + a quoting bug).

Usage:
    C:/Python39/python.exe dev/phase388_primitive_matrix.py
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["NO_PROXY"] = "127.0.0.1,localhost,::1"
os.environ["no_proxy"] = "127.0.0.1,localhost,::1"

import requests  # noqa: E402
from xssentinel.core import polyglot as POLY  # noqa: E402
from xssentinel.core import verifier as V  # noqa: E402

FIXED_TOKEN = "388fixed"
MSG = f"xss_poly_{FIXED_TOKEN}"
PRIMITIVES = list(POLY._EXEC_PRIMITIVES)  # product corpus, never hand-typed
ESCS = ("encode_quotes", "raw", "html", "encode_angles")
SINKS = ("none", "dom")
OUT = (ROOT / "benchmark" / "results" /
       "phase388_primitive_matrix_20261113.json")


def _start_bench():
    spec = importlib.util.spec_from_file_location(
        "bench_server", str(ROOT / "benchmark" / "server.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    box, started = {}, threading.Event()
    threading.Thread(
        target=mod.run_server, args=(0,),
        kwargs={"ready_callback": lambda s: (
            box.__setitem__("p", s.server_address[1]), started.set())},
        daemon=True).start()
    assert started.wait(10)
    time.sleep(0.2)
    return f"http://127.0.0.1:{box['p']}"


class _H(BaseHTTPRequestHandler):
    body = "<p>placeholder</p>"

    def do_GET(self):
        data = self.body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def _payload(primitive, why):
    """Ask the PRODUCT builder for this exact shape (no reconstruction)."""
    saved = POLY._EXEC_PRIMITIVES
    POLY._EXEC_PRIMITIVES = [(primitive, why)]
    try:
        return POLY.build_multi_stage_polyglot(FIXED_TOKEN)
    finally:
        POLY._EXEC_PRIMITIVES = saved


def _render(session, base, esc, sink, payload):
    url = (f"{base}/fuzz/render?ctx=script_dq&esc={esc}&sink={sink}"
           f"&q={quote(payload)}")
    r = session.get(url, timeout=20)
    return r.text, dict(r.headers)


def _browser(browser, port, html):
    _H.body = html
    fired = {"hit": False, "msg": ""}
    page = browser.new_page()
    page.on("dialog", lambda d, box=fired: (
        box.__setitem__("hit", True),
        box.__setitem__("msg", d.message),
        d.dismiss()))
    try:
        page.goto(f"http://127.0.0.1:{port}/", wait_until="load",
                  timeout=15000)
        page.wait_for_timeout(900)
    finally:
        page.close()
    return fired["hit"], fired["msg"]


def main() -> int:
    base = _start_bench()
    session = requests.Session()
    session.trust_env = False
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    from playwright.sync_api import sync_playwright

    rows = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        for primitive, why in PRIMITIVES:
            payload = _payload(primitive, why)
            for sink in SINKS:
                for esc in ESCS:
                    html, headers = _render(session, base, esc, sink, payload)
                    v = V.verify_semantic(html, MSG, headers)
                    fired, msg = _browser(browser, port, html)
                    rows.append({
                        "primitive": primitive,
                        "why": why,
                        "esc": esc, "sink": sink,
                        "payload": payload,
                        "verifier_confirmed": bool(v.get("confirmed")),
                        "verifier_context": v.get("context"),
                        "browser_dialog": fired,
                        "dialog_message": msg,
                        "html_sha256": hashlib.sha256(
                            html.encode("utf-8")).hexdigest()[:16],
                    })
            same = [r for r in rows
                    if r["primitive"] == primitive
                    and r["esc"] == "encode_quotes"]
            print(f"{primitive[:52]:52} "
                  f"verifier={[r['verifier_confirmed'] for r in same]} "
                  f"browser={[r['browser_dialog'] for r in same]}")
        browser.close()
    srv.shutdown()

    controls_valid = (
        any(r["browser_dialog"] for r in rows if r["esc"] == "raw")
        and not any(r["browser_dialog"] for r in rows
                    if r["esc"] in ("html", "encode_angles")))
    live, verifier_only = [], []
    for primitive, _why in PRIMITIVES:
        same = [r for r in rows if r["primitive"] == primitive
                and r["esc"] == "encode_quotes"]
        if all(r["verifier_confirmed"] and r["browser_dialog"]
               for r in same):
            live.append(primitive)
        elif all(r["verifier_confirmed"] and not r["browser_dialog"]
                 for r in same):
            verifier_only.append(primitive)
    artifact = {
        "meta": {
            "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "method": ("product _EXEC_PRIMITIVES x product "
                       "build_multi_stage_polyglot x real /fuzz/render x "
                       "engine verifier x real Chromium dialog"),
            "fixed_token": FIXED_TOKEN, "token": MSG,
            "escs": list(ESCS), "sinks": list(SINKS),
            "context": "script_dq",
            "controls_valid": controls_valid,
        },
        "summary": {
            "shapes": len(PRIMITIVES), "arms": len(rows),
            "controls_valid": controls_valid,
            "true_detection": live,
            "verifier_only": verifier_only,
        },
        "rows": rows,
    }
    OUT.write_text(json.dumps(artifact, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    print(f"\ncontrols_valid={controls_valid} "
          f"true_detection={len(live)} verifier_only={len(verifier_only)}")
    for prim in verifier_only:
        print(f"  verifier-only: {prim}")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
