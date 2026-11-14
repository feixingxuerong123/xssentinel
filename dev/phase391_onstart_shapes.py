#!/usr/bin/env python3
"""Phase 391: measure the onstart shapes Phase 389 explicitly left unmeasured.

Phase 389 banned exactly one (element, handler) pair -- ("marquee", "onstart")
-- and wrote "`<div onstart>` and similar shapes were NOT measured this round,
so per 'nothing unmeasured enters a gate' they stay as they are".  This is
that measurement.  It is a FACT TABLE, not a fix: the browser column says
what Chromium actually does, the verifier column says what the engine
currently claims, and the two are never merged into a verdict here.

Controls (ABORT if either fails, never "run it and see"):
  positive  <img src=x onerror=alert(TOKEN)>        -> dialog MUST fire
  negative  <div onclick=alert(TOKEN)> (no click)   -> dialog MUST NOT fire
  baseline  <marquee onstart=...>                   -> Phase 389's inert pair

Usage:  python dev/phase391_onstart_shapes.py
Output: benchmark/results/phase391_onstart_shapes_20261114.json
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["NO_PROXY"] = "127.0.0.1,localhost,::1"
os.environ["no_proxy"] = "127.0.0.1,localhost,::1"

from xssentinel.core import verifier as V  # noqa: E402
from xssentinel.core import sandbox as S  # noqa: E402

TOKEN = "xssv_p391"
MSG = f"xss_p391_{TOKEN}"
HEADERS = {"Content-Type": "text/html; charset=utf-8"}
OUT = (ROOT / "benchmark" / "results" /
       "phase391_onstart_shapes_20261114.json")

ELEMENTS = ("marquee", "div", "span", "p", "section", "a", "img", "svg",
            "table", "input")
VOID = frozenset({"img", "input"})


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


def _page(inner: str) -> str:
    return f"<!doctype html><html><body>{inner}</body></html>"


def _shapes() -> list[tuple[str, str]]:
    """(label, html).  No hand-written 'nearby' payloads: every handler body
    is the same alert(TOKEN), only the host element and the attribute shape
    change -- that is the dimension under measurement."""
    out = []
    for el in ELEMENTS:
        close = "" if el in VOID else f"</{el}>"
        out.append((f"<{el} onstart>",
                    _page(f'<{el} onstart="alert(\'{MSG}\')">x{close}')))
    # Phase 362's XSSMaze shape: angle-bracket stripping leaves `onstart`
    # on the HOST element with a stray `marquee` attribute, not a <marquee>.
    out.append(("<div marquee onstart>",
                _page(f'<div marquee onstart="alert(\'{MSG}\')">x</div>')))
    # Mechanism arms: separate "an on* attribute exists" from "a start
    # event was actually dispatched".  XSSMaze level5 is a page with its
    # own scripts; a bare-HTML no-exec result does not by itself settle it.
    out.append(("<div onstart + dispatch start>",
                _page(f'<div id="t" onstart="alert(\'{MSG}\')">x</div>'
                      '<script>document.getElementById("t")'
                      '.dispatchEvent(new Event("start"));</script>')))
    out.append(("<marquee onstart + start()>",
                _page(f'<marquee id="t" onstart="alert(\'{MSG}\')">x</marquee>'
                      '<script>document.getElementById("t").start();</script>')))
    out.append(("control_positive_onerror",
                _page(f'<img src=x onerror="alert(\'{MSG}\')">')))
    out.append(("control_negative_onclick",
                _page(f'<div onclick="alert(\'{MSG}\')">x</div>')))
    return out


def _browser(browser, port: int, html: str) -> tuple[bool, str]:
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
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    from playwright.sync_api import sync_playwright

    rows = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            for label, html in _shapes():
                v = V.verify_semantic(html, MSG, HEADERS)
                hit, msg = _browser(browser, port, html)
                try:
                    state = S.judge(html, MSG, sink="parser").state
                except Exception as e:
                    state = f"ERROR:{type(e).__name__}"
                rows.append({
                    "shape": label,
                    "html": html,
                    "html_sha256": hashlib.sha256(
                        html.encode("utf-8")).hexdigest()[:16],
                    "verifier_confirmed": bool(v.get("confirmed")),
                    "verifier_detail": v.get("detail"),
                    "sandbox_state": state,
                    "browser_dialog": hit,
                    "dialog_message": msg,
                })
                print(f"{label:32} verifier={v.get('confirmed')!s:5} "
                      f"sandbox={state:12} browser={hit}", flush=True)
        finally:
            browser.close()
    srv.shutdown()

    by_label = {r["shape"]: r for r in rows}
    controls_valid = (
        by_label["control_positive_onerror"]["browser_dialog"] is True
        and by_label["control_negative_onclick"]["browser_dialog"] is False
        and by_label["<marquee onstart>"]["browser_dialog"] is False)
    if not controls_valid:
        print("ABORT: controls invalid -- no verdict is written", flush=True)
        return 2

    verifier_only = sorted(r["shape"] for r in rows
                           if r["verifier_confirmed"]
                           and not r["browser_dialog"]
                           and not r["shape"].startswith("control_"))
    live = sorted(r["shape"] for r in rows
                  if r["verifier_confirmed"] and r["browser_dialog"]
                  and not r["shape"].startswith("control_"))
    artifact = {
        "meta": {
            "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "date": "2026-11-14",
            "tree": "2.1.0 + Phase 390 harness correction",
            "method": ("element x handler shape; product verifier + sandbox "
                       "judge + real Chromium dialog; one shared alert token"),
            "token": MSG,
            "elements": list(ELEMENTS),
            "controls_valid": controls_valid,
        },
        "summary": {
            "arms": len(rows),
            "controls_valid": controls_valid,
            "verifier_only": verifier_only,
            "live": live,
        },
        "rows": rows,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(artifact, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    print(f"\ncontrols_valid={controls_valid} "
          f"verifier_only={len(verifier_only)} live={len(live)}")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
