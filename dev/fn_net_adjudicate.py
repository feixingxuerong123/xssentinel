#!/usr/bin/env python3
"""Adjudicate fn_net FP candidates with the FINDING'S OWN payload (388).

The net's FP arm only says: "the verifier refused the top-3 CORPUS shapes we
tried, yet the scanner reported something".  That is a candidate, not a
verdict -- the scanner may have used a shape the net never tried.  Phase 256
established the method; this script makes it a repeatable command so nobody
has to hand-write a "nearby" browser case again (§8.17's false conclusion
came from exactly that: an entity-escaped ``</script>`` never closes a
rawtext script, and a hand-built raw-close string had a quoting bug).

For every candidate this script:

1. scans the SAME (ctx, esc, sink) fixture with the real scanner;
2. takes each finding's OWN payload, marks a fresh token, re-renders it in
   the SAME fixture, and asks the engine verifier again;
3. loads that EXACT rendered HTML in real headless Chromium and records the
   dialog (not a reconstructed fragment);
4. runs ``raw`` (positive) and ``html`` / ``encode_angles`` (negative)
   controls to prove the oracle can see and refuse an execution.

Verdict: verifier AND browser agree on the original escaping ->
``true_detection``; both refuse -> ``real_fp``; disagreement or broken
controls -> ``inconclusive`` (never guessed).

Usage:
    C:/Python39/python.exe dev/fn_net_adjudicate.py \
        --net benchmark/results/fn_net_20261113.json
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
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
from benchmark.runner import _invoke_scanner  # noqa: E402
from xssentinel.core import verifier as V  # noqa: E402

TOKEN = "xssv_adjud388"
CONTROLS = ("raw", "html", "encode_angles")
METHOD = ("finding-own-payload / same-fixture re-render / engine verifier / "
          "real Chromium dialog / raw+html+encode_angles controls")


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


def _render(session, base, ctx, esc, sink, value):
    # The composition comes ONLY from the candidate row.  Never hardcode a
    # rendering here: a "nearby" shape is how §8.17 reached a false verdict.
    url = (f"{base}/fuzz/render?ctx={ctx}&esc={esc}&sink={sink}"
           f"&q={quote(value)}")
    r = session.get(url, timeout=20)
    return r.text, dict(r.headers)


def _browser_dialog(browser, port, html):
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
        page.wait_for_timeout(700)
    finally:
        page.close()
    return fired["hit"], fired["msg"]


def _verdict(same, arms):
    controls_valid = (
        arms["raw"]["browser_dialog"] is True
        and all(arms[e]["browser_dialog"] is False for e in CONTROLS[1:]))
    if not controls_valid:
        return "inconclusive", False
    if same["verifier_confirmed"] and same["browser_dialog"]:
        return "true_detection", True
    if not same["verifier_confirmed"] and not same["browser_dialog"]:
        return "real_fp", True
    return "inconclusive", True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--net", required=True,
                    help="fn_net JSON artifact whose FP candidates to judge")
    ap.add_argument("--out", default=None,
                    help="adjudication artifact (default: date-stamped)")
    args = ap.parse_args()

    net_path = Path(args.net)
    net = json.loads(net_path.read_text(encoding="utf-8"))
    date = re.search(r"(\d{8})", net_path.name)
    stamp = date.group(1) if date else time.strftime("%Y%m%d")
    out = Path(args.out) if args.out else (
        ROOT / "benchmark" / "results" /
        f"fn_net_adjudication_{stamp}.json")

    candidates = [r for r in net["rows"]
                  if not r["verified"] and r["findings"] > 0]
    base = _start_bench()
    session = requests.Session()
    session.trust_env = False
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    from playwright.sync_api import sync_playwright

    results = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        for cand in candidates:
            ctx, esc, sink = cand["ctx"], cand["esc"], cand["sink"]
            scan_url = (f"{base}/fuzz/render?ctx={ctx}&esc={esc}"
                        f"&sink={sink}&q=probe")
            rep, _el, err = _invoke_scanner(
                scan_url, timeout=90, max_payloads=14,
                max_transforms=12, engine=net["meta"]["engine"])
            if err or rep is None:
                print(f"ABORT [{ctx}/{esc}/{sink}]: scan error {err}")
                return 2
            finding_rows = []
            for f in (rep.get("findings") or []):
                payload = f.get("payload") or ""
                if not payload:
                    continue
                marked = V.mark(payload, TOKEN)
                arms = {}
                # dict.fromkeys keeps the candidate's own escaping first and
                # avoids rendering it twice when it is itself a control.
                for arm_esc in dict.fromkeys((esc,) + CONTROLS):
                    html, headers = _render(session, base, ctx, arm_esc,
                                            sink, marked)
                    v = V.verify_semantic(html, TOKEN, headers)
                    fired, msg = _browser_dialog(browser, port, html)
                    arms[arm_esc] = {
                        "verifier_confirmed": bool(v.get("confirmed")),
                        "verifier_context": v.get("context"),
                        "verifier_detail": str(v.get("detail") or "")[:200],
                        "browser_dialog": fired,
                        "dialog_message": msg,
                        "html_sha256": hashlib.sha256(
                            html.encode("utf-8")).hexdigest()[:16],
                    }
                verdict, controls_valid = _verdict(arms[esc], arms)
                finding_rows.append({
                    "type": f.get("type"),
                    "severity": f.get("severity"),
                    "payload": payload,
                    "marked": marked,
                    "arms": arms,
                    "controls_valid": controls_valid,
                    "verdict": verdict,
                })
                print(f"{ctx}/{esc}/sink={sink} {f.get('type')}: "
                      f"verifier={arms[esc]['verifier_confirmed']} "
                      f"browser={arms[esc]['browser_dialog']} "
                      f"-> {verdict}")
            results.append({
                "ctx": ctx, "esc": esc, "sink": sink,
                "net_finding_types": cand["types"],
                "findings": finding_rows,
                "verdict": (finding_rows[0]["verdict"]
                            if len(finding_rows) == 1
                            else ("inconclusive" if not finding_rows
                                  else "mixed")),
            })
        browser.close()
    srv.shutdown()

    counts = {"candidates": len(results)}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    artifact = {
        "meta": {
            "net_artifact": net_path.name,
            "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "method": METHOD, "token": TOKEN,
            "controls": list(CONTROLS),
            "engine": net["meta"]["engine"],
        },
        "summary": counts,
        "candidates": results,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(artifact, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    print(f"\n{json.dumps(counts, ensure_ascii=False)}\nwrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
