# -*- coding: utf-8 -*-
"""Range #7 runner: an independent CMS, scored with the real CLI.

Same topology as ranges 3-6: the server runs in THIS process, the scanner
runs as a subprocess.  Differences that matter for scoring:

  * stored cases are declared sync-only in the manifest (the async engine
    has no stored pass), so their async row is SKIP, not FN;
  * `--headless` is passed only where the manifest asks for it -- the two
    DOM cases -- so a reflected case cannot be credited by browser work it
    does not need;
  * the gate is the same standard as range4: any FN/FP/ERROR fails, and a
    `headless: true` positive that scored TP without a fired browser
    finding fails too (a dead Chromium must not pass as a weaker TP).

Usage:  python range7/runner.py [--engine both] [--timeout 120]
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import requests  # noqa: E402
from range_gate import (evidence_gaps, failing_rows,  # noqa: E402
                        invoke_with_retries)
from server import run_server  # noqa: E402

PORT = 19707


def _invoke_scanner(url: str, timeout: int, max_payloads: int,
                    max_transforms: int, engine: str, headless: bool,
                    stored: dict | None) -> tuple[dict | None, float, str]:
    out_path = os.path.join(tempfile.gettempdir(), f"r7_poc_{os.getpid()}.json")
    cmd = [sys.executable, "-m", "xssentinel",
           "-u", url, "-f", "json", "-o", out_path,
           "--progress", "none", "--log-level", "error",
           "--max-payloads", str(max_payloads),
           "--max-transforms", str(max_transforms),
           "--timeout", "10"]
    if headless:
        cmd.append("--headless")
    if stored:
        cmd += ["--stored-inject", stored["inject"],
                "--stored-view", stored["view"],
                "--stored-param", stored.get("param", "text")]
    if engine == "async":
        cmd += ["--async", "--threads", "4"]
    start = time.perf_counter()
    err = ""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, cwd=str(ROOT))
        if proc.returncode not in (0, 1):
            err = f"exit={proc.returncode}: {proc.stderr[:200]}"
    except subprocess.TimeoutExpired:
        err = f"timeout after {timeout}s"
    elapsed = time.perf_counter() - start
    report = None
    try:
        if os.path.isfile(out_path):
            content = open(out_path, encoding="utf-8").read().strip()
            if content:
                report = json.loads(content)
    except Exception as e:  # noqa: BLE001
        if not err:
            err = f"report parse: {e}"
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass
    return report, elapsed, err


def score(report: dict | None, case: dict) -> str:
    fs = (report or {}).get("findings", [])
    if case["gt"] == "safe":
        bad = [f for f in fs
               if f.get("severity") in ("high", "medium", "critical")
               and not str(f.get("type", "")).startswith("csp_")]
        return "FP" if bad else "TN"
    hits = [f for f in fs
            if f.get("severity") in ("high", "medium", "critical")]
    return "TP" if hits else "FN"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", default="both", choices=["sync", "async", "both"])
    ap.add_argument("--timeout", type=int, default=150)
    ap.add_argument("--budget", default="10,6")
    ap.add_argument("--out", default=str(Path(__file__).parent / "results.json"))
    args = ap.parse_args()
    mp, mt = (int(x) for x in args.budget.split(","))

    started = threading.Event()
    threading.Thread(target=run_server, args=(PORT,),
                     kwargs={"ready_callback": lambda s: started.set()},
                     daemon=True).start()
    if not started.wait(10):
        print("[!] range7 server failed to start")
        return 1
    time.sleep(0.2)
    base = f"http://127.0.0.1:{PORT}"
    r = requests.get(f"{base}/", timeout=5)
    assert r.status_code == 200 and "Range7" in r.text, "probe failed"
    print(f"[*] Range7 ready on {base}")

    manifest = json.loads((Path(__file__).parent / "manifest.json")
                          .read_text(encoding="utf-8"))
    cases_by_id = {c["id"]: c for c in manifest["cases"]}
    engines = ["sync", "async"] if args.engine == "both" else [args.engine]
    rows: list[dict] = []
    summary: dict[str, dict[str, int]] = {}
    for eng in engines:
        print(f"\n=== engine={eng} ===")
        counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "SKIP": 0, "ERROR": 0}
        for case in manifest["cases"]:
            if case.get("engines") and eng not in case["engines"]:
                counts["SKIP"] += 1
                rows.append({"engine": eng, "case_id": case["id"],
                             "verdict": "SKIP"})
                print(f"  [{eng:5}] {case['id']:18} SKIP  (manifest: "
                      f"{case['engines']} only)")
                continue
            url = f"{base}{case['path']}"
            if case.get("param"):
                url += f"?{case['param']}=xssentinel"
            stored = None
            if case.get("stored_inject"):
                stored = {"inject": base + case["stored_inject"],
                          "view": base + case["stored_view"],
                          "param": case.get("stored_param", "text")}
            report, elapsed, err, attempts = invoke_with_retries(
                _invoke_scanner, url, timeout=args.timeout, max_payloads=mp,
                max_transforms=mt, engine=eng,
                headless=bool(case.get("headless")), stored=stored)
            verdict = "ERROR" if (err and report is None) else score(report, case)
            counts[verdict] += 1
            detail = []
            for f in (report or {}).get("findings", []):
                hl = f.get("headless") or {}
                detail.append({"type": f.get("type"),
                               "severity": f.get("severity"),
                               "context": f.get("context"),
                               "param": f.get("param"),
                               "headless_outcome": hl.get("outcome")})
            confirmed = sum(1 for d in detail
                            if d["headless_outcome"] == "fired")
            n = len(detail)
            top = ""
            if detail:
                top = (f"{detail[0]['type']}/{detail[0]['severity']}/"
                       f"{detail[0]['context']}/{detail[0]['headless_outcome']}")
            mark = "" if verdict in ("TP", "TN") else f"   <-- {verdict} {err[:60]!r}"
            print(f"  [{eng:5}] {case['id']:18} {verdict:5} findings={n:2} "
                  f"{elapsed:5.1f}s{mark}")
            if top:
                print(f"          top: {top}  browser-confirmed={confirmed}")
            rows.append({"engine": eng, "case_id": case["id"],
                         "verdict": verdict, "findings": n,
                         "confirmed": confirmed,
                         "elapsed_s": round(elapsed, 1), "retries": attempts,
                         "findings_detail": detail, "error": err[:200]})
        print(f"  => TP{counts['TP']} FP{counts['FP']} TN{counts['TN']} "
              f"FN{counts['FN']} SKIP{counts['SKIP']} ERR{counts['ERROR']}")
        summary[eng] = counts

    payload = {
        "meta": {"range": "range7",
                 "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
                 "engines": engines, "max_payloads": mp,
                 "max_transforms": mt, "per_case_timeout": args.timeout,
                 "construct_probe": "tests/test_range7_construct.py"},
        "counts": summary,
        "rows": rows,
    }
    Path(args.out).write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                              encoding="utf-8")
    print(f"\n[*] written -> {args.out}")

    bad = failing_rows(rows)
    if bad:
        print("\n[!] RANGE7 GATE FAILED (TP/TN required on every case):")
        for row in bad:
            print(f"    - [{row['engine']}] {row['case_id']}: "
                  f"{row['verdict']} {row.get('error', '')[:120]}")
        return 1
    gaps = evidence_gaps(rows, cases_by_id)
    if gaps:
        print("\n[!] RANGE7 GATE FAILED (positive without browser evidence):")
        for eng, cid in gaps:
            print(f"    - [{eng}] {cid}: TP but no finding fired in the browser")
        return 1
    print("[*] Range7 gate: every case scored, every positive browser-confirmed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
