#!/usr/bin/env python3
"""Range #6 gate runner -- sanitizer edition.

Gate semantics are the range4/range5 standard: TP/TN required on every
case, FN/FP/ERROR => exit 1.  The FP rule is the Phase 160 one already
used by range4/5: on a safe case, any high/medium/critical finding that
is not a low-severity csp_* hygiene note counts as a false positive.

Two deviations from range5/runner.py, both learned the hard way:

  * ``server`` and ``runner`` are loaded BY PATH (importlib), never by
    bare name.  This repo has a second module called ``server``
    (benchmark/server.py) and a second called ``runner``
    (benchmark/runner.py); a bare import resolves by sys.path order, and
    in a full suite some earlier test has already put the wrong one in
    sys.modules (Phase 221d: test_range5 died exactly there).
  * the server binds ("127.0.0.1", 0) and the real port is captured from
    ready_callback.  No fixed port, no probe loop (Phase 206: Windows
    SO_REUSEADDR makes a successful bind prove nothing).
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from range_gate import failing_rows, invoke_with_retries  # noqa: E402


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


server = _load_module("range6_server", HERE / "server.py")


def _invoke_scanner(url: str, timeout: int, max_payloads: int,
                    max_transforms: int, engine: str) -> tuple[dict | None, float, str]:
    out_path = os.path.join(tempfile.gettempdir(),
                            f"r6_poc_{os.getpid()}.json")
    cmd = [sys.executable, "-m", "xssentinel",
           "-u", url, "-f", "json", "-o", out_path,
           "--progress", "none", "--log-level", "error",
           "--max-payloads", str(max_payloads),
           "--max-transforms", str(max_transforms),
           "--timeout", "10"]
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
    except Exception as e:
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
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", default="both", choices=["sync", "async", "both"])
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--out", default=str(HERE / "results.json"),
                    help="where to land the scored rows (retained products)")
    args = ap.parse_args()

    box: dict = {}
    started = threading.Event()

    def _ready(srv):
        box["port"] = srv.server_address[1]
        started.set()

    threading.Thread(target=server.run_server, args=(0,),
                     kwargs={"ready_callback": _ready},
                     daemon=True).start()
    if not started.wait(10):
        print("[!] range6 server failed to start")
        return 1
    time.sleep(0.3)
    base = f"http://127.0.0.1:{box['port']}"
    import requests
    # The runner owns this server: trust it only after a real probe.
    r = requests.get(f"{base}/", timeout=5)
    assert r.status_code == 200 and "Range6" in r.text, "probe failed"
    print(f"[*] Range6 ready on {base}")

    manifest = json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))
    engines = ["sync", "async"] if args.engine == "both" else [args.engine]
    all_rows = []
    summary: dict[str, dict[str, int]] = {}
    for eng in engines:
        print(f"\n=== engine={eng} ===")
        counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "ERROR": 0}
        for case in manifest["cases"]:
            url = f"{base}{case['path']}?{case['param']}=xssentinel"
            report, elapsed, err, attempts = invoke_with_retries(
                _invoke_scanner, url, timeout=args.timeout, max_payloads=8,
                max_transforms=4, engine=eng)
            verdict = "ERROR" if (err and report is None) else score(report, case)
            counts[verdict] += 1
            detail = [{"type": f.get("type"), "severity": f.get("severity"),
                       "context": f.get("context")}
                      for f in (report or {}).get("findings", [])]
            n = len(detail)
            mark = "" if verdict in ("TP", "TN") else f"   <-- {verdict} {err[:60]!r}"
            if attempts:
                mark += f"   (retried {attempts}x)"
            print(f"  [{eng:5}] {case['id']:24} {verdict:5} "
                  f"findings={n:2} {elapsed:5.1f}s{mark}")
            for d in detail:
                print(f"          - {d['severity']:6s} {d['type']}")
            all_rows.append({"engine": eng, "case_id": case["id"],
                             "verdict": verdict, "findings": n,
                             "elapsed_s": round(elapsed, 1),
                             "retries": attempts,
                             "findings_detail": detail, "error": err[:200]})
        print(f"  => TP{counts['TP']} FP{counts['FP']} TN{counts['TN']} "
              f"FN{counts['FN']} ERR{counts['ERROR']}")
        summary[eng] = counts

    payload = {
        "meta": {"range": "range6", "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
                 "engines": engines, "max_payloads": 8, "max_transforms": 4,
                 "per_case_timeout": args.timeout,
                 "construct_validity": "server bytes are query-independent "
                                       "(static shells); pinned by "
                                       "tests/test_range6.py"},
        "counts": summary,
        "rows": all_rows,
    }
    Path(args.out).write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                              encoding="utf-8")
    print(f"\n[*] written -> {args.out}")

    bad = failing_rows(all_rows)
    if bad:
        print("\n[!] RANGE6 GATE FAILED (TP/TN required on every case):")
        for r in bad:
            print(f"    - [{r['engine']}] {r['case_id']}: "
                  f"{r['verdict']} {r['error'][:120]}")
        return 1
    print("[*] Range6 gate: every case scored as ground truth requires")
    return 0


if __name__ == "__main__":
    sys.exit(main())
