# -*- coding: utf-8 -*-
"""Is a Rust/single-binary rewrite worth it?  Measure where wall time goes.

Question (2026-11-06): "does a single binary / native rewrite give a REAL
speedup, ignoring how long it takes to build?"  A language rewrite can only
remove CPU time.  So measure the CPU fraction of a real scan, and how wall
time reacts when the target adds pure network latency:

* If wall grows with latency while CPU stays flat, the scan is I/O-bound and
  Amdahl caps the speedup from any language change at 1/(1 - cpu_fraction).
* cProfile shows whether the CPU that DOES exist is pure Python logic or
  C-extension work (lxml/bs4), which a rewrite would have to re-implement.

Output: dev/_perf_breakdown.json
"""
from __future__ import annotations

import json
import os
import statistics
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = os.path.join(ROOT, "dev", "_perf_tmp")
os.makedirs(TMP, exist_ok=True)
PY = sys.executable
ENV = {**os.environ, "NO_PROXY": "127.0.0.1,localhost",
       "no_proxy": "127.0.0.1,localhost", "PYTHONIOENCODING": "utf-8",
       "PYTHONPATH": ROOT}

WRAPPER = r'''
import json, sys, time
from xssentinel.__main__ import main
_t0 = time.perf_counter(); _c0 = time.process_time()
_rc = main(sys.argv[1:])
print("PERF " + json.dumps({"rc": _rc,
    "wall": round(time.perf_counter() - _t0, 4),
    "cpu": round(time.process_time() - _c0, 4)}), file=sys.stderr)
'''

PROFILE_WRAPPER = r'''
import cProfile, pstats, sys, io
from xssentinel.__main__ import main
_p = cProfile.Profile()
_p.enable(); main(sys.argv[1:]); _p.disable()
_s = io.StringIO()
pstats.Stats(_p, stream=_s).sort_stats("cumtime").print_stats(18)
print(_s.getvalue())
'''


class T(BaseHTTPRequestHandler):
    delay = 0.0
    hits = 0

    def do_GET(self):
        from urllib.parse import parse_qs, urlparse
        if T.delay:
            time.sleep(T.delay)
        T.hits += 1
        q = (parse_qs(urlparse(self.path).query).get("q") or [""])[-1]
        b = ("<html><body><div id=out>" + q +
             "</div></body></html>").encode("utf-8", "replace")
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


class Quiet(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass


def scan_interleaved(target, delays=(0.0, 0.03), repeats=7):
    """Alternate delays each round so host-side drift hits both equally.

    The first (non-interleaved) run had wall times swinging 0.77s <-> 4.2s
    while CPU stayed at 0.5-0.7s: the loopback degradation this project has
    documented since Phase 201.  Interleaving removes that confound; min
    wall is the closest estimate of an undisturbed run.
    """
    rows = {d: [] for d in delays}
    argv = ["-u", target, "-o", os.path.join(TMP, "r.json"), "-f", "json",
            "--max-payloads", "3", "--max-transforms", "1",
            "--dom-engine", "static", "--timeout", "3"]
    for _ in range(repeats):
        for d in delays:
            T.delay = d
            p = subprocess.run([PY, "-c", WRAPPER, *argv], cwd=TMP, env=ENV,
                               capture_output=True, timeout=120)
            line = [ln for ln in p.stderr.decode("utf-8", "replace").splitlines()
                    if ln.startswith("PERF ")]
            if not line:
                raise RuntimeError(p.stderr[-500:].decode("utf-8", "replace"))
            rows[d].append(json.loads(line[-1][5:]))
    out = {}
    for d, rs in rows.items():
        wall = [r["wall"] for r in rs]
        cpu = [r["cpu"] for r in rs]
        frac = statistics.median(cpu) / min(wall)
        out[str(d)] = {
            "delay_s": d, "repeats": rs,
            "wall_min": round(min(wall), 3),
            "wall_med": round(statistics.median(wall), 3),
            "wall_max": round(max(wall), 3),
            "cpu_min": round(min(cpu), 3),
            "cpu_med": round(statistics.median(cpu), 3),
            "cpu_max": round(max(cpu), 3),
            "cpu_fraction_of_undisturbed_wall": round(frac, 4),
            "amdahl_max_speedup": round(1 / (1 - frac), 2) if frac < 1 else None,
        }
    a, b = out[str(delays[0])], out[str(delays[1])]
    out["latency_sensitivity"] = {
        "wall_delta_s": round(b["wall_med"] - a["wall_med"], 3),
        "cpu_delta_s": round(b["cpu_med"] - a["cpu_med"], 3),
        "note": "wall grows with network latency while CPU stays flat -> "
                "I/O-bound; a language rewrite can only touch the CPU part.",
    }
    return out


def main():
    srv = Quiet(("127.0.0.1", 0), T)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    target = "http://127.0.0.1:%d/?q=probe" % srv.server_address[1]
    result = {"python": sys.version}

    # 1. cold start: import cost only (what a single binary would remove).
    cold = []
    for _ in range(5):
        t = time.perf_counter()
        subprocess.run([PY, "-c", "import xssentinel.__main__"], cwd=ROOT,
                       env=ENV, capture_output=True, timeout=60)
        cold.append(round(time.perf_counter() - t, 3))
    result["cold_import_s"] = {"values": cold,
                               "median": statistics.median(cold)}

    # 2. real scans at two network latencies, interleaved.
    result["scans"] = scan_interleaved(target)

    # Project onto the documented 60-case cross-tool run (README.md:233,
    # XSSentinel 346s).  That runner is SEQUENTIAL and starts a fresh
    # subprocess per case (benchmark/run_cross_tool.py engine_fingerprint
    # docstring), so cold start is paid 60 times.  This is a projection from
    # the local measurement, not a re-run of the 60-case benchmark.
    cpu_med = result["scans"]["0.03"]["cpu_med"]
    cold_med = result["cold_import_s"]["median"]
    share = cpu_med * 60 / 346
    result["projection_60case"] = {
        "source": "README 60-case cross-tool: 346s; sequential subprocess/case",
        "per_case_wall_s": round(346 / 60, 2),
        "cold_start_paid_60x_s": round(cold_med * 60, 1),
        "cold_start_share": round(cold_med * 60 / 346, 3),
        "cpu_paid_60x_s": round(cpu_med * 60, 1),
        "cpu_share": round(share, 3),
        "amdahl_upper_bound_x": round(1 / (1 - share), 2),
        "note": "Language rewrite can only touch cpu_share; the cold-start "
                "share is removed by batch/daemon, not by Rust.",
    }

    # 3. where CPU time actually goes (profile distorts absolute times;
    #    only the function distribution is used).
    argv = ["-u", target, "-o", os.path.join(TMP, "prof.json"), "-f", "json",
            "--max-payloads", "3", "--max-transforms", "1",
            "--dom-engine", "static", "--timeout", "3"]
    p = subprocess.run([PY, "-c", PROFILE_WRAPPER, *argv], cwd=TMP, env=ENV,
                       capture_output=True, timeout=180)
    profile_lines = p.stdout.decode("utf-8", "replace").splitlines()
    header = next((i for i, ln in enumerate(profile_lines)
                   if "cumtime" in ln), 0)
    result["profile_top"] = [ln.rstrip() for ln in
                             profile_lines[header:header + 22]]

    srv.shutdown()
    srv.server_close()
    with open(os.path.join(ROOT, "dev", "_perf_breakdown.json"), "w",
              encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=1)

    print("cold import median: %ss  %s" %
          (result["cold_import_s"]["median"], result["cold_import_s"]["values"]))
    for k, s in result["scans"].items():
        if not isinstance(s, dict) or "wall_med" not in s:
            continue
        print("delay %-5s wall=%.3fs (min %.3f) cpu=%.3fs cpu%%=%.1f%% "
              "amdahl_max=%.2fx" %
              (k, s["wall_med"], s["wall_min"], s["cpu_med"],
               s["cpu_fraction_of_undisturbed_wall"] * 100,
               s["amdahl_max_speedup"] or 0))
    print("latency sensitivity:", result["scans"]["latency_sensitivity"])
    print("profile top:")
    for ln in result["profile_top"][:12]:
        print("  ", ln.strip()[:120])
    return 0


if __name__ == "__main__":
    sys.exit(main())
