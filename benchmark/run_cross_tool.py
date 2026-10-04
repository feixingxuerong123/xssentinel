#!/usr/bin/env python
"""Phase 107: cross-tool comparison against THIRD-PARTY detection corpus.

Why this exists
---------------
Our 107-case benchmark plateaus at f1=1.000, but every one of those cases
was designed by us and every fix was made against a case we wrote.  That
is a self-referential loop: it proves we agree with ourselves.

This runner breaks the loop by scoring XSSentinel and third-party tools
against the SAME targets:
  * nuclei-dast-xss  -- ProjectDiscovery's DAST XSS templates: their
                        payloads, their matching, their idea of a finding
  * dalfox           -- if installed
Both are maintained outside this repo, so agreement/disagreement is
evidence about our detection rather than a restatement of our own cases.

Output: per-tool TP/FP/TN/FN + a per-case matrix + disagreement
attribution (who missed what, who claimed what).

Usage
-----
    python benchmark/run_cross_tool.py --out benchmark/results/cross_tool.json
    python benchmark/run_cross_tool.py --ids pos-elem-01,neg-escape-01 ...
    python benchmark/run_cross_tool.py --all        # slow: ~44s/case nuclei
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
from http.server import ThreadingHTTPServer

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)
sys.path.insert(0, _ROOT)

from benchmark.adapters import get_adapters  # noqa: E402
from benchmark.server import BenchmarkHandler, load_routes  # noqa: E402

# A representative slice: one per vulnerable context family, plus the
# SAFE families that trip reflection-only tools (escaped / comment /
# attribute / CSP / JSONP / encoded RCDATA).
#
# Naming trap: "neg-" here means "a defence is present", NOT "safe".
# neg-rcdata-01..04 and neg-filter-01..03/05/06 are ground-truth
# VULNERABLE (the defence is bypassable); the safe twins carry an
# explicit escape_* mode or a different suffix.
DEFAULT_IDS = [
    # vulnerable -- one per context / defence-bypass family
    "pos-elem-01", "pos-attr-01", "pos-attr-05", "pos-script-01",
    "pos-script-03", "pos-comment-01", "pos-url-01", "pos-dom-01",
    "pos-svg-01", "pos-polyglot-01", "neg-rcdata-01", "neg-filter-01",
    # safe -- where reflection-only tools tend to false-positive
    "neg-escape-01", "neg-comment-01", "neg-attr-01", "neg-csp-01",
    "neg-jsonp-01", "neg-rcdata-05",
]


def stratified_slice(cases: list, n: int) -> list:
    """Pick n cases round-robin over (ground_truth, context) groups.

    Deterministic -- no seed to keep in sync -- and it cannot silently
    collapse onto one big family: the 192-case manifest has 82 html_element
    cases, so a naive head(n) sample measures one context and calls it a
    comparison.  Round-robin spends the budget on breadth first, then tops
    up the families that still have cases left.
    """
    groups: dict[tuple, list] = {}
    for c in cases:
        groups.setdefault((c["ground_truth"], c["context"]), []).append(c)
    # stable order: vulnerable before safe, then context name
    ordered = sorted(groups, key=lambda k: (k[0] != "vulnerable", k[0], k[1]))
    picked, depth = [], 0
    while len(picked) < n:
        added = False
        for key in ordered:
            bucket = groups[key]
            if depth < len(bucket):
                picked.append(bucket[depth])
                added = True
                if len(picked) >= n:
                    break
        if not added:
            break  # fewer cases than requested
        depth += 1
    return picked[:n]


def tool_version(adapter) -> str:
    """Record what build of the third-party tool the evidence was gathered
    against -- a comparison without the compared version is not reproducible."""
    binary = getattr(adapter, "_binary", None)
    if not binary:
        path = getattr(adapter, "_path", None)
        return f"source:{path}" if path else "builtin"
    flag = "-version" if "nuclei" in os.path.basename(binary).lower() else "version"
    try:
        proc = subprocess.run([binary, flag],
                              capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=30)
        # dalfox answers with an ANSI box-drawing fox before the number, and
        # printing that to a GBK console is what once killed the whole run.
        text = ((proc.stdout or "") + (proc.stderr or "")).encode(
            "ascii", "replace").decode("ascii")
        found = re.search(r"v?\d+\.\d+\.\d+[-\w]*", text)
        return found.group(0) if found else (
            (text.strip().splitlines() or ["unknown"])[-1][:60])
    except Exception as exc:  # noqa: BLE001 - version stamping must never kill a run
        return f"unknown ({exc})"


def engine_fingerprint() -> str:
    """Hash of every engine source file -- recorded in the artifact.

    Each XSSentinel case re-imports the package in a fresh subprocess, so a
    scan of the tree *while the run is in flight* silently mixes builds and
    the per-tool numbers stop meaning anything.  Fingerprinting before and
    after turns "we think nothing moved" into a checked claim.
    """
    h = hashlib.sha256()
    root = os.path.join(_ROOT, "xssentinel")
    for dirpath, dirnames, filenames in sorted(os.walk(root)):
        dirnames.sort()
        for fn in sorted(filenames):
            if fn.endswith(".py"):
                p = os.path.join(dirpath, fn)
                h.update(p.encode("utf-8", "replace"))
                with open(p, "rb") as f:
                    h.update(f.read())
    return h.hexdigest()[:16]


def main() -> int:
    # Third-party tools print whatever they like (ANSI art, emoji, \xc2\xa0).
    # On a GBK console that raised UnicodeEncodeError from a plain print()
    # and aborted the run mid-report, so the console is forced to UTF-8 with
    # lossy fallback: a garbled glyph must never cost us a measurement.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(
        _HERE, "results", "cross_tool.json"))
    ap.add_argument("--md", default=os.path.join(
        _HERE, "results", "cross_tool.md"))
    ap.add_argument("--ids", default="", help="comma-separated case ids")
    ap.add_argument("--all", action="store_true", help="run every case")
    ap.add_argument("--sample", type=int, default=0, metavar="N",
                    help="deterministic stratified slice of N cases, one per "
                         "(ground_truth, context) before repeating a family")
    ap.add_argument("--tools", default="XSSentinel,nuclei-dast-xss",
                    help="comma-separated adapter names")
    # 8896 sat inside a Windows dynamic-reservation range on some boots
    # (Phase 179: netsh excludedportrange swallows the whole 88xx habit);
    # the project-wide answer is 18xxx, so the default follows it.
    ap.add_argument("--port", type=int, default=18896)
    args = ap.parse_args()

    man = json.load(open(os.path.join(_HERE, "manifest.json"),
                         encoding="utf-8"))
    all_cases = man["cases"] if isinstance(man, dict) else man
    by_id = {c["id"]: c for c in all_cases}

    missing = []
    if args.all:
        cases = list(all_cases)
    elif args.ids:
        ids = [s.strip() for s in args.ids.split(",") if s.strip()]
        cases = [by_id[i] for i in ids if i in by_id]
        missing = [i for i in ids if i not in by_id]
    elif args.sample:
        cases = stratified_slice(all_cases, args.sample)
    else:
        cases = [by_id[i] for i in DEFAULT_IDS if i in by_id]
        missing = [i for i in DEFAULT_IDS if i not in by_id]
    if missing:
        print(f"[!] unknown case ids: {missing}")

    wanted = {s.strip() for s in args.tools.split(",") if s.strip()}
    adapters = [a for a in get_adapters(only_available=True)
                if a.name in wanted]
    if not adapters:
        print("[!] no requested adapter is available")
        return 1
    versions = {a.name: tool_version(a) for a in adapters}
    fp_start = engine_fingerprint()
    print(f"[*] tools: {', '.join(a.name for a in adapters)}")
    print(f"[*] engine fingerprint: {fp_start}")
    for name, ver in versions.items():
        print(f"    {name}: {ver}")
    print(f"[*] cases: {len(cases)}")

    BenchmarkHandler.routes = load_routes()
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), BenchmarkHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{args.port}"
    time.sleep(0.5)

    per_tool: dict[str, dict] = {}
    matrix: dict[str, dict] = {c["id"]: {"ground_truth": c["ground_truth"],
                                        "mode": c["mode"],
                                        "context": c["context"]} for c in cases}
    try:
        for a in adapters:
            print(f"\n[*] {a.name}")
            cm = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "errors": 0}
            t_start = time.time()
            for c in cases:
                r = a.scan_case(base, c)
                det = bool(r["detected"])
                err = r.get("error")
                if err:
                    # Any error -- timeout, "not installed", rc!=0, or a run
                    # that emitted unparseable output -- means this case was
                    # not measured.  Scoring it TN/FN would let a crash
                    # masquerade as a verdict; the adapters' own contract
                    # says so, and the old check caught only two of the five
                    # error shapes and scored the rest as clean.
                    cm["errors"] += 1
                    matrix[c["id"]][a.name] = None
                    mark = "ERR"
                else:
                    matrix[c["id"]][a.name] = det
                    gt = c["ground_truth"]
                    if gt == "vulnerable":
                        k = "tp" if det else "fn"
                    else:
                        k = "fp" if det else "tn"
                    cm[k] += 1
                    mark = {"tp": "TP", "fn": "FN", "fp": "FP",
                            "tn": "TN"}[k]
                print(f"    {c['id']:18} gt={c['ground_truth']:10} "
                      f"{mark:3} ({r['time_s']:.1f}s)"
                      f"{f' [{err}]' if err else ''}", flush=True)
            scored = cm["tp"] + cm["fp"] + cm["tn"] + cm["fn"]
            cm["completed"] = scored
            prec = cm["tp"] / (cm["tp"] + cm["fp"]) if cm["tp"] + cm["fp"] else None
            rec = cm["tp"] / (cm["tp"] + cm["fn"]) if cm["tp"] + cm["fn"] else None
            cm["precision"] = round(prec, 4) if prec is not None else None
            cm["recall"] = round(rec, 4) if rec is not None else None
            cm["f1"] = (round(2 * prec * rec / (prec + rec), 4)
                        if prec and rec else None)
            cm["total_time_s"] = round(time.time() - t_start, 1)
            per_tool[a.name] = cm
    finally:
        srv.shutdown()

    # ---- disagreement attribution -------------------------------------
    names = [a.name for a in adapters]
    disagreements = []
    for cid, row in matrix.items():
        gt = row["ground_truth"]
        for name in names:
            if name not in row or row[name] is None:
                continue  # errored: not measured, so not a disagreement
            det = row[name]
            if gt == "vulnerable" and not det:
                disagreements.append(
                    {"case": cid, "context": row["context"], "tool": name,
                     "kind": "missed-a-real-XSS"})
            if gt == "safe" and det:
                disagreements.append(
                    {"case": cid, "context": row["context"], "tool": name,
                     "kind": "false-positive"})

    out = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "base_url": base,
        "tools": names,
        "tool_versions": versions,
        "engine_fingerprint_start": fp_start,
        "engine_fingerprint_end": engine_fingerprint(),
        "engine_stable": fp_start == engine_fingerprint(),
        "slice": {"requested_sample": args.sample, "all": args.all,
                  "ids": [c["id"] for c in cases]},
        "cases": len(cases),
        "per_tool": per_tool,
        "matrix": matrix,
        "disagreements": disagreements,
    }
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"\n[+] saved {args.out}")

    # ---- markdown report ----------------------------------------------
    lines = ["# Cross-tool XSS comparison (third-party corpus)", "",
             f"Generated: {out['generated']}  ",
             f"Targets: {base}  ",
             f"Cases: {len(cases)} (same targets for every tool)  ",
             f"Engine build: `{fp_start}` "
             f"({'stable across the run' if out['engine_stable'] else 'CHANGED MID-RUN -- numbers are not attributable'})  ",
             "Tool builds: " + ", ".join(f"{n} = {versions[n]}" for n in names),
             "",
             "| tool | TP | FP | TN | FN | errors | precision | recall | f1 | time (s) |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for n in names:
        c = per_tool[n]
        lines.append(
            f"| {n} | {c['tp']} | {c['fp']} | {c['tn']} | {c['fn']} | "
            f"{c['errors']} | {c['precision']} | {c['recall']} | {c['f1']} | "
            f"{c['total_time_s']} |")
    lines += ["", "## Per-case matrix", "",
              "| case | context | ground truth | " + " | ".join(names) + " |",
              "|---|---|---|" + "---|" * len(names)]
    for cid, row in matrix.items():
        cells = []
        for n in names:
            if n not in row:
                cells.append("-")
            elif row[n] is None:
                cells.append("err")
            else:
                det = row[n]
                gt = row["ground_truth"]
                ok = (det and gt == "vulnerable") or (not det and gt == "safe")
                cells.append(("yes" if det else "no") + ("" if ok else " !"))
        lines.append(f"| {cid} | {row['context']} | {row['ground_truth']} | " +
                     " | ".join(cells) + " |")
    lines += ["", "## Disagreements with ground truth", ""]
    if not disagreements:
        lines.append("(none)")
    for d in disagreements:
        lines.append(f"- `{d['case']}` ({d['context']}): **{d['tool']}** "
                     f"{d['kind']}")
    with open(args.md, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"[+] saved {args.md}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
