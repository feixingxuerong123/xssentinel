# -*- coding: utf-8 -*-
"""The generative FN/FP net -- behavioural coverage over (context x escaping
x page-feature sink).

Why this exists: the LAYER coverage matrix is 52/52 (every engine layer is
exercised by at least one manifest case), so "layer has no case" is no longer
where the gaps are.  What the matrix does NOT say is whether the engine still
finds the reflection when the SAME shape is rendered in a different context
with a different escaping/filter in front of it -- and whether it stays
SILENT when that reflection is dead.  The first question is the escaping-blind
FN family (Phase 123, 128, 130); the second is its mirror image, the
escaping-blind FP family, and it is the one the net used to skip.

Method (the benchmark-case-authoring skill's Phase 130 rule, and the reason
this net is honest): the ENGINE'S OWN verifier is the ground truth, not
"there must be a finding".  Otherwise a target that never simulated the shape
would be scored as a false negative, i.e. the net would talk to itself.

For every (context x escaping x sink) combination /fuzz/render can render:

  verifier confirms  + scanner reports    -> covered (with the real finding
                                             types printed, not just a count)
  verifier confirms  + scanner silent     -> FN CANDIDATE (a real miss)
  verifier refuses   + scanner silent     -> neutralised (informational)
  verifier refuses   + scanner reports    -> FP CANDIDATE (Phase 251: this
                                             arm is what was missing; it is
                                             the escaping-blind FP family)

A candidate is a candidate, not a verdict: the verifier only judges the
``--top`` corpus shapes, so a finding can be a real detection whose payload
shape the net never tried.  Every candidate must be re-verified against the
finding's OWN payload before it is called a bug (that is what
dev/_p251_fp_check.py does).

Two harness lessons are baked in, both measured the hard way in Phase 231:
  * the scanner side goes through benchmark.runner._invoke_scanner (the CLI
    subprocess the matrix itself scores through) -- an in-process
    Scanner(scan_target) on this endpoint sent 66 requests and confirmed
    nothing, a harness artefact, not an engine verdict;
  * the scan runs from a CLEAN url (q=probe); pre-filling q with the marked
    payload hands the scanner a poisoned baseline.

The endpoint itself is Phase 129's /fuzz/render (EXTRA_ROUTES -- never
scored); the sink dimension is Phase 251 (the endpoint already had it; the
net never strung it on).

Run:  C:/Python39/python.exe dev/fn_net.py [--only ctx:esc,...]
      [--sinks none,dom] [--top N] [--out PATH]
      writes benchmark/results/fn_net_<date>.json (a re-runnable baseline).

Lives in dev/ WITHOUT the "_" prefix on purpose: unlike a one-off probe this
is meant to be kept and re-run after judgement-semantics changes.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

import requests  # noqa: E402

from xssentinel.core import verifier  # noqa: E402
from xssentinel.core.payloads import by_context  # noqa: E402

# Endpoint ctx name -> corpus context key.  Both sides taken from the code:
# the left from _FUZZ_TEMPLATES in benchmark/server.py, the right from the
# corpus's own context keys (xssentinel/core/payloads.py), NOT guessed.
CTX_MAP = {
    "text": "html_element",
    "attr_dq": "html_attribute_dq",
    "attr_sq": "html_attribute_sq",
    "attr_bare": "html_attribute_noquote",
    "script_dq": "script_string_dq",
    "script_sq": "script_string_sq",
    "href": "url_javascript",
    "svg": "svg_context",
    "comment": "html_comment",
}

SINKS = ["none", "dom"]

ESCS = ["raw", "html", "attr", "strip_script", "encode_angles",
        "encode_quotes", "strip_tags", "strip_handlers", "entity_decode",
        "escape_lt_only", "strip_script_recursive"]


def _start_server():
    spec = importlib.util.spec_from_file_location(
        "bench_server", os.path.join(ROOT, "benchmark/server.py"))
    srv_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(srv_mod)
    box, started = {}, threading.Event()
    threading.Thread(
        target=srv_mod.run_server, args=(0,),
        kwargs={"ready_callback": lambda s: (
            box.__setitem__("p", s.server_address[1]), started.set())},
        daemon=True).start()
    assert started.wait(10), "benchmark server did not start"
    time.sleep(0.2)
    return f"http://127.0.0.1:{box['p']}"


def _scan(url, tries=2):
    from benchmark.runner import _invoke_scanner
    last = None
    for _ in range(tries):
        rep, el, err = _invoke_scanner(url, timeout=60, max_payloads=14,
                                       max_transforms=12, engine="sync")
        last = (rep, el, err)
        if rep is not None and not err:
            return rep, el, err
    return last


def _get(url):
    return requests.get(url, timeout=30)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="",
                    help="limit to these combos: 'ctx' or 'ctx:esc'")
    ap.add_argument("--sinks", default="none,dom",
                    help="page-feature sinks to sweep (comma separated)")
    ap.add_argument("--top", type=int, default=3,
                    help="corpus shapes tried per combination")
    ap.add_argument("--out", default="", help="result JSON path")
    args = ap.parse_args()

    only_ctx = {x.split(":", 1)[0] for x in args.only.split(",") if x}
    only_pair = {tuple(x.split(":", 1)) for x in args.only.split(",")
                 if ":" in x}

    covered = fn_candidates = neutralised = fp_candidates = 0
    fn_rows, fp_rows, rows = [], [], []
    sinks = [x for x in args.sinks.split(",") if x]

    base = _start_server()
    print(f"server {base}  sinks={sinks}")
    t0 = time.time()
    for ctx, corpus_ctx in CTX_MAP.items():
        if only_ctx and ctx not in only_ctx and not any(
                p[0] == ctx for p in only_pair):
            continue
        corpus = by_context(corpus_ctx)
        if not corpus:
            print(f"[{ctx}] no corpus for {corpus_ctx} -- skipped")
            continue
        picks = corpus[:args.top]
        for sink in sinks:
            for esc in ESCS:
                if only_pair and (ctx, esc) not in only_pair:
                    continue
                # Ground truth: the FIRST corpus payload the ENGINE'S OWN
                # verifier confirms live in this (ctx, esc, sink) rendering.
                live = None
                for pi, item in enumerate(picks):
                    cand = item["payload"]
                    token = f"fn{abs(hash((ctx, esc, sink, pi))) % 10**8}"
                    marked = verifier.mark(cand, token)
                    url = (f"{base}/fuzz/render?ctx={ctx}&esc={esc}"
                           f"&sink={sink}"
                           f"&q={requests.utils.quote(marked)}")
                    try:
                        r = _get(url)
                    except Exception:
                        continue
                    verdict = verifier.verify_semantic(r.text, token,
                                                       dict(r.headers))
                    if verdict.get("confirmed"):
                        live = cand
                        break
                scan_url = (f"{base}/fuzz/render?ctx={ctx}&esc={esc}"
                            f"&sink={sink}&q=probe")
                if live is None:
                    # Phase 251 FP ARM.  "The verifier refuses every corpus
                    # shape" used to be the end of the story; now it is
                    # followed by "did the scanner report anyway?" -- which
                    # is the escaping-blind FP family (reflection dead, page
                    # feature alive, layer fires on the feature alone).
                    r2, _el2, err2 = _scan(scan_url)
                    n2, t2 = -1, []
                    if err2 or r2 is None:
                        t2 = [f"ERROR:{str(err2)[:40]}"]
                    else:
                        fs2 = r2.get("findings") or []
                        n2 = len(fs2)
                        t2 = sorted({f.get("type") for f in fs2})
                    neutralised += 1
                    rows.append({"ctx": ctx, "esc": esc, "sink": sink,
                                 "verified": False, "payload": None,
                                 "findings": n2, "types": t2})
                    if n2 > 0:
                        fp_candidates += 1
                        fp_rows.append((ctx, esc, sink, n2, t2))
                        print(f"  FP?     {ctx:10} {esc:22} sink={sink:5} "
                              f"findings={n2} {t2}")
                    else:
                        print(f"  neutral {ctx:10} {esc:22} sink={sink:5} "
                              f"(verifier refuses all {len(picks)} shapes, "
                              f"scanner silent)")
                    continue
                payload = live
                report, elapsed, err = _scan(scan_url)
                if err or report is None:
                    n, types = -1, [f"ERROR:{err[:40]}"]
                else:
                    fs = report.get("findings", [])
                    n = len(fs)
                    types = sorted({f.get("type") for f in fs})
                rows.append({"ctx": ctx, "esc": esc, "sink": sink,
                             "verified": True, "payload": payload,
                             "findings": n, "types": types})
                if n > 0:
                    covered += 1
                    print(f"  covered {ctx:10} {esc:22} sink={sink:5} "
                          f"findings={n} {types}")
                else:
                    fn_candidates += 1
                    fn_rows.append((ctx, esc, sink, payload, n, types))
                    print(f"  FN?     {ctx:10} {esc:22} sink={sink:5} "
                          f"findings={n} payload={payload[:50]!r}")

    out = args.out or os.path.join(ROOT, "benchmark", "results",
                                   f"fn_net_{time.strftime('%Y%m%d')}.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"meta": {"generated": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "endpoint": "/fuzz/render",
                            "budgets": {"max_payloads": 14,
                                        "max_transforms": 12},
                            "top": args.top,
                            "engine": "sync",
                            "sinks": sinks},
                   "summary": {"covered": covered,
                               "fn_candidates": fn_candidates,
                               "fp_candidates": fp_candidates,
                               "neutralised": neutralised},
                   "rows": rows}, fh, ensure_ascii=False, indent=1)
    print(f"saved: {out}")
    print("=" * 70)
    print(f"covered={covered} fn_candidates={fn_candidates} "
          f"fp_candidates={fp_candidates} neutralised={neutralised} "
          f"({time.time() - t0:.0f}s)")
    if fp_rows:
        print("FP candidates (verifier REFUSES, scanner reports anyway):")
        for ctx, esc, sink, n, types in fp_rows:
            print(f"  {ctx}/{esc}/sink={sink}: findings={n} {types}")
    if fn_rows:
        print("FN candidates (verifier-confirmed, scanner silent):")
        for ctx, esc, sink, payload, n, types in fn_rows:
            print(f"  {ctx}/{esc}/sink={sink}: {payload[:80]!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
