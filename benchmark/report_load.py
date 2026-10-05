"""Report-layer load benchmark (OPTIMIZATION 2.2).

2.2 asks for a BASELINE before any optimization talk: "1000 findings 的
HTML 生成 < 2s(当前未测量,先建基准 —— 没有基线就别谈优化了多少)".
This script generates N deterministic synthetic findings shaped like the
scanner's real output (``_record`` fields + proof + headless verdicts,
varying types/contexts/severities/lengths) and times every report format
against them.

Usage:
    python benchmark/report_load.py                 # 1000 findings, 8 formats
    python benchmark/report_load.py --findings 200 --formats html,json

The result JSON lands in benchmark/results/report_load_<ts>.json so the
baseline is a committed artifact, not a memory.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from datetime import datetime

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)

from xssentinel.core import report as report_mod  # noqa: E402

_TYPES = [
    ("reflected", "html_element"), ("reflected", "html_attribute_dq"),
    ("reflected", "script_string_dq"), ("reflected", "url_javascript"),
    ("reflected", "event_handler"), ("reflected", "template_angular"),
    ("dom_dynamic", "html_element"), ("blind", "blind_oob"),
    ("polyglot_reflection", "html_element"), ("csp_bypass", "csp_header"),
    ("stored_dom", "stored_dom_view"), ("dom", "html_element"),
]
_SEVERITIES = ["high", "medium", "low"]
_CONFIDENCES = ["high", "medium", "low"]
_EVIDENCE = ["browser-executed", "model-only", "browser-unavailable",
             "browser-refuted", "oob-confirmed"]
_TRANSFORMS = [[], ["concat_stamp"], ["hpp"], ["csp_gadget"],
               ["mixed_case", "html_entity_named"], ["polyglot"]]
_CONTEXTS = ["login", "comment", "search", "profile", "admin", "api"]

_PAYLOAD_TAILS = [
    "<script>alert('xssv_{tok}')</script>",
    "\"><svg/onload=alert('xssv_{tok}')>",
    "';alert('xssv_{tok}')//",
    "<img src=x onerror=alert('xssv_{tok}')>",
    "{{constructor.constructor(\"alert('xssv_{tok}')\")()}}",
    "<script src=https://cdn.example/gadget?cb=alert('xssv_{tok}')//></script>",
]


def synthetic_findings(n: int, seed: int = 20261005) -> list:
    """N deterministic findings shaped like the scanner's real output.

    Field-for-field these mirror ``Scanner._record`` (plus the OOB/DOM
    producers): every key the report builders read is present with a
    realistic length, and the mix of types/severities/evidence classes is
    varied so per-type branches in the builders all get exercised.
    """
    rng = random.Random(seed)
    out = []
    for i in range(n):
        ftype, context = _TYPES[i % len(_TYPES)]
        tok = f"{rng.getrandbits(32):08x}"
        payload = _PAYLOAD_TAILS[i % len(_PAYLOAD_TAILS)].format(tok=tok)
        payload += "x" * rng.randint(0, 120)
        host = f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.1"
        port = rng.choice([80, 8080, 8443, 3000])
        path = f"/{_CONTEXTS[i % len(_CONTEXTS)]}/item{rng.randint(1, 50)}"
        url = f"http://{host}:{port}{path}"
        confirmed = rng.random() < 0.55
        headless = None
        if ftype in ("reflected", "dom_dynamic"):
            headless = ({"available": True, "confirmed": confirmed,
                         "outcome": "fired" if confirmed else "not-fired",
                         "detail": "load-benchmark stub"} if rng.random() < 0.7
                        else {"available": False, "confirmed": False,
                              "outcome": "unavailable",
                              "detail": "playwright not installed; skipped"})
        d = {
            "url": url, "method": rng.choice(["GET", "POST"]),
            "param": rng.choice(["q", "comment", "search", "name",
                                 "callback", "redirect"]),
            "type": ftype, "context": context,
            "payload": payload,
            "transform": list(rng.choice(_TRANSFORMS)),
            "severity": rng.choice(_SEVERITIES),
            "confidence": rng.choice(_CONFIDENCES),
            "detail": (f"Token reflected in {context} and confirmed by the "
                       f"semantic model (load-benchmark row {i}); the "
                       f"original finding detail carried a longer story "
                       f"than this, but 200 chars is realistic."),
            "evidence_class": rng.choice(_EVIDENCE),
            "evidence": ("<div class=\"result\">" + payload[:80] +
                         "</div> -- trailing page context"),
            "param_in": rng.choice(["query", "body"]),
            "headless": headless,
            "proof": {"status": rng.choice([200, 200, 200, 500]),
                      "method": "GET", "param": "q",
                      "payload": payload[:60],
                      "snippet": payload[:120]},
        }
        if ftype == "csp_bypass":
            d["csp_header"] = ("script-src 'self' https://cdn.example; "
                               "object-src 'none'")
            d["bypass_type"] = "script_gadget"
        if ftype == "blind":
            d["evidence_class"] = "oob-confirmed"
            d["proof"] = {"callback": f"http://cb.example/{tok}",
                          "callback_query": "c=admin%3D1&l=%7B%7D"}
        out.append(type("F", (), {"data": d, "to_dict": lambda s=None,
                                                  _d=d: _d})())
    return out


_FORMATS = {
    "html": report_mod.build_html,
    "json": report_mod.build_json,
    "csv": report_mod.build_csv,
    "sarif": report_mod.build_sarif,
    "junit": report_mod.build_junit,
    "markdown": report_mod.build_markdown,
    "burp": report_mod.build_burp_xml,
    "nuclei": report_mod.build_nuclei_yaml,
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--findings", type=int, default=1000)
    ap.add_argument("--formats", default=",".join(_FORMATS))
    ap.add_argument("--seed", type=int, default=20261005)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    findings = synthetic_findings(args.findings, args.seed)
    meta = {"scan_started": datetime.now().isoformat(timespec="seconds"),
            "scan_ended": datetime.now().isoformat(timespec="seconds"),
            "requests": args.findings * 14}
    target = "http://load-benchmark.example/"

    results = {}
    for name in [f for f in args.formats.split(",") if f]:
        fn = _FORMATS.get(name)
        if fn is None:
            print(f"[!] unknown format: {name}", file=sys.stderr)
            return 2
        t0 = time.perf_counter()
        text = fn(findings, target, meta)
        dt = time.perf_counter() - t0
        results[name] = {"seconds": round(dt, 4),
                         "bytes": len(text.encode("utf-8", "replace"))}
        print(f"  {name:<9} {dt:8.3f}s  {len(text):>10,} chars")

    worst = max(v["seconds"] for v in results.values())
    print(f"\n[*] {args.findings} findings; slowest format {worst:.3f}s "
          f"(2.2 acceptance: html < 2s)")

    out_path = args.out or os.path.join(
        _HERE, "results",
        f"report_load_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump({"findings": args.findings, "seed": args.seed,
                   "results": results}, fh, indent=2)
    print(f"[+] {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
