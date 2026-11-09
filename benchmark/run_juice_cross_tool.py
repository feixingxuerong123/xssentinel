#!/usr/bin/env python
"""Cross-tool, per-case MATRIX on a REAL third-party application.

Why this is NOT an F1 comparison
--------------------------------
The repo already has a fair head-to-head rig (``run_cross_tool.py`` +
``adapters.run_comparison``), but it assumes every case can be delivered to
every tool.  On a real SPA that assumption breaks: OWASP Juice Shop's XSS
challenges live on Angular hash routes (``/#/search?q=...``).  A URL fragment
is NEVER sent in an HTTP request, so a request-only scanner cannot be handed
the injection point at all -- scoring its "0 findings" as FN would be a
measurement error, not a result.  Conversely the server-reachable surfaces
we can deliver to everyone are true negatives (the REST search does not
reflect; /redirect HTML-escapes).  There is no server-deliverable positive,
so a balanced confusion matrix cannot exist on this target.

``adapters.not_comparable()`` is CASE-shaped (non-GET / stored / scenario /
upload).  It cannot express "reachable for a browser-driven tool, unreachable
for an HTTP-only one".  Rather than weaken that existing contract, this
runner reuses ONLY the adapters' unified ``scan_case -> detected`` output and
records delivery shape as a separate, objective column (``fragment_only`` is
computed from the URL, never from a hand-written tool allowlist).

It therefore publishes a FACT TABLE, not a scorecard:
  * the exact URL every tool received (identical for all three);
  * each tool's detected / error / wall time / raw output head;
  * which URLs carry a fragment (no HTTP request can carry it);
  * no TP/FP/TN/FN, no precision/recall/F1, no "who won".

Ground truth is the target's OWN answer key (data/static/challenges.yml),
plus two measured controls from dev/juiceshop_external.py surfaces / writes.

Usage::

    .venv/Scripts/python.exe benchmark/run_juice_cross_tool.py \
        --base http://127.0.0.1:18900 \
        --out benchmark/results/juice_cross_tool_20261110.json

Requires the Juice Shop target to be up (dev/juiceshop_external.py serve)
and NO_PROXY=127.0.0.1,localhost in the environment.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
from datetime import datetime, timezone
from urllib.parse import urlsplit

_HERE = pathlib.Path(__file__).resolve().parent
_ROOT = _HERE.parent
sys.path.insert(0, str(_ROOT))

from benchmark import adapters  # noqa: E402
from benchmark.runner import _build_target_url  # noqa: E402

#: One row per REAL application surface.  ``ground_truth`` never comes from
#: this repo's own 194-case matrix; it is either an official challenge key
#: or an independently measured control (see the 2026-11-09 Juice report).
CASES = [
    {
        "id": "js-dom-search",
        "path": "/#/search", "param": "q",
        "ground_truth": "pos",
        "answer_key": "localXssChallenge (DOM XSS)",
        "in_denominator": True,
        "note": "official challenge; Angular hash route binds [innerHTML]",
    },
    {
        "id": "js-dom-track-result",
        "path": "/#/track-result", "param": "id",
        "ground_truth": "pos",
        "answer_key": "reflectedXssChallenge (Reflected XSS)",
        "in_denominator": True,
        "note": "official challenge; Angular hash route",
    },
    {
        "id": "js-api-search",
        "path": "/rest/products/search", "param": "q",
        "ground_truth": "neg",
        "answer_key": "measured control: surfaces reflects=False",
        "in_denominator": True,
        "note": "server-reachable; a finding here is a false positive",
    },
    {
        "id": "js-redirect",
        "path": "/redirect", "param": "to",
        "ground_truth": "neg",
        "answer_key": "measured control: writes escaped_iframe=True",
        "in_denominator": True,
        "note": "server-reachable; reflects but HTML-escapes",
    },
    {
        "id": "js-dom-search-result",
        "path": "/#/search-result", "param": "q",
        "ground_truth": "pos-derived",
        "answer_key": None,
        "in_denominator": False,
        "note": ("same DOM sink family, NOT separately listed in "
                 "challenges.yml -- supplementary observation only"),
    },
]


def _delivery_shape(url: str) -> dict:
    """Objective, URL-derived facts.  No tool-name allowlist anywhere."""
    parts = urlsplit(url)
    return {
        "fragment_only": bool(parts.fragment) and "?" in parts.fragment,
        "http_path": parts.path or "/",
        "http_query": parts.query,
        "note": ("injection point sits in the URL fragment; no HTTP "
                 "request can carry it" if parts.fragment and
                 "?" in parts.fragment else
                 "injection point is server-reachable via the request line"),
    }


def tool_versions(base: str) -> dict:
    """Record what actually ran, so the matrix can be re-read years later."""
    import subprocess
    out = {"XSSentinel": f"this checkout ({_git_head()})"}
    for name, argv, needle in (
        ("dalfox", ["dalfox", "version"], "v2."),
        ("nuclei-dast-xss", ["nuclei", "-version"], "v3."),
    ):
        try:
            p = subprocess.run(argv, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=30)
            text = (p.stdout or "") + (p.stderr or "")
            line = next((ln.strip() for ln in text.splitlines()
                         if needle in ln), "")
            out[name] = line or f"rc={p.returncode} (version line not found)"
        except Exception as e:                       # noqa: BLE001
            out[name] = f"unknown ({type(e).__name__})"
    out["nuclei templates"] = str(pathlib.Path.home() /
                                  "nuclei-templates/dast/vulnerabilities/xss")
    return out


def _git_head() -> str:
    import subprocess
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                              cwd=str(_ROOT), capture_output=True,
                              text=True, timeout=15).stdout.strip()
    except Exception:                                # noqa: BLE001
        return "unknown"


def run(base: str, only: list[str] | None = None) -> dict:
    available = adapters.get_adapters()
    if only:
        available = [a for a in available if a.name in only]
    print(f"[*] adapters: {[a.name for a in available]}", flush=True)
    print(f"[*] base: {base}  cases: {len(CASES)}", flush=True)

    rows = []
    for adapter in available:
        for case in CASES:
            url = _build_target_url(base, case)
            shape = _delivery_shape(url)
            try:
                r = adapter.scan_case(base, case)
            except Exception as e:                   # noqa: BLE001
                r = {"detected": False, "raw_output": "", "time_s": 0.0,
                     "error": f"runner exception: {type(e).__name__}: {e}"}
            row = {
                "tool": adapter.name,
                "case_id": case["id"],
                "url": url,
                "ground_truth": case["ground_truth"],
                "answer_key": case["answer_key"],
                "in_denominator": case["in_denominator"],
                "note": case["note"],
                **shape,
                "detected": bool(r.get("detected")),
                "error": r.get("error"),
                "time_s": round(float(r.get("time_s") or 0.0), 2),
                "raw_output_head": str(r.get("raw_output") or "")[:240],
            }
            rows.append(row)
            print(f"  {adapter.name:<18} {case['id']:<22} "
                  f"detected={row['detected']!s:<5} err={row['error'] or '-'} "
                  f"fragment={shape['fragment_only']!s:<5} "
                  f"{row['time_s']}s", flush=True)

    tools = sorted({r["tool"] for r in rows})
    return {
        "generated_utc": datetime.now(timezone.utc).isoformat(
            timespec="seconds"),
        "tree": _git_head(),
        "target": base,
        "target_app": "OWASP Juice Shop v20.2.0 (official node22_win32_x64 release)",
        "answer_key_file": ("dev/_juiceshop/app/juice-shop_20.2.0/"
                            "data/static/challenges.yml"),
        "scoring_policy": ("FACT TABLE ONLY. No TP/FP/TN/FN or F1: "
                           "delivery reachability differs per tool and "
                           "there is no server-deliverable positive."),
        "tool_versions": tool_versions(base),
        "cases": CASES,
        "tools": tools,
        "rows": rows,
        "summary": {
            t: {
                "cases": sum(1 for r in rows if r["tool"] == t),
                "detected": sum(1 for r in rows
                                if r["tool"] == t and r["detected"]),
                "errors": sum(1 for r in rows
                              if r["tool"] == t and r["error"]),
                "wall_s": round(sum(r["time_s"] for r in rows
                                    if r["tool"] == t), 2),
                "detected_on_fragment": sum(
                    1 for r in rows if r["tool"] == t
                    and r["detected"] and r["fragment_only"]),
                "detected_on_server": sum(
                    1 for r in rows if r["tool"] == t
                    and r["detected"] and not r["fragment_only"]),
            } for t in tools
        },
    }


def to_markdown(data: dict) -> str:
    lines = [
        "# Cross-tool per-case matrix on a real application (FACT TABLE)",
        "",
        f"- generated (UTC): `{data['generated_utc']}`",
        f"- tree: `{data['tree']}` / target: `{data['target']}`",
        f"- app: {data['target_app']}",
        f"- answer key: `{data['answer_key_file']}`",
        "",
        "> **" + data["scoring_policy"] + "**",
        "",
        "## Tool versions (actually invoked)",
        "",
    ]
    for k, v in data["tool_versions"].items():
        lines.append(f"- **{k}**: `{v}`")
    lines += ["", "## Case set", "",
              "| id | ground truth | answer key | fragment | in denominator |",
              "|---|---|---|---|---|"]
    for c in data["cases"]:
        url = _build_target_url(data["target"], c)
        lines.append(
            f"| `{c['id']}` | {c['ground_truth']} | "
            f"{c['answer_key'] or '—'} | "
            f"{_delivery_shape(url)['fragment_only']} | "
            f"{c['in_denominator']} |")
    lines += ["", "## Per-case results", "",
              "| tool | case | detected | error | fragment | secs |",
              "|---|---|---|---|---|---|"]
    for r in data["rows"]:
        lines.append(
            f"| {r['tool']} | `{r['case_id']}` | {r['detected']} | "
            f"{r['error'] or '—'} | {r['fragment_only']} | {r['time_s']} |")
    lines += ["", "## Counts (NOT a confusion matrix)", "",
              "| tool | cases | detected | errors | wall s | on fragment | on server |",
              "|---|---|---|---|---|---|---|"]
    for t, s in data["summary"].items():
        lines.append(
            f"| {t} | {s['cases']} | {s['detected']} | {s['errors']} | "
            f"{s['wall_s']} | {s['detected_on_fragment']} | "
            f"{s['detected_on_server']} |")
    lines += [
        "",
        "## Why no score",
        "",
        "1. A URL fragment is not transmitted in an HTTP request. Any tool "
        "whose input model is an HTTP request cannot be handed the injection "
        "point on the three hash-route rows; a zero there is **not measured**, "
        "not a miss.",
        "2. Both server-reachable rows are true negatives (REST search does "
        "not reflect; /redirect HTML-escapes). There is no server-deliverable "
        "positive, so TP and recall have no denominator.",
        "3. Tool configurations differ by nature (e.g. nuclei's DAST set "
        "contains a browser-driven `dom-xss.yaml`, dalfox is request-only, "
        "and this repo's adapter runs XSSentinel at gate budgets WITHOUT "
        "`--headless`). The earlier `--headless` Juice Shop run is a "
        "DIFFERENT configuration and is deliberately not mixed in.",
        "4. Therefore TP/FP/TN/FN, precision, recall and F1 would all be "
        "fabricated precision. This table reports what each tool actually "
        "emitted on the identical URL, nothing more.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base", default=os.environ.get(
        "XS_JUICE_BASE", "http://127.0.0.1:18900"))
    ap.add_argument("--out", default=str(
        _ROOT / "benchmark/results/juice_cross_tool_latest.json"))
    ap.add_argument("--md", default="")
    ap.add_argument("--tools", default="",
                    help="comma-separated adapter names (default: all available)")
    args = ap.parse_args()

    only = [x.strip() for x in args.tools.split(",") if x.strip()] or None
    data = run(args.base, only)
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    md = pathlib.Path(args.md) if args.md else out.with_suffix(".md")
    md.write_text(to_markdown(data), encoding="utf-8")
    print(f"\n[+] json: {out}\n[+] md:   {md}", flush=True)
    print(json.dumps(data["summary"], indent=2), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
