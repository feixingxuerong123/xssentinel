#!/usr/bin/env python
"""Independent browser evidence for Phase 381's two ``delivered`` rows.

Phase 381 deliberately stopped at DELIVERY: it proved the server echoed the
official payload verbatim in a decoded field, and said explicitly that "a
stored string in a JSON field is not a rendered XSS".  This runner closes
exactly that gap with an INDEPENDENT Playwright Chromium (never the product's
own verdict): for each of the two rows it runs a payload arm and a clean
control arm on the real OWASP Juice Shop v20.2.0 target, and records what the
browser actually did.

  * a ``dialog`` event is the execution evidence, not an iframe in the DOM;
  * each payload arm has a matched control arm. A dialog in the CONTROL arm
    would mean leftover payload from an earlier run contaminated the target,
    and is reported as ``control_contaminated`` rather than as a hit;
  * no TP/FP/TN/FN, no precision/recall/F1. Two rows with different delivery
    shapes and prerequisites are not a denominator.

Ground truth is the official ``challenges.yml`` string reused from Phase 381
(no second hand-typed payload).  The target's admin JWT is used only to seed
the browser's localStorage and is NEVER written to the report.

Usage::

    NO_PROXY=127.0.0.1,localhost .venv/Scripts/python.exe \
        benchmark/run_juice_render.py \
        --tree "$(git rev-parse --short HEAD)" \
        --out benchmark/results/juice_render_20261110.json
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import time
from datetime import datetime, timezone

import requests
from playwright.sync_api import sync_playwright

_HERE = pathlib.Path(__file__).resolve().parent
_ROOT = _HERE.parent
sys.path.insert(0, str(_ROOT))

from benchmark.run_juice_challenges import (  # noqa: E402
    OFFICIAL_PAYLOAD,
    _git_head,
    _jwt_data,
    _login,
)

SCORING_POLICY = (
    "FACT TABLE ONLY. Independent Chromium dialog/DOM evidence per arm; "
    "no TP/FP/TN/FN, precision, recall or F1. A dialog in the control arm "
    "means contamination, not a detection."
)
CLEAN_IP = "203.0.113.7"
CLEAN_DESCRIPTION = "The all-time classic."
ARMS = ("payload", "control")

CASES = (
    {"key": "httpHeaderXssChallenge",
     "view": "/#/privacy-security/last-login-ip", "click": None,
     "setup": "True-Client-IP header -> fresh-login JWT -> SPA route"},
    {"key": "restfulXssChallenge",
     "view": "/#/search?q=Apple",
     "click": "mat-card section[role=button]",
     "setup": ("PUT /api/Products/1 description -> dispatch_event click on "
               "the product info section (the app's welcome overlay blocks "
               "real pointer clicks; BOTH arms use the same method)")},
)


def _setup(case: dict, arm: str, base: str, session: requests.Session,
           auth: dict) -> dict:
    """Write this arm's state, then return a FRESH browser token."""
    value = OFFICIAL_PAYLOAD if arm == "payload" else None
    if case["key"] == "httpHeaderXssChallenge":
        r = session.get(base + "/rest/saveLoginIp",
                        headers={**auth, "True-Client-IP": value or CLEAN_IP},
                        timeout=10)
        _, token = _login(base, session)
        echo = str(_jwt_data(token).get("lastLoginIp", ""))
        return {"token": token, "inject_status": r.status_code,
                "server_echo": echo[:200],
                "server_has_payload": OFFICIAL_PAYLOAD in echo}
    r = session.put(base + "/api/Products/1", headers=auth,
                    json={"description": value or CLEAN_DESCRIPTION},
                    timeout=10)
    echo = str(session.get(base + "/api/Products/1", timeout=10)
               .json()["data"]["description"])
    _, token = _login(base, session)
    return {"token": token, "inject_status": r.status_code,
            "server_echo": echo[:200],
            "server_has_payload": OFFICIAL_PAYLOAD in echo}


def _browser_probe(browser, token: str, url: str, click: str | None) -> dict:
    """The project's independent dialog oracle (cf. bwapp_matrix.py)."""
    ctx = browser.new_context()
    dialogs: list[str] = []
    try:
        ctx.add_init_script(
            "window.localStorage.setItem('token', " + json.dumps(token) + ");")
        page = ctx.new_page()

        def on_dialog(dialog):
            try:
                dialogs.append(dialog.message)
            finally:
                try:
                    dialog.dismiss()
                except Exception:                        # noqa: BLE001
                    pass

        page.on("dialog", on_dialog)
        error = None
        click_method = None
        page.goto(url, wait_until="domcontentloaded", timeout=30000)
        page.wait_for_timeout(1200)
        if click:
            # The app opens a welcome overlay whose cdk-overlay-backdrop
            # intercepts ALL pointer events; a normal locator.click() times
            # out. Dispatching the click event reaches the same Angular
            # handler. Both arms use this identical method so the pair stays
            # comparable, and the method is recorded in the fact table.
            try:
                page.locator(click).first.dispatch_event("click")
                click_method = "dispatch_event"
                page.wait_for_timeout(1800)
            except Exception as exc:                     # noqa: BLE001
                error = (f"dispatch {click}: {type(exc).__name__}: "
                         f"{str(exc)[:120]}")
        else:
            page.wait_for_timeout(2200)
        html = page.content()
        return {
            "click_method": click_method,
            "dialogs": dialogs,
            "iframe_count": page.locator("iframe").count(),
            "payload_in_dom": OFFICIAL_PAYLOAD in html,
            "javascript_src_in_dom": 'src="javascript:' in html,
            "html_len": len(html),
            "error": error,
        }
    except Exception as exc:                             # noqa: BLE001
        return {"click_method": None, "dialogs": dialogs, "iframe_count": 0,
                "payload_in_dom": False,
                "javascript_src_in_dom": False, "html_len": 0,
                "error": f"{type(exc).__name__}: {str(exc)[:180]}"}
    finally:
        ctx.close()


def run(base: str, tree: str = "") -> dict:
    session = requests.Session()
    auth, _ = _login(base, session)
    original = str(session.get(base + "/api/Products/1", timeout=10)
                   .json()["data"]["description"])
    rows = []
    t0 = time.time()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True, args=["--no-proxy-server"])
        try:
            for case in CASES:
                for arm in ARMS:
                    setup = _setup(case, arm, base, session, auth)
                    url = base + case["view"]
                    probe = _browser_probe(browser, setup["token"], url,
                                           case["click"])
                    fired = any("xss" in str(msg).lower()
                                for msg in probe["dialogs"])
                    if arm == "control" and fired:
                        verdict = "control_contaminated"
                    elif probe["error"]:
                        verdict = "error"
                    elif fired:
                        verdict = "browser_executed"
                    else:
                        verdict = "not_executed"
                    rows.append({
                        "key": case["key"],
                        "arm": arm,
                        "setup": case["setup"],
                        "view_url": url,
                        "click": case["click"],
                        "inject_status": setup["inject_status"],
                        "server_echo": setup["server_echo"],
                        "server_has_payload": setup["server_has_payload"],
                        "click_method": probe["click_method"],
                        "dialogs": probe["dialogs"],
                        "iframe_count": probe["iframe_count"],
                        "payload_in_dom": probe["payload_in_dom"],
                        "javascript_src_in_dom":
                            probe["javascript_src_in_dom"],
                        "html_len": probe["html_len"],
                        "verdict": verdict,
                        "error": probe["error"],
                    })
                    print(f"  {case['key']:<30} {arm:<8} {verdict:<22} "
                          f"dialogs={probe['dialogs']}", flush=True)
        finally:
            browser.close()
            # Always put the target's product field back, whichever arm ran.
            session.put(base + "/api/Products/1", headers=auth,
                        json={"description": original}, timeout=10)
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
    return {
        "generated_utc": datetime.now(timezone.utc).isoformat(
            timespec="seconds"),
        "tree": _git_head(tree),
        "target": base,
        "scoring_policy": SCORING_POLICY,
        "official_payload": OFFICIAL_PAYLOAD,
        "clean_control_values": {"ip": CLEAN_IP,
                                 "description": CLEAN_DESCRIPTION},
        "browser": "independent Playwright Chromium, headless, dialog oracle",
        "cases": [c["key"] for c in CASES],
        "arms": list(ARMS),
        "rows": rows,
        "counts": counts,
        "wall_s": round(time.time() - t0, 2),
        "restored": {"product_1_description": original},
    }


def to_markdown(data: dict) -> str:
    lines = [
        "# Independent browser evidence for the delivered rows (FACT TABLE)",
        "",
        f"- generated (UTC): `{data['generated_utc']}`",
        f"- tree: `{data['tree']}` / target: `{data['target']}`",
        f"- browser: {data['browser']}",
        f"- wall: {data['wall_s']}s / rows: {len(data['rows'])}",
        "",
        "> **" + data["scoring_policy"] + "**",
        "",
        "## Matched payload / control arms",
        "",
        "| key | arm | inject | server has payload | dialogs | iframes | "
        "payload in DOM | verdict |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in data["rows"]:
        lines.append(
            f"| `{r['key']}` | `{r['arm']}` | {r['inject_status']} | "
            f"{r['server_has_payload']} | {r['dialogs']} | "
            f"{r['iframe_count']} | {r['payload_in_dom']} | "
            f"`{r['verdict']}` |")
    lines += ["", "## Per-arm detail", ""]
    for r in data["rows"]:
        lines.append(f"- **`{r['key']}` / `{r['arm']}`** → `{r['verdict']}`")
        lines.append(f"  - setup: {r['setup']}")
        lines.append(f"  - view: `{r['view_url']}`"
                     + (f" + click `{r['click']}` via "
                        f"`{r['click_method']}`" if r["click"] else ""))
        lines.append(f"  - server echo: `{r['server_echo']}`")
        lines.append(f"  - DOM: html_len={r['html_len']}, "
                     f"javascript_src={r['javascript_src_in_dom']}")
        if r["error"]:
            lines.append(f"  - error: `{r['error']}`")
    lines += ["", "## Counts (NOT a confusion matrix)", "",
              "| verdict | rows |", "|---|---|"]
    for verdict, n in sorted(data["counts"].items()):
        lines.append(f"| `{verdict}` | {n} |")
    lines += [
        "",
        "## Why no score",
        "",
        "1. Two rows with different delivery shapes (an authenticated header "
        "write vs a product description write) and an SPA-click prerequisite "
        "are not two comparable cases; there is no denominator.",
        "2. Execution evidence is a real ``dialog`` event. An iframe in the "
        "DOM, a stored string, or the product's own finding is not execution.",
        "3. Each payload arm has a matched clean control. A dialog in the "
        "control arm is reported as contamination, never as a hit.",
        "4. A ``not_executed`` result on this official v20.2.0 build is a "
        "fact about this target, not a verdict on the scanner.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base", default=os.environ.get(
        "XS_JUICE_BASE", "http://127.0.0.1:18900"))
    ap.add_argument("--out", default=str(
        _ROOT / "benchmark" / "results" / "juice_render_latest.json"))
    ap.add_argument("--md", default="")
    ap.add_argument("--tree", default=os.environ.get("XS_TREE", ""),
                    help="git short hash; an unavailable git ABORTS")
    args = ap.parse_args()
    data = run(args.base, args.tree)
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    md = pathlib.Path(args.md) if args.md else out.with_suffix(".md")
    md.write_text(to_markdown(data), encoding="utf-8")
    print(f"[+] json: {out}\n[+] md:   {md}", flush=True)
    print(json.dumps(data["counts"], indent=2), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
