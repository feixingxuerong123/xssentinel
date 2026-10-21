"""Phase 300: judge the payloads we actually send.

Phase 299 measured the gap: of the 427 payloads the scanner sends by
default (first 14 per context x 40 contexts), 168 carry a token that no
measured oracle corpus has ever judged -- so the pure-Python sandbox's
verdict for them has no Chromium cross-check.  This script judges exactly
those cells.

Scope decisions, stated because they bound what the numbers mean:

  * ONE host per payload, chosen by its family (FAMILY_HOST below), not
    the full payload x host matrix (~3360 cells).  The question is "does
    the sandbox agree with Chromium about the payloads we actually send",
    not "is every payload right in every context".
  * FAMILY_HOST is best-effort and explicit.  The oracle models 20 HTML
    hosts; the scanner has 40 payload families.  Families whose shape no
    HTML host can represent (OOB callbacks, postMessage sources,
    service-worker scripts, prototype-pollution gadgets) are SKIPPED and
    listed in the artifact -- counting them as "judged" would be a lie.
  * The result goes to benchmark/results/oracle_default_sent.json.  The
    main oracle file answers a different question and is not touched.

Usage:
  python -m benchmark.oracle_default_sent            # full run (~4 min)
  python -m benchmark.oracle_default_sent --limit 5   # smoke
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys

from xssentinel.core import payloads as P

import benchmark.browser_dom_oracle as O
import benchmark.corpus_gap as CG

OUT = os.path.join("benchmark", "results", "oracle_default_sent.json")
MAX_PER_CONTEXT = 14          # scanner default --max-payloads

# family -> oracle host.  "" means "cannot be modelled by an HTML host".
FAMILY_HOST = {
    "html_element": "text",
    "html_attribute_dq": "attr_dq",
    "html_attribute_sq": "attr_sq",
    "html_attribute_noquote": "attr_unq",
    "script_string_dq": "script_dq",
    "script_string_sq": "script_dq",
    "script_block": "script_block",
    "url_javascript": "href_dq",
    "url_href": "href_dq",
    "css_context": "style",
    "event_handler": "event_dq",
    "svg_context": "svg_style",
    "math_context": "math_mtext",
    "html_comment": "comment",
    "script_template": "template",
    "template_angular": "template",
    "template_vue": "template",
    "cdata": "text",
    "meta_refresh": "text",
    "dom_clobber": "text",
    "framework_react": "text",
    "framework_vue": "text",
    "framework_angular": "text",
    "framework_svelte": "text",
    "framework_mustache": "text",
    "markdown": "text",
    "header_reflection": "text",
    "path_xss": "text",
    "error_page": "text",
    "dangling_markup": "text",
    "script_gadget": "script_block",
    "css_exfil": "style",
    "data_uri": "href_dq",
    "interaction_events": "event_dq",
    "portswigger_events": "event_dq",
    "html5_new": "text",
    "blind_oob": "",              # needs a callback listener
    "service_worker": "",         # payload is a JS file body, not a document
    "postmessage_source": "",     # needs a receiver page
    "prototype_gadget": "",       # needs a JS gadget harness
}


def unjudged_default_payloads() -> list[tuple[str, str, str]]:
    """(family, payload, host) for the default-sent payloads with no
    judged token.  host == "" means the family is skipped."""
    sandbox_tokens = CG._sandbox_tokens()
    out: list[tuple[str, str, str]] = []
    for fam in P.contexts():
        host = FAMILY_HOST.get(fam, "text")
        for payload in list(P.for_context(fam))[:MAX_PER_CONTEXT]:
            toks = CG._tokens(payload)
            if not any(t not in sandbox_tokens for t in toks):
                continue
            out.append((fam, payload, host))
    return out


def run(limit: int = 0):
    from playwright.sync_api import sync_playwright

    todo = unjudged_default_payloads()
    # dedupe: the same (payload, host) string pair is one question
    seen: set[tuple[str, str]] = set()
    cells: list[tuple[str, str, str]] = []
    skipped: list[dict] = []
    for fam, payload, host in todo:
        if not host:
            skipped.append({"family": fam, "payload": payload[:120],
                            "why": "no HTML host can model this family"})
            continue
        key = (payload, host)
        if key in seen:
            continue
        seen.add(key)
        cells.append((fam, payload, host))

    hosts = {hid: doc for hid, doc, _ in O.HOSTS}
    srv, base = O._serve()
    O._Handler.PAGES = {"/blank": "<html><body></body></html>"}
    rows: list[dict] = []
    seq = 0
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            ctx = browser.new_context()
            ctx.add_init_script(O._INIT_STAMP)
            page = ctx.new_page()
            page.goto(base + "/blank", wait_until="load")
            for fam, payload, hid in cells:
                if limit and len(rows) >= limit:
                    break
                seq += 1
                pkey, bkey = f"/p{seq}", f"/b{seq}"
                # The oracle's sentinel is O.X ("__x()"), so the shipped
                # alert(1) must be substituted exactly as the main oracle's
                # corpus_gap block does -- judging the raw string would make
                # every row vacuously inert (measured: 160/160 inert, and the
                # sandbox "agreed" because no token was in either document).
                marked = payload.replace("alert(1)", O.X)
                doc = hosts[hid].replace("__P__", marked)
                O._Handler.PAGES[pkey] = doc
                O._Handler.PAGES[bkey] = "<html><body></body></html>"
                row: dict = {"payload": payload[:200], "family": fam,
                             "host": hid, "document": doc,
                             "sentinel_present": O.X in marked,
                             "tags": ["default_sent"]}
                settle = max(300, O.SETTLE_OVERRIDES.get(payload, 0),
                             O.HOST_SETTLE_OVERRIDES.get(hid, 0))
                if not O._goto(page, base + "/blank"):
                    row.update({"exec_parser": None, "exec_ihn1": None,
                                "harness_error": "loopback reset"})
                    rows.append(row)
                    continue
                O._clear(page)
                try:
                    page.goto(base + pkey, wait_until="commit")
                    O._wait_load(page)
                    page.wait_for_timeout(settle)
                    row["exec_parser"] = O._hit(page, pkey)[0]
                except Exception as e:  # noqa: BLE001
                    row["exec_parser"] = None
                    row["parser_err"] = str(e)[:120]
                if not O._goto(page, base + bkey):
                    row["exec_ihn1"] = None
                    row["harness_error"] = "loopback reset before sink2"
                    rows.append(row)
                    continue
                O._clear(page)
                try:
                    a = page.evaluate(O._PROBE, {"html": doc,
                                                 "settle": settle})
                    row["exec_ihn1"] = O._hit(page, bkey)[0]
                    row["serialized"] = a["ser"]
                except Exception as e:  # noqa: BLE001
                    row["exec_ihn1"] = None
                    row["ihn_err"] = str(e)[:120]
                rows.append(row)
                print(f"  {fam:20s} {hid:10s} parser="
                      f"{'Y' if row.get('exec_parser') else ('?' if row.get('exec_parser') is None else '.')}"
                      f" ihn1={'Y' if row.get('exec_ihn1') else ('?' if row.get('exec_ihn1') is None else '.')}",
                      flush=True)
            browser.close()
    finally:
        srv.shutdown()
    return rows, skipped


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args(argv)
    rows, skipped = run(limit=args.limit)
    payload = {
        "oracle": "chromium",
        "question": "payloads the scanner sends by default that the main "
                    "oracle never judged (one host per family)",
        "generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "count": len(rows),
        "skipped_families": len(skipped),
        "skipped": skipped,
        "rows": rows,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=1)
    print(f"\nwrote {OUT}: {len(rows)} cells, {len(skipped)} skipped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
