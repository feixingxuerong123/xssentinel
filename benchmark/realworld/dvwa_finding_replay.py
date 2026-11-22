"""Replay xssentinel's OWN finding payloads against the live DVWA instance.

A finding's payload is not ground truth just because the scanner printed it.
This script takes payloads out of the scan reports, replays them with the
same authenticated session, and asks a real Chromium whether a dialog fired.

Usage:
  python benchmark/realworld/dvwa_finding_replay.py --cookie-file FILE
"""

import argparse
import glob
import json
import os
import re

import requests
from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8080"
PATTERN = "benchmark/results/dvwa_scan_*_20261118.json"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cookie-file", required=True)
    ap.add_argument("--out", default="benchmark/results/dvwa_live_finding_replay_20261118.json")
    args = ap.parse_args()
    sid = open(args.cookie_file, encoding="utf-8").read().strip().split("=", 1)[1]

    rows = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        for path in sorted(glob.glob(PATTERN)):
            m = re.search(r"dvwa_scan_(low|medium|high)_(\w+?)_20261118\.json$",
                          os.path.basename(path))
            if not m:
                continue
            level, surface = m.groups()
            report = json.load(open(path, encoding="utf-8"))
            for f in report.get("findings", []):
                if f.get("type") not in ("reflected", "stored"):
                    continue
                payload = f["payload"]
                param = f["param"]
                ctx = browser.new_context()
                ctx.add_cookies([
                    {"name": "security", "value": level, "url": BASE},
                    {"name": "PHPSESSID", "value": sid, "url": BASE},
                ])
                s = requests.Session()
                s.trust_env = False
                s.cookies.set("security", level, domain="127.0.0.1", path="/")
                s.cookies.set("PHPSESSID", sid, domain="127.0.0.1", path="/")

                dialogs = []
                page = ctx.new_page()
                page.on("dialog", lambda d: (dialogs.append(d.message), d.accept()))
                if f["type"] == "reflected":
                    url = (f.get("poc") or {}).get("url") or f["url"]
                    if not url:
                        url = BASE + "/vulnerabilities/xss_r/?name=" + requests.utils.quote(payload)
                    try:
                        page.goto(url, timeout=5000, wait_until="domcontentloaded")
                        page.wait_for_timeout(700)
                    except Exception as exc:
                        rows.append({"level": level, "surface": surface,
                                     "type": f["type"], "param": param,
                                     "payload": payload, "error": str(exc)[:120]})
                        page.close()
                        ctx.close()
                        continue
                else:
                    # Clear guestbook so only this payload is on the view page.
                    s.post(BASE + "/vulnerabilities/xss_s/",
                           data={"btnClear": "Clear Guestbook"}, timeout=10)
                    data = {"txtName": "probe", "mtxMessage": "probe",
                            "btnSign": "Sign Guestbook"}
                    data[param] = payload
                    s.post(BASE + "/vulnerabilities/xss_s/",
                           data=data, timeout=10)
                    try:
                        page.goto(BASE + "/vulnerabilities/xss_s/",
                                  timeout=5000, wait_until="domcontentloaded")
                        page.wait_for_timeout(700)
                    except Exception as exc:
                        rows.append({"level": level, "surface": surface,
                                     "type": f["type"], "param": param,
                                     "payload": payload, "error": str(exc)[:120]})
                        page.close()
                        ctx.close()
                        continue
                page.close()
                ctx.close()
                rows.append({
                    "level": level, "surface": surface, "type": f["type"],
                    "param": param, "payload": payload,
                    "scanner_severity": f["severity"],
                    "dialog_confirmed": bool(dialogs),
                    "dialogs": dialogs,
                })
        browser.close()

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(rows, fh, ensure_ascii=False, indent=2)
    for r in rows:
        print("%-6s %-18s %-10s param=%-12s dialog=%s %s" % (
            r["level"], r["surface"], r["type"], r["param"],
            r.get("dialog_confirmed"), r.get("dialogs", [])[:1]))
    print("facts:", args.out)


if __name__ == "__main__":
    main()
