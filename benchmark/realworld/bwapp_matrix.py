#!/usr/bin/env python3
"""bWAPP security_level matrix: Playwright ground truth vs xssentinel verdict.

Faces: reflected (xss_get.php), stored (xss_stored_1.php), header (xss_user_agent.php).
Levels: 0=low, 1=medium, 2=high.  Roles: bee (admin), bwuser (non-admin).

Nothing here touches the target's database directly: stored entries are written
through the application's own blog form and cleared with its own delete button.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import requests
from playwright.sync_api import sync_playwright

REPO = Path(__file__).resolve().parents[2]
BASE = "http://127.0.0.1:8081"
TMP = REPO / "tests" / "_pytest_tmp"
RESULTS = REPO / "benchmark" / "results"
TRUTH_FILE = RESULTS / "bwapp_matrix_truth.json"
SCAN_FILE = RESULTS / "bwapp_matrix_scan.json"
FINAL_FILE = RESULTS / "bwapp_matrix_20261103.json"
MD_FILE = RESULTS / "bwapp_matrix_20261103.md"

LEVELS = [(0, "low"), (1, "medium"), (2, "high")]
CREDS = {"bee": ("bee", "bug"), "bwuser": ("bwuser", "bwpass123")}
ROLE_ORDER = ["bwuser", "bee"]

# Same carrier shape for both roles; only the numeric marker differs so a
# cross-role "Show all" page can tell whose entry fired which dialog.
OFFSET = {"bwuser": 10, "bee": 50}


def env_temp():
    TMP.mkdir(parents=True, exist_ok=True)
    e = os.environ.copy()
    e["TEMP"] = str(TMP)
    e["TMP"] = str(TMP)
    e["TERM"] = "dumb"
    return e


def carriers_for(role):
    b = OFFSET[role]
    return [
        {"id": "script", "n": b + 1,
         "payload": "<script>alert(%d)</script>" % (b + 1),
         "tag": "<script>alert(%d)</script>" % (b + 1)},
        {"id": "img", "n": b + 11,
         "payload": "<img src=x onerror=alert(%d)>" % (b + 11),
         "tag": "<img src=x onerror=alert(%d)>" % (b + 11)},
        {"id": "svg", "n": b + 21,
         "payload": "<svg onload=alert(%d)>" % (b + 21),
         "tag": "<svg onload=alert(%d)>" % (b + 21)},
        {"id": "attr-escape", "n": b + 31,
         "payload": '"><img src=x onerror=alert(%d)>' % (b + 31),
         "tag": "<img src=x onerror=alert(%d)>" % (b + 31)},
    ]


def login(user, password):
    s = requests.Session()
    r = s.post(BASE + "/login.php",
               data={"login": user, "password": password, "form": "submit"},
               timeout=15)
    if "Welcome" not in r.text:
        raise RuntimeError("login failed for %s (status %s)" % (user, r.status_code))
    return s


def set_level(sess, lvl):
    sess.post(BASE + "/security_level_set.php",
              data={"security_level": str(lvl), "form": "submit"}, timeout=15)
    html = sess.get(BASE + "/portal.php", timeout=15).text
    m = re.search(r"Current:\s*<b>(low|medium|high)</b>", html)
    if not m:
        raise RuntimeError("security_level did not take effect for level %s" % lvl)
    return m.group(1)


def page_level(html):
    m = re.search(r"Current:\s*<b>(low|medium|high)</b>", html)
    return m.group(1) if m else None


def clear_entries(sess):
    sess.post(BASE + "/xss_stored_1.php",
              data={"blog": "submit", "entry_delete": ""}, timeout=15)


def cookie_list(sess):
    return [{"name": k, "value": v, "domain": "127.0.0.1", "path": "/"}
            for k, v in sess.cookies.get_dict().items()]


def _echo(html, carrier):
    """Raw echo verdict; medium's addslashes prefixes a backslash to quotes."""
    escaped = ("\\" + carrier["payload"]) in html
    return {
        "payload_in": carrier["payload"] in html,
        "addslashes_escaped": escaped,
        "payload_exact": (carrier["payload"] in html) and not escaped,
        "tag_intact": carrier["tag"] in html,
    }


def http_reflected(sess, carrier):
    r = sess.get(BASE + "/xss_get.php",
                 params={"firstname": carrier["payload"], "lastname": "x",
                         "form": "submit"}, timeout=15)
    html = r.text
    i = html.rfind("Welcome ")
    out = {"status": r.status_code, "level": page_level(html), "url": r.url,
            "context": html[i:i + 260] if i >= 0 else ""}
    out.update(_echo(html, carrier))
    return out


def http_header(sess, carrier):
    r = sess.get(BASE + "/xss_user_agent.php",
                 headers={"User-Agent": carrier["payload"]}, timeout=15)
    html = r.text
    i = html.find("Your User-Agent:")
    out = {"status": r.status_code, "level": page_level(html),
            "context": html[i:i + 260] if i >= 0 else ""}
    out.update(_echo(html, carrier))
    return out


def http_stored_write(sess, carrier, *, show_all=False):
    data = {"blog": "submit", "entry_all": ""} if show_all else \
           {"entry": carrier["payload"], "blog": "submit", "entry_add": ""}
    r = sess.post(BASE + "/xss_stored_1.php", data=data, timeout=15)
    html = r.text
    needle = "alert(%d)" % carrier["n"]
    i = html.find(needle)
    if i < 0:
        i = html.find('id="table_yellow"')
    out = {"status": r.status_code, "level": page_level(html),
            "context": html[max(0, i - 150):i + 200] if i >= 0 else ""}
    out.update(_echo(html, carrier))
    return out


def http_stored_view(sess, carrier):
    r = sess.get(BASE + "/xss_stored_1.php", timeout=15)
    html = r.text
    needle = "alert(%d)" % carrier["n"]
    i = html.find(needle)
    out = {"status": r.status_code, "level": page_level(html),
            "context": html[max(0, i - 150):i + 200] if i >= 0 else "",
            "html": html}
    out.update(_echo(html, carrier))
    return out


def browser_probe(browser, cookies, url, *, ua=None, show_all=False):
    ctx = browser.new_context(user_agent=ua) if ua else browser.new_context()
    try:
        ctx.add_cookies(cookies)
        page = ctx.new_page()
        dialogs = []

        def _on_dialog(d):
            try:
                dialogs.append(d.message)
            finally:
                try:
                    d.dismiss()
                except Exception:
                    pass

        page.on("dialog", _on_dialog)
        page.goto(url, wait_until="domcontentloaded", timeout=30000)
        page.wait_for_timeout(300)
        if show_all:
            page.uncheck("#entry_add")
            page.check("#entry_all")
            page.click("button[name='blog']")
            page.wait_for_load_state("domcontentloaded", timeout=30000)
        page.wait_for_timeout(2500)
        html = page.content()
        main = page.query_selector("#main")
        text = main.inner_text()[:240] if main else ""
        return {"dialogs": dialogs, "html": html, "text": text, "error": None}
    except Exception as exc:
        return {"dialogs": [], "html": "", "text": "", "error": repr(exc)}
    finally:
        ctx.close()


def browser_until(browser, cookies, url, carrier, *, ua=None, show_all=False,
                  expect=True):
    res = browser_probe(browser, cookies, url, ua=ua, show_all=show_all)
    if expect and str(carrier["n"]) not in [str(m) for m in res["dialogs"]]:
        again = browser_probe(browser, cookies, url, ua=ua, show_all=show_all)
        res["dialogs"] = res["dialogs"] + again["dialogs"]
        res["html"] = again["html"] or res["html"]
        res["text"] = again["text"] or res["text"]
        res["error"] = res["error"] or again["error"]
        res["retried"] = True
    return res


def carrier_verdict(carrier, http_res, browser_res):
    executed = str(carrier["n"]) in [str(m) for m in browser_res.get("dialogs", [])]
    return {
        "payload_exact": bool(http_res.get("payload_exact")),
        "tag_intact": bool(http_res.get("tag_intact")),
        "executed": bool(executed),
        "dialogs": browser_res.get("dialogs", []),
        "dom_tag_intact": carrier["tag"] in browser_res.get("html", ""),
        "text": browser_res.get("text", "")[:200],
        "error": browser_res.get("error"),
        "page_level": http_res.get("level"),
    }


# --------------------------------------------------------------------------
# Phase 1: ground truth
# --------------------------------------------------------------------------
def phase_truth(level_filter, role_filter):
    sessions = {r: login(*CREDS[r]) for r in role_filter}
    rows = []
    cross = []
    checks = []

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        for lvl, lname in LEVELS:
            if lvl not in level_filter:
                continue
            confirmed = {}
            for role in role_filter:
                confirmed[role] = set_level(sessions[role], lvl)
            checks.append({"level": lname, "confirmed": confirmed,
                           "all_ok": all(v == lname for v in confirmed.values())})
            for role in role_filter:
                clear_entries(sessions[role])

            for role in ROLE_ORDER:
                if role not in role_filter:
                    continue
                sess = sessions[role]
                cookies = cookie_list(sess)
                for carrier in carriers_for(role):
                    http_ref = http_reflected(sess, carrier)
                    br_ref = browser_until(browser, cookies, http_ref["url"], carrier,
                                           expect=(lname != "high"))
                    rows.append({
                        "level": lname, "level_id": lvl, "face": "reflected",
                        "carrier": carrier["id"], "role": role, "n": carrier["n"],
                        "http": {k: http_ref[k] for k in
                                 ("status", "payload_in", "addslashes_escaped",
                                  "payload_exact", "tag_intact", "context")},
                        "browser": carrier_verdict(carrier, http_ref, br_ref),
                    })

                    http_hdr = http_header(sess, carrier)
                    br_hdr = browser_until(browser, cookies,
                                           BASE + "/xss_user_agent.php", carrier,
                                           ua=carrier["payload"],
                                           expect=(lname != "high"))
                    rows.append({
                        "level": lname, "level_id": lvl, "face": "header",
                        "carrier": carrier["id"], "role": role, "n": carrier["n"],
                        "http": {k: http_hdr[k] for k in
                                 ("status", "payload_in", "addslashes_escaped",
                                  "payload_exact", "tag_intact", "context")},
                        "browser": carrier_verdict(carrier, http_hdr, br_hdr),
                    })

                    http_w = http_stored_write(sess, carrier)
                    view = http_stored_view(sess, carrier)
                    http_v = {"status": view["status"], "level": view["level"],
                              "payload_in": view["payload_in"],
                              "addslashes_escaped": view["addslashes_escaped"],
                              "payload_exact": view["payload_exact"],
                              "tag_intact": view["tag_intact"],
                              "context": view["context"]}
                    br_st = browser_until(browser, cookies,
                                          BASE + "/xss_stored_1.php", carrier,
                                          expect=(lname != "high"))
                    rows.append({
                        "level": lname, "level_id": lvl, "face": "stored",
                        "carrier": carrier["id"], "role": role, "n": carrier["n"],
                        "http": {k: http_w[k] for k in
                                 ("status", "payload_in", "addslashes_escaped",
                                  "payload_exact", "tag_intact", "context")},
                        "http_view": {k: http_v[k] for k in
                                      ("status", "payload_in", "addslashes_escaped",
                                       "payload_exact", "tag_intact", "context")},
                        "browser": carrier_verdict(carrier, http_v, br_st),
                    })

            # Cross-role: bee viewing bwuser's low-privilege blog entries.
            if "bee" in role_filter and "bwuser" in role_filter:
                bee = sessions["bee"]
                bc = carriers_for("bwuser")
                default_html = bee.get(BASE + "/xss_stored_1.php", timeout=15).text
                visible_default = [c["id"] for c in bc
                                   if "alert(%d)" % c["n"] in default_html]
                show = http_stored_write(bee, bc[0], show_all=True)
                br_show = browser_probe(browser, cookie_list(bee),
                                        BASE + "/xss_stored_1.php", show_all=True)
                msgs = [str(m) for m in br_show.get("dialogs", [])]
                bw_alerts = [c["n"] for c in bc if str(c["n"]) in msgs]
                if lname != "high" and len(bw_alerts) < len(bc):
                    again = browser_probe(browser, cookie_list(bee),
                                          BASE + "/xss_stored_1.php", show_all=True)
                    br_show["dialogs"] = br_show.get("dialogs", []) + again.get("dialogs", [])
                    br_show["html"] = again.get("html") or br_show.get("html", "")
                    br_show["error"] = br_show.get("error") or again.get("error")
                    msgs = [str(m) for m in br_show.get("dialogs", [])]
                    bw_alerts = [c["n"] for c in bc if str(c["n"]) in msgs]
                bee_alerts = [c["n"] for c in carriers_for("bee")
                              if str(c["n"]) in msgs]
                visible_show = [c["id"] for c in bc
                                if "alert(%d)" % c["n"] in br_show.get("html", "")]
                cross.append({
                    "level": lname, "level_id": lvl, "viewer": "bee", "writer": "bwuser",
                    "visible_without_show_all": visible_default,
                    "visible_with_show_all": visible_show,
                    "show_all_http_status": show["status"],
                    "dialogs": br_show.get("dialogs", []),
                    "bwuser_alerts_executed": bw_alerts,
                    "bee_alerts_executed": bee_alerts,
                    "error": br_show.get("error"),
                })
            clear_entries(sessions["bee"])
        browser.close()

    doc = {"generated": datetime.now().isoformat(timespec="seconds"),
           "level_checks": checks, "rows": rows, "cross_role": cross}
    TRUTH_FILE.write_text(json.dumps(doc, ensure_ascii=False, indent=2),
                          encoding="utf-8")
    print("truth rows:", len(rows), "cross:", len(cross), "->", TRUTH_FILE)


# --------------------------------------------------------------------------
# Phase 2: scanner
# --------------------------------------------------------------------------
def scan_once(sess, level_name, face, headless):
    cookie = "; ".join("%s=%s" % (k, v) for k, v in sess.cookies.get_dict().items())
    out = TMP / ("bwmat_%s_%s_%s_%s.json" % (
        level_name, face, "hl" if headless else "static", os.getpid()))
    url = {"reflected": BASE + "/xss_get.php?firstname=xssprobe&lastname=x&form=submit",
           "stored": BASE + "/xss_stored_1.php",
           "header": BASE + "/xss_user_agent.php"}[face]
    cmd = [sys.executable, "-m", "xssentinel", "-u", url,
           "-f", "json", "-o", str(out), "--progress", "none",
           "--log-level", "error", "--max-payloads", "14",
           "--max-transforms", "12", "--threads", "2", "--timeout", "10",
           "-b", cookie, "--no-stored-auto"]
    if headless:
        cmd.append("--headless")
    if face == "stored":
        cmd += ["--stored-inject", BASE + "/xss_stored_1.php",
                "--stored-method", "POST", "--stored-param", "entry",
                "--stored-view", BASE + "/xss_stored_1.php",
                "--stored-extra", "blog=submit", "--stored-extra", "entry_add="]
    t0 = time.time()
    try:
        p = subprocess.run(cmd, cwd=str(REPO), env=env_temp(),
                           capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return {"face": face, "headless": headless, "timeout": True,
                "findings": [], "seconds": round(time.time() - t0, 1), "rc": None}
    findings = []
    requests_made = None
    requests_attempted = None
    if out.exists():
        try:
            doc = json.loads(out.read_text(encoding="utf-8", errors="replace"))
            findings = doc.get("findings") or []
            requests_made = doc.get("requests")
            requests_attempted = doc.get("requests_attempted")
        except Exception:
            findings = []
        out.unlink(missing_ok=True)
    keep_fields = ("type", "param", "severity", "confidence", "payload",
                   "context", "detail", "evidence_class", "url", "method")
    slim = [{k: f.get(k) for k in keep_fields if k in f} for f in findings]
    return {"face": face, "headless": headless, "timeout": False,
            "findings": slim, "seconds": round(time.time() - t0, 1),
            "requests": requests_made,
            "requests_attempted": requests_attempted,
            "rc": p.returncode, "stderr": (p.stderr or "")[-300:]}


def scan_face_findings(face, findings):
    if face == "reflected":
        keep = [f for f in findings
                if f.get("type") in ("reflected", "dom", "dom_dynamic", "dom_static")]
    elif face == "header":
        keep = [f for f in findings if f.get("type") == "header_xss"]
    else:
        keep = [f for f in findings if f.get("type") in ("stored", "stored_dom")]
    return keep


def phase_scan(level_filter, role_filter):
    sessions = {r: login(*CREDS[r]) for r in role_filter}
    scans = []
    for lvl, lname in LEVELS:
        if lvl not in level_filter:
            continue
        for role in role_filter:
            set_level(sessions[role], lvl)
        for role in ROLE_ORDER:
            if role not in role_filter:
                continue
            for face in ("reflected", "stored", "header"):
                rec = {"level": lname, "level_id": lvl, "face": face, "role": role}
                for headless in (False, True):
                    s = scan_once(sessions[role], lname, face, headless)
                    keep = scan_face_findings(face, s["findings"])
                    rec["headless" if headless else "default"] = {
                        "detected": bool(keep),
                        "hits": keep,
                        "seconds": s["seconds"],
                        "requests": s.get("requests"),
                        "requests_attempted": s.get("requests_attempted"),
                        "rc": s["rc"],
                        "timeout": s.get("timeout"),
                        "all_findings": s["findings"],
                    }
                scans.append(rec)
        for role in role_filter:
            clear_entries(sessions[role])
    SCAN_FILE.write_text(json.dumps(
        {"generated": datetime.now().isoformat(timespec="seconds"), "scans": scans},
        ensure_ascii=False, indent=2), encoding="utf-8")
    print("scans:", len(scans), "->", SCAN_FILE)


# --------------------------------------------------------------------------
# Phase 3: merge + markdown
# --------------------------------------------------------------------------
def classify(executed, detected):
    if executed and detected:
        return "TP"
    if executed and not detected:
        return "FN"
    if (not executed) and detected:
        return "FP"
    return "TN"


def phase_report():
    truth = json.loads(TRUTH_FILE.read_text(encoding="utf-8"))
    scan = json.loads(SCAN_FILE.read_text(encoding="utf-8"))
    scan_map = {(s["level"], s["face"], s["role"]): s for s in scan["scans"]}

    lines = []
    lines.append("# bWAPP security_level 矩阵（low / medium / high × 面 × 载体 × 角色）")
    lines.append("")
    lines.append("生成时间：%s　靶：bWAPP 2.2 @ http://127.0.0.1:8081" % truth["generated"])
    lines.append("")
    lines.append("## 1. 档位切换确认")
    lines.append("")
    lines.append("| 档 | bee 页面 Current | bwuser 页面 Current | 生效 |")
    lines.append("|---|---|---|---|")
    for c in truth["level_checks"]:
        cf = c["confirmed"]
        lines.append("| %s | %s | %s | %s |" % (
            c["level"], cf.get("bee", "-"), cf.get("bwuser", "-"),
            "是" if c["all_ok"] else "否"))
    lines.append("")
    lines.append("## 2. 主矩阵（72 组：3 档 × 3 面 × 4 载体 × 2 角色）")
    lines.append("")
    lines.append("回显：`Y/Y`=完整 payload 原样保留且标签存活；`N/Y`=标签存活但完整 payload 被改（medium addslashes 给 `\"` 加反斜杠）；`N/N`=已实体化。")
    lines.append("")
    lines.append("| 档 | 面 | 载体 | 角色 | 回显 | 浏览器执行 | 扫描默认 | 扫描 headless | 归类(默认) | 行级一致(默认) |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|")
    for r in truth["rows"]:
        key = (r["level"], r["face"], r["role"])
        s = scan_map.get(key, {})
        d = (s.get("default") or {}).get("detected")
        h = (s.get("headless") or {}).get("detected")
        ex = r["browser"]["executed"]
        echo = ("Y" if r["http"].get("payload_exact") else "N") + "/" + \
               ("Y" if r["http"].get("tag_intact") else "N")
        cls = classify(ex, bool(d))
        ok = "是" if ex == bool(d) else "否"
        lines.append("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            r["level"], r["face"], r["carrier"], r["role"], echo,
            "执行" if ex else "未执行",
            "报" if d else "未报", "报" if h else "未报", cls, ok))
    lines.append("")
    lines.append("## 3. 存储型跨角色（bee 查看 bwuser 的低权限条目）")
    lines.append("")
    lines.append("| 档 | 不勾 Show all 可见 bwuser 条目 | 勾 Show all 可见 | Show all 弹窗 | 执行到的 bwuser 标记 |")
    lines.append("|---|---|---|---|---|")
    for c in truth["cross_role"]:
        lines.append("| %s | %s | %s | %s | %s |" % (
            c["level"], ",".join(c["visible_without_show_all"]) or "无",
            ",".join(c["visible_with_show_all"]) or "无",
            ", ".join(map(str, c["dialogs"])) or "无",
            ",".join(map(str, c["bwuser_alerts_executed"])) or "无"))
    lines.append("")
    lines.append("## 4. 扫描器原始判定（面级）")
    lines.append("")
    lines.append("| 档 | 面 | 角色 | 默认 detected | 默认 findings(type/param/confidence) | 默认请求数 | 默认耗时(s) | headless detected | headless findings |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for s in scan["scans"]:
        d = s["default"]
        h = s["headless"]
        df = "; ".join("%s/%s/%s" % (f.get("type"), f.get("param"), f.get("confidence"))
                       for f in d["hits"]) or "-"
        hf = "; ".join("%s/%s/%s" % (f.get("type"), f.get("param"), f.get("confidence"))
                       for f in h["hits"]) or "-"
        lines.append("| %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            s["level"], s["face"], s["role"],
            "是" if d["detected"] else "否", df,
            d.get("requests"), d.get("seconds"),
            "是" if h["detected"] else "否", hf))
    lines.append("")
    MD_FILE.write_text("\n".join(lines), encoding="utf-8")
    FINAL_FILE.write_text(json.dumps({"truth": truth, "scan": scan},
                                     ensure_ascii=False, indent=2), encoding="utf-8")
    print("report ->", MD_FILE, "| merged ->", FINAL_FILE)


def main():
    TMP.mkdir(parents=True, exist_ok=True)
    os.environ["TEMP"] = str(TMP)
    os.environ["TMP"] = str(TMP)
    ap = argparse.ArgumentParser()
    ap.add_argument("--phase", choices=["truth", "scan", "report", "all"],
                    default="all")
    ap.add_argument("--levels", default="0,1,2")
    ap.add_argument("--roles", default="bee,bwuser")
    args = ap.parse_args()
    lv = [int(x) for x in args.levels.split(",") if x != ""]
    roles = [x for x in args.roles.split(",") if x]
    if args.phase in ("truth", "all"):
        phase_truth(lv, roles)
    if args.phase in ("scan", "all"):
        phase_scan(lv, roles)
    if args.phase in ("report", "all"):
        phase_report()


if __name__ == "__main__":
    main()
