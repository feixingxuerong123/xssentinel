"""Phase 392 / M3: OWASP NodeGoat -- third-party app, third-party answer key.

Why
---
external_validity_20261108.md §5 lists "更多第三方靶场" as a gap.  XSSMaze is
blocked on this machine (wsl.exe denied / Docker daemon down), so this round
adds ONE more real third-party application that runs natively: OWASP NodeGoat
(master, zip downloaded via mirror), its official seed data and its official
source as the answer key -- with every shape ALSO adjudicated by a real
Chromium load (the same dialog notion the project's browser arm uses).

Answer key provenance (source citations live with each KEY entry below):
  * server.js:135-137 -- swig `autoescape: false` for the app template
    loader; the `autoescape: true` fix is literally a comment block.
  * app/views/profile.html -- unescaped `{{lastName}}` / `{{ssn}}` /
    `{{bankAcc}}` / `{{address}}` inside value="..." attributes and
    unescaped `{{updateError}}`.
  * app/routes/profile.js -- the invalid-bankRouting error path re-renders
    the user's input unescaped (reflection, no storage).
  * app/views/memos.html -- `{{ marked(doc.memo) }}` with marked@0.3.5
    `sanitize: true` (server.js:126-129).  marked's own docs call `sanitize`
    deprecated and insufficient; whether a given payload survives is a
    MEASURED question, not assumed either way.
  * app/routes/profile.js:21-25 -- official FIXME: firstName is encoded for
    HTML context but used as an <a href>; javascript: URIs survive HTML
    encoding and require a click (activation) -- recorded as its own shape,
    never counted as a load-exec miss.

Honesty rules (Phase 380/381 discipline):
  * Fact table only.  No F1, no rates, no comparison with XSSMaze numbers.
  * The app is unreachable => ABORT, never a silent "0 findings is fine"
    (Phase 327 "假无发现" family).
  * Memos cannot be deleted once inserted; the memo delivery runs LAST and
    the planted state is disclosed in the report (Phase 381 rule).

Usage (app must already be running; startup commands are printed on failure)::

    python benchmark/run_nodegoat.py --tree <short-sha> \
        --base http://127.0.0.1:18946
Writes benchmark/results/phase392_nodegoat_20261114.{json,md}
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

RESULT_STEM = "phase392_nodegoat_20261114"
DEFAULT_BASE = "http://127.0.0.1:18946"
PREFLIGHT_MARKER = 'name="userName"'
SEED_USER = "admin"           # artifacts/db-reset.js (official seed)
SEED_PASS = "Admin_123"       # artifacts/db-reset.js:18 (official seed)
ENGINE_TIMEOUT = 600
DALFOX_TIMEOUT = 45
NUCLEI_TIMEOUT = 120

BENIGN = {
    "firstName": "Admin",
    "lastName": "Benign",
    "ssn": "111-22-3333",
    "dob": "1980-01-01",
    "address": "1 Main Street",
    "bankAcc": "123456789",
    "bankRouting": "123456789#",
    "website": "https://example.invalid/",
}
PLANT = {
    "last": '"><svg onload=alert(841)>',
    "ssn": '"><svg onload=alert(842)>',
    "bankAcc": '"><svg onload=alert(843)>',
    "address": '"><svg onload=alert(844)>',
    "memo": "<img src=x onerror=alert(846)>",
    "href": "javascript:alert(847)",
}

# (id, target_page, delivery_field, payload, citation, expect)
KEY = [
    ("V1-lastname-attr-breakout", "/profile", "lastName", PLANT["last"],
     "server.js:135-137 autoescape:false + app/views/profile.html:45 "
     "value=\"{{lastName}}\"", "exec"),
    ("V2-ssn-attr-breakout", "/profile", "ssn", PLANT["ssn"],
     "app/views/profile.html:49 value=\"{{ssn}}\" (same autoescape:false)",
     "exec"),
    ("V3-bankacc-attr-breakout", "/profile", "bankAcc", PLANT["bankAcc"],
     "app/views/profile.html:57 value=\"{{bankAcc}}\"", "exec"),
    ("V4-address-attr-breakout", "/profile", "address", PLANT["address"],
     "app/views/profile.html:66 value=\"{{address}}\"", "exec"),
    ("V5-updateerror-reflection", "(POST response)", "lastName(Reflect)",
     PLANT["last"],
     "app/routes/profile.js invalid-bankRouting path re-renders user input "
     "+ app/views/profile.html:24 {{updateError}}; fields re-rendered raw",
     "exec"),
    ("V6-memos-marked", "/memos", "memo", PLANT["memo"],
     "app/views/memos.html {{ marked(doc.memo) }} + server.js:126-129 "
     "marked sanitize:true -- survival is measured, not assumed", "adjudicate"),
    ("V7-firstname-href-jsuri", "/profile", "firstName", PLANT["href"],
     "app/routes/profile.js:21-25 official FIXME: HTML-encoded in URL "
     "context -> javascript: survives; needs click (activation)",
     "activation-load-inert"),
]


def preflight(base: str) -> None:
    try:
        r = requests.get(f"{base}/login", timeout=10)
    except requests.RequestException as e:
        print(f"[abort] NodeGoat 不可达: {e}\n"
              "启动方式:\n"
              "  mongod --port 27018 --dbpath dev/_nodegoat_db\n"
              "  cd dev/_nodegoat && npm install\n"
              "  NODE_ENV=development PORT=18946 "
              "MONGODB_URI=mongodb://localhost:27018/nodegoat node server.js\n"
              "  node artifacts/db-reset.js (同环境变量)", file=sys.stderr)
        raise SystemExit(3)
    if r.status_code != 200 or PREFLIGHT_MARKER not in r.text:
        print(f"[abort] /login 不像 NodeGoat (rc={r.status_code}, "
              f"marker={PREFLIGHT_MARKER in r.text})", file=sys.stderr)
        raise SystemExit(3)


def login(base: str) -> requests.Session:
    s = requests.Session()
    r = s.post(f"{base}/login",
               data={"userName": SEED_USER, "password": SEED_PASS},
               timeout=15, allow_redirects=False)
    if r.status_code not in (302, 303):
        raise SystemExit(f"[abort] 登录失败 rc={r.status_code}")
    # follow redirect to land the session cookie
    s.get(f"{base}/", timeout=15)
    if not s.cookies:
        raise SystemExit("[abort] 登录后无会话 cookie")
    return s


def plant_profile(s: requests.Session, base: str, field: str, value: str,
                  reflect_error: bool = False) -> requests.Response:
    body = dict(BENIGN)
    body[field] = value
    if reflect_error:
        body["bankRouting"] = "not-a-routing-number"
    return s.post(f"{base}/profile", data=body, timeout=15)


def oracle_urls(urls: dict[str, str], cookie: str = "") -> dict[str, dict]:
    """Real Chromium, dialog-on-load, loopback-only network.

    The session cookie is injected into the browser context: without it
    isLoggedIn() bounces every page to /login and the stored shapes would be
    'measured' on the wrong page (measured in this round: first run without
    the cookie read V1-V4 as inert; that run was discarded, not reported).
    """
    from playwright.sync_api import sync_playwright

    out: dict[str, dict] = {}
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context()
        if cookie:
            context.add_cookies([{"name": "connect.sid", "value": cookie,
                                  "url": "http://127.0.0.1"}])

        def _route(route):
            url = route.request.url
            if "://127.0.0.1" in url or "://localhost" in url:
                route.continue_()
            else:
                route.abort()

        context.route("**/*", _route)
        for cid, url in urls.items():
            seen: list[str] = []

            def _dialog(dialog, _seen=seen):
                _seen.append(str(dialog.message)[:80])
                try:
                    dialog.dismiss()
                except Exception:  # noqa: BLE001
                    pass

            page = context.new_page()
            page.on("dialog", _dialog)
            try:
                page.goto(url, timeout=6000, wait_until="domcontentloaded")
            except Exception:  # noqa: BLE001
                pass
            page.wait_for_timeout(2000)
            out[cid] = {"oracle": "exec" if seen else "inert",
                        "dialogs": seen[:3]}
            page.close()
        browser.close()
    return out


def run_engine(base: str, cookie: str, out_path: str) -> dict:
    from benchmark.adapters import DEFAULT_MAX_PAYLOADS, DEFAULT_MAX_TRANSFORMS

    # The authenticated pages are the answer-key pages; scan them directly
    # (base-page crawling alone never reaches them in the allotted depth).
    batch_path = os.path.join(_ROOT, "dev", "_p392_nodegoat_urls.txt")
    with open(batch_path, "w", encoding="utf-8") as fh:
        fh.write(f"{base}/profile\n{base}/memos\n")
    cmd = [
        sys.executable, "-m", "xssentinel",
        "--batch", batch_path,
        "-f", "json", "-o", "-",
        "--progress", "none", "--log-level", "error",
        "--timeout", "10",
        "--max-payloads", str(DEFAULT_MAX_PAYLOADS),
        "--max-transforms", str(DEFAULT_MAX_TRANSFORMS),
        "-b", f"connect.sid={cookie}",
    ]
    try:
        t0 = time.time()
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace",
                              timeout=ENGINE_TIMEOUT, cwd=_ROOT)
        elapsed = time.time() - t0
    finally:
        try:
            os.unlink(batch_path)
        except OSError:
            pass
    # NOTE: batch + `-o FILE` was measured (Phase 392) to produce rc=0 with
    # NO file and NO stdout -- a silent no-output path recorded as a defect
    # candidate in the round report.  This runner therefore uses `-o -`
    # (stdout JSONL, the Phase 359 contract) and parses the stream.
    findings = []
    rows: list = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    for rep in rows:
        for f in rep.get("findings") or []:
            findings.append({
                "url": f.get("url", ""),
                "layer": f.get("layer") or f.get("type", ""),
                "severity": f.get("severity", ""),
                "evidence": str(f.get("evidence", ""))[:160],
            })
    return {"rc": proc.returncode, "seconds": round(elapsed, 1),
            "findings": findings,
            "stderr_tail": (proc.stderr or "")[-400:]}


def run_tools(base: str, cookie: str) -> dict:
    rows = []
    for tool, cmd_fn, ceiling in (
        ("dalfox", _dalfox_cmd, DALFOX_TIMEOUT),
        ("nuclei", _nuclei_cmd, NUCLEI_TIMEOUT),
    ):
        for page in ("/profile", "/memos"):
            url = f"{base}{page}"
            ceiling_here = ceiling if page == "/memos" else max(ceiling, 90)
            t0 = time.time()
            try:
                p = subprocess.run(cmd_fn(url, cookie), capture_output=True,
                                   text=True, encoding="utf-8",
                                   errors="replace", timeout=ceiling_here,
                                   cwd=_ROOT)
                hits = _hits(tool, p.stdout or "")
                rows.append({"tool": tool, "page": page, "detected": bool(hits),
                             "hits": len(hits),
                             "seconds": round(time.time() - t0, 1),
                             "error": ""})
            except subprocess.TimeoutExpired:
                rows.append({"tool": tool, "page": page, "detected": False,
                             "hits": 0, "seconds": ceiling_here,
                             "error": "timeout"})
            except FileNotFoundError:
                rows.append({"tool": tool, "page": page, "detected": False,
                             "hits": 0, "seconds": 0.0, "error": "not-installed"})
            except Exception as e:  # noqa: BLE001
                rows.append({"tool": tool, "page": page, "detected": False,
                             "hits": 0, "seconds": round(time.time() - t0, 1),
                             "error": type(e).__name__})
    return {"rows": rows,
            "note": "FACT TABLE ONLY. No TP/FP/TN/FN or rates (Phase 380 "
                    "rule): third-party tools got a cookie, not an "
                    "execution-level oracle, and budgets differ."}


def _dalfox_cmd(url: str, cookie: str) -> list[str]:
    return ["dalfox", "url", url, "--cookie", f"connect.sid={cookie}",
            "--format", "json", "--silence", "--timeout", "30",
            "--worker", "1"]


def _nuclei_cmd(url: str, cookie: str) -> list[str]:
    templates = os.path.join(os.path.expanduser("~"), "nuclei-templates",
                             "dast", "vulnerabilities", "xss")
    return ["nuclei", "-u", url, "-dast", "-t", templates, "-jsonl",
            "-silent", "-no-color", "-timeout", "10", "-retries", "1",
            "-duc", "-nc", "-H", f"Cookie: connect.sid={cookie}"]


def _hits(tool: str, stdout: str) -> list[dict]:
    hits = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        if tool == "dalfox":
            if str(j.get("type", "")).lower() == "vulnerability":
                hits.append(j)
        else:
            sev = str((j.get("info") or {}).get("severity", "")).lower()
            if sev in ("medium", "high", "critical"):
                hits.append(j)
    return hits


def to_markdown(data: dict) -> str:
    L: list[str] = []
    L.append("# Phase 392 / M3:OWASP NodeGoat(官方应用 + 官方种子 + 源码答案键)")
    L.append("")
    L.append(data["honesty_header"])
    L.append("")
    L.append("| key | 投递页 | 字段 | oracle(load 态) | 预期 | 对话框 | 源码依据 |")
    L.append("|---|---|---|---|---|---|---|")
    for k in data["oracle_rows"]:
        L.append(f"| {k['id']} | {k['page']} | {k['field']} | {k['oracle']} | "
                 f"{k['expect']} | {k['dialogs'][:1] or '-'} | {k['citation']} |")
    L.append("")
    L.append("## 控制页")
    L.append("")
    for k in data["control_rows"]:
        L.append(f"- {k['id']}: oracle={k['oracle']}")
    L.append("")
    e = data.get("engine")
    if e:
        L.append(f"## XSSentinel 端到端(rc={e['rc']},{e['seconds']}s)")
        L.append("")
        L.append("| url | layer | severity | evidence |")
        L.append("|---|---|---|---|")
        for f in e["findings"]:
            L.append(f"| {f['url']} | {f['layer']} | {f['severity']} | "
                     f"{f['evidence'][:80]} |")
        L.append("")
    L.append("## 第三方工具事实表(只记事实,不算分)")
    L.append("")
    L.append("| tool | page | detected | hits | seconds | error |")
    L.append("|---|---|---|---|---|---|")
    for r in data.get("tools", {}).get("rows", []):
        L.append(f"| {r['tool']} | {r['page']} | {r['detected']} | {r['hits']} | "
                 f"{r['seconds']} | {r['error']} |")
    L.append("")
    if "tools" in data:
        L.append(f"边界:{data['tools']['note']}")
        L.append("")
    L.append("## 不可比项")
    L.append("")
    for line in data["not_comparable"]:
        L.append(f"- {line}")
    L.append("")
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tree", required=True)
    ap.add_argument("--base", default=DEFAULT_BASE)
    ap.add_argument("--skip-engine", action="store_true",
                    help="只跑 oracle 事实表(冒烟)")
    ap.add_argument("--skip-tools", action="store_true")
    args = ap.parse_args()

    preflight(args.base)
    s = login(args.base)
    cookie = None
    for c in s.cookies:
        if c.name == "connect.sid":
            cookie = c.value
            break
    if not cookie:
        raise SystemExit("[abort] 会话里没有 connect.sid cookie")

    # baseline: benign profile + benign memo (control)
    plant_profile(s, args.base, "lastName", BENIGN["lastName"])
    s.post(f"{args.base}/memos", data={"memo": "hello from phase392 control"},
           timeout=15)

    # controls first: benign profile page + benign memos page
    control_pages = {
        "ctl-profile-benign": f"{args.base}/profile",
        "ctl-memos-benign": f"{args.base}/memos",
    }
    verdicts = oracle_urls(control_pages, cookie)

    # Stored deliveries, one at a time: /profile is a SINGLE record and every
    # POST rewrites every field, so batching "plant all, load once" would let
    # each later POST wipe the earlier payloads (first run measured exactly
    # that artifact; the run was discarded, not reported).
    for kid, page, field, payload, _citation, _expect in KEY:
        if field not in ("lastName", "ssn", "bankAcc", "address"):
            continue
        plant_profile(s, args.base, field, payload)
        verdicts.update(oracle_urls({kid: f"{args.base}{page}"}, cookie))
        plant_profile(s, args.base, field, BENIGN[field])  # restore

    # V5: reflection-only in the POST response itself (error path, not stored)
    v5 = plant_profile(s, args.base, "lastName", PLANT["last"],
                       reflect_error=True)
    baked: dict[str, str] = {"V5-updateerror-reflection": v5.text}
    plant_profile(s, args.base, "lastName", BENIGN["lastName"])  # restore

    # V7 activation shape (firstName) -- recorded, never counted as exec miss
    plant_profile(s, args.base, "firstName", PLANT["href"])

    # V6 memos LAST (memos cannot be deleted once inserted)
    s.post(f"{args.base}/memos", data={"memo": PLANT["memo"]}, timeout=15)

    # serve the captured V5 POST-response bytes for the oracle
    # (port 0: the Hyper-V excluded ranges shift per boot -- 18949 bound
    # fine on 11-14 and was 10013-blocked on 11-15)
    srv_port = 0

    class _H(BaseHTTPRequestHandler):
        def do_GET(self):
            body = baked.get(self.path.lstrip("/"), b"not found")
            if isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", srv_port), _H)
    srv_port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    batch = {
        "V5-updateerror-reflection":
            f"http://127.0.0.1:{srv_port}/V5-updateerror-reflection",
        "V7-firstname-href-jsuri": f"{args.base}/profile",
        "V6-memos-marked": f"{args.base}/memos",
    }
    verdicts.update(oracle_urls(batch, cookie))
    srv.shutdown()

    control_rows = [{"id": cid, "oracle": verdicts[cid]["oracle"],
                     "dialogs": verdicts[cid]["dialogs"]}
                    for cid in control_pages]
    for cid in control_pages:
        if verdicts[cid]["oracle"] != "inert":
            print(f"[abort] 控制页 {cid} oracle={verdicts[cid]['oracle']} "
                  "(良性页不该有对话框)", file=sys.stderr)
            return 3

    oracle_rows = []
    for kid, page, field, payload, citation, expect in KEY:
        v = verdicts[kid]
        oracle_rows.append({"id": kid, "page": page, "field": field,
                            "payload_head": payload[:60], "oracle": v["oracle"],
                            "dialogs": v["dialogs"], "expect": expect,
                            "citation": citation})
    for row in oracle_rows:
        if row["expect"] == "exec" and row["oracle"] != "exec":
            # honest adjudication beats expectation -- keep the measurement
            row["expect_vs_oracle"] = "EXPECTATION_MISSED"

    data = {
        "phase": "392-m3",
        "tree": args.tree,
        "base": args.base,
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "honesty_header": (
            "OWASP NodeGoat master(官方 zip,ghfast 镜像)在 127.0.0.1 运行,"
            "官方种子账号(artifacts/db-reset.js),答案键 = 官方源码引用 + "
            "本机 Chromium load 态对话框实测。事实表,不是 F1 跑分;不与 "
            "XSSMaze / 194 矩阵 / bWAPP / Juice Shop 并列。"),
        "oracle_rows": oracle_rows,
        "control_rows": control_rows,
        "not_comparable": [
            "本表不与 XSSMaze(官方靶+官方 scorer,唯一 F1 来源)、194 矩阵、"
            "bWAPP、Juice Shop 的任何数字并列;population 只有 7 个投递形状,"
            "不构成任何率",
            "V6 的 marked sanitize 存活与否是测量结论,官方文档自认 sanitize "
            "不充分——不据此宣称 marked 有/无洞",
            "V7 是 activation 形状(load 态必然 inert),不计入未检出",
            "第三方工具行是事实表:dalfox/nuclei 拿到的是会话 cookie,"
            "不是执行级 oracle,预算也不同(Phase 380 规则)",
            "本轮向靶场写入 1 条 memo(不可删)+ 多次 profile 覆写,状态已披露",
        ],
    }

    if not args.skip_engine:
        # re-plant the stored shape so the scanner sees stored content present
        plant_profile(s, args.base, "lastName", PLANT["last"])
        out_path = os.path.join(_HERE, "results", RESULT_STEM + "_scan.json")
        data["engine"] = run_engine(args.base, cookie, out_path)

    if not args.skip_tools:
        plant_profile(s, args.base, "lastName", PLANT["last"])
        data["tools"] = run_tools(args.base, cookie)

    out_json = os.path.join(_HERE, "results", RESULT_STEM + ".json")
    os.makedirs(os.path.dirname(out_json), exist_ok=True)
    with open(out_json, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    with open(os.path.splitext(out_json)[0] + ".md", "w",
              encoding="utf-8") as fh:
        fh.write(to_markdown(data))
    print(f"json -> {out_json}")
    for r in oracle_rows:
        print(f"  {r['id']:<32} oracle={r['oracle']:<6} expect={r['expect']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
