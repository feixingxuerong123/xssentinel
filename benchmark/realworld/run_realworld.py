#!/usr/bin/env python3
"""Real-world XSS regression runner (OWASP Juice Shop + DVWA, fixed images).

This is deliberately SEPARATE from benchmark/runner.py's self-authored 194-case
matrix: the targets here are third-party applications, the ground truth comes
from their own challenge catalogue / source tree plus an independent Playwright
check, and the case list is frozen in cases.json.

v2 adds two authenticated apps:
  * Juice Shop ``NODE_ENV=unsafe`` (Docker-disabled challenges re-enabled):
    API-only XSS (PUT /api/Products/:id) and HTTP-header XSS
    (GET /rest/saveLoginIp with True-Client-IP).
  * DVWA (digest-pinned image, admin/password, security=low): login-required
    reflected XSS and persistent guestbook XSS.

Each tool gets the same seeded application state.  Tools that structurally
cannot drive an authenticated write + SPA render are marked BLOCKED with the
reason, not silently scored as a false negative.

Usage::

    # bring the three fixed targets up first (see README.md)
    python benchmark/realworld/run_realworld.py
    python benchmark/realworld/run_realworld.py --tools xssentinel,dalfox,nuclei
    python benchmark/realworld/run_realworld.py --tools burp,acunetix  # unavailable report

Tool availability is measured, not assumed:
  * dalfox / nuclei paths come from $DALFOX_BIN and $NUCLEI_BIN, with known
    host install locations as fallbacks.
  * Burp Pro / Acunetix are reported as "unavailable / not executed" unless
    their REST endpoint AND key are configured.  No fabricated numbers.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PY = Path(sys.executable)
DEFAULT_CASES = Path(__file__).with_name("cases.json")
DEFAULT_OUT = Path(__file__).with_name("results") / "realworld_v2.json"
DEFAULT_MD = Path(__file__).with_name("results") / "realworld_v2.md"
TMP = REPO / "tests" / "_pytest_tmp"

XSS_TYPES = {"reflected", "stored", "stored_dom", "dom", "dom_dynamic",
             "header_xss", "cookie_xss", "path_xss"}
OFFICIAL_PAYLOAD = '<iframe src="javascript:alert(`xss`)">'


def _env_temp() -> dict:
    env = os.environ.copy()
    TMP.mkdir(parents=True, exist_ok=True)
    env["TEMP"] = str(TMP)
    env["TMP"] = str(TMP)
    env["TERM"] = "dumb"
    return env


def _run(cmd, timeout: int) -> tuple[subprocess.CompletedProcess | None, float]:
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, cwd=str(REPO), env=_env_temp(),
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout,
                              stdin=subprocess.DEVNULL)
        return proc, time.time() - t0
    except subprocess.TimeoutExpired:
        return None, time.time() - t0


def _which(*cands) -> str | None:
    for c in cands:
        if not c:
            continue
        p = shutil.which(c)
        if p:
            return p
        if Path(c).exists():
            return c
    return None


def _json_or_none(text: str):
    try:
        return json.loads(text)
    except Exception:
        return None


def _abs(base: str, path: str) -> str:
    if path.startswith(("http://", "https://")):
        return path
    return base.rstrip("/") + "/" + path.lstrip("/")


# --------------------------------------------------------------------------
# Auth / setup (the same seeded state is handed to every tool)
# --------------------------------------------------------------------------
def dvwa_login(base: str) -> dict:
    import requests
    s = requests.Session()
    g = s.get(base + "/login.php", timeout=10)
    tok = re.search(r"name='user_token' value='([^']+)'", g.text or "")
    data = {"username": "admin", "password": "password", "Login": "Login"}
    if tok:
        data["user_token"] = tok.group(1)
    s.post(base + "/login.php", data=data, timeout=10)
    sec = s.get(base + "/security.php", timeout=10)
    m = re.search(r"name='user_token' value='([^']+)'", sec.text or "")
    payload = {"security": "low", "seclev_submit": "Submit"}
    if m:
        payload["user_token"] = m.group(1)
    s.post(base + "/security.php", data=payload, timeout=10)
    return {"cookie": "; ".join(f"{k}={v}" for k, v in s.cookies.get_dict().items()),
            "session": s}


def juice_login(base: str) -> dict:
    import requests
    r = requests.post(base + "/rest/user/login",
                      json={"email": "admin@juice-sh.op", "password": "admin123"},
                      headers={"Content-Type": "application/json"}, timeout=10)
    try:
        tok = r.json()["authentication"]["token"]
    except Exception as exc:
        raise RuntimeError(f"Juice Shop login failed ({r.status_code}): {exc}")
    return {"token": tok, "header": "Authorization: Bearer " + tok}


def bwapp_login(base: str) -> dict:
    import requests
    s = requests.Session()
    s.post(base + "/login.php", data={
        "login": "bee", "password": "bug", "form": "submit",
        "security_level": "0"}, timeout=10)
    return {"cookie": "; ".join(f"{k}={v}" for k, v in s.cookies.get_dict().items()),
            "session": s}


def selfhosted_login(base: str, user: str, password: str) -> dict:
    import requests
    s = requests.Session()
    s.post(base + "/login", data={"user": user, "pass": password}, timeout=10)
    return {"cookie": "; ".join(f"{k}={v}" for k, v in s.cookies.get_dict().items()),
            "session": s}


def prepare_case(case: dict, app: dict) -> dict:
    """Log in and perform the case's write setup.  Returns auth material."""
    import requests
    base = app["base_url"]
    auth: dict = {}
    if case.get("auth") == "dvwa":
        auth = dvwa_login(base)
    elif case.get("auth") == "juice":
        auth = juice_login(base)
        headers = {"Authorization": auth["header"].split(": ", 1)[1],
                   "Content-Type": "application/json"}
        for op in case.get("setup") or []:
            if op == "seed_product":
                requests.put(base + "/api/Products/1", headers=headers,
                             json={"description": OFFICIAL_PAYLOAD}, timeout=10)
            elif op == "reset_product":
                # The scanner's stored-DOM arm writes its own payload and
                # needs a clean baseline; a pre-seeded description can fire a
                # dialog before the instrumented run attaches its hooks.
                requests.put(base + "/api/Products/1", headers=headers,
                             json={"description": ""}, timeout=10)
            elif op == "save_login_ip":
                requests.get(base + "/rest/saveLoginIp",
                             headers={**headers, "True-Client-IP": OFFICIAL_PAYLOAD},
                             timeout=10)
    elif case.get("auth") == "bwapp":
        auth = bwapp_login(base)
    elif case.get("auth") == "sh_alice":
        auth = selfhosted_login(base, "alice", "alicepass")
    elif case.get("auth") == "sh_admin":
        auth = selfhosted_login(base, "admin", "adminpass")
    for op in case.get("setup") or []:
        if op == "seed_guestbook":
            writer = selfhosted_login(base, "alice", "alicepass")
            writer["session"].post(base + "/guestbook",
                                   data={"body": "<script>alert('sh_seed')</script>"},
                                   timeout=10)
    return auth


# --------------------------------------------------------------------------
# Tool runners
# --------------------------------------------------------------------------
def run_xssentinel(case: dict, app: dict, auth: dict, timeout: int,
                   headless: bool):
    base = app["base_url"]
    report = TMP / f"rw2_{os.getpid()}_{int(time.time() * 1000)}_{headless}.json"
    cmd = [str(PY), "-m", "xssentinel", "-u", _abs(base, case["url"]),
           "-f", "json", "-o", str(report), "--progress", "none",
           "--log-level", "error", "--max-payloads", "14",
           "--max-transforms", "12", "--threads", "2", "--timeout", "10"]
    if headless:
        cmd.append("--headless")
    if case.get("auth") in ("dvwa", "bwapp", "sh_alice", "sh_admin"):
        cmd += ["-b", auth["cookie"]]
    elif case.get("auth") == "juice":
        # --login-json now seeds BOTH the HTTP Authorization header and the
        # browser localStorage token (Phase 289b), which SPA route guards read.
        cmd += ["--login-json", "--login-url", base + "/rest/user/login",
                "--login-user", "admin@juice-sh.op", "--login-field-user",
                "email", "--login-pass", "admin123"]
    stored = (case.get("xssentinel") or {}).get("stored")
    if stored:
        cmd += ["--stored-inject", _abs(base, stored["inject"]),
                "--stored-method", stored.get("method", "POST"),
                "--stored-param", stored.get("param", "q")]
        if stored.get("json"):
            cmd.append("--stored-json")
        if stored.get("header"):
            cmd += ["--stored-header", stored["header"]]
        if stored.get("view"):
            cmd += ["--stored-view", _abs(base, stored["view"])]
        if stored.get("view_click"):
            cmd += ["--stored-view-click", stored["view_click"]]
        if stored.get("dom"):
            cmd.append("--stored-dom")
        if stored.get("relogin"):
            cmd.append("--stored-relogin")
        for k, v in (stored.get("extra") or {}).items():
            cmd += ["--stored-extra", f"{k}={v}"]
    if os.environ.get("RW_DEBUG"):
        print("[cmd]", " ".join(cmd), file=sys.stderr)
    proc, dt = _run(cmd, timeout)
    if os.environ.get("RW_DEBUG") and proc is not None:
        print("[stdout]", proc.stdout[-600:], file=sys.stderr)
        print("[stderr]", proc.stderr[-600:], file=sys.stderr)
    findings = []
    if os.environ.get("RW_DEBUG"):
        print("[report]", report, "exists=", report.exists(), file=sys.stderr)
    if report.exists():
        doc = _json_or_none(report.read_text(encoding="utf-8", errors="replace"))
        findings = (doc or {}).get("findings") or []
        if os.environ.get("RW_DEBUG"):
            print("[findings]", [(f.get("type"), f.get("severity"))
                                 for f in findings], file=sys.stderr)
        report.unlink(missing_ok=True)
    xss = [(f.get("type"), f.get("severity"), f.get("confidence"),
            f.get("evidence_class"))
           for f in findings
           if f.get("type") in XSS_TYPES
           and f.get("severity") in ("medium", "high", "critical")]
    return {"detected": bool(xss), "xss": xss,
            "rc": None if proc is None else proc.returncode,
            "seconds": round(dt, 1),
            "note": "" if proc is not None else "timeout"}


def _dalfox_bin() -> str | None:
    return _which(os.environ.get("DALFOX_BIN"),
                  r"C:\GoWorkspace\bin\dalfox.exe",
                  r"C:\Users\Administrator\go\bin\dalfox.exe", "dalfox")


def run_dalfox(case: dict, app: dict, auth: dict, timeout: int):
    binary = _dalfox_bin()
    if not binary:
        return {"detected": False, "status": "unavailable",
                "reason": "dalfox binary not found", "seconds": 0}
    cmd = [binary, "url", _abs(app["base_url"], case["url"]),
           "--format", "json", "--silence", "--skip-headless"]
    if auth.get("cookie"):
        cmd += ["-C", auth["cookie"]]
    if auth.get("header"):
        cmd += ["-H", auth["header"]]
    df = case.get("dalfox") or {}
    if df.get("method"):
        cmd += ["-X", df["method"]]
    if df.get("data"):
        cmd += ["-d", df["data"]]
    proc, dt = _run(cmd, timeout)
    out = (proc.stdout or "") if proc else ""
    hits = []
    doc = _json_or_none(out.strip())
    if isinstance(doc, list):
        for item in doc:
            if isinstance(item, dict) and str(item.get("type", "")).upper() == "V":
                hits.append(item.get("severity") or "?")
    if not hits and '"type":"V"' in out.replace(" ", ""):
        hits = re.findall(r'"severity"\s*:\s*"([^"]+)"', out)
    return {"detected": bool(hits), "xss": [("dalfox-V", s) for s in hits],
            "rc": None if proc is None else proc.returncode,
            "seconds": round(dt, 1),
            "note": "" if proc is not None else "timeout"}


def _nuclei_bin() -> str | None:
    return _which(os.environ.get("NUCLEI_BIN"),
                  r"C:\Users\Administrator\go\bin\nuclei.exe",
                  r"C:\GoWorkspace\bin\nuclei.exe", "nuclei")


def run_nuclei(case: dict, app: dict, auth: dict, timeout: int):
    binary = _nuclei_bin()
    templates = os.environ.get("NUCLEI_XSS_TEMPLATES") or str(
        Path.home() / "nuclei-templates" / "dast" / "vulnerabilities" / "xss")
    if not binary:
        return {"detected": False, "status": "unavailable",
                "reason": "nuclei binary not found", "seconds": 0}
    cmd = [binary, "-u", _abs(app["base_url"], case["url"]),
           "-dast", "-t", templates, "-jsonl", "-silent",
           "-no-color", "-timeout", "10", "-retries", "1", "-duc", "-nc"]
    if auth.get("cookie"):
        cmd += ["-H", "Cookie: " + auth["cookie"]]
    if auth.get("header"):
        cmd += ["-H", auth["header"]]
    proc, dt = _run(cmd, timeout)
    hits = []
    for line in ((proc.stdout or "") if proc else "").splitlines():
        obj = _json_or_none(line.strip())
        if not obj:
            continue
        sev = str((obj.get("info") or {}).get("severity") or "").lower()
        if sev in ("medium", "high", "critical"):
            hits.append((obj.get("template-id") or "?", sev))
    return {"detected": bool(hits), "xss": hits,
            "rc": None if proc is None else proc.returncode,
            "seconds": round(dt, 1),
            "note": "" if proc is not None else "timeout"}


def run_zap(case: dict, app: dict, auth: dict, timeout: int):
    """OWASP ZAP arm: measured availability, never fabricated.

    The image could not be pulled on this host (ghcr anonymous pull denied;
    Docker Hub mirrors returned TLS timeout/403; GitHub was unreachable) and
    there is no local ZAP install.  Keep the entry point so a host with ZAP
    can wire `zap-baseline.py` / `zap-full-scan.py` here.
    """
    return {"detected": False, "status": "unavailable",
            "reason": ("OWASP ZAP not installed and image pull failed "
                       "(ghcr denied / Docker Hub mirror TLS timeout / "
                       "GitHub unreachable); arm NOT executed"),
            "seconds": 0}


def run_commercial(name: str):
    """No installation/licence on this host -> say so; never invent numbers."""
    env_key = {"burp": "BURP_REST_URL", "acunetix": "ACUNETIX_URL"}[name]
    if not os.environ.get(env_key):
        return {"detected": False, "status": "unavailable",
                "reason": (f"{name}: no {env_key} configured on this host; "
                           "no installation/licence was available, so the arm "
                           "was NOT executed"), "seconds": 0}
    return {"detected": False, "status": "not-executed",
            "reason": (f"{name}: endpoint is configured but this runner has no "
                       "adapter wired; implement run_{name}() before scoring"),
            "seconds": 0}


def tool_version(name: str) -> str:
    try:
        if name == "dalfox":
            b = _dalfox_bin()
            if not b:
                return "unavailable"
            p, _ = _run([b, "version"], 20)
            return ((p.stdout or "") + (p.stderr or "")).strip().splitlines()[0][:80]
        if name == "nuclei":
            b = _nuclei_bin()
            if not b:
                return "unavailable"
            p, _ = _run([b, "-version"], 20)
            m = re.search(r"v\d+\.\d+\.\d+", (p.stdout or "") + (p.stderr or ""))
            return m.group(0) if m else "unknown"
    except Exception:
        pass
    if name.startswith("xssentinel"):
        return "repo HEAD (editable install)"
    return "unavailable"


TOOL_RUNNERS = {
    "xssentinel": lambda c, a, au, t: run_xssentinel(c, a, au, t, False),
    "xssentinel-headless": lambda c, a, au, t: run_xssentinel(c, a, au, t, True),
    "dalfox": run_dalfox,
    "nuclei": run_nuclei,
    "zap": run_zap,
    "burp": lambda c, a, au, t: run_commercial("burp"),
    "acunetix": lambda c, a, au, t: run_commercial("acunetix"),
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    ap.add_argument("--tools", default="xssentinel,xssentinel-headless,dalfox,nuclei")
    ap.add_argument("--timeout", type=int, default=240)
    ap.add_argument("--base", action="append", default=[], metavar="KEY=URL",
                    help="Override a base_url from cases.json (repeatable), "
                         "e.g. --base dvwa=http://127.0.0.1:8088")
    ap.add_argument("--only", default=None,
                    help="Comma-separated case ids to run (debugging aid)")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--md", type=Path, default=DEFAULT_MD)
    args = ap.parse_args()

    meta = json.loads(args.cases.read_text(encoding="utf-8"))
    apps = dict(meta.get("_meta", {}).get("apps", {}))
    if not apps:
        print("[!] cases.json has no _meta.apps block", file=sys.stderr)
        return 2
    for kv in args.base:
        k, _, v = kv.partition("=")
        if k in apps and v:
            apps[k]["base_url"] = v
    cases = meta["cases"]
    if args.only:
        wanted = {c.strip() for c in args.only.split(",") if c.strip()}
        cases = [c for c in cases if c["id"] in wanted]
    tools = [t.strip() for t in args.tools.split(",") if t.strip()]
    unknown = [t for t in tools if t not in TOOL_RUNNERS]
    if unknown:
        print(f"[!] unknown tools: {unknown}", file=sys.stderr)
        return 2

    # Fail fast if a target is down.
    import requests
    for key, app in apps.items():
        try:
            requests.get(app["base_url"], timeout=5)
        except Exception as exc:
            print(f"[!] {key} at {app['base_url']} is not reachable: {exc}",
                  file=sys.stderr)
            return 3

    results = {}
    for tool in tools:
        rows = []
        for case in cases:
            app = apps[case["app"]]
            blocked = (case.get("blocked_tools") or {}).get(tool)
            if blocked:
                res = {"detected": False, "status": "blocked", "reason": blocked,
                       "seconds": 0, "xss": []}
            else:
                auth = prepare_case(case, app)
                res = TOOL_RUNNERS[tool](case, app, auth, args.timeout)
            res["case"] = case["id"]
            res["category"] = case.get("category")
            res["gt"] = case["ground_truth"]
            if blocked or res.get("status") in ("unavailable", "not-executed"):
                res["verdict"] = "BLOCKED"
            elif res["detected"]:
                res["verdict"] = "TP" if case["ground_truth"] == "vulnerable" else "FP"
            else:
                res["verdict"] = "FN" if case["ground_truth"] == "vulnerable" else "TN"
            rows.append(res)
            print(f"[{tool}] {case['id']:34s} {res['verdict']:7s} "
                  f"{res['seconds']}s {res.get('xss') or res.get('reason', '')}")
        results[tool] = rows

    args.out.parent.mkdir(parents=True, exist_ok=True)
    doc = {"generated": datetime.now().isoformat(timespec="seconds"),
           "cases_version": meta.get("_meta", {}).get("version"),
           "apps": apps, "cases": cases,
           "tools": {t: {"version": tool_version(t), "rows": r}
                     for t, r in results.items()}}
    args.out.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        "# Real-world XSS regression v2 — Juice Shop 20.2.0 + DVWA",
        "",
        f"Generated: {doc['generated']}",
        "",
        "Apps: " + "; ".join(
            f"`{k}` {v['base_url']} ({v['image'].split('@')[0]})"
            for k, v in apps.items()),
        "",
        "| tool | status | TP | FN | FP | TN | blocked | recall | FPR | wall(s) |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for tool, rows in results.items():
        scored = [r for r in rows if r["verdict"] != "BLOCKED"]
        blocked = len(rows) - len(scored)
        tp = sum(1 for r in scored if r["verdict"] == "TP")
        fn = sum(1 for r in scored if r["verdict"] == "FN")
        fp = sum(1 for r in scored if r["verdict"] == "FP")
        tn = sum(1 for r in scored if r["verdict"] == "TN")
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        wall = sum(r["seconds"] for r in rows)
        status = "scored" if scored else "unavailable"
        lines.append(f"| {tool} | {status} | {tp} | {fn} | {fp} | {tn} | "
                     f"{blocked} | {recall:.3f} | {fpr:.3f} | {wall:.1f} |")

    lines += ["", "## Per-case", "",
              "| case | app | category | GT | " + " | ".join(results.keys()) + " |",
              "|---|---|---|---|" + "---|" * len(results)]
    for case in cases:
        cells = []
        for tool in results:
            row = next(r for r in results[tool] if r["case"] == case["id"])
            if row["verdict"] == "BLOCKED":
                cells.append("BLOCKED")
            else:
                cells.append(row["verdict"])
        lines.append(f"| {case['id']} | {case['app']} | {case.get('category','-')} | "
                     f"{case['ground_truth']} | " + " | ".join(cells) + " |")

    lines += ["", "## Blocked-tool reasons", ""]
    for case in cases:
        for tool, reason in (case.get("blocked_tools") or {}).items():
            lines.append(f"- `{tool}` / `{case['id']}`: {reason}")

    lines += ["", "## Caveats",
              "- dalfox/nuclei are URL-shaped scanners. A `#`-fragment DOM case "
              "never reaches the sink they can inject into (the fragment is "
              "stripped client-side), so those three DOM rows are structurally "
              "FN rather than a tuning failure.",
              "- dalfox/nuclei cannot execute an authenticated "
              "PUT /api/Products/:id or a header write followed by an SPA "
              "render; API-only and header rows are marked BLOCKED, not FN.",
              "- Burp Pro / Acunetix were unavailable on this host (no "
              "installation/licence), so their arms are reported as not "
              "executed rather than scored.",
              "- Ground truth is from the official challenge catalogue / app "
              "source plus an independent Playwright dialog check on "
              "2026-11-03 (see cases.json evidence fields), never from this "
              "scanner's own verdict."]
    args.md.parent.mkdir(parents=True, exist_ok=True)
    args.md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\n[+] {args.out}\n[+] {args.md}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
