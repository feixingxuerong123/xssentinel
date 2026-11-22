"""One-off DVWA x local-glm-5.3-flash batch, 2026-11-19.

Serial by design: one scan at a time, --threads 2, AI report via a single
candidate => concurrency never exceeds 3. Re-logs in before every scan because
DVWA's PHPSESSID goes stale after repeated scans (see PHASE400 handoff).
"""
import json
import os
import re
import subprocess
import sys
import time

import requests

BASE = "http://127.0.0.1:8080"
REPO = r"D:\qoder\xssentinel"
OUTDIR = os.path.join(REPO, "benchmark", "results")
LLM_CFG = os.path.join(OUTDIR, "llm_local_glm53_20261119.json")
STAMP = "20261119"

CASES = [
    ("low_reflected", "low", "/vulnerabilities/xss_r/?name=xssprobe", None),
    ("medium_reflected", "medium", "/vulnerabilities/xss_r/?name=xssprobe", None),
    ("high_reflected", "high", "/vulnerabilities/xss_r/?name=xssprobe", None),
    ("low_stored", "low", "/vulnerabilities/xss_s/", "mtxMessage"),
]

ENV = os.environ.copy()
for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
    ENV.pop(k, None)
tmp = os.path.join(REPO, ".cache", "xssentinel", "tmp")
os.makedirs(tmp, exist_ok=True)
ENV["TEMP"] = tmp
ENV["TMP"] = tmp
ENV["TERM"] = "dumb"


def login():
    s = requests.Session()
    s.trust_env = False
    tok = re.search(r"name='user_token' value='([0-9a-f]+)'",
                    s.get(BASE + "/login.php", timeout=10).text).group(1)
    r = s.post(BASE + "/login.php", data={
        "username": "admin", "password": "password",
        "Login": "Login", "user_token": tok,
    }, allow_redirects=True, timeout=10)
    assert "Logout" in r.text, "login failed"
    return s.cookies.get("PHPSESSID")


rows = []
for name, level, path, stored_param in CASES:
    sid = login()
    cookie = f"security={level}; PHPSESSID={sid}"
    out = os.path.join(OUTDIR, f"dvwa_{name}_ai_{STAMP}.json")
    cmd = [sys.executable, "-m", "xssentinel", "-u", BASE + path,
           "-b", cookie, "-f", "json", "-o", out,
           "--max-payloads", "14", "--max-transforms", "12",
           "--threads", "2", "--timeout", "10",
           "--progress", "none", "--log-level", "error",
           "--ai-report", "--ai-config", LLM_CFG,
           "--ai-lang", "zh", "--ai-timeout", "60"]
    if stored_param:
        cmd += ["--stored-inject", BASE + path,
                "--stored-param", stored_param,
                "--stored-view", BASE + path,
                "--stored-method", "POST"]
    t0 = time.time()
    proc = subprocess.run(cmd, cwd=REPO, env=ENV, capture_output=True,
                          text=True, encoding="utf-8", errors="replace",
                          timeout=300, stdin=subprocess.DEVNULL)
    dt = round(time.time() - t0, 1)
    finding_types, ai = [], {}
    if os.path.isfile(out):
        doc = json.load(open(out, encoding="utf-8"))
        finding_types = [(f.get("type"), f.get("severity"))
                         for f in doc.get("findings", [])]
        ai = doc.get("ai_report") or {}
    row = {
        "case": name, "level": level, "path": path,
        "rc": proc.returncode, "seconds": dt,
        "findings": finding_types,
        "ai_ok": ai.get("ok"), "ai_used_llm": ai.get("used_llm"),
        "ai_degraded": ai.get("degraded"),
        "ai_model": ai.get("model"), "ai_failovers": ai.get("failovers"),
        "ai_elapsed": ai.get("elapsed"),
        "ai_chars": sum(len(a.get("detail", "")) for a in ai.get("attempts", [])),
        "stderr_tail": (proc.stderr or "")[-300:],
    }
    rows.append(row)
    print(json.dumps(row, ensure_ascii=False), flush=True)

with open(os.path.join(OUTDIR, f"dvwa_batch_local_llm_{STAMP}.json"), "w",
          encoding="utf-8") as fh:
    json.dump(rows, fh, ensure_ascii=False, indent=2)
print("BATCH DONE", len(rows), "cases", flush=True)
