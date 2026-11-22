"""DVWA x local-glm-5.3-flash, round 2 (2026-11-19b): headless browser evidence.

Diff vs the 20261119 batch:
  * run under C:/Python39 (has playwright + Chromium) with --headless, so a
    finding carries browser-executed evidence, not browser-unavailable;
  * --ai-timeout 120 to absorb the local flash model's occasional slow report;
  * still serial by design: one scan at a time, --threads 2, single LLM
    candidate => end-to-end concurrency never exceeds 3.
Re-logs in before every scan (DVWA PHPSESSID goes stale after repeated scans).
"""
import json
import os
import re
import subprocess
import time

import requests

BASE = "http://127.0.0.1:8080"
REPO = r"D:\qoder\xssentinel"
OUTDIR = os.path.join(REPO, "benchmark", "results")
LLM_CFG = os.path.join(OUTDIR, "llm_local_glm53_20261119.json")
PY = r"C:\Python39\python.exe"
STAMP = "20261119b"

CASES = [
    ("low_reflected", "low", "/vulnerabilities/xss_r/?name=xssprobe", None),
    ("medium_reflected", "medium", "/vulnerabilities/xss_r/?name=xssprobe", None),
    ("high_reflected", "high", "/vulnerabilities/xss_r/?name=xssprobe", None),
    ("low_stored", "low", "/vulnerabilities/xss_s/", "mtxMessage"),
]

ENV = os.environ.copy()
for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
    ENV.pop(k, None)
ENV["NO_PROXY"] = "127.0.0.1,localhost"
ENV["no_proxy"] = "127.0.0.1,localhost"
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
    out = os.path.join(OUTDIR, f"dvwa_{name}_headless_ai_{STAMP}.json")
    cmd = [PY, "-m", "xssentinel", "-u", BASE + path,
           "-b", cookie, "-f", "json", "-o", out,
           "--max-payloads", "14", "--max-transforms", "12",
           "--threads", "2", "--timeout", "10", "--headless",
           "--progress", "none", "--log-level", "error",
           "--ai-report", "--ai-config", LLM_CFG,
           "--ai-lang", "zh", "--ai-timeout", "120"]
    if stored_param:
        cmd += ["--stored-inject", BASE + path,
                "--stored-param", stored_param,
                "--stored-view", BASE + path,
                "--stored-method", "POST"]
    t0 = time.time()
    proc = subprocess.run(cmd, cwd=REPO, env=ENV, capture_output=True,
                          text=True, encoding="utf-8", errors="replace",
                          timeout=420, stdin=subprocess.DEVNULL)
    dt = round(time.time() - t0, 1)
    findings, ai = [], {}
    if os.path.isfile(out):
        doc = json.load(open(out, encoding="utf-8"))
        for f in doc.get("findings", []):
            h = f.get("headless") or {}
            findings.append({
                "type": f.get("type"), "severity": f.get("severity"),
                "confidence": f.get("confidence"),
                "evidence_class": f.get("evidence_class"),
                "headless_available": h.get("available"),
                "headless_confirmed": h.get("confirmed"),
                "headless_outcome": h.get("outcome"),
                "headless_detail": h.get("detail"),
            })
        ai = doc.get("ai_report") or {}
    row = {
        "case": name, "level": level, "path": path,
        "rc": proc.returncode, "seconds": dt,
        "findings": findings,
        "ai_ok": ai.get("ok"), "ai_used_llm": ai.get("used_llm"),
        "ai_degraded": ai.get("degraded"),
        "ai_model": ai.get("model"), "ai_failovers": ai.get("failovers"),
        "ai_elapsed": ai.get("elapsed"),
        "ai_chars": sum(len(a.get("detail", "")) for a in ai.get("attempts", [])),
        "stderr_tail": (proc.stderr or "")[-300:],
    }
    rows.append(row)
    print(json.dumps(row, ensure_ascii=False), flush=True)

with open(os.path.join(OUTDIR, f"dvwa_batch_headless_ai_{STAMP}.json"), "w",
          encoding="utf-8") as fh:
    json.dump(rows, fh, ensure_ascii=False, indent=2)
print("BATCH DONE", len(rows), "cases", flush=True)
