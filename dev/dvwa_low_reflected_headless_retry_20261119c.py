"""Retry low_reflected (20261119c) whose AI report hit the 120s timeout."""
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

ENV = os.environ.copy()
for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
    ENV.pop(k, None)
ENV["NO_PROXY"] = "127.0.0.1,localhost"
ENV["no_proxy"] = "127.0.0.1,localhost"
tmp = os.path.join(REPO, ".cache", "xssentinel", "tmp")
ENV["TEMP"] = tmp
ENV["TMP"] = tmp
ENV["TERM"] = "dumb"

s = requests.Session()
s.trust_env = False
tok = re.search(r"name='user_token' value='([0-9a-f]+)'",
                s.get(BASE + "/login.php", timeout=10).text).group(1)
r = s.post(BASE + "/login.php", data={
    "username": "admin", "password": "password",
    "Login": "Login", "user_token": tok,
}, allow_redirects=True, timeout=10)
assert "Logout" in r.text, "login failed"
cookie = f"security=low; PHPSESSID={s.cookies.get('PHPSESSID')}"

path = "/vulnerabilities/xss_r/?name=xssprobe"
out = os.path.join(OUTDIR, "dvwa_low_reflected_headless_ai_retry_20261119c.json")
cmd = [PY, "-m", "xssentinel", "-u", BASE + path, "-b", cookie,
       "-f", "json", "-o", out, "--max-payloads", "14", "--max-transforms", "12",
       "--threads", "2", "--timeout", "10", "--headless",
       "--progress", "none", "--log-level", "error",
       "--ai-report", "--ai-config", LLM_CFG, "--ai-lang", "zh", "--ai-timeout", "180"]
t0 = time.time()
proc = subprocess.run(cmd, cwd=REPO, env=ENV, capture_output=True, text=True,
                      encoding="utf-8", errors="replace", timeout=420,
                      stdin=subprocess.DEVNULL)
dt = round(time.time() - t0, 1)
findings, ai = [], {}
if os.path.isfile(out):
    doc = json.load(open(out, encoding="utf-8"))
    for f in doc.get("findings", []):
        h = f.get("headless") or {}
        findings.append({"type": f.get("type"), "severity": f.get("severity"),
                         "evidence_class": f.get("evidence_class"),
                         "headless_outcome": h.get("outcome")})
    ai = doc.get("ai_report") or {}
row = {"case": "low_reflected", "rc": proc.returncode, "seconds": dt,
       "findings": findings, "ai_ok": ai.get("ok"),
       "ai_used_llm": ai.get("used_llm"), "ai_degraded": ai.get("degraded"),
       "ai_model": ai.get("model"), "ai_failovers": ai.get("failovers"),
       "ai_elapsed": ai.get("elapsed"),
       "ai_chars": sum(len(a.get("detail", "")) for a in ai.get("attempts", [])),
       "stderr_tail": (proc.stderr or "")[-300:]}
print(json.dumps(row, ensure_ascii=False), flush=True)
