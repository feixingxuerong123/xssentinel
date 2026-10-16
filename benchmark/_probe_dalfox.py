"""Calibrate dalfox verdict: run dalfox against 1 vuln + 1 safe case, dump raw JSON."""
import json
import subprocess
import sys
import threading

sys.path.insert(0, "benchmark")
from server import run_server, load_routes  # noqa: E402

PORT = 8907
base = f"http://127.0.0.1:{PORT}"
cases = json.load(open("benchmark/manifest.json", encoding="utf-8"))
cases = cases["cases"] if isinstance(cases, dict) else cases

targets = [
    c for c in cases if c["id"] in ("pos-elem-01", "neg-escape-01", "neg-encode-02")
]
ready = threading.Event()
server_holder = {}


def on_ready(srv):
    server_holder["srv"] = srv
    ready.set()


t = threading.Thread(target=run_server, args=(PORT,),
                     kwargs={"ready_callback": on_ready}, daemon=True)
t.start()
assert ready.wait(10), "server failed to start"
print("server ready")

for c in targets:
    url = f"{base}{c['path']}?q=test"
    print(f"\n{'='*70}\n[{c['id']}] gt={c['ground_truth']} mode={c.get('mode')} url={url}")
    proc = subprocess.run(
        ["D:/qoder/bin/dalfox.exe", "url", url,
         "--format", "json", "--silence", "--timeout", "30", "--worker", "1"],
        capture_output=True, text=True, timeout=90,
    )
    print(f"exit={proc.returncode}")
    print("--- stdout raw (first 1500 chars) ---")
    print(proc.stdout[:1500])
    print("--- stderr (first 300) ---")
    print(proc.stderr[:300])
    try:
        findings = json.loads(proc.stdout)
        print(f"--- parsed: {len(findings)} findings, types={[f.get('type') for f in findings]} ---")
    except Exception as e:
        print(f"--- JSON parse failed: {e} ---")

server_holder["srv"].shutdown()
print("\ndone")
