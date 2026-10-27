# -*- coding: utf-8 -*-
"""驱动验证：多线程 origin + PassiveProxy + drain_captures + 端到端报告"""
import sys, threading, time, socket
sys.path.insert(0, "D:/qoder/xssentinel")
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from xssentinel.core.requester import Requester
from xssentinel.core.passive_proxy import PassiveProxy, drain_captures
from xssentinel.core.scanner import Scanner
from xssentinel.core.retire_js import scan_html
from xssentinel.core.sqli import run_sqli_check

class _H(BaseHTTPRequestHandler):
    def do_GET(self):
        p = urlparse(self.path)
        q = parse_qs(p.query).get("q", [""])[0]
        body = f"<html><body><div>{q}</div></body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        ln = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(ln).decode("utf-8", "replace")
        body = f"<html><body><div>{raw}</div></body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass

origin = ThreadingHTTPServer(("127.0.0.1", 8978), _H)
threading.Thread(target=origin.serve_forever, daemon=True).start()
print("[*] origin up on 8978")

proxy = PassiveProxy(port=8898, host="127.0.0.1", scope="127.0.0.1:8978",
                     requester=Requester(timeout=10))
proxy.start()

scanner = Scanner(requester=Requester(timeout=10), use_headless=False,
                  max_transforms=4, max_payloads=6, crawl=False,
                  threads=4, dom_engine="static", verbose=False)

stop = threading.Event()
fast_findings = []
def on_scan(method, url, params, data):
    try:
        for f in run_sqli_check(proxy.requester, url, method=method,
                                params=params, data=data):
            fast_findings.append(f)
    except Exception as e:
        print("sqli err:", e)
    try:
        html = proxy.requester.get(url).text or ""
        for f in scan_html(html, base_url=url):
            fast_findings.append(f)
    except Exception as e:
        print("retire err:", e)

worker = threading.Thread(target=drain_captures,
                          args=(proxy, scanner, 0.5, stop, on_scan), daemon=True)
worker.start()
time.sleep(1)

def raw_get(target):
    s = socket.create_connection(("127.0.0.1", 8898), timeout=10)
    try:
        s.sendall(f"GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".encode())
        buf = b""
        while True:
            c = s.recv(65536)
            if not c: break
            buf += c
        return buf.decode("utf-8", "replace")
    finally:
        s.close()

def raw_post(target, body):
    s = socket.create_connection(("127.0.0.1", 8898), timeout=10)
    try:
        s.sendall((f"POST {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                   f"Content-Type: application/x-www-form-urlencoded\r\n"
                   f"Content-Length: {len(body)}\r\n"
                   f"Connection: close\r\n\r\n{body}").encode())
        buf = b""
        while True:
            c = s.recv(65536)
            if not c: break
            buf += c
        return buf.decode("utf-8", "replace")
    finally:
        s.close()

print("[*] GET /vuln?q=hello (vulnerable)")
r = raw_get("http://127.0.0.1:8978/vuln?q=hello")
print("    status:", r.split("\r\n")[0])
print("[*] POST /form (vulnerable body)")
r = raw_post("http://127.0.0.1:8978/form", "q=posted")
print("    status:", r.split("\r\n")[0])

deadline = time.time() + 40
while time.time() < deadline and proxy.stats["scans"] < 2:
    time.sleep(1)
print("[*] stats:", proxy.stats)
print("[*] scanner findings:", len(scanner.findings))
for f in scanner.findings:
    d = f.to_dict()
    print("   FINDING:", d.get("type"), "|", d.get("url"),
          "| param=", d.get("param"), "|", d.get("severity"), "|", d.get("confidence"))
print("[*] fast findings:", len(fast_findings))
for f in fast_findings:
    print("   FAST:", f.get("type"), "|", f.get("db", f.get("library", "")),
          "|", f.get("param", ""), "|", f.get("severity"))

stop.set(); proxy.stop()
if scanner.findings:
    from xssentinel.cli_runner import _write_report
    _write_report(scanner, "passive://proxy", "passive_drive_report.json", "json",
                  meta={"passive": True, "stats": proxy.stats})
    print("[*] report written: passive_drive_report.json")
print("DONE")
