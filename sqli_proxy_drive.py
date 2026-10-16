# -*- coding: utf-8 -*-
"""验证：SQLi 回显端点走被动代理 -> 捕获 -> 快检命中"""
import sys, threading, time, socket
sys.path.insert(0, "D:/qoder/xssentinel")
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from xssentinel.core.requester import Requester
from xssentinel.core.passive_proxy import PassiveProxy
from xssentinel.core.sqli import run_sqli_check

class _H(BaseHTTPRequestHandler):
    def do_GET(self):
        p = urlparse(self.path)
        q = parse_qs(p.query).get("q", [""])[0]
        if "'" in q or '"' in q:
            body = f"<html>You have an error in your SQL syntax near '{q}'</html>".encode()
        else:
            body = b"<html><body>ok</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass

origin = ThreadingHTTPServer(("127.0.0.1", 8982), _H)
threading.Thread(target=origin.serve_forever, daemon=True).start()
time.sleep(0.3)

proxy = PassiveProxy(port=8897, host="127.0.0.1", scope="127.0.0.1:8982",
                     requester=Requester(timeout=10))
proxy.start()
time.sleep(0.5)

# 走代理发请求（浏览器场景）
s = socket.create_connection(("127.0.0.1", 8897), timeout=10)
s.sendall(b"GET http://127.0.0.1:8982/search?q=test HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
s.recv(65536); s.close()
time.sleep(1)

print("proxy stats:", proxy.stats)
# 从捕获队列取出端点并跑 SQLi 快检
method, url, params, data = proxy.captures.get(timeout=5)
print("captured:", method, url, params, data)
finds = run_sqli_check(proxy.requester, url, method=method, params=params, data=data)
print("sqli findings:", len(finds))
for f in finds:
    print("  ", f["db"], f["param"], f["probe"], "->", f["evidence"][:60])
proxy.stop()
print("DONE")
