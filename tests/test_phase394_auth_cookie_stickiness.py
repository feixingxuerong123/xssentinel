# -*- coding: utf-8 -*-
"""Phase 394: operator-supplied (-b) cookies survive probe Set-Cookie.

Measured on NodeGoat (Phase 392): probe responses that Set-Cookie a fresh
anonymous `connect.sid` silently replaced the operator's session in the
shared cookie jar -- the jar held TWO same-name values, the anonymous one
won, and the whole authenticated scan degraded to the login page with every
number still reading "0 findings is fine".  The requester now re-asserts the
pinned values after every response (`Requester._send` is the single choke
point both engines go through).

The test drives the REAL Requester against a real loopback server:

  * `/probe`  -- sets a FRESH anonymous connect.sid (the pollution event);
  * `/protected` -- answers 200 only when the ORIGINAL session value arrives,
    and records the raw Cookie header for the assertion.

Regression pin: an UNPINNED jar (no `-b`) still adopts the fresh cookie --
the fix must not turn into "ignore every Set-Cookie".
"""
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.requester import Requester  # noqa: E402

ORIGINAL = "s%3Aoriginal-session-value.Pinned"
FRESH = "s%3Afresh-anonymous-value.Probe"
SEEN: list[str] = []


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/probe":
            SEEN.append("probe:" + (self.headers.get("Cookie") or ""))
            body = b"<html><body>probe</body></html>"
            self.send_response(200)
            self.send_header("Set-Cookie", f"connect.sid={FRESH}; Path=/")
        elif self.path == "/protected":
            SEEN.append("protected:" + (self.headers.get("Cookie") or ""))
            if ORIGINAL in (self.headers.get("Cookie") or ""):
                body = b"<html><body>protected</body></html>"
                self.send_response(200)
            else:
                body = b"<html><body>login</body></html>"
                self.send_response(302)
                self.send_header("Location", "/login")
        else:
            body = b"nope"
            self.send_response(404)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _serve():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def test_pinned_cookie_survives_probe_set_cookie():
    SEEN.clear()
    srv, port = _serve()
    try:
        req = Requester(timeout=10, cookies={"connect.sid": ORIGINAL})
        req.get(f"http://127.0.0.1:{port}/probe")
        resp = req.get(f"http://127.0.0.1:{port}/protected")
        assert resp.status_code == 200, (
            "the operator's session was replaced by the probe's fresh "
            f"cookie; Cookie header seen: {SEEN[-1]}")
        protected_header = next(s for s in SEEN if s.startswith("protected:"))
        assert ORIGINAL in protected_header
        assert FRESH not in protected_header
    finally:
        srv.shutdown()


def test_unpinned_jar_still_adopts_fresh_cookies():
    SEEN.clear()
    srv, port = _serve()
    try:
        req = Requester(timeout=10)
        req.get(f"http://127.0.0.1:{port}/probe")
        resp = req.get(f"http://127.0.0.1:{port}/protected")
        protected_header = next(s for s in SEEN if s.startswith("protected:"))
        assert FRESH in protected_header, (
            "the fix must not blanket-ignore Set-Cookie: an unpinned jar "
            f"keeps adopting fresh values (saw {protected_header})")
        # 302 -> /login (which 404s in this minimal fixture); the redirect
        # chain itself is proof the fresh cookie was NOT the original
        assert resp.status_code != 200
    finally:
        srv.shutdown()
