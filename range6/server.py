# -*- coding: utf-8 -*-
"""Range #6 -- the sanitizer range (vendored DOMPurify 2.0.7 vs 3.4.17).

The sanitizer layer (``core/sanitizer_bypass.py``) had no end-to-end gate:
its findings are static pattern matches -- a version string in a script
path, an unsafe config literal, a sanitize()->innerHTML flow -- and nothing
ever proved those patterns sit on a page where the claimed vulnerability
REALLY executes (or really doesn't).  range4 answered the same question
for React/Vue; this is the sanitizer edition.

The pair is a real CVE, not a synthetic one:

  * /unsafe ships DOMPurify **2.0.7** -- before 2.0.8, i.e. inside
    CVE-2020-26870's range (mXSS: the sanitized output re-parses in the
    browser into a live element the sanitizer's tree never contained).
    Measured, not assumed: the form/math/mglyph namespace-confusion PoC
    produces a real dialog through the vendored file in Chromium
    (dev/_r6_mxss_premise.py).
  * /safe ships **3.4.17** (the vendor's current release; every published
    advisory is closed by 3.4.16).  The identical PoC is stripped: the
    sanitized output contains no live element, no dialog.

The two pages are the SAME shell -- same param, same flow
(URLSearchParams -> DOMPurify.sanitize -> innerHTML), same everything
except which vendored build the script tag points at.  Ground truth is
authored from the vendor's advisory ranges plus the browser measurement,
independent of how the scanner observes any of it.

Construct validity is range5's lesson at full strength: **the param never
touches server-side bytes.**  Both pages are static shells; the app reads
``location.search`` client-side, so the safe twin cannot reflect the
attacker string -- there is no server-side interpolation to reflect
through.
"""
from __future__ import annotations

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_VENDOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor")

# The CVE-2020-26870 namespace-confusion PoC (Bentkowski's family): the
# sanitizer's tree never contains a real <img> -- it is buried inside
# <mglyph>/<style> foreign-content confusion -- so its onerror is never
# filtered; the serialized output then re-parses into a live element.
# Kept here (not only in tests) so the page documents what it is for.
POCTEXT = ("<form><math><mtext></form><form><mglyph><style></math>"
           "<img src onerror=alert(1)>")

# STATIC bytes: identical for every query string, by construction.
# The only difference between the twins is the vendored version path.
_PAGE = """<!doctype html><html><head><title>Range6 %(label)s</title></head>
<body>
<h1>Range6 %(label)s</h1>
<div id="out"></div>
<script src="/vendor/dompurify/%(ver)s/purify.min.js"></script>
<script>
var q = new URLSearchParams(location.search).get('q') || '';
var clean = DOMPurify.sanitize(q);
document.getElementById('out').innerHTML = clean;
</script>
</body></html>"""

_PAGE_INDEX = """<!doctype html><html><head><title>Range6</title></head>
<body><h1>Range6 -- DOMPurify 2.0.7 (CVE-2020-26870) vs 3.4.17</h1>
<ul>
<li><a href="/unsafe?q=hi">/unsafe (dompurify 2.0.7)</a></li>
<li><a href="/safe?q=hi">/safe (dompurify 3.4.17)</a></li>
</ul>
</body></html>"""

_PAGES = {
    "/": _PAGE_INDEX,
    "/unsafe": _PAGE % {"label": "unsafe", "ver": "2.0.7"},
    "/safe": _PAGE % {"label": "safe", "ver": "3.4.17"},
}


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"     # keep-alive; every reply carries
                                      # Content-Length (project convention)

    def log_message(self, *a):
        pass

    def _send(self, body: bytes, ctype: str):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0].split("#", 1)[0]
        if path in _PAGES:
            self._send(_PAGES[path].encode(), "text/html; charset=utf-8")
            return
        if path.startswith("/vendor/"):
            vendor_root = os.path.realpath(_VENDOR)
            fp = os.path.realpath(
                os.path.join(vendor_root, path[len("/vendor/"):]))
            if fp.startswith(vendor_root) and os.path.isfile(fp):
                ctype = ("application/javascript" if fp.endswith(".js")
                         else "text/plain")
                with open(fp, "rb") as f:
                    self._send(f.read(), ctype)
                return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()


def run_server(port: int = 0, ready_callback=None) -> None:
    """Start the range server and serve until shutdown().

    ``port=0`` binds an ephemeral port; the real one is available from the
    ``ready_callback`` (``srv.server_address[1]``).  No fixed port and no
    probe loop: the Phase 206 lesson (SO_REUSEADDR lets a second socket
    bind to someone else's listener, so "bind succeeded" proves nothing).
    """
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    if ready_callback is not None:
        ready_callback(srv)
    srv.serve_forever()


if __name__ == "__main__":
    print("range6 server (ephemeral port; use the runner or the test "
          "fixture, which capture the real port from ready_callback)")
    run_server()
