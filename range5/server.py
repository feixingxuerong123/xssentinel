# -*- coding: utf-8 -*-
"""Range #5 -- the Lit range (vendored lit 3.3.3 / lit-html 3.3.3 /
lit-element 4.2.2 / @lit/reactive-element 2.1.2).

range4 rendered its reflections through React/Vue with the param
reflected into a server-side JS config line -- and its first version
shipped a safe twin whose config line was ITSELF a script-string sink,
which measured four FPs before the construct probe caught it.  This
range applies that lesson at full strength: **the param never touches
the server-side bytes.**  Both pages are static shells; the app reads
``location.search`` client-side.  The safe twin cannot reflect the
attacker string because there is no server-side interpolation to
reflect through -- construct validity by construction, not by probe.

Shapes:
  * /unsafe?q=  -- the app renders ``html`<div>${unsafeHTML(q)}</div>` ``:
    the unsafeHTML directive parses markup BY DESIGN (Lit's analogue of
    React's dangerouslySetInnerHTML / Vue's v-html).  The marker reaches
    the DOM through the directive's Element.innerHTML write.
  * /safe?q=    -- identical shell, ``html`<div>${q}</div>` ``: Lit
    interpolations create TEXT nodes (auto-escaping), safe by
    construction.  Same param, same component, different directive.

Ground truth is authored from the framework semantics (unsafeHTML does
not escape; ${} interpolations do), independent of how the scanner
observes sinks.
"""
from __future__ import annotations

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_PORT = 19705
_VENDOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor")

_IMPORT_MAP = """<script type="importmap">
{"imports": {
  "lit": "/vendor/lit/index.js",
  "lit/": "/vendor/lit/",
  "lit-html": "/vendor/lit-html/lit-html.js",
  "lit-html/": "/vendor/lit-html/",
  "lit-element": "/vendor/lit-element/index.js",
  "lit-element/": "/vendor/lit-element/",
  "@lit/reactive-element": "/vendor/reactive-element/reactive-element.js",
  "@lit/reactive-element/": "/vendor/reactive-element/"
}}
</script>"""

# STATIC bytes: identical for every query string, by construction.
_PAGE_UNSAFE = """<!doctype html><html><head><title>Range5 unsafe</title>
""" + _IMPORT_MAP + """</head><body>
<div id="out"></div>
<script type="module">
import {html, render} from 'lit';
import {unsafeHTML} from 'lit/directives/unsafe-html.js';
const q = new URLSearchParams(location.search).get('q') || '';
render(html`<div id="victim">${unsafeHTML(q)}</div>`,
       document.getElementById('out'));
</script>
</body></html>"""

_PAGE_SAFE = """<!doctype html><html><head><title>Range5 safe</title>
""" + _IMPORT_MAP + """</head><body>
<div id="out"></div>
<script type="module">
import {html, render} from 'lit';
const q = new URLSearchParams(location.search).get('q') || '';
render(html`<div id="victim">${q}</div>`,
       document.getElementById('out'));
</script>
</body></html>"""

_PAGE_INDEX = """<!doctype html><html><head><title>Range5</title></head>
<body><h1>Range5 -- Lit unsafeHTML vs text interpolation</h1>
<ul>
<li><a href="/unsafe?q=hi">/unsafe (unsafeHTML)</a></li>
<li><a href="/safe?q=hi">/safe (text interpolation)</a></li>
</ul>
</body></html>"""

_PAGES = {"/": _PAGE_INDEX, "/unsafe": _PAGE_UNSAFE, "/safe": _PAGE_SAFE}


class H(BaseHTTPRequestHandler):
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
        vendor_root = os.path.realpath(_VENDOR)
        fp = os.path.realpath(os.path.join(vendor_root, path[len("/vendor/"):]))
        if fp.startswith(vendor_root) and os.path.isfile(fp):
            ctype = ("application/javascript" if fp.endswith(".js")
                     else "application/json" if fp.endswith(".json")
                     else "application/octet-stream")
            with open(fp, "rb") as f:
                self._send(f.read(), ctype)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()


def run_server(port: int = _PORT, ready_callback=None) -> None:
    """Start the range server and serve until shutdown().

    ThreadingHTTPServer per the Phase 200 rule (single-thread + keep-alive
    starves every other client behind one idle connection).
    """
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    if ready_callback is not None:
        ready_callback(srv)
    srv.serve_forever()


if __name__ == "__main__":
    print(f"range5 server on http://127.0.0.1:{_PORT}")
    run_server()
