# -*- coding: utf-8 -*-
"""Sink families that must be instrumented because the browser honors them.

Everything here is stated from a measurement, not from a competitor's
changelog.  `dev/_p197_sinkoracle/probe_sink_oracle.py` renders each candidate
shape in real Chromium with an addressable source and records whether the
token executes:

  setAttributeNS(null,'onclick', attacker)  -> EXECUTES (on the next click)
  var f = eval; f(attacker)                 -> EXECUTES
  window['eval'](attacker)                  -> EXECUTES
  setTimeout(attacker, 50)                  -> EXECUTES
  new Function(attacker)()                  -> EXECUTES
  document.parseHTMLUnsafe(attacker) + append -> does NOT execute
  FileReader onload -> innerHTML            -> EXECUTES (source is a Blob)
  dataTransfer / clipboard                -> not addressable from a scan

That last set is the point: absorbing "dalfox added parseHTMLUnsafe" as a sink
would have added a claim the browser contradicts, while the namespaced handler
delivery we genuinely could not see stayed invisible.  So the DOM channel is
hooked where the measurement says it must be, and these tests keep it hooked.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from xssentinel.core import dom_engine  # noqa: E402


# ---------------------------------------------------------------------------
# the DOM channel must not be blind to namespaced handler delivery: measured
# in Chromium, setAttributeNS(null,'onclick', attacker string) executes on the
# next click -- see dev/_p197_sinkoracle/probe_sink_oracle.py
# ---------------------------------------------------------------------------
def test_dom_engine_hooks_setattributens_not_only_setattribute():
    js = dom_engine._init_script("MARKER")
    assert "Element.prototype.setAttributeNS" in js, (
        "setAttributeNS is not instrumented -- a sink the browser honors "
        "would be invisible to the DOM channel")
    assert "hit('setAttributeNS(" in js, "the hook records no hit"
    # it must not break the plain setAttribute hook that already existed
    assert js.index("Element.prototype.setAttribute =") < js.index(
        "Element.prototype.setAttributeNS =")


# ---------------------------------------------------------------------------
# end to end: the instrumented browser must actually report the hit
# ---------------------------------------------------------------------------
_HAS_PW = dom_engine.DynamicDomAnalyzer.available()


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        # A page whose ONLY dangerous delivery is the namespaced setter: the
        # attacker string lands in an on* handler through setAttributeNS, which
        # the plain setAttribute hook cannot see.
        body = ("<html><body><button id=b>x</button><script>"
                "var v = new URLSearchParams(location.search).get('q') || '';"
                "document.getElementById('b').setAttributeNS(null, 'onclick', v);"
                "</script></body></html>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.mark.skipif(not _HAS_PW, reason="playwright/chromium not available")
def test_dom_engine_reports_a_namespaced_handler_hit():
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    try:
        marker = "xssentinel_ns_probe"
        url = (f"http://127.0.0.1:{port}/?q="
               f"%3Cimg%20src%3Dx%20onerror%3D%7BMARKER%7D%3E")
        hits = dom_engine.DynamicDomAnalyzer(timeout=15).analyze(
            url, marker=marker)
    finally:
        srv.shutdown()
    sinks = [str(h.get("sink") if isinstance(h, dict) else h) for h in hits]
    assert any("setAttributeNS" in s for s in sinks), (sinks, hits)
