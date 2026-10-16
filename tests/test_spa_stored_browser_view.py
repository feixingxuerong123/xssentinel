# -*- coding: utf-8 -*-
"""Phase 244: a stored payload that only renders in the browser.

Phase 243 confirmed stored XSS by judging the viewer's HTML.  That is
blind to the shape modern apps actually have: the stored value is rendered
by client-side code, so it never appears in the response the scanner
fetched -- a real, executing stored XSS on an SPA route could not be
confirmed at all, and the write-face pipeline (241-243) visits exactly
those routes.

So the confirmation now has a browser arm: render the viewer with the
session seeded, and report two DISTINCT outcomes -- ``fired`` (a dialog
carried our token: it executed) and ``rendered`` (the token is in the live
DOM but nothing fired).  Only ``fired`` becomes a finding; ``rendered`` is
delivery evidence, and reporting it would flag every app that echoes user
input into a text node.

Gates:
  * SPA viewer that executes the stored value -> stored finding confirmed
    with --headless, and NOT confirmed without it (the HTML path is
    blind -- that difference is the point of this phase);
  * SPA viewer that escapes it -> the token is rendered but nothing fires,
    and NO finding appears (delivery is not execution).

Run: C:/Python39/python.exe -m pytest tests/test_spa_stored_browser_view.py -q
"""
from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.conftest import SOCKETPAIR_OK, loopback_healthy  # noqa: E402

_WRITE_PAGE = b"""<html><body>
<textarea name="msg"></textarea>
<button id="send">Send</button>
<script>
document.getElementById('send').addEventListener('click', function(){
  fetch('/api/notes', {method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({msg: document.querySelector('textarea').value})});
});
</script></body></html>"""

# An SPA viewer: the shell carries no stored value at all; the browser
# fetches the note and injects it as HTML, so the payload EXECUTES.  The
# stored value is assigned DIRECTLY -- wrapping it in an attribute of our
# own would break on the first payload containing a quote, i.e. it would
# measure the fixture's escaping instead of the capability.
_SPA_EXEC = b"""<html><body><div id="out"></div><script>
fetch('/api/notes').then(r => r.json()).then(d => {
  document.getElementById('out').innerHTML = d.msg;
});
</script></body></html>"""

# Same SPA, escaping: the token ends up in the DOM as text, nothing fires.
_SPA_ESCAPED = b"""<html><body><div id="out"></div><script>
fetch('/api/notes').then(r => r.json()).then(d => {
  document.getElementById('out').textContent = d.msg;
});
</script></body></html>"""


def _server(view_page: bytes):
    store: list = []

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, body: bytes, ctype="text/html; charset=utf-8"):
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?")[0]
            if path == "/write":
                self._send(_WRITE_PAGE)
            elif path == "/spa":
                self._send(view_page)
            elif path == "/api/notes":
                self._send(json.dumps({"msg": "".join(store)}).encode(),
                           "application/json")
            else:
                self._send(b"nope")

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n).decode("utf-8", "replace")
            if self.path.startswith("/api/notes"):
                try:
                    store.append(json.loads(raw).get("msg") or "")
                except Exception:
                    store.append("")
            self._send(b'{"ok":true}', "application/json")

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    holder, ready = {}, threading.Event()

    def _run():
        holder["p"] = srv.server_address[1]
        ready.set()
        srv.serve_forever()

    threading.Thread(target=_run, daemon=True).start()
    assert ready.wait(10)
    return srv, holder


def _run_round_trip(base: str, view: str, headless: bool) -> list:
    from xssentinel.core import dom_engine as dem
    from xssentinel.core.requester import Requester
    from xssentinel.core.scanner import Scanner

    faces = dem.DynamicDomAnalyzer(timeout=20).harvest(
        base + "/write", write_faces=True).get("write_faces") or []
    assert faces, "the write face was not observed -- fixture broken"
    # One payload x one transform on purpose: each variant costs a browser
    # render on the SPA viewer, and the capability under test does not
    # depend on the matrix size.
    sc = Scanner(requester=Requester(timeout=8), dom_engine="off",
                 verbose=False, max_payloads=1, max_transforms=1,
                 use_headless=headless)
    try:
        sc.scan_spa_write_faces(faces, base + "/write",
                                view_urls=[base + view])
    finally:
        if headless:
            dem.shutdown_thread_browser()
    return [f.data for f in sc.findings if f.data.get("type") == "stored"]


@pytest.mark.skipif(not SOCKETPAIR_OK, reason="no socketpair")
class TestBrowserRenderedViewer:
    def test_spa_viewer_is_confirmed_with_headless(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        srv, holder = _server(_SPA_EXEC)
        try:
            base = f"http://127.0.0.1:{holder['p']}"
            stored = _run_round_trip(base, "/spa", headless=True)
            assert stored, (
                "the SPA viewer executes the stored payload but the "
                "round-trip confirmed nothing")
            assert stored[0].get("confidence") == "high", stored[0]
            assert (stored[0].get("headless") or {}).get(
                "outcome") == "fired", stored[0]
        finally:
            srv.shutdown()

    def test_html_only_path_is_blind_to_an_spa_viewer(self):
        """The counter-proof that this phase is load-bearing: the same
        fixture WITHOUT --headless produces no confirmation, because the
        token is not in the HTML the scanner fetches."""
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        srv, holder = _server(_SPA_EXEC)
        try:
            base = f"http://127.0.0.1:{holder['p']}"
            assert _run_round_trip(base, "/spa", headless=False) == [], (
                "the HTML-only path confirmed an SPA viewer -- the blind "
                "spot this phase closes is not where we thought it was")
        finally:
            srv.shutdown()

    def test_escaping_spa_viewer_produces_no_finding(self):
        """Delivery is not execution: the token renders into the DOM as
        text, nothing fires, and NO stored finding appears."""
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        srv, holder = _server(_SPA_ESCAPED)
        try:
            base = f"http://127.0.0.1:{holder['p']}"
            assert _run_round_trip(base, "/spa", headless=True) == [], (
                "an escaping SPA viewer produced a stored finding")
        finally:
            srv.shutdown()
