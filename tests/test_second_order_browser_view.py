# -*- coding: utf-8 -*-
"""Phase 246/249: the browser arm reaches the second-order layer.

Phase 244 closed this blind spot for scan_stored: the viewer page was
judged by its HTML, and a modern app renders the stored value
client-side, so the token was never in the response at all.  The
second-order layer had the identical hole -- ``check_viewers`` does
``if token not in text: continue`` -- and Phase 246 applies the same fix:
render each viewer ONCE and let the browser say whether any injected
token EXECUTED there.  A token that is merely present ("rendered") is
delivery, not execution, and is not reported.

Phase 249: that evidence lives under the same ``headless`` key the stored
path uses, so the report's summary table can see it.  A private
``browser_evidence`` key read as "no browser check" next to a finding the
browser HAD confirmed.

Gates:
  * a second-order write whose viewer executes the payload -> a finding
    with context=browser_render and headless evidence (headless on);
  * the SAME fixture with headless off -> no finding (the HTML path is
    blind -- that difference is the point);
  * an escaping viewer -> the token renders, nothing fires, no finding.

Run: C:/Python39/python.exe -m pytest tests/test_second_order_browser_view.py -q
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

# The write face: a form that posts a field the second-order layer can
# inject into (the layer POSTs {param: payload} itself, no browser needed).
_WRITE_FORM = (b"<html><body><form method='post' action='/api/notes'>"
               b"<textarea name='msg'></textarea>"
               b"<input type='submit' value='Send'>"
               b"</form></body></html>")

# The SPA viewer: no token in the shell HTML; the browser fetches the note
# and injects it as HTML, so the payload EXECUTES.
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
            if path == "/inject":
                self._send(_WRITE_FORM)
            elif path == "/viewer":
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
                # The layer injects FORM-encoded (req.request(..., data=
                # {param: payload})) -- a JSON-only parser here stores an
                # empty string and the viewer renders nothing.  Accept both.
                from urllib.parse import parse_qs
                vals = parse_qs(raw, keep_blank_values=True).get("msg")
                if not vals:
                    try:
                        vals = [json.loads(raw).get("msg") or ""]
                    except Exception:
                        vals = [""]
                store.append(vals[0])
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


def _run_second_order(base: str, view: str, headless: bool) -> list:
    from xssentinel.core.requester import Requester
    from xssentinel.core.scanner import Scanner
    from xssentinel.core.second_order import scan_second_order

    sc = Scanner(requester=Requester(timeout=8), dom_engine="off",
                 verbose=False, use_headless=headless)
    try:
        return scan_second_order(sc, inject_url=base + "/api/notes",
                                 param="msg", method="POST",
                                 viewer_urls=[base + view])
    finally:
        from xssentinel.core import dom_engine as dem
        if headless:
            dem.shutdown_thread_browser()


@pytest.mark.skipif(not SOCKETPAIR_OK, reason="no socketpair")
class TestSecondOrderBrowserView:
    def test_spa_viewer_is_confirmed_with_headless(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        srv, holder = _server(_SPA_EXEC)
        try:
            base = f"http://127.0.0.1:{holder['p']}"
            results = _run_second_order(base, "/viewer", headless=True)
            assert results, (
                "the SPA viewer executes the injected payload but the "
                "second-order layer confirmed nothing")
            hit = results[0]
            assert hit.get("context") == "browser_render", hit
            # Phase 249: the evidence lives under the SAME key the stored
            # path uses, so report.py's summary table can see it.  The old
            # private key must be gone -- that rename is the fix.
            assert (hit.get("headless") or {}).get("outcome") == "fired", hit
            assert "browser_evidence" not in hit, (
                "the private key is back -- the report's summary table "
                "cannot see it and will say 'no browser check'")
            assert hit.get("evidence_class") == "browser-executed", hit
        finally:
            srv.shutdown()

    def test_html_only_path_is_blind_to_an_spa_viewer(self):
        """The counter-proof that this phase is load-bearing: without
        --headless the same fixture confirms nothing, because the token is
        not in the HTML the scanner fetches."""
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        srv, holder = _server(_SPA_EXEC)
        try:
            base = f"http://127.0.0.1:{holder['p']}"
            assert _run_second_order(base, "/viewer", headless=False) == [], (
                "the HTML-only path confirmed an SPA viewer -- the blind "
                "spot is not where we thought")
        finally:
            srv.shutdown()

    def test_escaping_viewer_produces_no_finding(self):
        """Delivery is not execution: the token renders into the DOM as
        text, nothing fires, and NO finding appears."""
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        srv, holder = _server(_SPA_ESCAPED)
        try:
            base = f"http://127.0.0.1:{holder['p']}"
            assert _run_second_order(base, "/viewer", headless=True) == [], (
                "an escaping SPA viewer produced a second-order finding")
        finally:
            srv.shutdown()
