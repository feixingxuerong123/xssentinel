# -*- coding: utf-8 -*-
"""Phase 243: stored XSS proven across pages, not just on the write page.

Phase 241 gave the SPA write face its round-trip, but the viewer was the
write page itself -- which on an SPA means the honest answer was always the
medium "same-session self-view" downgrade.  That is not evidence about the
application; it is evidence about where we happened to look.  Stored XSS is
by definition about OTHER viewers, and on an SPA the viewer is another
route.

So the discovered routes are now viewer candidates: after injecting, the
round-trip walks them and the first page that renders the token in an
executable context is the one that proves persistence.

Gates:
  * write page + a viewer that renders the stored value RAW -> a stored
    finding at high confidence naming that viewer;
  * the same fixture with an ESCAPING viewer -> no stored finding at all
    (the counter-proof: the extra views do not manufacture findings);
  * same fixture, no viewer candidates -> no high-confidence finding.

Run: C:/Python39/python.exe -m pytest tests/test_spa_stored_persistence.py -q
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

_VIEW_RAW = b"""<html><body><div class="notes">@@NOTES@@</div></body></html>"""
_VIEW_ESCAPED = b"""<html><body><div class="notes">@@NOTES@@</div></body></html>"""


def _server(view_template: bytes):
    # A real notes app KEEPS what was written -- measured the hard way: a
    # fixture that stores only the LAST payload ends up empty (the corpus
    # loop's final variant), so the viewer renders nothing.
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
            elif path == "/view":
                import html as _html
                raw = "".join(store)
                if b"&lt;" not in view_template:      # the RAW viewer
                    body = view_template.replace(b"@@NOTES@@",
                                                 raw.encode("utf-8"))
                else:                                  # the escaping viewer
                    body = view_template.replace(
                        b"@@NOTES@@", _html.escape(raw).encode("utf-8"))
                self._send(body)
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
            self._send(json.dumps({"ok": True}).encode(), "application/json")

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


def _round_trip(base: str, view_urls: list | None):
    """Discover the write face on /write, then run the round-trip."""
    from xssentinel.core import dom_engine as dem
    from xssentinel.core.requester import Requester
    from xssentinel.core.scanner import Scanner

    faces = dem.DynamicDomAnalyzer(timeout=20).harvest(
        base + "/write", write_faces=True).get("write_faces") or []
    assert faces, "the write face was not observed -- fixture broken"
    sc = Scanner(requester=Requester(timeout=8), dom_engine="off",
                 verbose=False, max_payloads=4, max_transforms=6)
    sc.scan_spa_write_faces(faces, base + "/write", view_urls=view_urls)
    return [f.data for f in sc.findings if f.data.get("type") == "stored"]


@pytest.mark.skipif(not SOCKETPAIR_OK, reason="no socketpair")
class TestStoredPersistenceAcrossPages:
    def test_viewer_route_proves_persistence(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        srv, holder = _server(_VIEW_RAW)
        try:
            base = f"http://127.0.0.1:{holder['p']}"
            stored = _round_trip(base, [base + "/view"])
            assert stored, "no stored finding despite a viewer that renders it"
            f = stored[0]
            assert f.get("confidence") == "high", f
            assert "/view" in (f.get("proof") or {}).get("view_url", ""), f
        finally:
            srv.shutdown()

    def test_escaping_viewer_yields_nothing(self):
        """Counter-proof: extra viewer pages must not manufacture findings."""
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        srv, holder = _server(
            _VIEW_ESCAPED.replace(b"@@NOTES@@", b"@@NOTES@@&lt;"))
        try:
            base = f"http://127.0.0.1:{holder['p']}"
            assert _round_trip(base, [base + "/view"]) == [], (
                "an escaping viewer produced a stored finding")
        finally:
            srv.shutdown()

    def test_without_viewer_candidates_no_high_confidence(self):
        """The self-view downgrade stands when nobody else is asked."""
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        srv, holder = _server(_VIEW_RAW)
        try:
            base = f"http://127.0.0.1:{holder['p']}"
            for f in _round_trip(base, None):
                assert f.get("confidence") != "high", (
                    "a high-confidence stored finding without an explicit "
                    f"viewer page: {f}")
        finally:
            srv.shutdown()
