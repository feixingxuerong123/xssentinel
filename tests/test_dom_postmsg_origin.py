"""Phase 187: postMessage probes measure ATTACKER-ORIGIN deliverability.

Absorbed from DOM Invader's origin-spoof mode: a cross-origin attacker's
postMessage always carries the SENDER's origin (or ``null`` from a sandboxed
iframe) -- the browser never lets it claim the victim's own origin.  The old
harness delivered the marker with ``origin = location.origin``, so a handler
that validated origin still fired the sink and the engine confirmed a
cross-origin XSS no attacker could reach.  Both engines share this harness.

These tests are behavioural (real Chromium, loopback only) and skip when no
browser is available -- same contract as the other dom_engine suites.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import dom_engine

_PAGE_OPEN = """<!DOCTYPE html><html><body>
<div id="out"></div>
<script>
window.addEventListener('message', function (e) {
  document.getElementById('out').innerHTML = e.data;
});
</script>
</body></html>"""

# The handler's origin gate is EFFECTIVE: only same-origin messages pass.
# The old harness (same-origin dispatch) fired this sink and CONFIRMED an
# exploitable XSS -- the measured verdict must be silence instead.
_PAGE_CHECKED = _PAGE_OPEN.replace(
    "function (e) {",
    "function (e) {\n  if (e.origin !== location.origin) return;")

# Handlers registered by property reach the same attacker-origin dispatch.
_PAGE_ONMSG = """<!DOCTYPE html><html><body>
<div id="out"></div>
<script>
window.onmessage = function (e) {
  document.getElementById('out').innerHTML = e.data;
};
</script>
</body></html>"""

_ROUTES = {"/open": _PAGE_OPEN, "/checked": _PAGE_CHECKED,
           "/onmsg": _PAGE_ONMSG}


class _H(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?")[0]
        body = (_ROUTES.get(path, "<html><body>nf</body></html>")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _postmsg_findings(engine, url):
    return [f for f in engine.analyze(url) if f.get("source") == "postMessage"]


@pytest.fixture(scope="module")
def pm_site():
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session (security software/TCP state)")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.2)
    yield f"http://127.0.0.1:{server.server_address[1]}"
    try:
        server.shutdown()
        server.server_close()
    except Exception:
        pass


@pytest.fixture(scope="module")
def engine():
    if not dom_engine.DynamicDomAnalyzer.available():
        pytest.skip("playwright/chromium not available")
    return dom_engine.DynamicDomAnalyzer(timeout=15)


class TestAttackerOriginPostMessage:
    def test_open_listener_still_confirmed(self, pm_site, engine):
        """No origin validation -> the attacker-origin message drives the
        sink; the finding must say so."""
        hits = _postmsg_findings(engine, f"{pm_site}/open")
        assert hits, "no-origin-check listener was missed entirely"
        assert any("ATTACKER origin" in (h.get("detail") or "") for h in hits)

    def test_origin_checked_listener_not_confirmed(self, pm_site, engine):
        """The FP this phase exists for: an effective origin gate used to be
        confirmed via the same-origin synthetic message.  Attacker-origin
        dispatch measures it as what it is -- not cross-origin exploitable."""
        hits = _postmsg_findings(engine, f"{pm_site}/checked")
        assert not hits, (
            "origin-checked listener still fired: harness dispatched a "
            "same-origin message the attacker cannot send")

    def test_onmessage_property_handler_reaches_dispatch(self, pm_site,
                                                         engine):
        hits = _postmsg_findings(engine, f"{pm_site}/onmsg")
        assert hits, "window.onmessage handler was not covered by the probe"
