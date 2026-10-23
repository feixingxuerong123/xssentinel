# -*- coding: utf-8 -*-
"""Page hints must not be attributed to a URL a redirect moved away from.

XSSMaze `redirect/level1..4` are controls: the value only reaches a
`Location:` header, the 302 lands on `/` with no query, and the landing page
is the lab's own React/Vue/WebSocket SPA.  Our report carried six medium
page-level hints against those URLs.  The rule here is narrow: when a
redirect changes the path and the final URL drops the injected parameters,
the document analyzed is a different resource, so framework / Trusted-Types
/ WebSocket hints and static DOM hints do not describe the scanned URL.
Dynamic DOM delivery is deliberately *not* gated (a fragment can survive a
redirect and genuinely execute on the landing page).
"""
import asyncio
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from xssentinel.core.page_relevance import (  # noqa: E402
    redirect_landing_drops_input)
from xssentinel.core.requester import Requester  # noqa: E402
from xssentinel.core.scanner import Scanner  # noqa: E402

LANDING = """<html><body><div id='out'></div><script>
var ws = new WebSocket('ws://example.test/socket');
ws.onmessage = function(e){ document.getElementById('out').innerHTML = e.data; };
var h = location.hash.slice(1);
document.getElementById('out').innerHTML = h;
</script></body></html>"""

HINT_TYPES = {
    "dom", "websocket_xss", "websocket_insecure",
    "trusted_types_no_policy", "trusted_types_taint_flow",
    "trusted_types_policy_bypass", "framework_react_xss",
    "framework_vue_xss", "framework_angular_xss",
}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/old":
            self.send_response(302)
            self.send_header("Location", "/landing")
            self.end_headers()
            return
        if path == "/keep":
            self.send_response(302)
            self.send_header("Location", "/landing?q=kept")
            self.end_headers()
            return
        if path == "/landing":
            raw = LANDING.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        self.send_response(404)
        self.end_headers()


@pytest.fixture(scope="module")
def base():
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# the pure rule
# ---------------------------------------------------------------------------
def test_no_redirect_is_relevant():
    assert not redirect_landing_drops_input(
        "http://h/a?q=1", "http://h/a?q=1", redirected=False, params={"q": "1"})


def test_same_path_after_redirect_is_relevant():
    assert not redirect_landing_drops_input(
        "http://h/a?q=1", "https://h/a/?q=1", redirected=True,
        params={"q": "1"})


def test_different_path_with_dropped_query_is_not_relevant():
    assert redirect_landing_drops_input(
        "http://h/old?q=1", "http://h/landing", redirected=True,
        params={"q": "1"})


def test_preserved_query_keeps_the_landing_page_relevant():
    assert not redirect_landing_drops_input(
        "http://h/old?q=1", "http://h/landing?q=1", redirected=True,
        params={"q": "1"})


def test_cross_host_redirect_is_not_the_same_resource():
    assert redirect_landing_drops_input(
        "http://h/old?q=1", "http://other/landing", redirected=True,
        params={"q": "1"})


def test_without_parameters_nothing_is_dropped():
    assert not redirect_landing_drops_input(
        "http://h/old", "http://h/landing", redirected=True, params=None)


def test_missing_shape_never_gates():
    assert not redirect_landing_drops_input("", "", True)
    assert not redirect_landing_drops_input("http://h/a", "", True)


# ---------------------------------------------------------------------------
# behavioural: the real scan path
# ---------------------------------------------------------------------------
def _scan(base, path):
    sc = Scanner(requester=Requester(timeout=8), max_payloads=2,
                 max_transforms=1, dom_engine="static")
    sc.scan_target(base + path, method="GET", params={"q": "x"}, data={},
                   oob_collect=False)
    sc.dedup()
    return [f.data for f in sc.findings]


def test_redirect_landing_carries_no_page_hints(base):
    types = {f.get("type") for f in _scan(base, "/old")}
    assert not (types & HINT_TYPES), (
        "page hints were attributed to a URL the redirect moved away from: "
        f"{sorted(types)}")


def test_preserved_query_still_gets_the_hints(base):
    """The gate must not blanket-silence redirects: the same landing page
    reached with the query preserved is still analyzed."""
    types = {f.get("type") for f in _scan(base, "/keep")}
    assert types & HINT_TYPES, (
        "the fixture no longer triggers any page hint -- the negative test "
        f"above would be vacuous; got {sorted(types)}")


# ---------------------------------------------------------------------------
# wiring guards (both engines)
# ---------------------------------------------------------------------------
def test_sync_dom_layer_uses_the_rule():
    from xssentinel.core import scanner_layers
    src = open(scanner_layers.__file__, encoding="utf-8").read()
    assert "redirect_landing_drops_input(" in src
    assert 'status="skipped"' in src


def test_page_dispatcher_gates_only_the_hint_layers():
    from xssentinel.core import advanced_layers
    src = open(advanced_layers.__file__, encoding="utf-8").read()
    assert "redirect_landing_drops_input(" in src
    for lid in ("L8_framework", "L8_trusted_types", "L8_websocket"):
        assert f'"{lid}"' in src, lid


def test_async_dom_layer_takes_the_flag():
    import inspect

    from xssentinel.core.async_scanner_layers import AsyncDetectionLayersMixin
    sig = inspect.signature(AsyncDetectionLayersMixin._scan_dom_async)
    assert "redirect_landing" in sig.parameters


def test_async_call_site_passes_the_flag():
    from xssentinel.core import async_scanner
    src = open(async_scanner.__file__, encoding="utf-8").read()
    assert "redirect_landing=redirect_landing_drops_input(" in src


class _Cov:
    def __init__(self):
        self.skipped = []

    def touch_layer(self, *a, **k):
        pass

    def record_layer(self, *a, **k):
        self.skipped.append((a, k))

    def record_finding(self, *a, **k):
        pass

    def record_request(self, *a, **k):
        pass


def test_async_static_analysis_is_skipped_but_the_baseline_path_stays(
        monkeypatch):
    from xssentinel.core import async_scanner_layers, dom
    from xssentinel.core.async_scanner import AsyncScanner

    calls = []
    monkeypatch.setattr(dom, "analyze",
                        lambda *a, **k: (calls.append(1), [])[1])
    sc = object.__new__(AsyncScanner)
    sc.coverage = _Cov()
    sc.verbose = False
    sc._resolve_dom_engine = lambda: None

    async def run(flag):
        agen = async_scanner_layers.AsyncDetectionLayersMixin._scan_dom_async(
            sc, "http://example.test/", "plain text", "GET",
            {"q": "x"}, redirect_landing=flag)
        return [f async for f in agen]

    assert asyncio.run(run(True)) == []
    assert calls == [], "static analysis ran on a redirect landing page"
    assert asyncio.run(run(False)) == []
    assert calls == [1], "the normal path stopped analyzing the page"
