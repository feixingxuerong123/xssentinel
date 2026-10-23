# -*- coding: utf-8 -*-
"""setHTMLUnsafe / parseHTMLUnsafe must stay instrumented.

XSSMaze `htmlunsafe/level1` (element) and `level5` (shadow root) take the
payload from location.hash and decodeURIComponent it straight into
setHTMLUnsafe; the query-reachable siblings (level2/4/6) were detected while
these two produced **zero findings** (2026-10-22 external run).  Without a
sink hook the DOM channel records no delivery at all, so the carrier wave
never runs and the page's own onerror never gets a chance to prove execution.

`Document.parseHTMLUnsafe` is the detached-tree form: a hit there is delivery
evidence, exactly like DOMParser -- the caller's append is what may execute.
"""
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from xssentinel.core import dom, dom_engine  # noqa: E402

_HAS_PW = dom_engine.DynamicDomAnalyzer.available()

_PAGES = {
    "/element": (
        "<html><body><div id='out'></div><script>"
        "var html = decodeURIComponent(location.hash.slice(1));"
        "document.getElementById('out').setHTMLUnsafe(html);"
        "</script></body></html>"),
    "/shadow": (
        "<html><body><div id='host'></div><script>"
        "var root = document.getElementById('host').attachShadow({mode:'open'});"
        "var html = decodeURIComponent(location.hash.slice(1));"
        "root.setHTMLUnsafe(html);"
        "</script></body></html>"),
    "/safe": (
        "<html><body><div id='out'></div><script>"
        "var html = decodeURIComponent(location.hash.slice(1));"
        "document.getElementById('out').textContent = html;"
        "</script></body></html>"),
    "/parse": (
        "<html><body><div id='out'></div><script>"
        "var q = location.search.slice(1);"
        "var d = Document.parseHTMLUnsafe(q);"
        "document.getElementById('out').append(...d.body.childNodes);"
        "</script></body></html>"),
}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = _PAGES.get(self.path.split("?")[0])
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        raw = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def test_init_script_instruments_both_setters_and_the_parser():
    js = dom_engine._init_script("MARKER")
    assert "'Element','ShadowRoot'" in js and "C.prototype.setHTMLUnsafe =" in js, (
        "setHTMLUnsafe is not instrumented -- XSSMaze htmlunsafe level1/5 "
        "would again report nothing")
    assert "Document.parseHTMLUnsafe = function" in js, (
        "the detached-tree form is not instrumented")


def test_static_analyzer_treats_sethtmlunsafe_as_a_sink():
    code = ("var h = location.hash.slice(1);"
            "document.getElementById('o').setHTMLUnsafe(h);")
    sinks = [f.get("sink", "") for f in dom.analyze_script(code)]
    assert any("setHTMLUnsafe" in s for s in sinks), sinks

    code = ("var q = new URLSearchParams(location.search).get('q');"
            "var d = Document.parseHTMLUnsafe(q);"
            "document.getElementById('o').append(...d.body.childNodes);")
    sinks = [f.get("sink", "") for f in dom.analyze_script(code)]
    assert any("parseHTMLUnsafe" in s for s in sinks), sinks


@pytest.fixture(scope="module")
def lab():
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


def _hits(lab, path):
    return dom_engine.DynamicDomAnalyzer(timeout=20).analyze(
        lab + path, marker="xssentinel_hu_probe")


@pytest.mark.skipif(not _HAS_PW, reason="playwright/chromium not available")
def test_element_sethtmlunsafe_executes_the_carrier(lab):
    hits = _hits(lab, "/element")
    hit = [h for h in hits if h.get("sink") == "Element.setHTMLUnsafe"]
    assert hit, hits
    assert any(h.get("executed") for h in hit), hit


@pytest.mark.skipif(not _HAS_PW, reason="playwright/chromium not available")
def test_shadow_root_sethtmlunsafe_executes_the_carrier(lab):
    hits = _hits(lab, "/shadow")
    hit = [h for h in hits if h.get("sink") == "ShadowRoot.setHTMLUnsafe"]
    assert hit, hits
    assert any(h.get("executed") for h in hit), hit


@pytest.mark.skipif(not _HAS_PW, reason="playwright/chromium not available")
def test_textcontent_twin_stays_silent(lab):
    hits = _hits(lab, "/safe")
    assert not any(h.get("executed") for h in hits), hits


@pytest.mark.skipif(not _HAS_PW, reason="playwright/chromium not available")
def test_document_parsehtmlunsafe_hook_records_delivery(lab):
    # Proves the assignment on the Document constructor really took effect in
    # Chromium; delivery only, the caller's append decides execution.
    hits = _hits(lab, "/parse")
    assert any(h.get("sink") == "Document.parseHTMLUnsafe" for h in hits), hits
