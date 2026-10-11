# -*- coding: utf-8 -*-
"""Phase 216: the last crawl-parity line -- L8 carriers + JSONP on crawled
endpoints.

Phase 215 wired the page-layer trio (DOM / advanced / CSP) for crawled
endpoints.  Two layers remained unwired, and sync runs both on every
crawled endpoint:

  * L8 request-injection carriers (header / path / cookie / error-page
    XSS) -- observed here end-to-end: /l8 is LINKED (not the seed) and
    reflects the request's User-Agent header RAW into the HTML body, so
    the L8 header probe (payload in the UA) must come back confirmed on
    the crawled page.
  * The JSONP callback audit -- /jp answers ``?callback=X`` with
    ``X({...})`` as application/javascript and validates NOTHING; the
    audit's marker probe must come back confirmed at the callback
    position.

CORS and the XS-Leaks audit stay deliberately unwired: both dedupe per
ORIGIN inside the layer (``_cors_checked`` / ``_xsleak_audited``), so a
per-endpoint call after the seed's is structurally unreachable -- wiring
it would be a decorative call that can never fire.

Run: pytest tests/test_phase216_crawl_request_layers.py -q
"""
from __future__ import annotations

import ast
import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

SHELL_LINKS = ('<a href="/l8">l8</a><a href="/jp">jp</a>')


def _page(body: str) -> str:
    return ("<!doctype html><html><head><meta charset=\"utf-8\">"
            "<title>p</title></head><body>" + body + "</body></html>")


def _serve_vuln(self: BaseHTTPRequestHandler) -> None:
    """Vuln site: /l8 reflects the UA raw; /jp echoes any callback name."""
    path = self.path.split("?", 1)[0].split("#", 1)[0]
    if path == "/l8":
        ua = self.headers.get("User-Agent", "")
        body = _page(f"UA:{ua}")
        ctype = "text/html; charset=utf-8"
    elif path == "/jp":
        # Inline-JSONP glue: the callback name echoes into a SCRIPT BLOCK of
        # an HTML page.  A bare-JS document is NOT confirmable by the JSONP
        # layer today -- verify_semantic reads it as an html_element (no
        # jsonp-aware context analysis exists; the matrix has no positive
        # jsonp_xss case either, only whitelist safe twins).  That gate is
        # the layer's own pre-existing shape; changing it is a judgement-
        # plane round with its own oracle, not this phase.
        qs = parse_qs(urlparse(self.path).query)
        cb = (qs.get("callback") or [""])[0]
        if cb:
            body = _page(f"<script>{cb}({{\"ok\": 1}});</script>")
            ctype = "text/html; charset=utf-8"
        else:
            body = _page("<script>console.log(1);</script>")
            ctype = "text/html; charset=utf-8"
    elif path == "/":
        body = _page(SHELL_LINKS)
        ctype = "text/html; charset=utf-8"
    else:
        body = "<html><body>404</body></html>"
        ctype = "text/plain"
    self._send(body, ctype)


def _serve_safe(self: BaseHTTPRequestHandler) -> None:
    """Safe twins: /l8-safe reflects nothing; /jp-safe validates nothing to
    echo -- the callback parameter is ignored outright."""
    path = self.path.split("?", 1)[0].split("#", 1)[0]
    if path == "/l8-safe":
        body = _page("static text, no reflection")
        ctype = "text/html; charset=utf-8"
    elif path == "/jp-safe":
        body = '{"ok": 1}'
        ctype = "application/json"
    elif path == "/":
        body = _page('<a href="/l8-safe">l8</a><a href="/jp-safe">jp</a>')
        ctype = "text/html; charset=utf-8"
    else:
        body = "<html><body>404</body></html>"
        ctype = "text/plain"
    self._send(body, ctype)


class _Base(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body: str, ctype: str):
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture()
def lab(request):
    safe = getattr(request, "param", False)
    # Plain function in the class dict -> instance method (self flows).
    # staticmethod here silently broke every request (missing 'self') and
    # made the safe twin's silence assertion vacuously green.
    handler = type("H", (_Base,),
                   {"do_GET": _serve_safe if safe else _serve_vuln})
    srv = ThreadingHTTPServer(("127.0.0.1", _free_port()), handler)
    srv.timeout = 10
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _dom_available() -> bool:
    from xssentinel.core import dom_engine
    return dom_engine.DynamicDomAnalyzer.available()


needs_browser = pytest.mark.skipif(
    not _dom_available(),
    reason="playwright not installed; the shared-browser machinery is "
           "exercised by the crawl scan (see 203/215 thread notes)")


def _scan_res(base: str):
    """Async scan on a SEPARATE thread (203/215: the main test thread may
    carry a sync-Playwright binding from another file in this process)."""
    import asyncio
    import threading
    from xssentinel.core.async_scanner import AsyncScanner

    async def go():
        asc = AsyncScanner(crawl=True, crawl_depth=1, max_payloads=8,
                           advanced_layers=True)
        out = []
        async for f in asc.scan(base + "/"):
            out.append(f.data if hasattr(f, "data") else f)
        return out

    out: dict = {}

    def _runner():
        out["result"] = asyncio.run(go())

    t = threading.Thread(target=_runner, daemon=True)
    t.start()
    t.join(timeout=600)
    if "result" not in out:
        raise AssertionError("async scan did not finish within 600s -- "
                             "loop/browser cross-thread wedge (see 203)")
    return out["result"]


def test_helper_wires_the_full_page_layer_set():
    src = open(os.path.join(ROOT, "xssentinel/core/async_scanner_crawl.py"),
               encoding="utf-8").read()
    tree = ast.parse(src)
    helper = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.AsyncFunctionDef)
                  and n.name == "_crawl_page_layers")
    calls = {n.func.attr for n in ast.walk(helper)
             if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Attribute)}
    assert {"_scan_dom_async", "_scan_advanced_page", "_scan_csp_async",
            "_scan_request_layers", "_scan_jsonp_async"} <= calls, calls


@needs_browser
def test_l8_header_carrier_on_a_linked_page(lab):
    """/l8 is LINKED (not the seed) and echoes the User-Agent raw -- the L8
    header probe must confirm on the crawled page, not only on the seed."""
    found = _scan_res(lab)
    hits = [f for f in found
            if f.get("type") == "header_xss"
            and str(f.get("url", "")).split("?")[0].endswith("/l8")]
    assert hits, (
        "no header_xss finding on the LINKED page /l8 -- the L8 carriers "
        "are not wired into the crawled page layers")
    assert any("(header:User-Agent)" in str(f.get("param")) for f in hits), (
        f"the delivered carrier must be the User-Agent header: "
        f"{[f.get('param') for f in hits]}")


@needs_browser
def test_jsonp_audit_on_a_linked_page(lab):
    """/jp echoes ANY callback name at the function position -- the JSONP
    audit's marker probe must confirm on the crawled page."""
    found = _scan_res(lab)
    hits = [f for f in found
            if f.get("type") == "jsonp_xss"
            and str(f.get("url", "")).split("?")[0].endswith("/jp")]
    assert hits, (
        "no jsonp_xss finding on the LINKED page /jp -- the JSONP audit is "
        "not wired into the crawled page layers")


@needs_browser
@pytest.mark.parametrize("lab", [True], indirect=True)
def test_safe_twins_stay_silent(lab):
    found = _scan_res(lab)
    carrier_hits = [f for f in found
                    if f.get("type") in ("header_xss", "jsonp_xss",
                                         "cookie_xss", "path_xss")]
    assert not carrier_hits, (
        f"carrier findings on a site that reflects nothing: "
        f"{[(f.get('type'), f.get('url')) for f in carrier_hits]}")
