# -*- coding: utf-8 -*-
"""Phase 215: the rest of the 2.1.1 line -- mined endpoints, CSP on crawled
pages, fragment anchors.

Phase 214 wired the pop-time page layers for LINK-discovered endpoints.
Three recorded gaps remained, each closed here with its own assertion:

  1. MINED non-fragment endpoints (form actions with fields / JS-mined
     URLs) got reflection-only.  Nothing else ever fetches them, so the
     page layers cost one inline GET -- sync pays the same GET inside
     scan_endpoint.  The discriminating shape: a sink that reads a SPECIFIC
     parameter (``?v=``) whose name is only known from the form fields --
     the link path (query-less action URL) can never fire it, the mined
     params can.
  2. CSP never ran on crawled pages: the crawl fetch discarded the
     response headers.  Observed via the coverage tracker -- the L6_csp
     row must exist for a linked page (the seed already had it from the
     main loop).
  3. Fragment-bearing ANCHORS were excluded from the pop-time layers.
     They layer now, deduped on the fragment-stripped URL: findings._norm
     drops fragments, so sync registers /dup#one and /dup#two as ONE
     endpoint -- two browser passes for the same page would be cost
     without information, and async has no finding dedup, so the dupes
     would ship as two identical findings.

Run: pytest tests/test_phase215_crawl_mined_layers.py -q
"""
from __future__ import annotations

import ast
import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

SINK_V = r"""
function render() {
  var v = new URLSearchParams(location.search).get('v') || '';
  document.getElementById('out').innerHTML = v;
}
window.addEventListener('load', render);
"""

SINK_HASH = r"""
function render() {
  document.getElementById('out').innerHTML = location.hash;
}
window.addEventListener('load', render);
"""


def _page(sink_js: str, extra: str = "") -> str:
    return ("<!doctype html><html><head><meta charset=\"utf-8\">"
            "<title>p</title></head><body><div id=\"out\"></div>"
            + extra +
            "<script>" + sink_js + "</script></body></html>")


VULN_SEED = _page(SINK_HASH, (
    '<form action="/fa" method="get">'
    '<input type="text" name="v"><input type="submit"></form>'
    '<a href="/dup#one">one</a><a href="/dup#two">two</a>'
    '<a href="/sink?v=1">sink</a>'
    '<a href="/csp">csp</a>'))
VULN_PAGES = {
    "/": VULN_SEED,
    "/fa": _page(SINK_V),
    "/dup": _page(SINK_HASH),
    "/sink": _page(SINK_V),
    "/csp": _page(""),
}

# A page with an enforcing, classic-bypassable policy: the CSP layer emits
# `csp_bypass` for exactly this shape, so "the layer ran on the crawled
# page" becomes observable as a FINDING (async carries a no-op coverage
# facade, so coverage rows are structurally unavailable there).
CSP_HEADERS = {"/csp": {"Content-Security-Policy":
                        "default-src 'unsafe-inline'"}}

SAFE_SEED = _page("", (
    '<form action="/fa-safe" method="get">'
    '<input type="text" name="v"><input type="submit"></form>'))
SAFE_PAGES = {
    "/": SAFE_SEED,
    "/fa-safe": _page(SINK_V.replace(".innerHTML", ".textContent")),
}


class _Base(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    pages: dict = {}

    def do_GET(self):
        path = self.path.split("?", 1)[0].split("#", 1)[0]
        body = type(self).pages.get(path, "<html><body>404</body></html>")
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for k, v in type(self).headers_extra.get(path, {}).items():
            self.send_header(k, v)
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
    """Serve the vuln site, or the textContent twin when indirect=True."""
    safe = getattr(request, "param", False)
    handler = type("H", (_Base,), {
        "pages": SAFE_PAGES if safe else VULN_PAGES,
        "headers_extra": {} if safe else CSP_HEADERS,
    })
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
    reason="playwright not installed; the browser arm of this gate cannot run")


async def _scan(base: str):
    from xssentinel.core.async_scanner import AsyncScanner
    asc = AsyncScanner(crawl=True, crawl_depth=1, max_payloads=8,
                       advanced_layers=True)
    out = []
    async for f in asc.scan(base + "/"):
        out.append(f.data if hasattr(f, "data") else f)
    return out, asc


def _dyn_on(found, path: str, require_executed: bool = True) -> list:
    """dom_dynamic findings whose URL lands on ``path``.

    ``require_executed=False`` drops the ``evidence_class`` filter, and the
    count/dedupe assertions need that: Phase 260 measured this lab with
    dev/_p260_recorder.py and the engine discriminates by SOURCE --
    ``innerHTML = location.hash`` pages (/ and /dup) come back with
    ``executed=False`` (marker delivered to the sink, no execution observed,
    so the honest grade is browser-refuted), while the ``?v=`` pages (/fa,
    /sink) come back ``executed=True, carrier=html`` and grade
    browser-executed.  Filtering on browser-executed therefore counted "did
    the sink execute", not "was this page-layered exactly once".
    """
    return [f for f in found
            if f.get("type") == "dom_dynamic"
            and (not require_executed
                 or f.get("evidence_class") == "browser-executed")
            and str(f.get("url", "")).split("?")[0].split("#")[0]
            .rstrip("/").endswith(path)]


# ---------------------------------------------------------------------------
# static wiring guard (no browser)
# ---------------------------------------------------------------------------

def test_page_layer_helper_wires_the_trio():
    src = open(os.path.join(ROOT, "xssentinel/core/async_scanner_crawl.py"),
               encoding="utf-8").read()
    tree = ast.parse(src)
    helper = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.AsyncFunctionDef)
                  and n.name == "_crawl_page_layers")
    calls = {n.func.attr for n in ast.walk(helper)
             if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Attribute)}
    assert {"_scan_dom_async", "_scan_advanced_page",
            "_scan_csp_async"} <= calls, sorted(calls)
    crawl = next(n for n in ast.walk(tree)
                 if isinstance(n, ast.AsyncFunctionDef)
                 and n.name == "_crawl_and_scan")
    crawl_calls = [n for n in ast.walk(crawl)
                   if isinstance(n, ast.Call)
                   and isinstance(n.func, ast.Attribute)
                   and n.func.attr == "_crawl_page_layers"]
    # Two sites: the pop-time link block AND the mined branch.
    assert len(crawl_calls) >= 2, (
        "the page-layer helper must be wired from BOTH crawled-endpoint "
        "paths (link pop + mined discovery)")


# ---------------------------------------------------------------------------
# behavior (real browser)
# ---------------------------------------------------------------------------

@needs_browser
def test_mined_endpoint_gets_its_page_layers(lab):
    """/fa is reachable ONLY as a form action with a `v` field.  Its sink
    reads `?v=` -- a name the link path cannot know (the action URL carries
    no query), so this finding is reachable only through the mined params."""
    found, _asc = _scan_res(lab)
    hits = _dyn_on(found, "/fa")
    assert hits, (
        "no browser-executed DOM finding on the FORM-MINED endpoint /fa -- "
        "the mined branch lost its page layers")
    assert all(f.get("param") == "v" for f in hits), (
        f"the delivered key must be the form field: "
        f"{[f.get('param') for f in hits]}")


@needs_browser
def test_csp_layer_runs_on_a_linked_page(lab):
    """The crawl fetch used to discard the response headers, so CSP never
    saw a crawled page.  /csp is LINKED (not the seed) and serves an
    enforcing, classically-bypassable policy -- the layer's csp_bypass
    finding on it proves the layer ran with the crawled page's OWN headers
    (the seed's CSP row comes from the main loop and proves nothing here)."""
    found, _asc = _scan_res(lab)
    csp_hits = [f for f in found
                if f.get("type") == "csp_bypass"
                and str(f.get("url", "")).split("?")[0].endswith("/csp")]
    assert csp_hits, (
        "no csp_bypass finding on the LINKED page /csp -- the crawl fetch "
        "is still discarding the response headers; csp findings: "
        f"{[f.get('url') for f in found if f.get('type') == 'csp_bypass']}")


@needs_browser
def test_fragment_anchor_layers_run_once(lab):
    """/dup is linked twice (as /dup#one and /dup#two).  The page layers
    must run once: async has no finding dedup, so two browser passes would
    ship two identical findings."""
    found, _asc = _scan_res(lab)
    hits = _dyn_on(found, "/dup", require_executed=False)
    assert len(hits) == 1, (
        f"expected exactly one dom_dynamic on /dup (fragment-stripped "
        f"dedupe), got {len(hits)}: {[f.get('url') for f in hits]}")


@needs_browser
@pytest.mark.parametrize("lab", [True], indirect=True)
def test_safe_twin_stays_silent(lab):
    found, _asc = _scan_res(lab)
    dom_hits = [f for f in found if f.get("type") == "dom_dynamic"]
    assert not dom_hits, (
        f"DOM finding on a textContent site: {[f.get('url') for f in dom_hits]}")


def _scan_res(base: str):
    """Run the async scan on a SEPARATE thread.

    Phase 203's lesson, learned again the hard way: this file runs in the
    same pytest process as test_phase214_crawl_page_layers.py, whose sync
    arm binds the sync Playwright browser (and its loop) to the main test
    thread.  Individually every test passes; back-to-back in one process,
    ``asyncio.run`` on that thread wedges flat-CPU forever (measured:
    20 min, 0 bytes of output, three idle python processes).  A fresh
    thread has no loop binding, so the async half cannot inherit the
    wedge.
    """
    import asyncio
    import threading
    out: dict = {}

    def _runner():
        out["result"] = asyncio.run(_scan(base))

    t = threading.Thread(target=_runner, daemon=True)
    t.start()
    t.join(timeout=600)
    if "result" not in out:
        raise AssertionError("async scan did not finish within 600s -- "
                             "loop/browser cross-thread wedge (see 203)")
    return out["result"]
