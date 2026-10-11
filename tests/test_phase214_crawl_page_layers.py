# -*- coding: utf-8 -*-
"""Phase 214: crawled NON-fragment endpoints get their page layers in async.

The 2.1.1 record (Phase 209): async ``_crawl_and_scan`` scanned every
discovered endpoint with the reflection probe ALONE -- the fragment-route
branch got the DOM layer (Phase 209), but a plain linked page with a DOM
sink was invisible to ``--async`` whatever the marker reached through,
while sync registers every crawled page and runs the full ``scan_endpoint``
stack on it (browser DOM layer included).

The wiring point is deliberately POP time, not discovery time: at discovery
only the PARENT's text exists (analyzing it would be static analysis of the
wrong page), while at pop the endpoint has just been fetched for child-link
extraction anyway.  Three separate things can break the delivery, each with
its own assertion:

  1. the pop-time block must exist and actually run (AST guard + behavior),
  2. the layer URL must be DE-PARAMETERISED -- ``/sink?v=1`` handed to the
     browser together with ``params={"v": ...}`` appends a duplicate
     ``&v=...`` after its own ``?v=1``, the reader takes the first value
     and the marker never arrives (the same merged-query shape
     scanner_crawl.py documents for the reflected probe),
  3. the SEED must not be page-layered a second time at pop -- the main
     loop already ran the full pipeline on it.

Run: pytest tests/test_phase214_crawl_page_layers.py -q
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

# The linked page: reads a SPECIFIC query parameter into innerHTML, so the
# de-parameterisation assertion (2) has teeth -- with the merged
# ``?v=1&v=<marker>`` shape URLSearchParams.get('v') returns "1" and the
# marker never reaches the sink.
SINK_JS = r"""
function render() {
  var v = new URLSearchParams(location.search).get('v') || '';
  document.getElementById('out').innerHTML = v;
}
window.addEventListener('load', render);
"""

SEED_JS = r"""
function render() {
  document.getElementById('out').innerHTML = location.hash;
}
window.addEventListener('load', render);
"""

VULN_SINK = ("<!doctype html><html><head><meta charset=\"utf-8\">"
             "<title>s</title></head><body><div id=\"out\"></div>"
             "<script>" + SINK_JS + "</script></body></html>")

VULN_SEED = ("<!doctype html><html><head><meta charset=\"utf-8\">"
             "<title>p</title></head><body><div id=\"out\"></div>"
             "<a href=\"/sink?v=1\">sink</a>"
             "<script>" + SEED_JS + "</script></body></html>")

SAFE_SINK = VULN_SINK.replace(
    "document.getElementById('out').innerHTML = v;",
    "document.getElementById('out').textContent = v;")
SAFE_SEED = (VULN_SEED
             .replace("document.getElementById('out').innerHTML = "
                      "location.hash;",
                      "document.getElementById('out').textContent = "
                      "location.hash;")
             .replace('<a href="/sink?v=1">', '<a href="/sink-safe?v=1">'))

PAGES = {
    "/": VULN_SEED, "/sink": VULN_SINK,
}


class _Base(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body: str):
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        path = self.path.split("?", 1)[0].split("#", 1)[0]
        self._send(PAGES.get(path, "<html><body>404</body></html>"))


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture()
def lab(request):
    """Serve the vuln site, or the textContent twins when indirect=True."""
    safe = getattr(request, "param", False)
    pages = ({"/": SAFE_SEED, "/sink-safe": SAFE_SINK} if safe else PAGES)

    class H(_Base):
        pass
    H.do_GET = lambda self: self._send(
        pages.get(self.path.split("?", 1)[0].split("#", 1)[0],
                  "<html><body>404</body></html>"))
    srv = ThreadingHTTPServer(("127.0.0.1", _free_port()), H)
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

ENGINES = ["sync", "async"]


def _collect(engine: str, base: str) -> list:
    if engine == "sync":
        from xssentinel.core.requester import Requester
        from xssentinel.core.scanner import Scanner
        sc = Scanner(requester=Requester(timeout=10), crawl=True,
                     crawl_depth=1, use_headless=True, crawl_engine="auto")
        sc.scan_target(base + "/")
        return [f.data or {} for f in sc.findings]

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

    # Phase 203's lesson, hit again cross-file (2026-10-11): a sync-Playwright
    # test earlier in the same pytest process binds the browser loop to the
    # main test thread, and ``asyncio.run`` on that thread then wedges
    # flat-CPU.  Individually every arm passes; run the async half on a
    # fresh thread so it cannot inherit the binding.
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


# ---------------------------------------------------------------------------
# 1) the wiring exists (static guard -- survives without a browser)
# ---------------------------------------------------------------------------

def test_crawl_function_wires_the_page_layers():
    src = open(os.path.join(ROOT, "xssentinel/core/async_scanner_crawl.py"),
               encoding="utf-8").read()
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.AsyncFunctionDef)
              and n.name == "_crawl_and_scan")
    calls = {n.func.attr for n in ast.walk(fn)
             if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Attribute)}
    # Phase 215 moved the pop-time layer trio into _crawl_page_layers --
    # the wiring assert follows the call, it does not pin the file the
    # call lives in (that would re-create the 211 blind-window shape).
    assert {"_crawl_page_layers", "_scan_reflected",
            "_scan_dom_async"} <= calls, sorted(calls)
    # The layer URL must be de-parameterised (assertion 2's static half).
    assert 'bare_url = current_url.split("?", 1)[0]' in src
    # Seed/origin discrimination exists (assertion 3's static half).
    consts = {n.value for n in ast.walk(fn)
              if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    assert {"seed", "link"} <= consts


# ---------------------------------------------------------------------------
# 2) the delivery (real browser, both engines)
# ---------------------------------------------------------------------------

@needs_browser
@pytest.mark.parametrize("engine", ENGINES)
def test_linked_nonfragment_page_gets_its_dom_layer(lab, engine):
    """THE delivery assertion: /sink is discovered as a plain link and its
    DOM sink fires in a real browser -- via the POP-time page layers."""
    found = _collect(engine, lab)
    dyn = [f for f in found
           if f.get("type") == "dom_dynamic"
           and f.get("evidence_class") == "browser-executed"]
    # Sync re-attaches the endpoint's params to the DOM layer's URL
    # (scanner.py), so the finding url can carry the query -- match on the
    # path, not the raw string.
    sink_hits = [f for f in dyn
                 if str(f.get("url", "")).split("?")[0].endswith("/sink")]
    seed_hits = [f for f in dyn
                 if str(f.get("url", "")).split("?")[0].rstrip("/")
                 == lab.rstrip("/")]
    assert sink_hits, (
        f"[{engine}] no browser-executed DOM finding on the LINKED page "
        f"/sink -- the 2.1.1 gap is back; dom_dynamic urls: "
        f"{[f.get('url') for f in dyn]}")
    assert len(seed_hits) == 1, (
        f"[{engine}] the seed page was page-layered {len(seed_hits)} times "
        f"-- the main loop already scanned it; pop-time layers must skip "
        f"the seed")


@needs_browser
@pytest.mark.parametrize("engine", ENGINES)
@pytest.mark.parametrize("lab", [True], indirect=True)
def test_safe_twins_stay_silent(lab, engine):
    """textContent renders the same string as TEXT; a scanner that reports
    it cannot be trusted on the positive case."""
    found = _collect(engine, lab)
    dom_hits = [f for f in found if f.get("type") == "dom_dynamic"]
    assert not dom_hits, (
        f"[{engine}] DOM finding on a textContent site: "
        f"{[f.get('url') for f in dom_hits]}")
