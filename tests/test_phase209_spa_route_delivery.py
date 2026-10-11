# -*- coding: utf-8 -*-
"""Phase 209 delivery gate: one root URL -> one real finding on an SPA.

The goal this pins is the operator's sentence, not a layer: ``xssentinel -u
http://app/ --crawl --headless`` must find the XSS on an application whose
routing lives in the URL fragment.  Everything else in this file exists to
keep that sentence from degrading into a story.

Three separate things can break it, and each needs its own assertion:

  1. the route table must be read out of the app's own bundle,
  2. the route must reach the scan as a *fragment-bearing* endpoint,
  3. the browser must actually execute the sink there.

Item 3 is why this file needs a real browser, and the safe twin (textContent
instead of innerHTML) is why it needs two pages: a fixture that only proves
"we can report something" would pass with a scanner that reports everything.
That lesson is Phase 180's -- the first version of range4 measured the
fixture's own bug as a false positive.

Run: pytest tests/test_phase209_spa_route_delivery.py -q
"""
from __future__ import annotations

import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssentinel.core.scanner import Scanner  # noqa: E402
from xssentinel.core.requester import Requester  # noqa: E402

# The vulnerable page: a hash-routing SPA whose router reads `?v=` out of the
# fragment and writes it into innerHTML -- Angular's `[innerHTML]` shape,
# reduced to the browser's own primitive.  Everything the scanner may rely on
# is in the served bytes: the route table (`navigate([...], {queryParams})`)
# is only discoverable by reading app.js, exactly as on OWASP Juice Shop.
APP_JS = r"""
var HomeComponent = {};            // declared so the route table executes
var ROUTES = [{path: 'home', component: HomeComponent}];
function goHome(e) {
  var q = {queryParams: {v: e}};
  var router = {navigate: function () { return null; }};
  return router.navigate([`/home`], q);
}
function render() {
  var frag = location.hash || '';
  var qs = frag.indexOf('?') >= 0 ? frag.slice(frag.indexOf('?') + 1) : '';
  var params = new URLSearchParams(qs);
  var v = params.get('v') || '';
  document.getElementById('out').innerHTML = v;
}
window.addEventListener('hashchange', render);
window.addEventListener('load', render);
"""

SAFE_APP_JS = APP_JS.replace(
    "document.getElementById('out').innerHTML = v;",
    "document.getElementById('out').textContent = v;")

_SHELL = """<!doctype html><html><head><meta charset="utf-8"><title>r4x</title>
</head><body><app-root></app-root><div id="out"></div>
<script src="/app.js"></script></body></html>"""


class _Base(BaseHTTPRequestHandler):
    """Per-fixture handler body; the JS it serves is bound in `spa_server`.

    The class is subclassed per server rather than mutated, so the vulnerable
    and safe twins can never share state (a parametrised class attribute would
    leak across tests under any reordering).
    """

    app_js = APP_JS

    def log_message(self, *a):
        pass

    def _send(self, body: bytes, ctype: str):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0].split("#", 1)[0]
        if path in ("/", "/index.html"):
            self._send(_SHELL.encode(), "text/html; charset=utf-8")
        elif path == "/app.js":
            self._send(type(self).app_js.encode(), "application/javascript")
        else:
            self._send(b"not found", "text/plain")


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture()
def spa_server(request):
    """Serve the hash-routing SPA; the indirect param picks the twin."""
    safe = getattr(request, "param", False)
    handler = type("Handler", (_Base,),
                   {"app_js": SAFE_APP_JS if safe else APP_JS})
    srv = ThreadingHTTPServer(("127.0.0.1", _free_port()), handler)
    srv.timeout = 10
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _dom_available() -> bool:
    from xssentinel.core import dom_engine
    return dom_engine.DynamicDomAnalyzer.available()


needs_browser = pytest.mark.skipif(
    not _dom_available(),
    reason="playwright not installed; the browser arm of this gate cannot run")


ENGINES = ["sync", "async"]


def _collect(engine: str, url: str) -> list:
    """Scan the ORIGIN with one engine and return its finding dicts.

    Both engines get the same assertion because the Phase 209 gap was an
    engine asymmetry: async *discovered* the fragment route (its mining
    function returns it) and then examined it with the reflection layer
    alone -- a layer that cannot see a fragment, because the browser is the
    only thing that ever reads one.  Measured on Juice Shop: same target,
    sync 1 browser-executed high finding, async 0 findings over 374 requests.
    """
    if engine == "sync":
        sc = Scanner(requester=Requester(timeout=10), crawl=True, crawl_depth=1,
                     use_headless=True, crawl_engine="auto")
        sc.scan_target(url + "/")
        return [f.data or {} for f in sc.findings]

    import asyncio

    from xssentinel.core.async_scanner import AsyncScanner

    async def go():
        asc = AsyncScanner(crawl=True, crawl_depth=1, max_payloads=8,
                           advanced_layers=True)
        out = []
        async for f in asc.scan(url + "/"):
            out.append(f.data if hasattr(f, "data") else f)
        return out

    return asyncio.run(go())


@needs_browser
@pytest.mark.parametrize("engine", ENGINES)
@pytest.mark.parametrize("spa_server", [False], indirect=True)
def test_root_url_reaches_the_fragment_sink(spa_server, engine):
    """THE delivery assertion, per engine: scan the origin, hand the scanner
    no route at all."""
    found = _collect(engine, spa_server)
    hits = [f for f in found
            if f.get("type") == "dom_dynamic"
            and f.get("evidence_class") == "browser-executed"]
    routes = [str(f.get("url", "")) for f in found
              if "#/home" in str(f.get("url", ""))]
    assert hits, (
        f"[{engine}] no browser-executed DOM finding from the root URL; "
        f"routes reached: {routes}, all types: "
        f"{[f.get('type') for f in found]}")
    assert routes, f"[{engine}] the finding must sit on the fragment-routed page"
    # Phase 213: the delivered KEY rides on the finding, source-qualified.
    # The router reads `?v=` out of the fragment; no HTTP request ever sees
    # it, so the report must say `v@hash` -- not `v` (that would pretend the
    # query carried it) and not nothing (that was the pre-213 report gap:
    # the fixer could not tell which key to escape).  The raw-fragment probe
    # cannot outrun this assertion: on this page a bare `#<marker>` renders
    # an empty string, so only the named-key probe can fire the sink.
    assert all(f.get("param") == "v@hash" for f in hits), (
        f"[{engine}] fragment-delivered finding lost its delivered key: "
        f"{[f.get('param') for f in hits]}")


@needs_browser
@pytest.mark.parametrize("engine", ENGINES)
@pytest.mark.parametrize("spa_server", [True], indirect=True)
def test_safe_twin_stays_silent(spa_server, engine):
    """textContent renders the same string as TEXT -- that is not XSS, and a
    scanner that reports it here cannot be trusted on the positive case."""
    found = _collect(engine, spa_server)
    dom_hits = [f for f in found if f.get("type") == "dom_dynamic"]
    assert not dom_hits, (
        f"[{engine}] DOM finding on a textContent page: the fixture proves "
        "nothing, because the scanner would report a clean app too: "
        f"{[f.get('url') for f in dom_hits]}")
