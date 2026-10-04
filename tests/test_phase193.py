"""Phase 193: HPP probe + requires-interaction event coverage.

Two measurement additions:
  * HPP (dalfox --hpp parity): the parameter is sent twice -- first
    occurrence benign, second the payload.  A filter inspecting only the
    first occurrence passes the request while the backend renders the
    payload occurrence.  Both engines; query position this round.
  * requires-interaction handlers (pointer/mouse/clipboard/drag corpus):
    live attributes once reflected -- the headless verifier and the DOM
    engine dispatch synthetic interaction events on the token/marker-
    bearing elements, so the dialog/sink evidence can actually fire.
"""
from __future__ import annotations

import asyncio
import html
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import payloads  # noqa: E402
from xssentinel.core.dom_engine import interaction_dispatch_js  # noqa: E402
from xssentinel.core.payloads import _CROSS_CONTEXT  # noqa: E402


# ---------------------------------------------------------------------------
# corpus + dispatch builder units
# ---------------------------------------------------------------------------

def test_interaction_corpus_loads_and_is_registered():
    fam = payloads.by_context("interaction_events")
    assert len(fam) == 27
    assert "interaction_events" in payloads.contexts()
    for p in fam:
        assert "alert(1)" in (p.get("payload") or ""), p["id"]
        assert "requires_interaction" in p["tags"]


def test_interaction_corpus_covers_pointer_mouse_clipboard_drag():
    pls = " ".join(p["payload"] for p in
                   payloads.by_context("interaction_events"))
    for needle in ("onpointerdown", "onmouseup", "onmousemove",
                   "onmouseenter", "ondblclick", "onwheel", "oncopy",
                   "onpaste", "ondragstart", "ondrop", "ontouchstart",
                   "onsubmit", "onselect"):
        assert needle in pls, f"missing {needle}"


def test_both_engines_draw_interaction_events():
    pairs = dict(_CROSS_CONTEXT["html_element"])
    assert pairs.get("interaction_events") == 2


def test_dispatch_js_embeds_needle_and_event_set():
    import esprima
    js = interaction_dispatch_js("xssv_ab12cd34")
    assert '"xssv_ab12cd34"' in js
    for ev in ("pointerdown", "dblclick", "dragstart", "submit"):
        assert f'"{ev}"' in js
    esprima.parseScript(js)


# ---------------------------------------------------------------------------
# HPP, sync: a server whose "WAF" inspects only the FIRST occurrence
# ---------------------------------------------------------------------------

class _HppWafHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        u = urlparse(self.path)
        values = parse_qs(u.query, keep_blank_values=True).get("q", [])
        first = values[0] if values else ""
        if "<" in first:
            # the naive filter saw the first occurrence and neutered
            # EVERY echo of the parameter
            body = (f"<html><body><div>"
                    f"{html.escape(values[-1], quote=True) if values else ''}"
                    f"</div></body></html>").encode()
        elif u.path == "/first":
            # this backend renders the FIRST occurrence (which the filter
            # already passed because it is benign) -- the payload riding
            # the second occurrence is never rendered
            body = (f"<html><body><div>{values[0] if values else ''}"
                    f"</div></body></html>").encode()
        else:
            # /search: backend renders the LAST occurrence raw (PHP-style)
            body = (f"<html><body><div>{values[-1] if values else ''}"
                    f"</div></body></html>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture()
def hpp_site():
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _HppWafHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.2)
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def test_hpp_sync_confirms_through_first_occurrence_filter(hpp_site):
    """The standard ladder cannot confirm here: every single-occurrence
    payload carries '<' in the first (only) occurrence and is escaped.
    The duplicated request (first benign, second payload) renders raw."""
    from xssentinel.core.requester import Requester
    from xssentinel.core.scanner import Scanner

    sc = Scanner(requester=Requester(timeout=8), use_headless=False,
                 verbose=False)
    req = sc.req
    ok = sc._try_hpp(req, f"{hpp_site}/search", "GET", {"q": "probe"}, {},
                     "q", False,
                     [{"payload": "<svg onload=alert(1)>"}], "html_element")
    assert ok, "HPP did not confirm through the first-occurrence filter"
    hits = [f.data for f in sc.findings
            if "hpp" in tuple(f.data.get("transform") or [])]
    assert hits and hits[0]["type"] == "reflected"
    assert hits[0]["confidence"] == "high"
    assert "first occurrence" in hits[0]["detail"]


def test_hpp_sync_stays_silent_when_backend_takes_first(hpp_site):
    """FP guard: a backend that renders the FIRST occurrence never sees the
    payload -- the HPP probe must not confirm anything there."""
    from xssentinel.core.requester import Requester
    from xssentinel.core.scanner import Scanner

    sc = Scanner(requester=Requester(timeout=8), use_headless=False,
                 verbose=False)
    ok = sc._try_hpp(sc.req, f"{hpp_site}/first", "GET", {"q": "probe"}, {},
                     "q", False,
                     [{"payload": "<svg onload=alert(1)>"}], "html_element")
    # /first does not exist -> the handler 404s with an empty q -> nothing
    # reflects; either way no HPP finding may appear for this call.
    hits = [f.data for f in sc.findings
            if "hpp" in tuple(f.data.get("transform") or [])]
    assert not ok or not hits


def test_hpp_dedups_per_url_param(hpp_site):
    from xssentinel.core.requester import Requester
    from xssentinel.core.scanner import Scanner

    sc = Scanner(requester=Requester(timeout=8), use_headless=False,
                 verbose=False)
    base = {"payload": "<svg onload=alert(1)>"}
    first = sc._try_hpp(sc.req, f"{hpp_site}/search", "GET",
                        {"q": "probe"}, {}, "q", False, [base],
                        "html_element")
    assert first is True
    # second call for the same (url, param) must be a no-op
    assert sc._try_hpp(sc.req, f"{hpp_site}/search", "GET",
                       {"q": "probe"}, {}, "q", False, [base],
                       "html_element") is False


# ---------------------------------------------------------------------------
# HPP, async: dedicated first-occurrence-inspecting session stub
# ---------------------------------------------------------------------------

class _Resp:
    def __init__(self, text, status=200):
        self._text = text
        self.status = status
        self.headers = {"Content-Type": "text/html"}

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _FirstOccurrenceSession:
    """aiohttp stub whose filter inspects only the FIRST q occurrence."""

    def __init__(self):
        self.calls = []

    def request(self, method, url, params=None, headers=None, proxy=None,
                **kw):
        self.calls.append(params)
        pairs = params if isinstance(params, list) \
            else list((params or {}).items())
        first = next((v for k, v in pairs if k == "q"), "")
        if "<" in first:
            return _Resp("request blocked by filter")
        last = next((v for k, v in reversed(pairs) if k == "q"), "")
        return _Resp(f"<html><body><div>{last}</div></body></html>")

    def get(self, url, params=None, **kw):
        return self.request("GET", url, params=params, **kw)


def test_hpp_async_confirms_through_first_occurrence_filter():
    from xssentinel.core.async_scanner import AsyncScanner

    async def run():
        asc = AsyncScanner(max_concurrent=2, per_host_delay=0, jitter=0,
                           timeout=5, max_payloads=3, max_transforms=1,
                           advanced_layers=False)
        asc.waf_name = "generic"        # the sync gate: WAF presence
        asc._semaphore = asyncio.Semaphore(2)
        session = _FirstOccurrenceSession()
        out = []
        async for f in asc._probe_param(session, "http://t/search", "GET",
                                        "q", {"q": "probe"}, {}, False,
                                        "<html>baseline</html>"):
            out.append(f.data if hasattr(f, "data") else dict(f))
        return out

    got = asyncio.run(run())
    hpp = [d for d in got if "hpp" in tuple(d.get("transform") or [])]
    assert hpp, f"async HPP produced no finding: {[d.get('transform') for d in got]}"
    assert hpp[0]["confidence"] == "high"


# ---------------------------------------------------------------------------
# requires-interaction: real-browser confirmations
# ---------------------------------------------------------------------------

class _ReflectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        u = urlparse(self.path)
        q = (parse_qs(u.query).get("q") or [""])[0]
        body = (f"<!DOCTYPE html><html><body><div id=\"out\">"
                f"{q}</div></body></html>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def reflect_site():
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ReflectHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.2)
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def test_verify_headless_dispatches_interaction(reflect_site):
    """The feature proof: an onclick payload can only fire if something
    clicks it.  verify_headless now dispatches synthetic events on the
    token-bearing elements -- the dialog carries the token."""
    from xssentinel.core import dom_engine, verifier

    if not dom_engine.DynamicDomAnalyzer.available():
        pytest.skip("playwright/chromium not available")

    from xssentinel.core import verifier as v
    token = "xssv_" + "ab12cd34"
    marked = v.mark("<button onclick=alert(1)>x</button>", token)
    res = verifier.verify_headless(
        reflect_site + "/", "GET", {"q": marked}, None, None, token)
    assert res.get("available") is True, res
    assert res.get("confirmed") is True, res
    assert token in str(res.get("detail"))


def test_dom_engine_interaction_sink_hit():
    """DOM flow: the marker reaches an interactive element's data attribute
    (setAttribute is NOT a hooked sink), a click feeds it to innerHTML.
    The dispatch is what makes the sink fire -- the hit must carry
    via='interaction' and the finding must say so."""
    from xssentinel.core import dom_engine

    if not dom_engine.DynamicDomAnalyzer.available():
        pytest.skip("playwright/chromium not available")

    class _H(_ReflectHandler):
        pass

    def do_GET(self):
        from urllib.parse import urlparse
        u = urlparse(self.path)
        if u.path == "/dom-ia":
            body = (b"<!DOCTYPE html><html><body>"
                    b"<div id=\"out\"></div>"
                    b"<button id=b onclick=\"document.getElementById('out')"
                    b".innerHTML = this.getAttribute('data-x')\">x</button>"
                    b"<script>document.getElementById('b').setAttribute("
                    b"'data-x', decodeURIComponent("
                    b"location.hash.slice(1)));</script>"
                    b"</body></html>")
        else:
            body = b"<html><body>nf</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    _H.do_GET = do_GET
    server = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.2)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        engine = dom_engine.DynamicDomAnalyzer(timeout=15)
        findings = [f for f in engine.analyze(f"{base}/dom-ia")
                    if f.get("source") == "location.hash"]
        assert findings, "interaction-driven DOM sink was missed"
        assert any("synthetic interaction" in (f.get("detail") or "")
                   for f in findings)
    finally:
        server.shutdown()
        server.server_close()
