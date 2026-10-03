# -*- coding: utf-8 -*-
"""Phase 189: source-map ingestion (input surface + disclosure).

A ``.js.map`` with ``sourcesContent`` is the un-minified source of the bundle
the browser was given: the routes a minifier renamed, the API paths it
inlined, the sinks still spelled ``element.innerHTML =``.  Both engines now
mine it, and reading one back is itself reportable.

The guards that matter here are the negative ones: a map reference pointing
off-origin is never fetched (a page choosing the URL is not an invitation to
scan somebody else), a map without sourcesContent is not a disclosure, and an
oversized or non-JSON body must not stall a crawl.
"""
import asyncio
import base64
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from tests.conftest import loopback_healthy  # noqa: E402
from xssentinel.core import js_miner, sourcemap  # noqa: E402
from xssentinel.core.scanner_crawl import CrawlMixin  # noqa: E402

MAP = {
    "version": 3,
    "sources": ["webpack:///src/routes.js", "webpack:///src/widget.js"],
    "sourcesContent": [
        "const r = {path: '/api/v1/orders'}; fetch('/api/v1/orders');",
        "function render(u){ document.getElementById('o').innerHTML = u; }",
    ],
    "mappings": "AAAA",
}
MAP_TEXT = json.dumps(MAP)


# ---------------------------------------------------------------------------
# reference discovery
# ---------------------------------------------------------------------------
def test_relative_reference_resolves_against_the_script_url():
    urls = sourcemap.map_urls("https://app.example/static/app.min.js",
                              "var x=1;\n//# sourceMappingURL=app.min.js.map\n")
    assert urls == ["https://app.example/static/app.min.js.map"]


def test_legacy_and_block_comment_forms_and_absolute_paths():
    assert sourcemap.map_urls("https://a/x/y.js", "/*# sourceMappingURL=/maps/y.js.map */")[0] \
        == "https://a/maps/y.js.map"
    assert sourcemap.map_urls("https://a/y.js", "//@ sourceMappingURL=https://a/z.js.map")[0] \
        == "https://a/z.js.map"


def test_non_http_and_bogus_references_are_dropped():
    assert sourcemap.map_urls("https://a/y.js", "//# sourceMappingURL=file:///etc/passwd") == []
    assert sourcemap.map_urls("https://a/y.js", "sourceMappingURL=not-a-comment.map") == []


def test_reference_count_is_capped():
    text = "\n".join(f"//# sourceMappingURL=m{i}.js.map" for i in range(6))
    assert len(sourcemap.map_urls("https://a/y.js", text)) == sourcemap.MAX_MAPS_PER_SCRIPT


def test_inline_data_uri_map_needs_no_request():
    payload = base64.b64encode(MAP_TEXT.encode()).decode()
    text = f"//# sourceMappingURL=data:application/json;charset=utf-8;base64,{payload}"
    assert sourcemap.map_urls("https://a/y.js", text) == []
    assert sourcemap.analyze_map(sourcemap.inline_map(text))["has_content"]


# ---------------------------------------------------------------------------
# map judgement
# ---------------------------------------------------------------------------
def test_readable_map_yields_original_sources():
    res = sourcemap.analyze_map(MAP_TEXT)
    assert res["ok"] and res["has_content"] and res["sources"] == 2
    assert "/api/v1/orders" in res["js"]


def test_map_without_sources_content_is_not_a_disclosure():
    res = sourcemap.analyze_map(json.dumps({"version": 3, "sources": ["a.js"]}))
    assert res["ok"] and not res["has_content"] and res["js"] == ""
    assert sourcemap.disclosure("https://a/y.js.map", res) is None


def test_broken_bodies_are_judged_not_raised():
    for body in ("", "<html>404</html>", "[1,2,3]", '{"sourcesContent": ["x"'):
        assert sourcemap.analyze_map(body)["ok"] is False, body


def test_oversized_map_is_refused_before_parsing():
    res = sourcemap.analyze_map("x" * (sourcemap.MAX_MAP_BYTES + 10))
    assert res["ok"] is False and "bytes" in res["reason"]


def test_disclosure_fields():
    fields = sourcemap.disclosure("https://a/app.min.js.map",
                                  sourcemap.analyze_map(MAP_TEXT))
    assert fields["type"] == "source_map_exposed"
    assert fields["severity"] == "low"
    assert fields["evidence_class"] == "browser-unavailable"
    assert "app.min.js.map" in fields["detail"]


# ---------------------------------------------------------------------------
# the sync crawl wiring, against a real server
# ---------------------------------------------------------------------------
class _Harness:
    """Minimal stand-in for the Scanner attributes the mixin method touches."""

    def __init__(self, requester):
        self.req = requester
        self.bumps = 0
        self.added = []
        self.recorded = []
        self.coverage = self

    def _bump(self):
        self.bumps += 1

    def _add(self, finding):
        self.added.append(finding)

    def record_finding(self, url, method):
        self.recorded.append((url, method))

    def touch_layer(self, *a, **kw):
        pass


class _FakeResponse:
    def __init__(self, text):
        self.text = text


class _RecordingRequester:
    def __init__(self, bodies):
        self.bodies = bodies
        self.seen = []

    def get(self, url, **kw):
        self.seen.append(url)
        if url not in self.bodies:
            raise OSError("connection refused")
        return _FakeResponse(self.bodies[url])


def test_sync_pass_mines_the_source_and_reports_once():
    req = _RecordingRequester({"https://a/static/app.min.js.map": MAP_TEXT})
    h = _Harness(req)
    endpoints = CrawlMixin._mine_source_maps(
        h, "https://a/static/app.min.js",
        "//# sourceMappingURL=app.min.js.map")
    assert endpoints, "the un-minified source must feed the miner"
    assert any("/api/v1/orders" in ep[0] for ep in endpoints), endpoints
    assert len(h.added) == 1 and h.added[0].data["type"] == "source_map_exposed"
    assert h.recorded == [("https://a/static/app.min.js", "GET")]


def test_sync_pass_never_fetches_an_off_origin_map():
    req = _RecordingRequester({})
    h = _Harness(req)
    out = CrawlMixin._mine_source_maps(
        h, "https://a/app.min.js",
        "//# sourceMappingURL=https://evil.example/x.js.map")
    assert out == [] and req.seen == [] and h.added == []


def test_sync_pass_survives_a_dead_map_url():
    req = _RecordingRequester({})       # every fetch blows up
    h = _Harness(req)
    assert CrawlMixin._mine_source_maps(
        h, "https://a/app.min.js", "//# sourceMappingURL=missing.js.map") == []
    assert h.added == []


def test_mined_source_actually_reaches_the_endpoint_miner():
    """The point of the whole exercise: a route only present in the source."""
    assert js_miner.mine_js_file(MAP["sourcesContent"][0])["endpoints"]


# ---------------------------------------------------------------------------
# the async wiring
# ---------------------------------------------------------------------------
def _bare_async_scanner(requester):
    from xssentinel.core.async_scanner import AsyncScanner

    sc = AsyncScanner.__new__(AsyncScanner)
    sc.verbose = False
    sc.requests_made = 0
    sc.headers, sc.cookies = {}, None
    sc._get_sync_requester = lambda: requester

    async def _throttle(url):
        return None

    sc._throttle = _throttle
    return sc


def test_async_pass_mines_and_collects_the_finding():
    req = _RecordingRequester({"https://a/static/app.min.js.map": MAP_TEXT})
    sc = _bare_async_scanner(req)
    found = []

    async def go():
        return await sc._mine_source_maps(
            "https://a/static/app.min.js", "//# sourceMappingURL=app.min.js.map",
            found)

    endpoints = asyncio.run(go())
    assert endpoints and req.seen == ["https://a/static/app.min.js.map"]
    assert len(found) == 1 and found[0].data["type"] == "source_map_exposed"


def test_async_pass_skips_off_origin_and_reports_budget_stops():
    from xssentinel.core.budget import BudgetExhausted

    req = _RecordingRequester({})
    sc = _bare_async_scanner(req)

    async def go():
        return await sc._mine_source_maps(
            "https://a/app.min.js",
            "//# sourceMappingURL=https://other.example/x.js.map", [])

    assert asyncio.run(go()) == [] and req.seen == []

    class _Budgeted:
        def get(self, url, **kw):
            raise BudgetExhausted("cap")

    sc2 = _bare_async_scanner(_Budgeted())

    async def go2():
        await sc2._mine_source_maps(
            "https://a/app.min.js", "//# sourceMappingURL=m.js.map", [])

    with pytest.raises(BudgetExhausted):
        asyncio.run(go2())


# ---------------------------------------------------------------------------
# one real round trip, both halves
# ---------------------------------------------------------------------------
def test_end_to_end_over_real_http():
    if not loopback_healthy():
        pytest.skip("loopback degraded on this host")
    served = {
        "/static/app.min.js": ("application/javascript",
                               "var a=1;//# sourceMappingURL=app.min.js.map\n"),
        "/static/app.min.js.map": ("application/json", MAP_TEXT),
    }

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            body = served.get(self.path)
            if not body:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", body[0])
            self.send_header("Content-Length", str(len(body[1])))
            self.end_headers()
            self.wfile.write(body[1].encode())

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        from xssentinel.core.requester import Requester

        req = Requester(timeout=5)
        h = _Harness(req)
        script = f"{base}/static/app.min.js"
        js_text = req.get(script).text
        found = CrawlMixin._mine_source_maps(h, script, js_text)
        assert found, "routes present only in sourcesContent were recovered"
        assert len(h.added) == 1
        assert h.added[0].data["evidence"] == f"{base}/static/app.min.js.map"
    finally:
        srv.shutdown()
        srv.server_close()
