# -*- coding: utf-8 -*-
"""Low findings that cannot be an XSS: do not emit them at all.

Two families measured on XSSMaze controls (2026-10-22), both low severity:

  * HTML markup reflected into JSON / plain text -- a browser tab renders
    neither as markup.  `callback-level1` (application/javascript) and
    `ctype-level1` (text/xml) are REAL positives through the same low
    reflected path, so those two media types must survive.
  * static DOM hints with no attacker source, and URL-property loads
    (`.src`/`.data`, inert for javascript: in modern browsers).

The dynamic engine keeps reporting real reachability/execution.
"""
import asyncio
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from xssentinel.core import document_kind as dk  # noqa: E402
from xssentinel.core.async_scanner import AsyncScanner  # noqa: E402
from xssentinel.core.findings import Finding  # noqa: E402
from xssentinel.core.requester import Requester  # noqa: E402
from xssentinel.core.scanner import Scanner  # noqa: E402

PAGES = {
    "/json": ("application/json", "<div>{q}</div>"),
    "/plain": ("text/plain", "<div>{q}</div>"),
    "/js": ("application/javascript",
            "/**/ typeof {q} === 'function' && {q}({{\"a\":1}})"),
    "/xml": ("text/xml", "<?xml version=\"1.0\"?><root>{q}</root>"),
    "/src": ("text/html",
             "<html><body><img id='i'><script>"
             "var q = new URLSearchParams(location.search).get('q');"
             "document.getElementById('i').src = q;"
             "</script></body></html>"),
    "/nosource": ("text/html",
                  "<html><body><script>"
                  "function h(x) { document.title = x; }"
                  "</script></body></html>"),
    "/inner": ("text/html",
               "<html><body><div id='o'></div><script>"
               "var q = location.search;"
               "document.getElementById('o').innerHTML = q;"
               "</script></body></html>"),
}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        parts = urlsplit(self.path)
        ctype, template = PAGES.get(parts.path, ("text/plain", "nope"))
        q = (parse_qs(parts.query).get("q") or [""])[0]
        raw = template.format(q=q).encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


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


def _scan(base, path):
    sc = Scanner(requester=Requester(timeout=8), max_payloads=3,
                 max_transforms=1, dom_engine="static")
    sc.scan_target(base + path, method="GET", params={"q": "x"}, data={},
                   oob_collect=False)
    sc.dedup()
    return [f.data for f in sc.findings]


def test_media_type_classification():
    assert dk.is_data_only_media_type("application/json")
    assert dk.is_data_only_media_type("application/json; charset=utf-8")
    assert dk.is_data_only_media_type("application/problem+json")
    assert dk.is_data_only_media_type("text/plain")
    for keep in ("application/javascript", "text/xml", "text/html", ""):
        assert not dk.is_data_only_media_type(keep), keep


@pytest.mark.parametrize("path", ["/json", "/plain"])
def test_data_only_reflection_is_not_a_finding(base, path):
    findings = _scan(base, path)
    noise = [f for f in findings
             if f.get("type") in ("reflected", "polyglot_reflection")]
    assert not noise, findings


@pytest.mark.parametrize("path", ["/js", "/xml"])
def test_script_and_xml_reflections_still_report(base, path):
    findings = _scan(base, path)
    reflected = [f for f in findings if f.get("type") == "reflected"]
    assert reflected, (
        f"{path} is a real executable vector; suppressing it would be a FN")
    assert all(f.get("severity") == "low" for f in reflected), reflected


def test_low_static_dom_hints_are_not_emitted(base):
    for path in ("/src", "/nosource"):
        findings = _scan(base, path)
        assert not [f for f in findings if f.get("type") == "dom"], (path,
                                                                     findings)


def test_a_sourced_innerhtml_hint_still_reports(base):
    findings = _scan(base, "/inner")
    dom_rows = [f for f in findings if f.get("type") == "dom"]
    assert dom_rows, "the medium static hint disappeared"
    assert all(f.get("severity") == "medium" for f in dom_rows), dom_rows


class _Cov:
    def record_finding(self, *a, **k):
        pass


class _Lock:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def _async_enqueue(finding):
    sc = object.__new__(AsyncScanner)
    sc.findings = []
    sc.coverage = _Cov()
    sc._get_lock = lambda: _Lock()
    asyncio.run(sc._add_finding(finding))
    return sc.findings


def test_async_choke_point_drops_data_only_reflections():
    data_only = Finding(type="reflected", severity="low", url="http://h/",
                        content_type="application/json")
    data_only_poly = Finding(type="polyglot_reflection", severity="low",
                             url="http://h/", content_type="text/plain")
    kept = Finding(type="reflected", severity="low", url="http://h/",
                   content_type="application/javascript")
    assert _async_enqueue(data_only) == []
    assert _async_enqueue(data_only_poly) == []
    assert _async_enqueue(kept) == [kept]
