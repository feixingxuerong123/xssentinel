# -*- coding: utf-8 -*-
"""`.src` / `.data` assignments are URL loads, not HTML sinks.

`img.src = javascript:...` does not execute in any modern browser (XSSMaze
`dom-level10` is exactly that control).  The static analyzer may keep the
hint -- a javascript: iframe or a redirect chain can matter -- but without
the element type and scheme it cannot support a credible XSS claim, so the
hint is graded low.  The dynamic browser engine still reports actual
reachability/execution separately.
"""
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from xssentinel.core import dom  # noqa: E402
from xssentinel.core.requester import Requester  # noqa: E402
from xssentinel.core.scanner import Scanner  # noqa: E402

PAGE = """<html><body><img id='image'><script>
var q = new URLSearchParams(location.search).get('q');
document.getElementById('image').src = q;
</script></body></html>"""

PAGE_IFRAME = """<html><body><iframe id='frame'></iframe><script>
document.getElementById('frame').src = location.hash.substring(1);
</script></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = PAGE_IFRAME if self.path.startswith("/iframe") else PAGE
        raw = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
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


def _sink_conf(code, needle):
    return [(f.get("sink"), f.get("confidence")) for f in
            dom.analyze_script(code) if needle in (f.get("sink") or "")]


def _html_sink(html, needle):
    return [(f.get("sink"), f.get("confidence")) for f in
            dom.analyze(html, is_html=True)
            if needle in (f.get("sink") or "")]


def test_img_src_is_only_a_low_hint():
    html = ("<img id='i'><script>var q = location.search;"
            "document.getElementById('i').src = q;</script>")
    hits = _html_sink(html, ".src")
    assert hits, "the sink hint disappeared entirely"
    assert all(conf == "low" for _s, conf in hits), hits


def test_iframe_src_is_kept_at_medium():
    """XSSMaze dom-level18: iframe.src = location.hash executes javascript:.
    The tag comes from the page's id map -- a blanket URL-property cap made
    this a deterministic FN (measured 2026-10-23)."""
    html = ("<iframe id='frame'></iframe><script>"
            "document.getElementById('frame').src = location.hash.substring(1);"
            "</script>")
    hits = _html_sink(html, ".src")
    assert hits and any(conf == "medium" for _s, conf in hits), hits


def test_data_assignment_on_an_inert_element_is_low():
    html = ("<img id='x'><script>var q = location.search;"
            "document.getElementById('x').data = q;</script>")
    hits = _html_sink(html, ".data")
    assert hits, "the sink hint disappeared entirely"
    assert all(conf == "low" for _s, conf in hits), hits


def test_standalone_js_has_no_page_context_and_stays_low():
    hits = [(f.get("sink"), f.get("confidence"))
            for f in dom.analyze("var q = location.search; el.src = q;",
                                 is_html=False)
            if ".src" in (f.get("sink") or "")]
    assert hits and all(conf == "low" for _s, conf in hits), hits


def test_innerhtml_with_a_source_stays_medium():
    hits = _sink_conf("var q = location.search; el.innerHTML = q;", "innerHTML")
    assert hits and any(conf == "medium" for _s, conf in hits), hits


def test_location_href_is_not_capped_by_this_rule():
    hits = _sink_conf("var q = location.hash; location.href = q;", "location.href")
    assert hits and any(conf == "medium" for _s, conf in hits), hits


def test_scan_drops_the_url_property_hint_entirely(base):
    sc = Scanner(requester=Requester(timeout=8), max_payloads=2,
                 max_transforms=1, dom_engine="static")
    sc.scan_target(base + "/", method="GET", params={"q": "x"}, data={},
                   oob_collect=False)
    sc.dedup()
    dom_rows = [f.data for f in sc.findings if f.data.get("type") == "dom"]
    assert not dom_rows, (
        "a low URL-property hint is noise; the dynamic engine reports real "
        f"reachability separately: {dom_rows}")


def test_scan_keeps_the_iframe_hint(base):
    """dom-level18's shape: the tag-aware rule must not silence a real
    iframe src vector."""
    sc = Scanner(requester=Requester(timeout=8), max_payloads=2,
                 max_transforms=1, dom_engine="static")
    sc.scan_target(base + "/iframe", method="GET", params={"q": "x"}, data={},
                   oob_collect=False)
    sc.dedup()
    dom_rows = [f.data for f in sc.findings if f.data.get("type") == "dom"]
    assert dom_rows, "the iframe hint disappeared"
    assert any(r.get("severity") == "medium" for r in dom_rows), dom_rows
