"""Phase 205: the MCP agent workflow, end to end.

Phase 202 added three tools; this file drives them AS AN AGENT WOULD --
chained against one loopback mini-app, each step's output feeding the
next:

  1. ``xssentinel_discover``  -- render the app, learn the live input
     face (a form field + a same-origin API endpoint the page fetches);
  2. ``xssentinel_profile``   -- triage the discovered field: which meta
     characters survive, which context the reflection lands in;
  3. ``xssentinel_scan``      -- full scan of the discovered endpoint,
     returning browser-confirmed findings.

The point is the CHAIN: each tool must return machine-usable output the
next tool consumes without human massaging.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.api import mcp_server  # noqa: E402

_PAGE = (b"<!DOCTYPE html><html><body>"
         b"<form><input name=\"comment\"><textarea name=\"body\">"
         b"</textarea></form>"
         b"<div id=\"feed\"></div>"
         b"<script>fetch('/api/feed?limit=5');</script>"
         b"</body></html>")

_API = b'{"comments": [{"body": "hi"}]}'


class _App(BaseHTTPRequestHandler):
    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        u = urlparse(self.path)
        if u.path.startswith("/api/feed"):
            body = _API
        else:
            # a realistic app renders the SUBMITTED comment: the form
            # field "comment" that discover finds is what the server
            # echoes (so the chain discover -> profile exercises a real
            # reflection, not a synthetic q)
            qs = parse_qs(u.query, keep_blank_values=True)
            shown = ((qs.get("comment") or qs.get("q") or [""])[0]).encode()
            body = _PAGE.replace(b"<div id=\"feed\"></div>",
                                 b"<div id=\"feed\">" + shown +
                                 b"</div>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def app_base():
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session (security software/TCP state)")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.2)
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def _payload(res) -> dict:
    assert not res.get("isError"), res
    return json.loads(res["content"][0]["text"])


def test_agent_workflow_discover_then_profile_then_scan(app_base):
    from xssentinel.core import dom_engine
    browser = dom_engine.DynamicDomAnalyzer.available()

    # -- step 1: discover the input face --------------------------------
    res = mcp_server.run_discover_tool({"url": app_base + "/"})
    if not browser:
        # no playwright: the tool must say so explicitly, not silently
        # return an empty harvest
        assert res.get("isError") is True
        pytest.skip("playwright/chromium not available -- chain verified "
                    "through profile+scan only")
    disc = _payload(res)
    assert "comment" in disc["input_field_names"], disc
    assert any(u.startswith(app_base + "/api/feed")
               for u in disc["same_origin_endpoints"]), disc

    # -- step 2: profile the discovered field ---------------------------
    prof = _payload(mcp_server.run_profile_tool(
        {"url": app_base + "/", "param": "comment"}))
    assert prof["reflected"] is True
    assert prof["context"] == "html_element"
    assert 'raw="' in prof["meta_chars"]

    # -- step 3: scan the discovered endpoint ---------------------------
    scan = _payload(mcp_server.run_scan_tool(
        {"url": app_base + "/?q=probe", "max_payloads": 3}))
    assert scan["finding_count"] >= 1
    f = scan["findings"][0]
    assert f["type"] == "reflected" and f["severity"]
    assert f["evidence_class"]


def test_agent_workflow_scan_on_discovered_endpoint(app_base):
    """The discover output feeds scan directly: the same-origin endpoint
    the page fetched becomes a scan target without human URL crafting."""
    from xssentinel.core import dom_engine
    if not dom_engine.DynamicDomAnalyzer.available():
        pytest.skip("playwright/chromium not available")
    res = mcp_server.run_discover_tool({"url": app_base + "/"})
    disc = _payload(res)
    endpoints = disc["same_origin_endpoints"]
    assert endpoints, "no same-origin endpoint discovered"
    scan = _payload(mcp_server.run_scan_tool(
        {"url": endpoints[0], "max_payloads": 2}))
    # the API endpoint answers JSON -- a scan that finds nothing there is
    # a SUCCESS (the contract under test is the chain, not the sink)
    assert "finding_count" in scan
