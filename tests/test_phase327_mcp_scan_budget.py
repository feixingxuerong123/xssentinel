# -*- coding: utf-8 -*-
"""Phase 327: bounded MCP tool calls -- fast-fail on unreachable targets
and a wall-clock budget for ``xssentinel_scan``.

The recorded defect (Phase 324 ledger): a scan against a host whose port
is filtered/black-holed pays a full TCP SYN timeout per request --
measured ~6 s per attempt on this host -- and parameter mining starts
with hundreds of them, so ONE tool call could run for tens of minutes
and the agent saw a call that never returned.  Two bounds now exist:

  * a short pre-flight connection (connect failures only -- a slow but
    reachable server is NOT declared unreachable);
  * ``max_seconds`` on the scan tool (default 300): the run stops at the
    next request and returns an honest ``isError`` carrying the reason.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests.exceptions as rexc                            # noqa: E402

from xssentinel.api import mcp_server                          # noqa: E402
from xssentinel.api.mcp_server import (                        # noqa: E402
    _RequestGuard, _ToolTimeout, _tool_call, _preflight)


# ---------------------------------------------------------------------------
# 1. the pre-flight classifier
# ---------------------------------------------------------------------------
class _RaisingRequester:
    def __init__(self, exc):
        self._exc = exc

    def request(self, method, url, *a, **kw):
        raise self._exc


def _patch_build_requester(monkeypatch, requester):
    monkeypatch.setattr(
        "xssentinel.api.server._build_requester",
        lambda options: requester)


def test_connection_failure_is_unreachable(monkeypatch):
    _patch_build_requester(
        monkeypatch,
        _RaisingRequester(rexc.ConnectionError("connection refused")))
    err = _preflight({"url": "http://t/"}, "http://t/")
    assert err and "unreachable" in err, err
    assert "no probe storm" in err


def test_connect_timeout_is_unreachable(monkeypatch):
    _patch_build_requester(
        monkeypatch,
        _RaisingRequester(rexc.ConnectTimeout("connect timed out")))
    err = _preflight({}, "http://t/")
    assert err and "unreachable" in err, err


def test_read_timeout_is_NOT_unreachable(monkeypatch):
    """A slow-but-working server proves reachability; diagnosing it as
    unreachable would be a false statement about the target."""
    _patch_build_requester(
        monkeypatch,
        _RaisingRequester(rexc.ReadTimeout("slow body")))
    assert _preflight({}, "http://t/") is None


def test_http_status_errors_are_reachable(monkeypatch):
    class _Resp:
        status_code = 500

        def request(self, method, url, *a, **kw):
            return self

    _patch_build_requester(monkeypatch, _Resp())
    assert _preflight({}, "http://t/") is None


# ---------------------------------------------------------------------------
# 2. the deadline
# ---------------------------------------------------------------------------
def test_deadline_raises_the_base_exception_timeout():
    class _Inner:
        def request(self, *a, **kw):
            return "resp"

    guard = _RequestGuard(_Inner(), deadline=time.monotonic() - 1)
    try:
        guard.request("GET", "http://t/")
        raise AssertionError("guard must raise once the budget is spent")
    except _ToolTimeout as e:
        assert not isinstance(e, Exception)
        assert "budget" in str(e)


def test_live_scan_still_returns_the_normal_result():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            from urllib.parse import parse_qs, urlparse
            q = (parse_qs(urlparse(self.path).query).get("q") or [""])[0]
            body = ("<html><body><div id='o'>" + q + "</div></body></html>")\
                .encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        result = _tool_call({"name": "xssentinel_scan",
                             "arguments": {"url": base + "/?q=probe",
                                           "max_payloads": 3}})
        assert not result.get("isError"), result
        payload = json.loads(result["content"][0]["text"])
        assert payload["finding_count"] >= 1, payload
        assert result["structuredContent"] == payload
    finally:
        srv.shutdown()
        srv.server_close()


def test_scan_budget_overrun_is_a_visible_error(monkeypatch):
    """When the budget expires, ``_tool_call`` must answer with an
    ``isError`` carrying the reason -- silence would read as 'clean'."""
    class _Inner:
        def request(self, *a, **kw):
            return "resp"

    def fake_make(args, cancel_event=None, emit=None,
                  default_timeout=15, deadline=None):
        assert deadline is not None, "scan must pass a deadline"
        lead = deadline - time.monotonic()
        assert lead > 0, lead
        return _RequestGuard(_Inner(), cancel_event, emit,
                             deadline=time.monotonic() - 1)

    monkeypatch.setattr(mcp_server, "_preflight", lambda *a, **k: None)
    monkeypatch.setattr(mcp_server, "_make_requester", fake_make)
    result = _tool_call({"name": "xssentinel_scan",
                         "arguments": {"url": "http://t/",
                                       "max_seconds": 5}})
    assert result.get("isError") is True, result
    assert "budget" in result["content"][0]["text"], result


def test_param_mine_preflight_short_circuits(monkeypatch):
    monkeypatch.setattr(mcp_server, "_preflight",
                        lambda *a, **k: "target unreachable: ConnectionError")
    result = mcp_server.run_param_mine_tool({"url": "http://t/"})
    assert result.get("isError") is True
    assert "unreachable" in result["content"][0]["text"]


def test_scan_schema_exposes_max_seconds():
    prop = mcp_server._TOOL_SCAN_SCHEMA["properties"]["max_seconds"]
    assert prop["type"] == "integer"
    assert prop["default"] == 300
    assert (prop["minimum"], prop["maximum"]) == (5, 3600)


# ---------------------------------------------------------------------------
# 3. the real wire form: a filtered port fails in seconds, not minutes
# ---------------------------------------------------------------------------
def test_scan_against_a_blackholed_port_fails_fast():
    """Port 1 on loopback: no listener, and on a filtering host the
    connect() stalls until the short pre-flight timeout fires.  Either
    way the call must come back fast with an explicit error."""
    t0 = time.monotonic()
    result = mcp_server.run_scan_tool({"url": "http://127.0.0.1:1/",
                                       "timeout": 3, "max_seconds": 30})
    elapsed = time.monotonic() - t0
    assert result.get("isError") is True, result
    text = result["content"][0]["text"]
    assert ("unreachable" in text) or ("scan failed" in text), text
    assert elapsed < 30, elapsed
