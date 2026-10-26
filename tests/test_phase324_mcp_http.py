# -*- coding: utf-8 -*-
"""Phase 324: MCP remote surface -- structuredContent/outputSchema and the
Streamable HTTP transport on the ``--serve`` API.

Two gaps from the trend analysis (docs/TRENDING_20261026.md, P1):

  * 缺口 2 -- text-only tool results: agents had to re-parse truncated
    text.  Every tool now declares ``outputSchema`` and every SUCCESS
    result carries ``structuredContent`` with the SAME payload (text
    content is byte-identical to before; error results stay text-only).
  * 缺口 1 -- stdio-only transport: agent platforms that attach tools by
    URL (ARTEX / Claude / Cursor style) could not reach us.  ``POST /mcp``
    now speaks the same JSON-RPC dispatch the stdio mode serves, with the
    API server's ``--api-key`` and the shared same-origin gate applied.

The transport tests run a REAL ``StdlibServer`` on loopback and speak
HTTP through urllib; the dispatch-equivalence test pins that stdio and
HTTP cannot answer differently (they share ``dispatch_message``).
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.api import mcp_server                          # noqa: E402
from xssentinel.api.mcp_server import MCPServer, dispatch_message  # noqa: E402
from xssentinel.api.server import StdlibServer                  # noqa: E402

REQ = {"jsonrpc": "2.0", "id": 1}


# ---------------------------------------------------------------------------
# harness: session over injectable streams (same as test_mcp_server)
# ---------------------------------------------------------------------------
def _session(server: MCPServer, *msgs: dict) -> list[dict]:
    import io
    inn = io.StringIO("".join(json.dumps(m) + "\n" for m in msgs))
    out = io.StringIO()
    server._stdin, server._stdout = inn, out
    server.serve()
    return [json.loads(ln) for ln in out.getvalue().splitlines()]


class _Http:
    def __init__(self, base_url: str, api_key: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def post(self, path: str, body, headers: dict | None = None):
        hdrs = {"Accept": "application/json"}
        if self.api_key:
            hdrs["X-API-Key"] = self.api_key
        hdrs.update(headers or {})
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        if not isinstance(body, bytes):
            hdrs["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base_url + path, data=data,
                                     method="POST", headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.status, resp.read().decode("utf-8"), dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8"), dict(e.headers)

    def get(self, path: str):
        req = urllib.request.Request(self.base_url + path,
                                     headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read().decode("utf-8"), dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8"), dict(e.headers)

    def delete(self, path: str):
        req = urllib.request.Request(self.base_url + path, method="DELETE")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read().decode("utf-8"), dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8"), dict(e.headers)


class _XssHandler(BaseHTTPRequestHandler):
    """Loopback page that reflects the q parameter (scan target)."""

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


def _loopback_target():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _XssHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.2)
    return server, f"http://127.0.0.1:{server.server_address[1]}"


# ---------------------------------------------------------------------------
# 1. structuredContent / outputSchema
# ---------------------------------------------------------------------------
def test_success_result_carries_structured_content():
    srv, base = _loopback_target()
    try:
        res = dispatch_message({**REQ, "method": "tools/call", "params": {
            "name": "xssentinel_profile",
            "arguments": {"url": base + "/", "param": "q"}}})
        result = res["result"]
        assert not result.get("isError"), result
        text_payload = json.loads(result["content"][0]["text"])
        # structuredContent is the SAME object the text serializes
        assert result["structuredContent"] == text_payload
        assert result["structuredContent"]["reflected"] is True
    finally:
        srv.shutdown()
        srv.server_close()


def test_error_result_has_no_structured_content():
    # A fast error path on purpose: scanning an unreachable-but-filtered
    # port costs a full TCP SYN timeout per request on Windows (~21s each,
    # measured), and this test is about the result SHAPE, not scan speed.
    res = dispatch_message({**REQ, "method": "tools/call", "params": {
        "name": "xssentinel_scan", "arguments": {"url": "not-a-url",
                                                  "cookie": {}}}})
    result = res["result"]
    assert result["isError"] is True
    assert "structuredContent" not in result


def test_every_catalogue_entry_declares_an_output_schema():
    for tool in mcp_server.TOOL_DEFINITIONS:
        schema = tool.get("outputSchema")
        assert isinstance(schema, dict), tool["name"]
        assert schema.get("type") == "object", tool["name"]
        assert schema.get("properties"), tool["name"]
        # the table and the catalogue agree on which schema belongs where
        assert schema is mcp_server._TOOL_OUTPUT_SCHEMAS[tool["name"]], \
            tool["name"]


def test_stdio_and_dispatch_cannot_diverge():
    """The stdio serve() path must answer through dispatch_message -- one
    implementation, so the HTTP transport cannot drift from it."""
    (via_class,) = _session(MCPServer(), {**REQ, "method": "ping"})
    assert via_class == dispatch_message({**REQ, "method": "ping"})
    import inspect
    src = inspect.getsource(MCPServer._handle)
    assert "dispatch_message" in src, \
        "MCPServer._handle must delegate to dispatch_message"


# ---------------------------------------------------------------------------
# 2. HTTP transport: protocol surface
# ---------------------------------------------------------------------------
def test_initialize_over_http():
    server = StdlibServer(host="127.0.0.1", port=0)
    server.start_in_thread()
    try:
        status, body, _ = _Http(server.base_url).post(
            "/mcp", {**REQ, "method": "initialize",
                     "params": {"protocolVersion": "2025-06-18"}})
        assert status == 200
        data = json.loads(body)
        assert data["result"]["protocolVersion"] == "2025-06-18"
        assert data["result"]["serverInfo"]["name"] == "xssentinel"
    finally:
        server.shutdown()


def test_tools_list_over_http_includes_output_schemas():
    server = StdlibServer(host="127.0.0.1", port=0)
    server.start_in_thread()
    try:
        status, body, _ = _Http(server.base_url).post(
            "/mcp", {**REQ, "method": "tools/list"})
        assert status == 200
        tools = json.loads(body)["result"]["tools"]
        assert len(tools) == 7
        for t in tools:
            assert t["inputSchema"]
            assert t["outputSchema"], t["name"]
    finally:
        server.shutdown()


def test_scan_over_http_matches_the_stdio_contract():
    srv, base = _loopback_target()
    server = StdlibServer(host="127.0.0.1", port=0)
    server.start_in_thread()
    try:
        status, body, _ = _Http(server.base_url).post(
            "/mcp", {**REQ, "method": "tools/call", "params": {
                "name": "xssentinel_scan",
                "arguments": {"url": base + "/?q=probe",
                              "max_payloads": 3}}})
        assert status == 200
        result = json.loads(body)["result"]
        assert not result.get("isError"), result
        payload = json.loads(result["content"][0]["text"])
        assert payload["finding_count"] >= 1, payload
        assert result["structuredContent"] == payload
    finally:
        server.shutdown()
        srv.shutdown()
        srv.server_close()


def test_batch_returns_one_response_per_request():
    server = StdlibServer(host="127.0.0.1", port=0)
    server.start_in_thread()
    try:
        status, body, _ = _Http(server.base_url).post(
            "/mcp", [{**REQ, "method": "initialize",
                      "params": {"protocolVersion": "2025-03-26"}},
                     {"jsonrpc": "2.0", "id": 2, "method": "ping"}])
        assert status == 200
        resp = json.loads(body)
        assert isinstance(resp, list) and len(resp) == 2
        assert resp[0]["id"] == 1 and resp[0]["result"]["protocolVersion"] == \
            "2025-03-26"
        assert resp[1] == {"jsonrpc": "2.0", "id": 2, "result": {}}
    finally:
        server.shutdown()


def test_notifications_only_batch_is_accepted_without_body():
    server = StdlibServer(host="127.0.0.1", port=0)
    server.start_in_thread()
    try:
        status, body, _ = _Http(server.base_url).post(
            "/mcp", [{"jsonrpc": "2.0",
                      "method": "notifications/initialized"}])
        assert status == 202, (status, body)
        assert body == ""
    finally:
        server.shutdown()


def test_malformed_json_is_a_jsonrpc_parse_error_not_http_400():
    server = StdlibServer(host="127.0.0.1", port=0)
    server.start_in_thread()
    try:
        status, body, _ = _Http(server.base_url).post("/mcp", b"{not json}")
        assert status == 200, (status, body)
        data = json.loads(body)
        assert data["error"]["code"] == -32700
    finally:
        server.shutdown()


def test_get_and_delete_mcp_are_405():
    server = StdlibServer(host="127.0.0.1", port=0)
    server.start_in_thread()
    try:
        client = _Http(server.base_url)
        for method in (client.get, client.delete):
            status, body, headers = method("/mcp")
            assert status == 405, (status, body)
            assert headers.get("Allow") == "POST", headers
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# 3. HTTP transport: the security layers apply (no new open door)
# ---------------------------------------------------------------------------
def test_api_key_is_enforced_on_mcp():
    server = StdlibServer(host="127.0.0.1", port=0, api_key="secret123")
    server.start_in_thread()
    try:
        status, _, _ = _Http(server.base_url).post("/mcp", {**REQ,
                                                            "method": "ping"})
        assert status == 401
        status, body, _ = _Http(server.base_url, api_key="secret123").post(
            "/mcp", {**REQ, "method": "ping"})
        assert status == 200
        assert json.loads(body)["result"] == {}
    finally:
        server.shutdown()


def test_cross_origin_post_is_blocked_like_every_other_mutating_route():
    """The shared same-origin gate (Phase 70/196) must cover /mcp too --
    otherwise the newest endpoint would be the one hole in the wall."""
    server = StdlibServer(host="127.0.0.1", port=0)
    server.start_in_thread()
    try:
        status, body, _ = _Http(server.base_url).post(
            "/mcp", {**REQ, "method": "ping"},
            headers={"Origin": "http://evil.example"})
        assert status == 403, (status, body)
        assert "cross_origin_blocked" in body
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# 4. Flask front-end parity (skipped when Flask is not installed)
# ---------------------------------------------------------------------------
def test_flask_front_end_registers_mcp():
    """The Flask front-end must expose the SAME /mcp endpoint.

    Scope note: this environment's Flask/werkzeug pair breaks
    ``FlaskClient`` (``werkzeug.__version__`` was removed upstream, Flask
    still reads it), so the round trip is verified on the stdlib front-end
    above -- where it exercises the SAME ``_handle_mcp`` handler -- and
    this test pins the Flask-side route registration that makes the
    handler reachable.
    """
    try:
        import flask  # noqa: F401
    except ImportError:
        import pytest
        pytest.skip("Flask not installed")
    from xssentinel.api.server import FlaskServer
    srv = FlaskServer(api_key="k")
    rules = {(r.rule, m) for r in srv.app.url_map.iter_rules()
             for m in r.methods if m in ("GET", "POST", "DELETE")}
    assert ("/mcp", "POST") in rules, rules
    # GET/DELETE answer 405 through the same unsupported handler
    assert ("/mcp", "GET") in rules, rules
    assert ("/mcp", "DELETE") in rules, rules
