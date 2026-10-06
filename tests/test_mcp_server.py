"""Phase 189: MCP stdio server (dalfox v3 parity).

Three layers:
  * protocol unit tests through injectable streams (handshake, catalogue,
    error codes, notification silence);
  * ``run_scan_tool`` against a loopback reflected-XSS page (verdicts and
    compact shapes);
  * a REAL subprocess e2e: ``python -m xssentinel --mcp`` speaking the
    protocol over actual stdio, scanning a loopback target.
"""
from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.api import mcp_server  # noqa: E402
from xssentinel.api.mcp_server import MCPServer  # noqa: E402


def _session(server: MCPServer, *msgs: dict) -> list[dict]:
    """Feed messages, return the responses (one per request sent)."""
    import io
    inn = io.StringIO("".join(json.dumps(m) + "\n" for m in msgs))
    out = io.StringIO()
    server._stdin, server._stdout = inn, out
    server.serve()
    return [json.loads(ln) for ln in out.getvalue().splitlines()]


REQ = {"jsonrpc": "2.0", "id": 1}


class TestProtocol:
    def test_initialize_echoes_supported_version(self):
        (resp,) = _session(MCPServer(), {**REQ, "method": "initialize",
                                         "params": {"protocolVersion":
                                                    "2025-03-26"}})
        assert resp["result"]["protocolVersion"] == "2025-03-26"
        assert resp["result"]["capabilities"] == {"tools": {}}
        assert resp["result"]["serverInfo"]["name"] == "xssentinel"

    def test_initialize_unknown_version_gets_latest(self):
        (resp,) = _session(MCPServer(), {**REQ, "method": "initialize",
                                         "params": {"protocolVersion":
                                                    "1999-01-01"}})
        assert resp["result"]["protocolVersion"] == \
            mcp_server.LATEST_PROTOCOL_VERSION

    def test_tools_list_catalogue(self):
        (resp,) = _session(MCPServer(), {**REQ, "method": "tools/list"})
        tools = resp["result"]["tools"]
        assert [t["name"] for t in tools] == ["xssentinel_scan",
                                              "xssentinel_discover",
                                              "xssentinel_profile"]
        assert tools[0]["inputSchema"]["required"] == ["url"]
        assert tools[2]["inputSchema"]["required"] == ["url", "param"]

    def test_ping_and_notification_silence(self):
        resps = _session(MCPServer(),
                         {**REQ, "method": "ping"},
                         {"jsonrpc": "2.0", "method": "notifications/initialized"})
        # the notification produced NO response line
        assert len(resps) == 1 and resps[0]["result"] == {}

    def test_unknown_method_is_32601(self):
        (resp,) = _session(MCPServer(), {**REQ, "method": "resources/list"})
        assert resp["error"]["code"] == -32601

    def test_bad_json_is_32700(self):
        srv = MCPServer()
        import io
        srv._stdin = io.StringIO("{not json}\n")
        out = io.StringIO()
        srv._stdout = out
        srv.serve()
        (resp,) = [json.loads(line) for line in out.getvalue().splitlines()]
        assert resp["error"]["code"] == -32700

    def test_non_object_request_is_32600(self):
        (resp,) = _session(MCPServer(), [1, 2, 3])
        assert resp["error"]["code"] == -32600

    def test_unknown_tool_is_error_content(self):
        (resp,) = _session(MCPServer(), {**REQ, "method": "tools/call",
                                         "params": {"name": "nope",
                                                    "arguments": {}}})
        assert resp["result"]["isError"] is True
        assert "unknown tool" in resp["result"]["content"][0]["text"]


# ---------------------------------------------------------------------------
# run_profile_tool / run_discover_tool against loopback pages
# ---------------------------------------------------------------------------

class TestProfileTool:
    def test_full_reflection_profiles_cleanly(self):
        from tests.conftest import loopback_healthy
        if not loopback_healthy():
            import pytest
            pytest.skip("loopback degraded mid-session")
        server = ThreadingHTTPServer(("127.0.0.1", 0), _XssHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        time.sleep(0.2)
        base = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            res = mcp_server.run_profile_tool({"url": base + "/",
                                               "param": "q"})
            assert not res.get("isError")
            payload = json.loads(res["content"][0]["text"])
            assert payload["reflected"] is True
            assert payload["context"] == "html_element"
            assert payload["full_reflection"] is True
            # every probed meta char came back RAW
            assert 'raw="' in payload["meta_chars"]
            assert "stripped=" not in payload["meta_chars"]
        finally:
            server.shutdown()
            server.server_close()

    def test_profile_requires_url_and_param(self):
        res = mcp_server.run_profile_tool({"url": "http://t/"})
        assert res.get("isError") is True


# ---------------------------------------------------------------------------
# run_scan_tool against a loopback reflected-XSS page
# ---------------------------------------------------------------------------

class _XssHandler(BaseHTTPRequestHandler):
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


def test_run_scan_tool_finds_and_compacts():
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        import pytest
        pytest.skip("loopback degraded mid-session")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _XssHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.2)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        res = mcp_server.run_scan_tool({"url": base + "/?q=probe",
                                        "max_payloads": 2})
        assert not res.get("isError")
        payload = json.loads(res["content"][0]["text"])
        assert payload["finding_count"] >= 1
        f = payload["findings"][0]
        # compact shape: verdict fields present, delivery machinery absent
        assert "proof" not in f
        assert f["severity"] and f["evidence_class"]
        assert len(payload["findings"]) <= mcp_server._MAX_FINDINGS
    finally:
        server.shutdown()
        server.server_close()


def test_run_scan_tool_rejects_bad_url():
    res = mcp_server.run_scan_tool({"url": "not a url"})
    assert res.get("isError") is True
    res = mcp_server.run_scan_tool({"url": ""})
    assert res.get("isError") is True


# ---------------------------------------------------------------------------
# real subprocess stdio e2e
# ---------------------------------------------------------------------------

def test_mcp_subprocess_end_to_end():
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        import pytest
        pytest.skip("loopback degraded mid-session")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _XssHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.2)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        proc = subprocess.Popen(
            [sys.executable, "-m", "xssentinel", "--mcp"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, encoding="utf-8",
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        qout: queue.Queue = queue.Queue()
        threading.Thread(target=lambda: [qout.put(ln) for ln in proc.stdout],
                         daemon=True).start()
        try:
            proc.stdin.write(json.dumps(
                {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                 "params": {"protocolVersion": "2025-06-18"}}) + "\n")
            proc.stdin.write(json.dumps(
                {"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            proc.stdin.write(json.dumps(
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                 "params": {"name": "xssentinel_scan",
                            "arguments": {"url": base + "/?q=probe",
                                          "max_payloads": 2}}}) + "\n")
            proc.stdin.flush()
            init = json.loads(qout.get(timeout=60))
            assert init["result"]["protocolVersion"] == "2025-06-18"
            call = json.loads(qout.get(timeout=120))
            result = call["result"]
            assert not result.get("isError")
            payload = json.loads(result["content"][0]["text"])
            assert payload["finding_count"] >= 1
            assert payload["findings"][0]["type"] == "reflected"
        finally:
            proc.kill()
    finally:
        server.shutdown()
        server.server_close()
