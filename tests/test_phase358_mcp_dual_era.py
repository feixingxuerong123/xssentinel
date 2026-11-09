# -*- coding: utf-8 -*-
"""Phase 358: XSSentinel must be attachable by BOTH eras of MCP clients.

Measured gaps before this change (2026-11-05, this tree):

  * the current MCP revision is 2026-07-28 -- stateless, no ``initialize``
    handshake, mandatory ``server/discover``, per-request version in
    ``_meta`` -- while the server only advertised ...2025-06-18.  A
    ``server/discover`` probe got -32601, so a modern-only agent CLI could
    not attach at all, and a declared version of ``1900-01-01`` was silently
    accepted instead of answered with UnsupportedProtocolVersionError.
  * ``MCPServer._write`` used ``ensure_ascii=False`` on a TEXT stdout.  On
    Windows the console codepage is cp936/gbk, so any non-ASCII byte copied
    from a target (evidence, param names) raised UnicodeEncodeError and the
    client waited forever for a frame that never arrived.  Measured with a
    cp936 TextIOWrapper around BytesIO.

The fix is a "dual-era" server: legacy frames keep byte-for-byte the
responses shipped since Phase 189; frames declaring a modern version get
the 2026 shape.  These tests pin BOTH sides, plus the stdio UTF-8 channel
and the HTTP transport-level status codes.  Protocol facts come from
https://modelcontextprotocol.io/specification/2026-07-28/ (versioning,
server/discover, streamable-http).
"""
from __future__ import annotations

import io
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.test_phase324_mcp_http import _Http  # noqa: E402
from xssentinel.api import mcp_server as m  # noqa: E402
from xssentinel.api.mcp_server import MCPServer, dispatch_message  # noqa: E402
from xssentinel.api.server import StdlibServer  # noqa: E402

REQ = {"jsonrpc": "2.0", "id": 1}
MODERN = "2026-07-28"
LEGACY = "2025-06-18"


def _meta(version=MODERN):
    return {"_meta": {
        "io.modelcontextprotocol/protocolVersion": version,
        "io.modelcontextprotocol/clientInfo": {"name": "agent-cli",
                                               "version": "1.0"},
        "io.modelcontextprotocol/clientCapabilities": {},
    }}


def _modern(method, params=None, version=MODERN):
    p = _meta(version)
    p.update(params or {})
    return {**REQ, "method": method, "params": p}


# ---------------------------------------------------------------------------
# 1. discovery + era selection
# ---------------------------------------------------------------------------

def test_discover_advertises_both_eras():
    res = dispatch_message(_modern("server/discover"))["result"]
    assert res["resultType"] == "complete"
    assert MODERN in res["supportedVersions"]
    assert LEGACY in res["supportedVersions"]
    assert "2025-11-25" in res["supportedVersions"]
    assert res["capabilities"] == {"tools": {}}
    assert res["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] \
        == "xssentinel"
    assert res["ttlMs"] > 0 and res["cacheScope"] in ("public", "private")


def test_discover_without_meta_is_still_the_stdio_probe():
    """A stdio era probe may carry no version; it must not look like a
    legacy -32601 (that would make a dual-era client fall back to a
    handshake we would then happily serve -- confusing but not fatal)."""
    res = dispatch_message({**REQ, "method": "server/discover"})["result"]
    assert res["resultType"] == "complete"
    assert MODERN in res["supportedVersions"]


def test_legacy_initialize_shape_is_unchanged():
    res = dispatch_message({**REQ, "method": "initialize",
                            "params": {"protocolVersion": LEGACY}})["result"]
    assert set(res) == {"protocolVersion", "capabilities", "serverInfo",
                        "instructions"}
    assert res["protocolVersion"] == LEGACY


def test_legacy_initialize_never_answers_a_modern_version():
    res = dispatch_message({**REQ, "method": "initialize",
                            "params": {"protocolVersion": MODERN}})["result"]
    assert res["protocolVersion"] == m.LATEST_PROTOCOL_VERSION
    assert res["protocolVersion"] in m.LEGACY_PROTOCOL_VERSIONS


def test_legacy_tools_list_has_no_modern_fields():
    res = dispatch_message({**REQ, "method": "tools/list"})["result"]
    assert set(res) == {"tools"}


def test_modern_tools_list_is_cacheable_and_identifies_the_server():
    res = dispatch_message(_modern("tools/list"))["result"]
    assert res["resultType"] == "complete"
    assert res["ttlMs"] > 0 and res["cacheScope"] == "public"
    assert res["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] \
        == "xssentinel"
    # Phase 358's legacy catalogue is unchanged; Phase 377 appends the two
    # async tools ONLY here, in a fixed order.  A legacy frame still gets
    # exactly the seven (test_legacy_tools_list_shape + the Phase 377 guard).
    assert [t["name"] for t in res["tools"]] == [
        t["name"] for t in (m.TOOL_DEFINITIONS
                            + m._ASYNC_TOOL_DEFINITIONS)]


def test_unsupported_declared_version_offers_a_retry_list():
    resp = dispatch_message(_modern("tools/list", version="1900-01-01"))
    assert resp["error"]["code"] == -32022
    assert resp["error"]["data"]["requested"] == "1900-01-01"
    assert MODERN in resp["error"]["data"]["supported"]
    assert LEGACY in resp["error"]["data"]["supported"]


def test_known_legacy_version_in_meta_is_tolerated():
    """Some 2025 SDKs put _meta on every frame; do not reject them."""
    resp = dispatch_message(_modern("tools/list", version=LEGACY))
    assert "error" not in resp
    assert set(resp["result"]) == {"tools"}


def test_modern_unknown_method_is_32601():
    resp = dispatch_message(_modern("resources/list"))
    assert resp["error"]["code"] == -32601


# ---------------------------------------------------------------------------
# 2. modern tool results keep the two output channels in sync
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_runner(monkeypatch):
    """A target-derived non-ASCII payload, through the REAL _tool_call."""
    entry = m._TOOL_TABLE["xssentinel_scan"]

    def runner(args, **kw):
        return {"content": [{"type": "text", "text": json.dumps(
            {"finding_count": 1, "findings": [], "url": "http://t/",
             "evidence": "中文 🔍"}, ensure_ascii=False)}]}

    monkeypatch.setitem(m._TOOL_TABLE, "xssentinel_scan",
                        (entry[0], runner))


def test_modern_tool_call_accepts_meta_and_keeps_both_channels(fake_runner):
    msg = _modern("tools/call", {"name": "xssentinel_scan",
                                 "arguments": {"url": "http://t/"}})
    result = dispatch_message(msg)["result"]
    assert result["resultType"] == "complete"
    assert not result.get("isError")
    assert result["structuredContent"] == json.loads(
        result["content"][0]["text"])
    assert result["structuredContent"]["evidence"] == "中文 🔍"


# ---------------------------------------------------------------------------
# 3. stdio is a UTF-8 BYTE channel, not the OS console codepage
# ---------------------------------------------------------------------------

def test_stdio_write_survives_a_cp936_text_stdout(fake_runner):
    buf = io.BytesIO()
    stdout = io.TextIOWrapper(buf, encoding="cp936", newline="\n")
    msg = _modern("tools/call", {"name": "xssentinel_scan",
                                 "arguments": {"url": "http://t/"}})
    stdin = io.StringIO(json.dumps(msg, ensure_ascii=False) + "\n")
    srv = MCPServer(stdin=stdin, stdout=stdout)
    srv.serve()
    lines = buf.getvalue().decode("utf-8").splitlines()
    assert len(lines) == 1, lines
    payload = json.loads(lines[0])["result"]["structuredContent"]
    assert payload["evidence"] == "中文 🔍"


def test_stdio_read_decodes_utf8_from_a_cp936_text_stdin():
    raw = io.BytesIO((json.dumps(
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
         "params": {"name": "不存在的工具", "arguments": {}}},
        ensure_ascii=False) + "\n").encode("utf-8"))
    stdin = io.TextIOWrapper(raw, encoding="cp936", newline="\n")
    buf = io.BytesIO()
    stdout = io.TextIOWrapper(buf, encoding="cp936", newline="\n")
    MCPServer(stdin=stdin, stdout=stdout).serve()
    (line,) = buf.getvalue().decode("utf-8").splitlines()
    assert "不存在的工具" in json.loads(line)["result"]["content"][0]["text"]


def test_write_source_uses_the_byte_channel():
    """Guard against drifting back to a text-only write (the cp936 bug)."""
    import inspect
    src = inspect.getsource(MCPServer._write)
    assert ".encode(\"utf-8\")" in src or ".encode('utf-8')" in src
    assert "buffer" in src


# ---------------------------------------------------------------------------
# 4. Streamable HTTP: header/body consistency + transport status codes
# ---------------------------------------------------------------------------

@pytest.fixture
def http():
    server = StdlibServer(host="127.0.0.1", port=0)
    server.start_in_thread()
    try:
        yield _Http(server.base_url)
    finally:
        server.shutdown()


def _post(http, msg, headers=None):
    return http.post("/mcp", msg, headers=headers)


def test_http_modern_frame_with_matching_headers(http):
    hdrs = {"MCP-Protocol-Version": MODERN, "Mcp-Method": "tools/list",
            "Accept": "application/json, text/event-stream"}
    status, body, _ = _post(http, _modern("tools/list"), hdrs)
    assert status == 200
    assert json.loads(body)["result"]["resultType"] == "complete"


def test_http_header_body_mismatch_is_400_header_mismatch(http):
    hdrs = {"MCP-Protocol-Version": LEGACY, "Mcp-Method": "tools/list"}
    status, body, _ = _post(http, _modern("tools/list"), hdrs)
    assert status == 400
    err = json.loads(body)["error"]
    assert err["code"] == -32020
    assert "MCP-Protocol-Version" in err["message"]


def test_http_mcp_method_mismatch_is_400(http):
    hdrs = {"MCP-Protocol-Version": MODERN, "Mcp-Method": "ping"}
    status, body, _ = _post(http, _modern("tools/list"), hdrs)
    assert status == 400
    assert json.loads(body)["error"]["code"] == -32020


def test_http_header_names_are_case_insensitive(http):
    hdrs = {"mcp-protocol-version": MODERN, "mcp-method": "tools/list"}
    status, body, _ = _post(http, _modern("tools/list"), hdrs)
    assert status == 200, body


def test_http_unsupported_version_is_400_with_retry_list(http):
    hdrs = {"MCP-Protocol-Version": "1900-01-01"}
    status, body, _ = _post(http, _modern("tools/list",
                                           version="1900-01-01"), hdrs)
    assert status == 400
    assert json.loads(body)["error"]["code"] == -32022


def test_http_modern_unknown_method_is_404(http):
    hdrs = {"MCP-Protocol-Version": MODERN, "Mcp-Method": "resources/list"}
    status, body, _ = _post(http, _modern("resources/list"), hdrs)
    assert status == 404
    assert json.loads(body)["error"]["code"] == -32601


def test_http_legacy_frames_keep_200_and_no_modern_fields(http):
    status, body, _ = _post(http, {**REQ, "method": "tools/list"})
    assert status == 200
    assert set(json.loads(body)["result"]) == {"tools"}


# ---------------------------------------------------------------------------
# 5. the real shape an agent CLI uses: spawn the process, speak stdio
# ---------------------------------------------------------------------------

def test_real_subprocess_speaks_modern_mcp_over_utf8_stdio():
    """``python -m xssentinel mcp`` with pipes, not injected StringIOs.

    This is the path an agent's MCP client config actually launches.  It
    also proves stdout carries NOTHING but JSON-RPC frames (no banner, no
    logging) and that a non-ASCII tool name round-trips through the UTF-8
    byte channel on this Windows host.
    """
    import subprocess
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    frames = [
        _modern("server/discover"),
        {**REQ, "id": 2, "method": "tools/call",
         "params": {"name": "不存在的工具", "arguments": {}}},
    ]
    wire = b"".join(json.dumps(f, ensure_ascii=False).encode("utf-8") + b"\n"
                    for f in frames)
    proc = subprocess.Popen(
        [sys.executable, "-m", "xssentinel", "mcp"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, cwd=root)
    out, _err = proc.communicate(wire, timeout=30)
    lines = out.decode("utf-8").splitlines()
    assert len(lines) == 2, (lines, _err.decode("utf-8", "replace")[-400:])
    first, second = (json.loads(line) for line in lines)
    assert MODERN in first["result"]["supportedVersions"]
    assert "不存在的工具" in second["result"]["content"][0]["text"]
