# -*- coding: utf-8 -*-
"""Phase 384: caller credentials never echo through tool channels (§8.3 #11).

The audit question: do ``cookies`` / ``headers`` values sent BY THE CALLER
come back through a channel the TARGET did not put them in -- error
sentences, ``waf``, metadata, the security annotations themselves?

Method (same as dev/credential_echo_probe.py, whose full run backs this
guard): canary credentials to real loopback servers, full response bytes
grepped for the canaries, with a SERVER-SIDE arrival proof so a clean
result is not vacuous -- the credentials demonstrably travelled.

Measured fact pinned by the unreachable arm: requests' exception texts
embed host/port/path but never URL userinfo, so the
``scan failed: {type}: {e}`` / ``target unreachable: {e}`` echo paths have
no realistic credential source.  The reflecting arm proves the flip side:
when the TARGET itself echoes the credentials into its body, the tool
still reports nothing it did not have to -- a finding-less scan carries
no page bytes at all.
"""
from __future__ import annotations

import json
import os
import secrets
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.api import mcp_server as m  # noqa: E402

_SCAN = {"max_payloads": 1, "timeout": 5, "max_seconds": 30}
_TOOLS_WITH_URL = ("xssentinel_scan", "xssentinel_discover",
                   "xssentinel_profile", "xssentinel_verify",
                   "xssentinel_param_mine", "xssentinel_csp_analyze")


class _Target:
    """Loopback server on port 0; records whether canary creds arrived."""

    def __init__(self, mode: str = "static"):
        self._hits: list = []
        self._lock = threading.Lock()
        self.mode = mode
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                with outer._lock:
                    outer._hits.append({
                        "path": self.path,
                        "cookie": self.headers.get("Cookie") or "",
                        "canary": self.headers.get("X-Audit-Canary") or "",
                    })
                if outer.mode == "abrupt":
                    self.send_response(200)
                    self.send_header("Content-Length", "1000")
                    self.end_headers()
                    self.wfile.write(b"<html>")
                    self.connection.close()
                    return
                if outer.mode == "reflecting":
                    body = (
                        "<html><body>"
                        f"<p id=cookie>{self.headers.get('Cookie') or ''}</p>"
                        f"<p id=hdr>{self.headers.get('X-Audit-Canary') or ''}"
                        "</p></body></html>").encode()
                else:
                    body = b"<html><body><p>static</p></body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever,
                         daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/"

    def arrived(self, ck: str, hd: str) -> bool:
        with self._lock:
            return any(ck in h["cookie"] and hd in h["canary"]
                       for h in self._hits)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _call(tool: str, url: str, ck: str, hd: str) -> dict:
    m.configure_scope(None, allow_any_host=True)
    args = dict(_SCAN)
    args.update({"url": url, "cookies": {"xsaudit": ck},
                 "headers": {"X-Audit-Canary": hd}})
    if tool != "xssentinel_scan":
        args = {k: v for k, v in args.items()
                if k in ("url", "cookies", "headers", "timeout")}
    resp = m.dispatch_message({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": tool, "arguments": args,
                   "_meta": {m._META_VERSION_KEY: "2026-07-28"}}})
    return resp["result"]


def _assert_no_echo(result: dict, ck: str, hd: str, where: str) -> None:
    text = json.dumps(result, ensure_ascii=False)
    assert ck not in text, f"{where}: cookie canary echoed back: {text[:300]}"
    assert hd not in text, f"{where}: header canary echoed back: {text[:300]}"


def test_scan_on_a_clean_target_never_echoes_credentials():
    ck, hd = f"canary_ck_{secrets.token_hex(8)}", f"canary_hd_{secrets.token_hex(8)}"
    t = _Target("static")
    try:
        result = _call("xssentinel_scan", t.url, ck, hd)
        assert not result.get("isError"), result
        assert t.arrived(ck, hd), "canary creds never left home; arm vacuous"
        _assert_no_echo(result, ck, hd, "static scan")
    finally:
        t.stop()


def test_reflecting_target_page_bytes_stay_out_of_nonfinding_channels():
    """The TARGET echoes the credentials into its own body (arrival proof).
    A scan there legitimately finds the reflected probe cookies; the audit
    contract is that the canaries appear NOWHERE outside target-derived
    finding fields -- never in metadata, never in the safety annotations.
    """
    ck, hd = f"canary_ck_{secrets.token_hex(8)}", f"canary_hd_{secrets.token_hex(8)}"
    t = _Target("reflecting")
    try:
        result = _call("xssentinel_scan", t.url, ck, hd)
        assert not result.get("isError"), result
        assert t.arrived(ck, hd), "canary creds never left home; arm vacuous"
        # Strip every target-derived findings list, then the remainder --
        # the tool's own voice -- must be canary-free.
        stripped = json.loads(json.dumps(result))
        stripped.get("structuredContent", {}).pop("findings", None)
        _assert_no_echo(_without_findings(stripped), ck, hd,
                        "reflecting scan (non-finding channels)")
    finally:
        t.stop()


def _without_findings(obj):
    """Deep-remove every 'findings' list (the one target-derived channel)."""
    if isinstance(obj, dict):
        return {k: _without_findings(v) for k, v in obj.items()
                if k != "findings"}
    if isinstance(obj, list):
        return [_without_findings(v) for v in obj]
    return obj


def test_abrupt_target_close_leaks_nothing():
    ck, hd = f"canary_ck_{secrets.token_hex(8)}", f"canary_hd_{secrets.token_hex(8)}"
    t = _Target("abrupt")
    try:
        result = _call("xssentinel_scan", t.url, ck, hd)
        # Either answer is honest (an error, or a scan that swallowed a
        # transport error); the canary may ride in neither.
        _assert_no_echo(result, ck, hd, "abrupt close")
    finally:
        t.stop()


def test_unreachable_error_sentences_echo_no_credentials():
    ck, hd = f"canary_ck_{secrets.token_hex(8)}", f"canary_hd_{secrets.token_hex(8)}"
    closed = _closed_port()
    for tool in _TOOLS_WITH_URL:
        result = _call(tool, f"http://127.0.0.1:{closed}/", ck, hd)
        assert result.get("isError"), (tool, result)
        _assert_no_echo(result, ck, hd, f"{tool} unreachable")
