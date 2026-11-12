# -*- coding: utf-8 -*-
"""Phase 385: the run identity on every success result (§8.3 #8) + the
cost/workflow sentence in the instructions (§8.3 #10).

#8's recorded gap: a success result exposed no run_id and no elapsed time,
so an agent could not correlate a result with its progress stream, tell
two parallel scans apart, or reason about "was this call expensive".
Every SUCCESS result now carries ``run_id`` (``run_`` + 16 hex) and
``elapsed_ms`` (measured around the runner) in text AND structuredContent.
``budget_used`` is deliberately NOT added: ``requests_made`` +
``effective_max_seconds`` already cover consumption, and a redundant
field is a second number to rot.  ``next_actions`` is deliberately NOT
added: guidance addressed to a model is prompt-injection surface (the
project's own threat model); error-path ``hint`` fields already carry
recovery advice.

#10's recorded gap: ``_INSTRUCTIONS`` was two sentences and said nothing
about cost or workflow.  The scope declaration lives in the ``scope``
object (Phase 383); the static text now carries the cost reality and the
cheap-first workflow instead.
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.api import mcp_server as m  # noqa: E402

PAGE = b"<html><body><p>static page</p></body></html>"

_RUN_ID_RE = re.compile(r"^run_[0-9a-f]{16}$")


class _StaticTarget:
    def __init__(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(PAGE)))
                self.end_headers()
                self.wfile.write(PAGE)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever,
                         daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/"

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


def _modern_call(name: str, arguments: dict):
    resp = m.dispatch_message({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": arguments,
                   "_meta": {m._META_VERSION_KEY: "2026-07-28"}}})
    assert resp is not None
    return resp["result"]


def _payload(result: dict) -> dict:
    return json.loads(result["content"][0]["text"])


def test_scan_success_carries_run_identity_in_both_channels():
    t = _StaticTarget()
    try:
        result = _modern_call("xssentinel_scan", {
            "url": t.url, "max_payloads": 1, "timeout": 5})
        assert not result.get("isError"), result
        text = _payload(result)
        structured = result["structuredContent"]
        assert _RUN_ID_RE.match(text["run_id"]), text["run_id"]
        assert isinstance(text["elapsed_ms"], int) and text["elapsed_ms"] >= 0
        assert text["run_id"] == structured["run_id"]
        assert text["elapsed_ms"] == structured["elapsed_ms"]
    finally:
        t.stop()


def test_stamp_applies_to_every_tool_uniformly(monkeypatch):
    """The stamp is a dispatch-level contract, not a runner detail: a fake
    success from any tool -- including the cache-excluded status poll --
    comes back with the run identity in both channels."""
    def fake(args, cancel_event=None, emit=None):
        return {"content": [{"type": "text", "text": json.dumps({"ok": 1})}],
                "structuredContent": {"ok": 1}}
    cases = (
        (m._TOOL_TABLE, "xssentinel_profile",
         {"url": "http://127.0.0.1:1/"}),
        (m._TOOL_TABLE, "xssentinel_csp_analyze",
         {"url": "http://127.0.0.1:1/"}),
        (m._ASYNC_TOOL_TABLE, "xssentinel_scan_status",
         {"scan_id": "scan_x"}),
    )
    for table, name, args in cases:
        schema, _real = table[name]
        monkeypatch.setitem(table, name, (schema, fake))
        result = _modern_call(name, args)
        assert not result.get("isError"), (name, result)
        text = _payload(result)
        assert _RUN_ID_RE.match(text["run_id"]), (name, text)
        assert text["run_id"] == result["structuredContent"]["run_id"]
        monkeypatch.setitem(table, name, (schema, _real))


def test_cached_replay_carries_the_original_run_id():
    t = _StaticTarget()
    try:
        args = {"url": t.url, "max_payloads": 1, "timeout": 5}
        first = _modern_call("xssentinel_scan", args)
        p1 = _payload(first)
        second = _modern_call("xssentinel_scan", args)
        p2 = _payload(second)
        assert second["structuredContent"]["cache_hit"] is True
        # The replay is honest about what it is: the run that produced the
        # payload, not a fresh run pretending to be one.
        assert p2["run_id"] == p1["run_id"]
        assert p2["elapsed_ms"] == p1["elapsed_ms"]
    finally:
        t.stop()


def test_every_output_schema_declares_the_run_fields():
    for name, schema in (list(m._TOOL_OUTPUT_SCHEMAS.items())
                         + list(m._ASYNC_TOOL_OUTPUT_SCHEMAS.items())):
        props = schema.get("properties") or {}
        assert props.get("run_id") == {"type": "string"}, name
        assert props.get("elapsed_ms") == {"type": "integer"}, name


def test_instructions_carry_cost_and_workflow():
    assert "real requests" in m._INSTRUCTIONS
    assert "xssentinel_discover" in m._INSTRUCTIONS
    assert "async scan pair" in m._INSTRUCTIONS
    # ...and the discover result the agent actually reads carries them too.
    resp = m.dispatch_message({"jsonrpc": "2.0", "id": 2,
                               "method": "server/discover"})
    assert "real requests" in resp["result"]["instructions"]
