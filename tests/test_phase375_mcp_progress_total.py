# -*- coding: utf-8 -*-
"""Phase 375 / OPTIMIZATION.md §8.2 #6: progress needs a denominator.

Measured gap (dev/agent_surface_probe.py, 2026-11-06): five
``notifications/progress`` frames carried only ``progress`` (requests sent)
plus a start beacon.  No ``total``, no unit -- an agent cannot compute a
percentage or tell "running" from "stuck".

Contract pinned here, through the REAL stdio session (MCPServer.serve ->
dispatch_message -> _tool_call -> runner -> _progress_emitter -> _write):

  * a call WITH _meta.progressToken gets total > 0 on EVERY notification,
    progress <= total, and a message stating the unit;
  * ``progress`` still means "requests sent" (beacon 0, then 1, 2, 3...);
  * a call WITHOUT the token emits ZERO notifications;
  * the estimate grows if real traffic exceeds it (never progress > total).

A substituted runner emits counters without opening a socket, so this is a
protocol-shape test, not a scan verdict test.
"""
from __future__ import annotations

import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.api import mcp_server as m  # noqa: E402
from xssentinel.api.mcp_server import MCPServer  # noqa: E402


def _frame(token: bool, args=None):
    params = {"name": "xssentinel_scan",
              "arguments": args or {"url": "http://127.0.0.1/",
                                    "max_payloads": 5}}
    if token:
        params["_meta"] = {"progressToken": "tok-1"}
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": params}


def _session(msg):
    server = MCPServer()
    out = io.StringIO()
    server._stdin = io.StringIO(json.dumps(msg) + "\n")
    server._stdout = out
    server.serve()
    return [json.loads(line) for line in out.getvalue().splitlines()]


def _progress(frames):
    return [f["params"] for f in frames
            if f.get("method") == "notifications/progress"]


def _install_runner(monkeypatch, counters):
    schema = m._TOOL_TABLE["xssentinel_scan"][0]

    def fake_runner(args, cancel_event=None, emit=None):
        if emit is not None:
            for n in counters:
                emit(n)
        return {"content": [{"type": "text",
                             "text": '{"finding_count": 0}'}]}

    monkeypatch.setitem(m._TOOL_TABLE, "xssentinel_scan",
                        (schema, fake_runner))


def test_every_notification_has_total_unit_and_consistent_progress(monkeypatch):
    _install_runner(monkeypatch, [1, 2, 3])
    frames = _progress(_session(_frame(token=True)))
    assert len(frames) >= 4, frames
    for p in frames:
        assert p["progressToken"] == "tok-1"
        assert isinstance(p["total"], int) and p["total"] > 0, p
        assert p["progress"] <= p["total"], p
        assert "requests sent" in p["message"], p
    assert {p["progress"] for p in frames} >= {0, 1, 2, 3}
    beacon = next(p for p in frames if p["progress"] == 0)
    assert "started xssentinel_scan" in beacon["message"]


def test_no_progress_token_means_zero_notifications(monkeypatch):
    _install_runner(monkeypatch, [1, 2, 3])
    frames = _session(_frame(token=False))
    assert _progress(frames) == []
    assert any(f.get("id") == 1 for f in frames), "the tool still answered"


def test_estimate_grows_when_traffic_exceeds_it(monkeypatch):
    _install_runner(monkeypatch, [50])
    frames = _progress(_session(_frame(token=True)))
    biggest = max(p["progress"] for p in frames)
    assert biggest == 50
    for p in frames:
        assert p["progress"] <= p["total"], p
    assert any(p["total"] > 5 for p in frames), (
        "the estimate must grow instead of letting progress exceed it")


def test_estimate_uses_the_shared_url_contract_and_tool_budgets():
    # 3 query params x max_payloads 5 => 15; no hand-rolled URL parsing.
    assert m._estimate_progress_total(
        "xssentinel_scan",
        {"url": "http://127.0.0.1/?a=1&b=2&c=3", "max_payloads": 5}) == 15
    assert m._estimate_progress_total(
        "xssentinel_param_mine",
        {"url": "http://127.0.0.1/", "max_params": 7}) == 7
    assert m._estimate_progress_total(
        "xssentinel_scan", {"url": "http://127.0.0.1/"}) == 14
