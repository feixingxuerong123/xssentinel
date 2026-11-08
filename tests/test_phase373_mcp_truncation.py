# -*- coding: utf-8 -*-
"""Phase 373 / OPTIMIZATION.md §8.1-3: a capped result must say it is capped.

Measured gap: ``run_scan_tool`` did ``findings[:200]`` and reported
``finding_count = len(200)``; ``run_param_mine_tool`` reported the TOTAL in
``discovered_count`` while returning only the first 200 rows.  An agent reads
"200" as "all of them" -- the project rule "zero / truncation must not pretend
to be complete" was violated on the main Agent surface.

Each case drives the REAL tool runner with a substituted scanner / miner, so
the assertions see the actual JSON text AND the structuredContent that a
modern MCP frame delivers.  No socket is opened (pre-flight is stubbed).
"""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.api import mcp_server as m  # noqa: E402

TRUTH_FIELDS = ("total_findings", "truncated", "truncation_hint")
MINE_FIELDS = ("total_discovered", "truncated", "truncation_hint")


def _finding(i):
    return {"type": "reflected", "url": "http://127.0.0.1/",
            "method": "GET", "param": f"p{i}", "context": "html",
            "payload": "<script>", "severity": "high",
            "confidence": "high", "evidence_class": "semantic"}


def _row(i):
    return {"name": f"p{i}", "reflected": True, "length_delta": 3,
            "signal": "delta", "evidence": "reflected"}


def _stub_scan(monkeypatch, count):
    class _FakeScanner:
        def __init__(self, **kwargs):
            self.findings = [_finding(i) for i in range(count)]
            self.requests_made = 0
            self.waf_name = None

        def scan_target(self, *a, **k):
            pass

        def dedup(self):
            pass

    monkeypatch.setattr("xssentinel.core.scanner.Scanner", _FakeScanner)
    monkeypatch.setattr(m, "_preflight", lambda *a, **k: None)
    monkeypatch.setattr(m, "_make_requester", lambda *a, **k: object())
    return m.run_scan_tool({"url": "http://127.0.0.1/"})


def _stub_mine(monkeypatch, count):
    monkeypatch.setattr("xssentinel.core.param_miner.mine_params",
                        lambda *a, **k: [_row(i) for i in range(count)])
    monkeypatch.setattr(m, "_preflight", lambda *a, **k: None)
    monkeypatch.setattr(m, "_make_requester", lambda *a, **k: object())
    return m.run_param_mine_tool({"url": "http://127.0.0.1/"})


def _payload(result):
    assert not result.get("isError"), result
    return json.loads(result["content"][0]["text"])


@pytest.mark.parametrize("count,expected_truncated,expected_shown", [
    (250, True, m._MAX_FINDINGS),
    (m._MAX_FINDINGS, False, m._MAX_FINDINGS),
    (199, False, 199),
    (0, False, 0),
])
def test_scan_reports_the_total_and_the_cap(monkeypatch, count,
                                            expected_truncated,
                                            expected_shown):
    data = _payload(_stub_scan(monkeypatch, count))
    assert set(TRUTH_FIELDS) <= set(data)
    assert data["total_findings"] == count
    assert data["finding_count"] == expected_shown
    assert len(data["findings"]) == expected_shown
    assert data["truncated"] is expected_truncated
    if expected_truncated:
        assert data["finding_count"] < data["total_findings"]
        assert isinstance(data["truncation_hint"], str)
        assert "max_payloads" in data["truncation_hint"]
    else:
        assert data["truncation_hint"] is None


@pytest.mark.parametrize("count,expected_truncated,expected_shown", [
    (250, True, m._MAX_FINDINGS),
    (m._MAX_FINDINGS, False, m._MAX_FINDINGS),
    (5, False, 5),
])
def test_param_mine_reports_the_total_and_the_cap(monkeypatch, count,
                                                  expected_truncated,
                                                  expected_shown):
    data = _payload(_stub_mine(monkeypatch, count))
    assert set(MINE_FIELDS) <= set(data)
    assert data["total_discovered"] == count
    assert data["discovered_count"] == expected_shown
    assert len(data["discovered"]) == expected_shown
    assert data["truncated"] is expected_truncated
    if expected_truncated:
        assert data["discovered_count"] < data["total_discovered"]
        assert isinstance(data["truncation_hint"], str)
    else:
        assert data["truncation_hint"] is None


def test_both_output_schemas_declare_the_new_fields():
    schemas = m._TOOL_OUTPUT_SCHEMAS
    scan_props = schemas["xssentinel_scan"]["properties"]
    mine_props = schemas["xssentinel_param_mine"]["properties"]
    for key in TRUTH_FIELDS:
        assert key in scan_props, key
    for key in MINE_FIELDS:
        assert key in mine_props, key
    assert scan_props["truncated"]["type"] == "boolean"
    assert scan_props["truncation_hint"]["type"] == ["string", "null"]
    assert mine_props["truncated"]["type"] == "boolean"


def test_structured_channel_carries_the_same_truth(monkeypatch):
    """Text-only and structured clients must never disagree about the cap.
    Driven through the REAL dispatch entry point with a modern frame."""
    from xssentinel.api.mcp_server import dispatch_message

    _stub_scan(monkeypatch, 250)          # installs the substituted scanner
    frame = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {
                 "_meta": {"io.modelcontextprotocol/protocolVersion":
                           "2026-07-28"},
                 "name": "xssentinel_scan",
                 "arguments": {"url": "http://127.0.0.1/"}}}
    res = dispatch_message(frame)["result"]
    assert not res.get("isError"), res
    structured = res["structuredContent"]
    text = json.loads(res["content"][0]["text"])
    assert structured["truncated"] is True
    assert structured["total_findings"] == 250
    assert structured["truncated"] == text["truncated"]
    assert structured["total_findings"] == text["total_findings"]
