# -*- coding: utf-8 -*-
"""Phase 377 / OPTIMIZATION.md §8.2 #4 (item 3): async path for agents.

Measured gap: ``max_seconds`` defaults to 300s but MCP hosts kill one
``tools/call`` at 30-120s, and HTTP had no way to hand a long scan back to
the client.  Phase 376 let a client state its budget; this phase gives long
scans somewhere to live: submit -> poll -> collect.

What this guard pins, through the REAL dispatch and the REAL JobManager:

  * a LEGACY tools/list is byte-identical to the seven-tool catalogue, and
    a legacy frame cannot call either async tool (Phase 358 contract);
  * a MODERN tools/list appends exactly two tools, all with titles, hints
    and both schemas; the catalogue / dispatch / schema / title tables
    cannot drift apart;
  * a submit sends ZERO requests to the target;
  * submit -> poll returns the SAME compact findings, cap flags and
    effective budget a synchronous xssentinel_scan would have returned;
  * a cancelled job is NEVER settled as a "clean" scan;
  * wiring assertions on the call sites (helpers do not rot; callers do).

Only the network layer is substituted.  JobManager, its reaper, the worker,
run_scan_tool, _RequestGuard and dispatch_message are all real.
"""
from __future__ import annotations

import ast
import inspect
import json
import os
import sys
import textwrap
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.api import mcp_server as m  # noqa: E402
from xssentinel.api.mcp_server import dispatch_message  # noqa: E402

MODERN_META = {"_meta": {m._META_VERSION_KEY: "2026-07-28"}}
ASYNC_NAMES = {"xssentinel_scan_async", "xssentinel_scan_status"}


def _call(name, arguments, modern=True):
    params = {"name": name, "arguments": arguments}
    if modern:
        params.update(MODERN_META)
    return dispatch_message({"jsonrpc": "2.0", "id": 1,
                             "method": "tools/call",
                             "params": params})["result"]


def _payload(result):
    assert not result.get("isError"), result
    return json.loads(result["content"][0]["text"])


def _tools(modern):
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    if modern:
        msg["params"] = MODERN_META
    return dispatch_message(msg)["result"]["tools"]


def _finding(i):
    return {"type": "reflected", "url": "http://127.0.0.1/",
            "method": "GET", "param": f"p{i}", "context": "html",
            "payload": "<script>", "severity": "high",
            "confidence": "high", "evidence_class": "semantic"}


class _FakeRequester:
    def __init__(self):
        self.calls = 0

    def request(self, *a, **k):
        self.calls += 1

    def get(self, *a, **k):
        self.calls += 1

    def post(self, *a, **k):
        self.calls += 1


@pytest.fixture
def scan_env(monkeypatch):
    """Real JobManager + real worker + real run_scan_tool, fake socket."""
    state = {"findings": [_finding(i) for i in range(3)],
             "scans": 0}
    fake = _FakeRequester()

    class _FakeScanner:
        def __init__(self, **kw):
            self.findings = list(state["findings"])
            self.requests_made = 7
            self.waf_name = "fake-waf"
            self.requester = kw["requester"]

        def scan_target(self, *a, **k):
            state["scans"] += 1
            self.requester.get("http://127.0.0.1/")  # real _RequestGuard

        def dedup(self):
            pass

    monkeypatch.setattr("xssentinel.core.scanner.Scanner", _FakeScanner)
    monkeypatch.setattr(m, "_preflight", lambda *a, **k: None)
    monkeypatch.setattr("xssentinel.api.server._build_requester",
                        lambda cfg: fake)
    old = m._job_manager
    m._job_manager = None       # one fresh manager per test
    try:
        yield state
    finally:
        if m._job_manager is not None:
            m._job_manager._reaper_stop.set()
        m._job_manager = old


def _submit():
    return _payload(_call("xssentinel_scan_async",
                          {"url": "http://127.0.0.1/?a=1"}))


def _poll(scan_id, timeout=12.0, **extra):
    args = {"scan_id": scan_id}
    args.update(extra)
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = _payload(_call("xssentinel_scan_status", args))
        if last["terminal"]:
            return last
        time.sleep(0.1)
    pytest.fail(f"job never reached a terminal state: {last}")


# -- 1. legacy contract ----------------------------------------------------
def test_legacy_tools_list_is_byte_identical_to_the_seven_tool_catalogue():
    legacy = _tools(modern=False)
    assert len(legacy) == 7
    assert legacy == m.TOOL_DEFINITIONS
    assert ASYNC_NAMES.isdisjoint({t["name"] for t in legacy})
    # A modern frame must not have MUTATED the shared legacy catalogue.
    _tools(modern=True)
    assert _tools(modern=False) == m.TOOL_DEFINITIONS


def test_modern_tools_list_appends_exactly_two_async_tools():
    legacy = _tools(modern=False)
    modern = _tools(modern=True)
    assert len(modern) == len(legacy) + 2 == 9
    assert [t["name"] for t in modern[:len(legacy)]] == [
        t["name"] for t in legacy]
    assert {t["name"] for t in modern[len(legacy):]} == ASYNC_NAMES
    for tool in modern[len(legacy):]:
        assert tool["title"] and tool["annotations"]
        assert tool["inputSchema"] and tool["outputSchema"]


def test_async_tables_cannot_drift_from_each_other():
    catalogue = {t["name"] for t in m._ASYNC_TOOL_DEFINITIONS}
    assert catalogue == ASYNC_NAMES
    assert catalogue == set(m._ASYNC_TOOL_TABLE)
    assert catalogue == set(m._ASYNC_TOOL_OUTPUT_SCHEMAS)
    assert catalogue == set(m._ASYNC_TOOL_TITLES)
    by_name = {t["name"]: t for t in m._ASYNC_TOOL_DEFINITIONS}
    for name, (schema, _runner) in m._ASYNC_TOOL_TABLE.items():
        assert by_name[name]["inputSchema"] is schema, name
        assert by_name[name]["outputSchema"] is \
            m._ASYNC_TOOL_OUTPUT_SCHEMAS[name], name


def test_submit_and_scan_share_one_input_schema():
    # One validation path, not a second copy of 14 parameter definitions.
    assert (m._TOOL_SCAN_ASYNC_SCHEMA["properties"]
            is m._TOOL_SCAN_SCHEMA["properties"])


@pytest.mark.parametrize("name", sorted(ASYNC_NAMES))
def test_legacy_frame_cannot_call_async_tools(name):
    result = _call(name, {"url": "http://127.0.0.1/"}, modern=False)
    assert result["isError"] is True
    assert "unknown tool" in result["content"][0]["text"]


def test_discover_declares_the_async_workflow():
    result = dispatch_message(
        {"jsonrpc": "2.0", "id": 1, "method": "server/discover"})["result"]
    assert set(result["asyncTools"]) == ASYNC_NAMES
    assert "xssentinel_scan_status" in result["asyncWorkflow"]
    assert "NOT a clean scan" in result["asyncWorkflow"]


# -- 2. submit --------------------------------------------------------------
def test_submit_sends_zero_requests_and_returns_a_scan_id(monkeypatch,
                                                          scan_env):
    calls = []
    real_run = m.run_scan_tool

    def spy(*a, **k):
        calls.append("scan")
        return real_run(*a, **k)

    monkeypatch.setattr(m, "run_scan_tool", spy)
    payload = _submit()
    assert payload["scan_id"].startswith("scan_")
    assert payload["state"] == "pending"
    assert payload["status_tool"] == "xssentinel_scan_status"
    assert payload["poll_after_ms"] > 0
    assert calls == [], "submit must not run a scan on the calling thread"
    assert scan_env["scans"] == 0


def test_submit_validates_the_url_locally(scan_env):
    for bad in ("", "not-a-url"):
        result = _call("xssentinel_scan_async", {"url": bad})
        assert result["isError"] is True, bad
    assert scan_env["scans"] == 0


def test_submit_does_not_invent_a_second_url_policy(scan_env):
    """Scheme allowlisting lives UPSTREAM in the requester (Phase 368).

    Both runners only check absolute-URL shape here.  Pin the PARITY rather
    than pretending either one rejects ftp:// -- a second policy would make
    sync and async disagree about the same target (Phase 369's lesson).
    """
    for url in ("", "not-a-url", "ftp://example.com/",
                "http://127.0.0.1/?a=1"):
        async_err = bool(m.run_scan_async_tool({"url": url}).get("isError"))
        sync_err = bool(m.run_scan_tool({"url": url}).get("isError"))
        assert async_err == sync_err, url


# -- 3. submit -> poll -> SAME findings ------------------------------------
def test_poll_returns_the_same_findings_as_a_synchronous_scan(scan_env):
    sync = json.loads(m.run_scan_tool(
        {"url": "http://127.0.0.1/?a=1"})["content"][0]["text"])
    submitted = _submit()
    final = _poll(submitted["scan_id"])
    assert final["state"] == "completed"
    assert final["terminal"] is True
    assert final["findings"] == sync["findings"], (
        "async must hand back the SAME compact findings, not a re-scan")
    assert final["total_findings"] == sync["total_findings"]
    assert final["truncated"] == sync["truncated"]
    assert final["effective_max_seconds"] == sync["effective_max_seconds"]
    assert final["requests_made"] == sync["requests_made"]
    assert final["error"] is None
    assert "output_safety" in final and "untrusted_fields" in final


def test_poll_preserves_the_truncation_truth(scan_env):
    scan_env["findings"] = [_finding(i) for i in range(250)]
    final = _poll(_submit()["scan_id"])
    assert final["state"] == "completed"
    assert final["finding_count"] == m._MAX_FINDINGS
    assert final["total_findings"] == 250
    assert final["truncated"] is True
    assert isinstance(final["truncation_hint"], str)
    assert len(final["findings"]) == m._MAX_FINDINGS


def test_include_findings_false_keeps_counts_but_omits_the_array(scan_env):
    final = _poll(_submit()["scan_id"], include_findings=False)
    assert "findings" not in final
    assert final["finding_count"] == 3
    assert final["terminal"] is True


def test_unknown_scan_id_is_a_structured_error(scan_env):
    result = _call("xssentinel_scan_status",
                   {"scan_id": "scan_doesnotexist"})
    assert result["isError"] is True
    assert "unknown scan_id" in result["content"][0]["text"]
    err = result["structuredContent"]["error"]
    assert err["code"] == "unknown_scan_id"
    assert err["field"] == "scan_id"
    assert "xssentinel_scan_async" in err["hint"]


# -- 4. cancellation must never look like a clean scan ---------------------
def test_cancel_before_worker_starts_is_failed_not_clean(scan_env):
    submitted = _submit()
    cancelling = _payload(_call("xssentinel_scan_status",
                                {"scan_id": submitted["scan_id"],
                                 "cancel": True}))
    assert cancelling["cancelled"] is True
    final = _poll(submitted["scan_id"])
    # FAILED with an explicit reason -- never COMPLETED with zero findings.
    assert final["state"] == "failed"
    assert final["finding_count"] == 0
    assert final["error"] and "cancel" in final["error"].lower()
    assert scan_env["scans"] == 0, "cancelled pending job must not scan"


# -- 5. real job model + wiring --------------------------------------------
def test_async_path_uses_the_rest_job_manager(scan_env):
    from xssentinel.api.jobs import JobManager, JobState
    manager = m._get_job_manager()
    assert isinstance(manager, JobManager)
    submitted = _submit()
    job = manager.get(submitted["scan_id"])
    assert job.state in JobState.ACTIVE
    assert job.options["async_args"]["url"] == "http://127.0.0.1/?a=1"
    final = _poll(submitted["scan_id"])
    assert final["state"] in JobState.TERMINAL


def _calls_in(src, func_name):
    tree = ast.parse(textwrap.dedent(src))
    return [n for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and (getattr(n.func, "id", None) == func_name
                 or getattr(n.func, "attr", None) == func_name)]


def test_wiring_is_pinned_at_the_call_sites():
    # A helper cannot rot; a caller that stops using it can.
    dispatcher = inspect.getsource(m.dispatch_message)
    assert any("modern=modern" in ast.unparse(n) for n in
               _calls_in(dispatcher, "_tool_call"))
    call_src = inspect.getsource(m._tool_call)
    assert "_ASYNC_TOOL_TABLE.get(name)" in call_src
    assert "if entry is None and modern" in call_src
    modernize = inspect.getsource(m._modernize_tools)
    assert "_ASYNC_TOOL_DEFINITIONS" in modernize
    worker = inspect.getsource(m._async_scan_worker)
    assert _calls_in(worker, "run_scan_tool"), "worker must use the sync runner"
    assert "mark_completed" in worker and "mark_failed" in worker
    assert "scan aborted before completion" in worker
