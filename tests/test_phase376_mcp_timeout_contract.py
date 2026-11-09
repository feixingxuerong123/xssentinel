# -*- coding: utf-8 -*-
"""Phase 376 / OPTIMIZATION.md §8.2 #4 (items 1+2): the long-call contract.

Measured gap (dev/agent_surface_probe.py, 2026-11-06): ``max_seconds``
defaults to 300s while MCP hosts kill a single ``tools/call`` at 30-120s;
``server/discover`` advertised no budget at all; and HTTP had no
mid-flight cancellation, so a disconnected client's scan kept sending
ATTACK PAYLOADS until the server's own deadline expired.

What this guard pins, through real entry points (``dispatch_message`` ->
``_tool_call`` -> runner, and ``_handle_mcp`` -> watcher -> ``_RequestGuard``):

  * discover states the recommended client timeout, the server default and
    the ONE _meta key that negotiates them; schema and runner share it;
  * a MODERN client's budget is folded into ``max_seconds`` with
    min(client, server) -- it can shorten a scan but never lengthen it;
  * a LEGACY frame keeps exactly its old behaviour;
  * a malformed / too-small budget is an explicit structured error and the
    runner is NEVER called (no silent fallback to the 300s default);
  * a spent CLIENT budget names the client knob, not ``max_seconds``;
  * the HTTP watcher arms ONLY on a real EOF, never on pipelined data, and
    is opt-in when there is no socket;
  * a set cancel_event produces ZERO outbound requests and NO response.

Source assertions lock the WIRING, not just the helpers: the helper cannot
rot, but a caller that stops passing ``modern``/``cancel_event`` can.
"""
from __future__ import annotations

import ast
import inspect
import json
import os
import socket
import sys
import textwrap
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.api import mcp_server as m  # noqa: E402
from xssentinel.api import server as srv  # noqa: E402
from xssentinel.api.mcp_server import dispatch_message  # noqa: E402

MODERN_VERSION = "2026-07-28"


def _frame(args=None, meta=None, modern=True):
    params = {"name": "xssentinel_scan",
              "arguments": dict(args or {"url": "http://127.0.0.1/"})}
    params["_meta"] = ({m._META_VERSION_KEY: MODERN_VERSION} if modern
                       else {})
    if meta:
        params["_meta"].update(meta)
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": params}


def _spy_runner(monkeypatch, seen):
    """Swap ONLY the dispatch-table runner; everything above it is real."""
    schema = m._TOOL_TABLE["xssentinel_scan"][0]

    def fake(args, cancel_event=None, emit=None):
        seen.append(dict(args))
        return {"content": [{"type": "text", "text": "{}"}]}

    monkeypatch.setitem(m._TOOL_TABLE, "xssentinel_scan", (schema, fake))


def _calls_with_keyword(src, func_name, keyword):
    tree = ast.parse(textwrap.dedent(src))
    hits = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = (node.func.id if isinstance(node.func, ast.Name)
                else getattr(node.func, "attr", None))
        if name == func_name and any(k.arg == keyword
                                     for k in node.keywords):
            hits.append(node)
    return hits


# -- 1. server/discover advertises the budget reality -----------------------
def test_discover_advertises_both_budgets_and_the_negotiation_key():
    result = dispatch_message(
        {"jsonrpc": "2.0", "id": 1, "method": "server/discover"})["result"]
    assert result["recommendedTimeoutMs"] == m._RECOMMENDED_TIMEOUT_MS == 120000
    assert result["defaultMaxSeconds"] == m._DEFAULT_MAX_SECONDS == 300
    assert result["clientBudgetMetaKey"] == m._META_CLIENT_TIMEOUT_KEY
    assert "min(" in result["budgetPolicy"]
    # The prose must not hand-write a second copy of the key: rename the
    # constant and a stale instruction would send clients to a dead field.
    assert m._META_CLIENT_TIMEOUT_KEY in result["budgetPolicy"]
    assert (m._TOOL_SCAN_SCHEMA["properties"]["max_seconds"]["default"]
            == result["defaultMaxSeconds"])


def test_default_budget_has_one_definition_in_the_runner():
    # The helper cannot rot; a runner that hand-writes 300 again can.
    src = inspect.getsource(m.run_scan_tool)
    assert "300" not in src
    assert "_DEFAULT_MAX_SECONDS" in src


# -- 2. min(client, server) ------------------------------------------------
@pytest.mark.parametrize("args,client_ms,expected", [
    ({}, 30000, 30),                    # client shortens the default
    ({}, 999999999, 300),               # client can NEVER lengthen it
    ({"max_seconds": 600}, 30000, 30),  # client beats an explicit server arg
    ({"max_seconds": 10}, 30000, 10),   # server stays tighter
    ({}, 45500, 45),                    # floor: never outlast the client
])
def test_client_budget_is_folded_into_max_seconds(monkeypatch, args,
                                                  client_ms, expected):
    seen = []
    _spy_runner(monkeypatch, seen)
    dispatch_message(_frame(args, {m._META_CLIENT_TIMEOUT_KEY: client_ms}))
    assert seen and seen[0]["max_seconds"] == expected


def test_no_declaration_leaves_the_runner_untouched(monkeypatch):
    seen = []
    _spy_runner(monkeypatch, seen)
    dispatch_message(_frame())
    assert seen and "max_seconds" not in seen[0]


def test_legacy_frame_ignores_the_client_budget(monkeypatch):
    seen = []
    _spy_runner(monkeypatch, seen)
    dispatch_message(_frame({}, {m._META_CLIENT_TIMEOUT_KEY: 30000},
                            modern=False))
    assert seen and "max_seconds" not in seen[0]


def test_a_tool_without_max_seconds_is_not_rewritten(monkeypatch):
    seen = []
    schema = m._TOOL_TABLE["xssentinel_profile"][0]

    def fake(args, cancel_event=None, emit=None):
        seen.append(dict(args))
        return {"content": [{"type": "text", "text": "{}"}]}

    monkeypatch.setitem(m._TOOL_TABLE, "xssentinel_profile", (schema, fake))
    frame = _frame({}, {m._META_CLIENT_TIMEOUT_KEY: 30000})
    frame["params"]["name"] = "xssentinel_profile"
    frame["params"]["arguments"] = {"url": "http://127.0.0.1/", "param": "q"}
    dispatch_message(frame)
    assert seen and "max_seconds" not in seen[0]


# -- 3. malformed declarations fail loudly, with ZERO requests -------------
@pytest.mark.parametrize("bad", [
    "30000", None, True, -1, 0, float("nan"), float("inf"), 1000,
])
def test_bad_client_budget_is_a_structured_error_and_never_runs(monkeypatch,
                                                                bad):
    seen = []
    _spy_runner(monkeypatch, seen)
    result = dispatch_message(
        _frame({}, {m._META_CLIENT_TIMEOUT_KEY: bad}))["result"]
    assert result["isError"] is True
    assert seen == [], "a rejected declaration must not start a scan"
    err = result["structuredContent"]["error"]
    assert err["code"] == "invalid_argument_value", err
    assert err["field"] == m._META_CLIENT_TIMEOUT_KEY
    assert err["retryable"] is False


# -- 4. the effective budget is visible, and timeouts name the real knob ---
def test_effective_budget_is_reported_and_declared(monkeypatch):
    class _FakeScanner:
        def __init__(self, **kw):
            self.findings = []
            self.requests_made = 0
            self.waf_name = None

        def scan_target(self, *a, **k):
            pass

        def dedup(self):
            pass

    monkeypatch.setattr("xssentinel.core.scanner.Scanner", _FakeScanner)
    monkeypatch.setattr(m, "_preflight", lambda *a, **k: None)
    monkeypatch.setattr(m, "_make_requester", lambda *a, **k: object())
    result = m.run_scan_tool(
        {"url": "http://127.0.0.1/", "max_seconds": 30})
    data = json.loads(result["content"][0]["text"])
    assert data["effective_max_seconds"] == 30
    assert (m._TOOL_OUTPUT_SCHEMAS["xssentinel_scan"]["properties"]
            ["effective_max_seconds"]["type"] == "integer")


def test_client_limited_timeout_names_the_client_knob(monkeypatch):
    schema = m._TOOL_TABLE["xssentinel_scan"][0]

    def fake(args, cancel_event=None, emit=None):
        raise m._ToolTimeout(
            "wall-clock budget exceeded after 2 request(s)")

    monkeypatch.setitem(m._TOOL_TABLE, "xssentinel_scan", (schema, fake))
    result = dispatch_message(
        _frame({}, {m._META_CLIENT_TIMEOUT_KEY: 30000}))["result"]
    assert result["isError"] is True
    assert "client-declared budget of 30s" in result["content"][0]["text"]
    err = result["structuredContent"]["error"]
    assert err["code"] == "timeout"
    assert "clientTimeoutMs" in err["hint"]


# -- 5. HTTP disconnect watcher --------------------------------------------
def _wait(watcher, seconds=1.5):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if watcher.cancel_event.is_set():
            return True
        time.sleep(0.02)
    return False


def test_watcher_arms_on_peer_eof():
    a, b = socket.socketpair()
    watcher = srv._ClientDisconnectWatcher(a)
    watcher.start()
    try:
        assert watcher.active is True
        b.close()                         # empty buffer, like a read request
        assert _wait(watcher), "EOF must arm the cancel event"
    finally:
        watcher.stop()
        a.close()
    assert not watcher._thread.is_alive()


def test_watcher_ignores_an_alive_peer_and_pipelined_data():
    a, b = socket.socketpair()
    watcher = srv._ClientDisconnectWatcher(a)
    watcher.start()
    try:
        time.sleep(0.5)
        assert not watcher.cancel_event.is_set()
        b.send(b"GET /next HTTP/1.1\r\n")  # readable != disconnected
        time.sleep(0.5)
        assert not watcher.cancel_event.is_set()
    finally:
        watcher.stop()
        b.close()
        a.close()


@pytest.mark.parametrize("sock", [None, object()])
def test_watcher_is_opt_in_without_a_real_socket(sock):
    watcher = srv._ClientDisconnectWatcher(sock)
    watcher.start()
    watcher.stop()
    assert watcher.active is False
    assert not watcher.cancel_event.is_set()


def _install_requests(monkeypatch):
    """Real _make_requester -> _RequestGuard over a counting fake socket."""
    class _FakeRequester:
        def __init__(self):
            self.calls = 0

        def request(self, *a, **k):
            self.calls += 1

        def get(self, *a, **k):
            self.calls += 1

        def post(self, *a, **k):
            self.calls += 1

    class _FakeScanner:
        def __init__(self, **kw):
            self.requester = kw["requester"]
            self.findings = []
            self.requests_made = 0
            self.waf_name = None

        def scan_target(self, *a, **k):
            for _ in range(5):
                self.requester.get("http://127.0.0.1/")

        def dedup(self):
            pass

    fake = _FakeRequester()
    monkeypatch.setattr("xssentinel.api.server._build_requester",
                        lambda cfg: fake)
    monkeypatch.setattr("xssentinel.core.scanner.Scanner", _FakeScanner)
    monkeypatch.setattr(m, "_preflight", lambda *a, **k: None)
    return fake


def test_disconnected_client_sends_zero_requests_and_gets_no_answer(monkeypatch):
    fake = _install_requests(monkeypatch)
    cancelled = threading.Event()
    cancelled.set()
    # REAL chain: dispatch -> run_scan_tool -> _make_requester -> guard.
    assert dispatch_message(_frame(), cancel_event=cancelled) is None
    assert fake.calls == 0, "no payload may leave after a disconnect"


def test_alive_client_still_runs_the_same_chain(monkeypatch):
    """Control: the zero above is caused by cancellation, not by a stub."""
    fake = _install_requests(monkeypatch)
    alive = threading.Event()
    response = dispatch_message(_frame(), cancel_event=alive)
    assert response is not None
    assert not response["result"].get("isError")
    assert fake.calls == 5


class _Ctx:
    api_key_valid = True
    headers: dict = {}

    class handler:  # noqa: N801 -- mirrors the attribute name on RequestCtx
        connection = object()


def test_only_a_tools_call_arms_the_http_watcher(monkeypatch):
    seen = []

    class _SpyWatcher:
        def __init__(self, sock):
            seen.append(sock)
            self.cancel_event = threading.Event()
            self.active = False

        def start(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(srv, "_ClientDisconnectWatcher", _SpyWatcher)
    srv._handle_mcp(_Ctx(), None,
                    {"jsonrpc": "2.0", "id": 1, "method": "ping"}, {})
    assert seen == [None], "a ping needs no disconnect watcher"
    # Unknown tool: real dispatch, zero requests, but still a tools/call.
    srv._handle_mcp(_Ctx(), None, {
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "does_not_exist", "arguments": {}}}, {})
    assert len(seen) == 2 and seen[-1] is _Ctx.handler.connection


# -- 6. source-level wiring assertions -------------------------------------
def test_dispatch_forwards_the_era_to_the_one_negotiation_point():
    src = inspect.getsource(m.dispatch_message)
    assert _calls_with_keyword(src, "_tool_call", "modern"), (
        "the modern/legacy decision must reach _tool_call")
    assert "modern=modern" in src


def test_http_handler_forwards_the_cancel_event_and_owns_the_watcher():
    src = inspect.getsource(srv._handle_mcp)
    assert _calls_with_keyword(src, "dispatch_message", "cancel_event"), (
        "a watcher that is not wired into dispatch cannot abort anything")
    assert "_ClientDisconnectWatcher(" in src
    assert "watcher.start()" in src and "watcher.stop()" in src
    assert "finally:" in src
    ctx_src = inspect.getsource(srv._StdlibHandler._dispatch)
    assert "handler=self" in ctx_src, "the HTTP handler owns the only socket"
