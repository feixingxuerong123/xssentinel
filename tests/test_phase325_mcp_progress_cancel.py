# -*- coding: utf-8 -*-
"""Phase 325: MCP progress notifications + cancellation (stdio transport).

Before this phase the stdio loop was synchronous: a ``tools/call`` ran
inline, so the read loop was deaf during the only call that takes long --
a ``notifications/cancelled`` sent while a scan was running could never
arrive, and an agent had no progress signal at all.  Now:

  * ``tools/call`` runs on a worker thread; the read loop keeps listening;
  * a request carrying ``_meta.progressToken`` gets
    ``notifications/progress`` (requests sent, rate-limited, plus a start
    beacon at 0);
  * ``notifications/cancelled`` aborts the runner at its next request and
    the request gets NO response (the MCP spec's rule).

The HTTP transport is request/response and does not claim either.
"""
from __future__ import annotations

import io
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.api.mcp_server import (                        # noqa: E402
    MCPServer, _RequestGuard, _ToolCancelled, dispatch_message)

REQ = {"jsonrpc": "2.0", "id": 1}


# ---------------------------------------------------------------------------
# harness
# ---------------------------------------------------------------------------
def _session(server: MCPServer, *msgs: dict) -> list[dict]:
    inn = io.StringIO("".join(json.dumps(m) + "\n" for m in msgs))
    out = io.StringIO()
    server._stdin, server._stdout = inn, out
    server.serve()
    return [json.loads(ln) for ln in out.getvalue().splitlines()]


class _SlowHandler(BaseHTTPRequestHandler):
    """Loopback page that reflects q, slowly (0.3 s per request)."""

    delay = 0.3

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        time.sleep(self.delay)
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


def _start_slow(delay=0.3):
    _SlowHandler.delay = delay
    server = ThreadingHTTPServer(("127.0.0.1", 0), _SlowHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.2)
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def _profile_msg(mid, base, token=None):
    params = {"name": "xssentinel_profile",
              "arguments": {"url": base + "/", "param": "q"}}
    if token is not None:
        params["_meta"] = {"progressToken": token}
    return {"jsonrpc": "2.0", "id": mid, "method": "tools/call",
            "params": params}


# ---------------------------------------------------------------------------
# 1. progress notifications
# ---------------------------------------------------------------------------
def test_progress_token_gets_notifications_and_the_response():
    srv, base = _start_slow(0.05)
    try:
        out = _session(MCPServer(), _profile_msg(1, base, token="tok-1"))
        notes = [m for m in out if m.get("method") == "notifications/progress"]
        responses = [m for m in out if "result" in m]
        assert responses, out
        assert responses[0]["id"] == 1
        assert notes, "a progressToken must produce progress notifications"
        for n in notes:
            assert n["params"]["progressToken"] == "tok-1"
            assert isinstance(n["params"]["progress"], int)
        # the first beacon is the start marker at 0
        assert notes[0]["params"]["progress"] == 0, notes[0]
        assert "started" in notes[0]["params"].get("message", "")
        # and at least one request-count update follows
        assert any(n["params"]["progress"] >= 1 for n in notes), notes
    finally:
        srv.shutdown()
        srv.server_close()


def test_no_progress_token_means_no_notifications():
    srv, base = _start_slow(0.05)
    try:
        out = _session(MCPServer(), _profile_msg(1, base))
        assert not [m for m in out if m.get("method")], out
        assert [m for m in out if "result" in m], out
    finally:
        srv.shutdown()
        srv.server_close()


def test_progress_emitter_writes_wellformed_jsonrpc():
    out = io.StringIO()
    srv = MCPServer(stdout=out)
    emit = srv._progress_emitter("t9")
    emit(3, 10, "three requests")
    line = json.loads(out.getvalue().strip())
    assert line == {"jsonrpc": "2.0",
                    "method": "notifications/progress",
                    "params": {"progressToken": "t9", "progress": 3,
                               "total": 10, "message": "three requests"}}


# ---------------------------------------------------------------------------
# 2. the request guard (the thing that checks cancel + counts)
# ---------------------------------------------------------------------------
class _FakeInner:
    def __init__(self):
        self.calls = []

    def request(self, method, url, *a, **kw):
        self.calls.append((method, url))
        return "resp"


def test_guard_counts_requests_and_emits_totalless_progress():
    inner = _FakeInner()
    got = []
    guard = _RequestGuard(inner, None, lambda p, t: got.append((p, t)),
                          min_interval=0)
    assert guard.request("GET", "http://t/a") == "resp"
    assert guard.request("GET", "http://t/b") == "resp"
    assert guard.count == 2
    assert got == [(1, None), (2, None)]
    assert [c[1] for c in inner.calls] == ["http://t/a", "http://t/b"]


def test_guard_raises_the_base_exception_cancellation():
    """``_ToolCancelled`` must NOT be an ``Exception`` subclass: a runner's
    broad ``except Exception`` arms would otherwise turn a cancellation
    into a normal error result."""
    event = threading.Event()
    event.set()
    guard = _RequestGuard(_FakeInner(), event, None)
    try:
        guard.request("GET", "http://t/")
        raise AssertionError("guard must raise once cancelled")
    except _ToolCancelled as e:
        assert not isinstance(e, Exception)


def test_guard_passes_through_other_attributes():
    inner = _FakeInner()
    inner.headers = {"X-Test": "1"}
    guard = _RequestGuard(inner, None, None)
    assert guard.headers == {"X-Test": "1"}


# ---------------------------------------------------------------------------
# 3. cancellation semantics
# ---------------------------------------------------------------------------
def test_cancelled_dispatch_answers_nothing():
    srv, base = _start_slow(0.05)
    try:
        event = threading.Event()
        event.set()
        msg = _profile_msg(1, base)
        assert dispatch_message(msg, cancel_event=event) is None
    finally:
        srv.shutdown()
        srv.server_close()


def test_cancel_notification_suppresses_the_response():
    """End to end: the cancel line is read while the tool call runs, the
    runner aborts at its next request, and NO response is written."""
    srv, base = _start_slow(0.3)
    try:
        out = io.StringIO()
        server = MCPServer(stdout=out)
        inn = io.StringIO(
            json.dumps(_profile_msg(1, base)) + "\n"
            + json.dumps({"jsonrpc": "2.0",
                          "method": "notifications/cancelled",
                          "params": {"requestId": 1,
                                     "reason": "agent changed plan"}}) + "\n")
        server._stdin = inn
        t0 = time.monotonic()
        server.serve()
        elapsed = time.monotonic() - t0
        lines = [json.loads(ln) for ln in out.getvalue().splitlines() if ln]
        assert not [m for m in lines if m.get("id") == 1], lines
        # the single in-flight request is the bound: ~0.3 s, not unbounded
        assert elapsed < 5.0, elapsed
    finally:
        srv.shutdown()
        srv.server_close()


def test_cancel_of_unknown_request_id_is_ignored():
    out = io.StringIO()
    server = MCPServer(stdout=out)
    server._stdin = io.StringIO(
        json.dumps({"jsonrpc": "2.0", "method": "notifications/cancelled",
                    "params": {"requestId": 999}}) + "\n"
        + json.dumps({**REQ, "method": "ping"}) + "\n")
    server.serve()
    lines = [json.loads(ln) for ln in out.getvalue().splitlines() if ln]
    assert lines == [{"jsonrpc": "2.0", "id": 1, "result": {}}]


# ---------------------------------------------------------------------------
# 4. the read loop keeps listening while a tool call runs
# ---------------------------------------------------------------------------
def test_ping_is_answered_while_a_slow_tool_call_runs():
    """The whole point of the worker thread: a slow scan must not make the
    server deaf.  Ping is answered without waiting for the tool call."""
    srv, base = _start_slow(0.5)
    try:
        out = io.StringIO()
        server = MCPServer(stdout=out)
        server._stdin = io.StringIO(
            json.dumps(_profile_msg(1, base)) + "\n"
            + json.dumps({**REQ, "method": "ping", "id": 2}) + "\n")
        t0 = time.monotonic()
        server.serve()
        elapsed = time.monotonic() - t0
        lines = [json.loads(ln) for ln in out.getvalue().splitlines() if ln]
        ids = [m.get("id") for m in lines]
        assert 1 in ids and 2 in ids, lines
        # ping answered first (it does not queue behind the 0.5 s call)
        assert ids.index(2) < ids.index(1), lines
        assert elapsed < 10.0, elapsed
    finally:
        srv.shutdown()
        srv.server_close()


# ---------------------------------------------------------------------------
# 5. HTTP transport does not pretend to stream
# ---------------------------------------------------------------------------
def test_http_path_takes_no_progress_or_cancel_controls():
    """dispatch_message without the stdio kwargs is the HTTP path: it must
    answer normally even when the client sent a progressToken (the token
    is simply unused -- no stream exists there)."""
    srv, base = _start_slow(0.05)
    try:
        msg = _profile_msg(1, base, token="tok-http")
        resp = dispatch_message(msg)
        assert resp["id"] == 1 and "result" in resp
    finally:
        srv.shutdown()
        srv.server_close()
