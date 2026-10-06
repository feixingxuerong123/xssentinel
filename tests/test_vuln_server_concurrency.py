# -*- coding: utf-8 -*-
"""The vuln_server fixture must serve a second client WHILE one keeps-alive.

Phase 200 -- what actually happened: `python -m xssentinel --self-test`
exceeded its 900s bound twice (once under load, once on an idle machine).
Measured chain:

  * tests/vuln_server.py ran a single-thread ``HTTPServer`` with
    ``protocol_version = "HTTP/1.1"`` and no handler ``timeout``.  The
    scanner's requests.Session keeps its connection open between phases;
    the one server thread then parks in ``readline`` waiting for THAT
    connection's next request and never reaches ``accept()`` again.
  * netstat during the wedge: LISTENER plus several ESTABLISHED sockets,
    every NEW client (browser goto, PowerShell probe) timing out -- the
    concurrency probe's control case could not be served either.
  * the browser's ``goto`` burned its whole budget against that backlog,
    and the follow-up ``page.evaluate`` then blocked 436s in the field
    (763s in the controlled probe, dev/_silent_nav_probe.py).

PROJECT.md already codifies "lab services must be ThreadingHTTPServer AND
the handler must carry a timeout" for benchmark/server.py.  This file pins
the same contract for the self-test fixture, behaviourally:

  A  starvation regression: hold one keep-alive connection, a second
     client must still be served -- with a mutation control that runs the
     SAME scenario against the old single-thread server and asserts it
     times out, so the test cannot go green by accident;
  B  side-channel atomicity: /header-reflect reads ``_LAST_QUERY``, which
     used to be safe only because the server was single-threaded.  The
     lock is asserted DIRECTLY (the handler runs under
     ``_SIDE_CHANNEL_LOCK``) plus a concurrent distinct-UA sweep;
  C  handler timeout present (half-open connections must not pin threads).
"""
from __future__ import annotations

import http.client
import os
import socket
import sys
import threading
import time
from http.server import HTTPServer, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests import vuln_server  # noqa: E402

# Client B's window in scenario A.  Must be well under H.timeout (10s):
# the mutation control relies on the single-thread server still being
# blocked in the holder's readline for that whole window.
_SECOND_CLIENT_BUDGET_S = 5.0


def _start(server) -> int:
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    # Health-check instead of a blind sleep: the wedge under test is
    # precisely "server looks up but does not answer", so readiness must
    # be PROVED by a completed request.
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            conn.request("GET", "/safe?q=ping")
            resp = conn.getresponse()
            resp.read()
            conn.close()
            if resp.status == 200:
                return port
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("fixture server never answered its health check")


def _hold_keepalive(port: int) -> http.client.HTTPConnection:
    """Complete one request and leave the connection open (the wedge shape)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", "/echo?q=hold")
    resp = conn.getresponse()
    body = resp.read()
    assert resp.status == 200 and b"hold" in body
    # HTTP/1.1 default is keep-alive; do NOT close -- this is the client
    # that starved every other one on the old server.
    assert resp.getheader("Connection", "keep-alive").lower() != "close"
    return conn


def _second_client(port: int, timeout: float) -> tuple[int, bytes, float]:
    """One GET /header-reflect with a marker UA.  Returns (status, body, secs)."""
    t0 = time.monotonic()
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request("GET", "/header-reflect",
                     headers={"User-Agent": "probe-second-client"})
        resp = conn.getresponse()
        body = resp.read()
        return resp.status, body, time.monotonic() - t0
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# A. starvation: second client served while the first holds a keep-alive
# ---------------------------------------------------------------------------

def test_second_client_served_while_keepalive_held():
    server = ThreadingHTTPServer(("127.0.0.1", 0), vuln_server.H)
    port = _start(server)
    holder = None
    try:
        holder = _hold_keepalive(port)
        status, body, secs = _second_client(port, _SECOND_CLIENT_BUDGET_S)
        assert status == 200, f"second client not served in {secs:.1f}s"
        assert b"probe-second-client" in body, (
            "second client got a response, but not one for its own request")
        assert secs < _SECOND_CLIENT_BUDGET_S
    finally:
        if holder is not None:
            holder.close()
        server.shutdown()


def test_single_thread_server_still_starves_mutation_control():
    """Mutation control for A: the OLD shape must still exhibit the wedge.

    If this ever starts passing, either the scenario stopped reproducing
    the defect or the fixture changed shape -- either way A's green no
    longer proves anything and the control must be re-derived, not
    deleted.
    """
    # audit: single-thread reconstruction is THE point of this control
    server = HTTPServer(("127.0.0.1", 0), vuln_server.H)  # audit: mutation control
    port = _start(server)
    holder = None
    try:
        holder = _hold_keepalive(port)
        with pytest.raises((socket.timeout, TimeoutError,
                            ConnectionError, OSError)):
            # 3s: well inside H.timeout=10s, so the single thread is still
            # blocked on the holder and cannot accept client B.
            _second_client(port, 3.0)
    finally:
        if holder is not None:
            holder.close()
        server.shutdown()


# ---------------------------------------------------------------------------
# B. side-channel atomicity under the new threading model
# ---------------------------------------------------------------------------

def test_request_handling_runs_under_side_channel_lock(monkeypatch):
    """Every request's set->handle->respond section holds the lock.

    Direct contract: plant a handler that reports whether the lock is
    held.  Deterministic -- no race needed to see it.
    """
    seen = {}

    def _probe(q: str):
        seen["locked"] = vuln_server._SIDE_CHANNEL_LOCK.locked()
        return ("ok", 200, "text/plain")

    monkeypatch.setitem(vuln_server.PAGES, "/__lockcheck", _probe)
    server = ThreadingHTTPServer(("127.0.0.1", 0), vuln_server.H)
    port = _start(server)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/__lockcheck")
        resp = conn.getresponse()
        assert resp.status == 200
        resp.read()
        conn.close()
    finally:
        server.shutdown()
    assert seen.get("locked") is True, (
        "handler ran WITHOUT _SIDE_CHANNEL_LOCK held: concurrent requests "
        "would cross-contaminate _LAST_QUERY (ua/raw_body/cookie_theme)")


def test_concurrent_distinct_ua_no_cross_talk():
    """N concurrent /header-reflect calls must each echo their OWN UA.

    This is the semantic the lock exists to preserve: before threading it
    came for free from single-thread ordering; now it has to come from
    the lock.  16 threads x 1 request: under the lock the result is
    deterministic, so this is a regression net rather than a race probe.
    """
    server = ThreadingHTTPServer(("127.0.0.1", 0), vuln_server.H)
    port = _start(server)
    results: dict[str, bytes] = {}
    errors: list[Exception] = []
    barrier = threading.Barrier(16)

    def worker(i: int):
        ua = f"agent-{i:02d}"
        try:
            barrier.wait(timeout=10)
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
            conn.request("GET", "/header-reflect",
                         headers={"User-Agent": ua})
            resp = conn.getresponse()
            results[ua] = resp.read()
            conn.close()
        except Exception as exc:  # noqa: BLE001 -- collected for assertion
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert not errors, f"workers failed: {errors!r}"
        assert len(results) == 16, f"only {len(results)}/16 answered"
        for ua, body in results.items():
            assert ua.encode() in body, (
                f"{ua} got a body echoing a DIFFERENT request's UA: "
                f"{body[:120]!r} -- side channel crossed under concurrency")
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# C. handler timeout present
# ---------------------------------------------------------------------------

def test_handler_carries_socket_timeout():
    assert getattr(vuln_server.H, "timeout", None), (
        "vuln_server.H must set a socket timeout: without it a half-open "
        "connection (killed scanner, aborted browser tab) pins its thread "
        "in readline forever -- PROJECT.md lab-service rule")


def test_main_entry_uses_threading_server():
    """The __main__ entry point must keep the threading shape (textual pin).

    Behavioural coverage above exercises H on ThreadingHTTPServer directly;
    this pins the WIRING in tests/vuln_server.py::__main__, which no
    in-process test executes.
    """
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(here, "tests", "vuln_server.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    assert "ThreadingHTTPServer((" in src, (
        "__main__ must construct ThreadingHTTPServer")
    # A bare single-thread construction for H is the defect class itself.
    # Match the call START (ThreadingHTTPServer( contains HTTPServer( as a
    # substring, so a plain `in` check would flag the fixed line too).
    import re as _re
    assert not _re.search(r"(?<![\w.])HTTPServer\s*\(\(", src), (
        "found a bare HTTPServer( construction -- must be Threading")
