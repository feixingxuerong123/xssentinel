# -*- coding: utf-8 -*-
"""Phase 383: the MCP authorization boundary (OPTIMIZATION §8.1-1, P0).

Recorded defect: the server trusted "the URL the agent passed = operator
authorization".  An agent is an autonomous subject the scanned page can
prompt-inject, and these tools send real attack payloads -- so the scope
is now pinned by the OPERATOR at server start:

  * ``tofu`` (default) -- the first SUCCESSFUL url-taking call pins its
    origin; later calls to other origins are refused with zero requests.
    A failed call burns no pin.
  * ``allowlist`` -- --allow-host patterns (the CLI import gate's grammar,
    reused via core/scoping).
  * ``open`` -- only via --allow-any-host; discover says so out loud.

The refused call must send NOTHING (the pre-flight probe included), for
BOTH protocol eras (a boundary bypassable by downgrading is a wall with a
door in it), and must not be replayable from the result cache.  With a
scope configured, the sync engine's redirect boundary runs too: a
page-chosen cross-origin hop is recorded in ``boundary_stops`` and the
landing server is never visited -- asserted here by request counting on
real loopback servers, not by trusting the report.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.api import mcp_server as m  # noqa: E402

PAGE = b"<html><body><p>static page</p></body></html>"

_SCAN_ARGS = {"max_payloads": 1, "timeout": 5, "max_seconds": 30}


class _Target:
    """Counting loopback server on port 0: a static page + optional 302s.

    The hit list is the ground truth for "zero requests were sent" -- the
    boundary's promise is checked against the wire, not against the tool's
    own bookkeeping.
    """

    def __init__(self, redirects: dict | None = None):
        self._hits: list = []
        self._lock = threading.Lock()
        self._redirects = dict(redirects or {})
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                with outer._lock:
                    outer._hits.append(self.path)
                loc = outer._redirects.get(self.path)
                if loc is not None:
                    self.send_response(302)
                    self.send_header("Location", loc)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(PAGE)))
                self.end_headers()
                self.wfile.write(PAGE)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self._thread = threading.Thread(target=self.server.serve_forever,
                                        daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/"

    def hit_count(self, prefix: str | None = None) -> int:
        with self._lock:
            return sum(1 for h in self._hits
                       if prefix is None or h.startswith(prefix))

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _call(url: str, modern: bool = True, name: str = "xssentinel_scan",
          args: dict | None = None):
    arguments = dict(_SCAN_ARGS)
    arguments["url"] = url
    if args:
        arguments.update(args)
    params = {"name": name, "arguments": arguments}
    if modern:
        params["_meta"] = {m._META_VERSION_KEY: "2026-07-28"}
    return m.dispatch_message({"jsonrpc": "2.0", "id": 1,
                               "method": "tools/call", "params": params})


def _result(url: str, **kw) -> dict:
    resp = _call(url, **kw)
    assert resp is not None, "cancelled call must not answer"
    return resp["result"]


def _payload(result: dict) -> dict:
    assert not result.get("isError"), result
    return json.loads(result["content"][0]["text"])


def _denied(result: dict) -> str:
    assert result.get("isError"), result
    text = result["content"][0]["text"]
    assert text.startswith("target outside authorized scope:"), text
    return text


def _discover() -> dict:
    resp = m.dispatch_message({"jsonrpc": "2.0", "id": 2,
                               "method": "server/discover"})
    return resp["result"]


# ---------------------------------------------------------------------------
# tofu: pin-on-success, zero-request refusal
# ---------------------------------------------------------------------------
def test_tofu_first_call_pins_and_second_origin_is_refused_zero_requests():
    a, b = _Target(), _Target()
    try:
        m.configure_scope()
        payload = _payload(_result(a.url))
        assert payload["finding_count"] == 0
        second = _result(b.url)
        _denied(second)
        err = (second.get("structuredContent") or {}).get("error") or {}
        assert err.get("code") == "scope_denied", err
        assert err.get("field") == "url"
        assert err.get("retryable") is False
        # Zero requests means zero: the pre-flight probe included.
        assert b.hit_count() == 0, b._hits
        assert str(b.port) in second["content"][0]["text"]
    finally:
        a.stop()
        b.stop()


def test_same_origin_second_call_still_allowed():
    a = _Target()
    try:
        m.configure_scope()
        _payload(_result(a.url))
        _payload(_result(a.url))
    finally:
        a.stop()


def test_failed_first_call_burns_no_pin():
    closed = _closed_port()
    b = _Target()
    c = _Target()
    try:
        m.configure_scope()
        bad = _result(f"http://127.0.0.1:{closed}/")
        assert bad.get("isError"), bad
        # The unreachable first target must not have locked the scope.
        _payload(_result(b.url))
        _denied(_result(c.url))
        assert c.hit_count() == 0
    finally:
        b.stop()
        c.stop()


def test_denial_is_not_replayed_from_cache():
    a, b = _Target(), _Target()
    try:
        m.configure_scope()
        _payload(_result(a.url))          # a real, cacheable success
        first = _result(b.url)
        second = _result(b.url)
        assert _denied(first) == _denied(second)
        assert not second.get("cache_hit"), second
        assert b.hit_count() == 0
    finally:
        a.stop()
        b.stop()


def test_scan_async_submit_refused_out_of_scope():
    a, b = _Target(), _Target()
    try:
        m.configure_scope()
        _payload(_result(a.url))
        refused = _result(b.url, name="xssentinel_scan_async")
        _denied(refused)
        err = (refused.get("structuredContent") or {}).get("error") or {}
        assert err.get("code") == "scope_denied", err
        assert b.hit_count() == 0
    finally:
        a.stop()
        b.stop()


# ---------------------------------------------------------------------------
# allowlist: scoping grammar, host-grained, zero-request refusal
# ---------------------------------------------------------------------------
def test_allowlist_matches_host_across_ports_and_denies_other_hosts():
    a, b = _Target(), _Target()
    try:
        m.configure_scope(["127.0.0.1"])
        _payload(_result(a.url))
        # Same host, different port: the pattern is host-grained, allowed.
        _payload(_result(f"http://127.0.0.1:{b.port}/"))
        # Different host string on the SAME machine -> refused, and the
        # server's counter proves nothing was sent to it.
        hits_before = b.hit_count()
        denied = _result(f"http://localhost:{b.port}/")
        _denied(denied)
        assert b.hit_count() == hits_before
    finally:
        a.stop()
        b.stop()


def test_scope_semantics_reuse_the_scoping_judgment():
    """Unit level: one definition of 'in scope' (core/scoping._matches),
    origin-exact pins, unparseable URLs left to the runner's own check."""
    m.configure_scope([".example.com"])
    assert m._scope_denial("http://a.example.com/x") is None
    assert m._scope_denial("http://example.com/") is None
    assert m._scope_denial("http://evil.com/") is not None
    m.configure_scope()
    m._pin_scope("http://127.0.0.1:5/")
    assert m._scope_denial("http://127.0.0.1:5/") is None
    assert m._scope_denial("http://127.0.0.1:6/") is not None
    assert m._scope_denial("not a url") is None


# ---------------------------------------------------------------------------
# discover: the boundary is data, not silence -- including its absence
# ---------------------------------------------------------------------------
def test_discover_declares_tofu_scope_then_the_pin():
    a = _Target()
    try:
        m.configure_scope()
        disc = _discover()
        assert disc["scope"]["mode"] == "tofu"
        assert disc["scope"]["pinned"] == []
        assert "first-use pinning" in disc["instructions"]
        _payload(_result(a.url))
        after = _discover()
        assert after["scope"]["pinned"] == [f"http://127.0.0.1:{a.port}"]
        assert f"http://127.0.0.1:{a.port}" in after["instructions"]
    finally:
        a.stop()


def test_allow_any_host_is_open_and_disclosed():
    a, b = _Target(), _Target()
    try:
        m.configure_scope(None, allow_any_host=True)
        _payload(_result(a.url))
        _payload(_result(b.url))          # cross-origin, allowed
        disc = _discover()
        assert disc["scope"]["mode"] == "open"
        assert "NO authorization boundary" in disc["instructions"]
    finally:
        a.stop()
        b.stop()


# ---------------------------------------------------------------------------
# legacy frames: the boundary holds, the shape stays legacy
# ---------------------------------------------------------------------------
def test_legacy_frame_denial_keeps_legacy_shape():
    a, b = _Target(), _Target()
    try:
        m.configure_scope()
        _payload(_result(a.url))
        legacy = _result(b.url, modern=False)
        _denied(legacy)
        # Phase 358/372: a legacy error result has no structuredContent.
        assert "structuredContent" not in legacy
        assert b.hit_count() == 0
    finally:
        a.stop()
        b.stop()


# ---------------------------------------------------------------------------
# redirect boundary: the hop is recorded, the landing server never visited
# ---------------------------------------------------------------------------
def test_redirect_boundary_records_stop_and_landing_never_visited():
    b = _Target()
    a = _Target(redirects={"/redir": f"http://127.0.0.1:{b.port}/land"})
    try:
        m.configure_scope()
        payload = _payload(_result(a.url + "redir"))
        assert payload["boundary_stops"] == [
            f"http://127.0.0.1:{b.port}/land"], payload
        assert b.hit_count() == 0, b._hits
    finally:
        a.stop()
        b.stop()


def test_redirect_boundary_does_not_engage_without_a_scope():
    """open mode keeps the pre-383 behaviour: the redirect is followed."""
    b = _Target()
    a = _Target(redirects={"/redir": f"http://127.0.0.1:{b.port}/land"})
    try:
        m.configure_scope(None, allow_any_host=True)
        payload = _payload(_result(a.url + "redir"))
        assert payload["boundary_stops"] == [], payload
        # Followed: the landing server was reached (the pre-flight probe
        # and the scan each walk the chain, so count >= 1, not == 1).
        assert b.hit_count(prefix="/land") >= 1, b._hits
    finally:
        a.stop()
        b.stop()


# ---------------------------------------------------------------------------
# real stdio subprocess: the CLI entry configures from the environment
# ---------------------------------------------------------------------------
def test_real_stdio_subprocess_env_allowlist_and_denial():
    a, b = _Target(), _Target()
    try:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)       # host shim breaks CLI stderr asserts
        env[m._ENV_ALLOW_HOSTS] = "127.0.0.1"
        modern = {"_meta": {m._META_VERSION_KEY: "2026-07-28"}}
        frames = [
            {"jsonrpc": "2.0", "id": 1, "method": "server/discover"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "xssentinel_scan",
                        "arguments": dict(_SCAN_ARGS, url=a.url), **modern}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "xssentinel_scan",
                        "arguments": dict(
                            _SCAN_ARGS, url=f"http://localhost:{b.port}/"),
                        **modern}},
        ]
        wire = b"".join(json.dumps(f, ensure_ascii=False).encode("utf-8")
                        + b"\n" for f in frames)
        proc = subprocess.Popen(
            [sys.executable, "-m", "xssentinel", "mcp"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, cwd=root, env=env)
        out, err = proc.communicate(wire, timeout=120)
        lines = out.decode("utf-8").splitlines()
        assert len(lines) == 3, (lines, err.decode("utf-8", "replace")[-400:])
        # Responses are matched by id, not by line order: tools/call runs
        # on the transport's worker pool, so the slow scan (id 2) and the
        # fast refusal (id 3) finish in either order.
        by_id = {json.loads(line)["id"]: json.loads(line)["result"]
                 for line in lines}
        disc, ok, refused = by_id[1], by_id[2], by_id[3]
        assert disc["scope"]["mode"] == "allowlist", disc
        payload = json.loads(ok["content"][0]["text"])
        assert payload["finding_count"] == 0, payload
        _denied(refused)
        assert b.hit_count() == 0, b._hits
    finally:
        a.stop()
        b.stop()
