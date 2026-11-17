"""Phase 400: GET cache WRITE condition must mirror the READ condition.

Root cause (measured, benchmark/results/phase400_*_20261117.json):
``Requester.get()`` skips the cache READ when a per-request ``headers`` is
present (line 609 ``not headers``), but the cache WRITE (line 628) omitted
``not headers``.  So a header-carrying canary request -- even though it never
reads the cache -- WRITES its response into the LRU under the bare URL.  When
that response is a login page (L8_cookie canary bounced to /login), every
subsequent bare-URL GET from advanced layers / crawler / stored paths silently
receives the stale login page despite the operator session being authenticated
and intact (Phase 394 pin reassert keeps the jar correct).

Phase 396 fixed only ONE reader (``scan_stored_auto`` -> cache_get=False).
This guard fixes the SOURCE: header-varying requests must not write the cache,
exactly as they must not read it.  One change protects all readers.

Real Requester + real loopback server, no stubs.  Loopback bypasses the
injected egress proxy (Phase 392 lesson).
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from xssentinel.core.requester import Requester

_AUTH = (b'<html><body><form method="POST" action="/profile">'
         b'<input name="firstName"></form><div>bankRouting</div></body></html>')
_LOGIN = (b'<html><body><form method="POST" action="/login">'
          b'<input name="userName"></form></body></html>')


class _H(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 (BaseHTTPRequestHandler contract)
        cookie = self.headers.get("Cookie") or ""
        body = _AUTH if "connect.sid=good" in cookie else _LOGIN
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def target(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy",
                 "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/profile"
    srv.shutdown()


def _authed(req: Requester) -> Requester:
    req.session.cookies.set("connect.sid", "good",
                            domain="127.0.0.1", path="/")
    req._pinned_cookies = list(req.session.cookies)
    return req


def test_header_varying_request_does_not_write_cache(target):
    """A header-carrying canary response must not enter the LRU."""
    req = _authed(Requester(timeout=5))
    req.get(target, headers={"Cookie": "connect.sid=evil"})
    assert target not in req._cache, (
        "header-varying GET wrote its response into the bare-URL cache; "
        "write condition must mirror the read condition's 'not headers'")


def test_bare_get_not_poisoned_by_prior_header_canary(target):
    """End-to-end: after a bounced canary, a bare GET sees the AUTH page."""
    req = _authed(Requester(timeout=5))
    req.get(target, headers={"Cookie": "connect.sid=evil"})  # bounced -> LOGIN
    bare = req.get(target)  # operator session is 'good'
    assert "bankRouting" in (bare.text or ""), (
        "bare GET ate the stale login page written by the canary")
    assert 'name="userName"' not in (bare.text or "")


def test_bare_get_still_writes_cache_regression(target):
    """Guard is not vacuous: ordinary bare GETs must still populate cache."""
    req = _authed(Requester(timeout=5))
    req.get(target)  # bare, authenticated -> AUTH
    assert target in req._cache, "bare GET must still write cache (regression)"
    h0 = req.cache_hits
    req.get(target)
    assert req.cache_hits > h0, "second bare GET must be a cache hit"


def test_cache_read_condition_unchanged_for_headers(target):
    """Read side must keep skipping cache for header-varying requests."""
    req = _authed(Requester(timeout=5))
    req.get(target)  # seed cache with AUTH page
    h0 = req.cache_hits
    req.get(target, headers={"Cookie": "connect.sid=evil"})
    assert req.cache_hits == h0, (
        "header-varying GET must not READ from cache (read contract unchanged)")
