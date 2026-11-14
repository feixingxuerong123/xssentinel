"""Phase 396: stored-auto must fetch the write page under the *operator's* session.

Measured on live OWASP NodeGoat
(``benchmark/results/phase396_stored_trace_20261115_{baseline,fix}.json``):
an L8_cookie canary request legitimately bounced to /login and its 200
response was cached under the bare /profile URL. ``scan_stored_auto`` used the
default ``cache_get=True``, read that stale LOGIN page, found only a login form
(``_AUTO_SKIP_FORM``) and silently ran zero writes -- ``_send`` was never
called. With ``cache_get=False`` the same scan found 1 write face, called
``scan_stored`` and emitted a ``stored`` finding (3 -> 4 findings).

The guard calls the REAL ``StoredAutoMixin.scan_stored_auto`` with a REAL
``Requester`` and a real loopback server. Only ``scan_stored`` is stubbed: the
real one would fire the entire payload ladder. The stub records its kwargs and
returns False, which is the real method's "not confirmed" contract; it never
touches the requester, so it cannot change the fetch being measured.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from xssentinel.core.coverage import CoverageTracker
from xssentinel.core.requester import Requester
from xssentinel.core.scanner_stored_auto import StoredAutoMixin

_LOGIN = (b'<html><form method="POST" action="/login">'
          b'<input name="userName"><input type="password" name="password">'
          b'</form></html>')
_AUTH = (b'<html><form method="POST" action="/profile">'
         b'<input type="text" name="firstName">'
         b'<input type="text" name="lastName">'
         b'</form></html>')


class _Handler(BaseHTTPRequestHandler):
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
    # loopback must not be routed through the injected egress proxy
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.delenv(name, raising=False)
    srv = HTTPServer(("127.0.0.1", 0), _Handler)  # port 0: outside the
    # Windows excluded range 18923-19822 (measured Phase 393)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}/profile"
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=5)


class _Scanner(StoredAutoMixin):
    """Minimal host object: real mixin method, real requester, real coverage."""

    def __init__(self, req):
        self.req = req
        self.coverage = CoverageTracker()
        self.stored_auto = True
        self.verbose = False
        self.requests_made = 0
        self.calls: list[dict] = []

    def _bump(self):
        self.requests_made += 1

    def scan_stored(self, *args, **kw):
        self.calls.append(dict(kw, inject_url=args[0] if args else None))
        return False


def _auth(req: Requester):
    """Operator session arrives after the poisoning request (as 394's pin does)."""
    req.session.cookies.set("connect.sid", "good", domain="127.0.0.1", path="/")


def test_poisoned_cache_does_not_hide_write_face(target):
    req = Requester(timeout=5)
    cold = req.get(target)                 # unauthenticated -> login page
    assert b"userName" in cold.content    # and it IS cached (status 200, bare URL)
    assert req.cache_hits == 0

    _auth(req)
    # CONTROL: a normal cached GET under the now-authenticated session still
    # returns the stale login page. If this were not true, the guard would be
    # vacuous (the variant could pass without any fix).
    stale = req.get(target)
    assert b"userName" in stale.content
    assert req.cache_hits >= 1

    sc = _Scanner(req)
    hits_before, sends_before = req.cache_hits, req.tally.attempted
    ran = sc.scan_stored_auto(target)

    assert ran >= 1, "the stored pass must exercise the real write face"
    assert len(sc.calls) >= 1
    assert sc.calls[0]["param"] == "firstName"   # from _AUTH, not _LOGIN
    assert sc.calls[0]["inject_url"] == target
    assert req.cache_hits == hits_before, "auto fetch must not consume the cache"
    assert req.tally.attempted > sends_before, "auto fetch must issue a real GET"


def test_clean_cache_path_unchanged(target):
    req = Requester(timeout=5, cookies={"connect.sid": "good"})
    sc = _Scanner(req)
    assert sc.scan_stored_auto(target) >= 1
    assert sc.calls[0]["param"] == "firstName"


def test_explicit_page_text_never_fetches(target):
    req = Requester(timeout=5)
    sc = _Scanner(req)
    sends_before = req.tally.attempted
    assert sc.scan_stored_auto(target, page_text=_AUTH.decode()) >= 1
    assert req.tally.attempted == sends_before
    assert sc.calls[0]["param"] == "firstName"


def test_source_contract_auto_fetch_bypasses_cache():
    """The variant must have exactly one behavioural anchor to flip.

    Phase 394 lesson: a function body does not rot, its *call sites* do. This
    pins the single page-fetch call site; dev/phase396_mutations.py proves the
    guard goes red when the kwarg is removed.
    """
    import inspect
    from xssentinel.core import scanner_stored_auto as mod

    src = inspect.getsource(mod.StoredAutoMixin.scan_stored_auto)
    assert src.count("self.req.get(page_url, cache_get=False)") == 1
    assert src.count("self.req.get(") == 1
    # Every stored viewer GET uses the same freshness contract (no second
    # hand-rolled copy that silently defaults back to the LRU).
    stored_src = (mod.__file__.replace("scanner_stored_auto.py",
                                       "scanner_stored.py"))
    from pathlib import Path
    text = Path(stored_src).read_text(encoding="utf-8")
    assert "get(cand, cache_get=False)" in text
    assert "get(view_url, cache_get=False)" in text
