"""Phase 200: the async engine's sync-layer transport is HERMETIC.

The L7 advanced layers / crawl mining / transport layers probe through a
thread-offloaded SYNC Requester (`_get_sync_requester`).  That requester
hits the real network -- legitimate under a live scan, but tests that
drive the probe pipeline with stub sessions leaked those probes to
whatever fake host the test named: each unresolvable lookup cost seconds
of DNS timeout on a degraded resolver (measured: 6 leaked requests x
7-11s = the "55s per _probe_param" that OPTIMIZATION 3.8 first recorded
as a mystery "verdict CPU" cost).  The guard makes the leak a refusal,
which is the truthful verdict for a scan with no real transport.
"""
from __future__ import annotations

import asyncio
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_PAGE = ('<!DOCTYPE html><html><body><form><input name=q value="">'
         '</form></body></html>')


class _Resp:
    def __init__(self, text):
        self._t = text
        self.status = 200
        self.headers = {"Content-Type": "text/html; charset=utf-8"}

    async def text(self):
        return self._t

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _StubSession:
    def __init__(self):
        self.n = 0

    def request(self, method, url, params=None, headers=None, proxy=None,
                **kw):
        self.n += 1
        return _Resp(_PAGE)

    def get(self, url, **kw):
        return self.request("GET", url, **kw)


@pytest.fixture()
def count_real_sends(monkeypatch):
    """Count every REAL request the `requests` library would put on the
    wire for the duration of one test."""
    sent = {"n": 0}
    import requests.adapters
    orig = requests.adapters.HTTPAdapter.send

    def traced(self, request, *a, **k):
        sent["n"] += 1
        return orig(self, request, *a, **k)

    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", traced)
    return sent


def test_stub_session_probe_leaks_zero_real_requests(count_real_sends):
    """The regression this phase exists for: a fully stubbed probe pipeline
    with advanced layers on must make ZERO real-network requests."""
    from xssentinel.core.async_scanner import AsyncScanner

    async def run():
        asc = AsyncScanner(max_concurrent=2, per_host_delay=0, jitter=0,
                           timeout=5, max_payloads=3, max_transforms=2,
                           advanced_layers=True)
        asc._semaphore = asyncio.Semaphore(2)
        s = _StubSession()
        async for _f in asc._probe_param(s, "http://t/search", "GET", "q",
                                         {"q": "probe"}, {}, False, _PAGE):
            pass
        return s.n

    stub_calls = asyncio.run(run())
    assert stub_calls > 0                    # the pipeline itself ran
    assert count_real_sends["n"] == 0, (
        f"{count_real_sends['n']} real-network request(s) leaked from a "
        f"stubbed-session probe (the L7 sync layers used a real "
        f"Requester)")


def test_offline_transport_refuses_sending_but_constructs():
    """Construction stays legal (wiring tests capture the requester);
    SENDING is what the guard refuses."""
    from xssentinel.core.async_scanner import AsyncScanner

    asc = AsyncScanner(max_concurrent=2, per_host_delay=0, jitter=0,
                       timeout=5, advanced_layers=True)
    assert not getattr(asc, "_sync_layers_online", False)
    req = asc._get_sync_requester()
    with pytest.raises(RuntimeError, match="sync-layer transport is offline"):
        req.session.request("GET", "http://t/search")
    # and no real adapter was ever reached for the refused request
    with pytest.raises(RuntimeError, match="sync-layer transport is offline"):
        req.request("GET", "http://t/search")


def test_live_scan_sets_the_transport_flag():
    """The production path (real aiohttp session) must arm the sync-layer
    transport -- the layers are part of the scan's detection surface."""
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session (security software/TCP state)")

    class _H(BaseHTTPRequestHandler):
        def do_GET(self):
            body = _PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.2)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        from xssentinel.core.async_scanner import AsyncScanner

        async def run():
            asc = AsyncScanner(max_concurrent=2, per_host_delay=0, jitter=0,
                               timeout=8, advanced_layers=True)
            async for _f in asc.scan(base + "/", params={"q": "probe"}):
                pass
            return asc

        asc = asyncio.run(run())
        assert getattr(asc, "_sync_layers_online", False) is True
    finally:
        server.shutdown()
        server.server_close()
