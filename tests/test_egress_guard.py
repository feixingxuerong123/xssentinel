# -*- coding: utf-8 -*-
"""Phase 189: credentials belong to the origins the operator named.

Why this exists: both engines let the *scanned page* decide where the
operator's secrets go.  A ``Location: http://attacker.example/`` was enough
to ship ``-H "X-Api-Key: ..."`` and ``--cookie sid=...`` to a third party --
the same class of defect disclosed for Dalfox as GHSA-mph2-gf5w-6f9f.

These tests are end-to-end against two real loopback origins rather than
mocks, because the whole bug lives in what the HTTP client actually puts on
the wire after a redirect:

* requests 2.32.5 / urllib3 2.6.3 strip ``Authorization`` and a header-named
  ``Cookie`` only when the **host string** changes, and never strip a custom
  header or a domain-less session cookie;
* aiohttp 3.13.3 strips nothing, and applies its cookie jar *after*
  ``on_request_redirect`` fires -- so the jar needs its own gate, which is
  why this file asserts on cookies as well as headers.
"""
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from tests.conftest import loopback_healthy  # noqa: E402
from xssentinel.core.egress import EgressPolicy, origin, same_origin  # noqa: E402
from xssentinel.core.requester import Requester  # noqa: E402

# Lower-cased because the landing pad reads what it receives case-insensitively.
SENTINELS = {
    "x-api-key": "SECRET-API-KEY",
    "authorization": "Bearer SECRET-BEARER",
    "x-tenant": "SECRET-TENANT",
}


def _landing_headers():
    """The headers the LAST origin in a chain actually received."""
    return dict(_State.landed[-1]) if _State.landed else {}


class _State:
    landed = []      # headers seen by the landing origin
    visits = []      # every path requested, in order


class _Handler(BaseHTTPRequestHandler):
    """Redirector + landing pad.  ``?to=`` chooses the next hop's origin."""

    def do_GET(self):
        _State.visits.append(self.path)
        if self.path.startswith("/land"):
            _State.landed.append(
                {k.lower(): v for k, v in self.headers.items()})
            return self._reply(200, b"landed")
        if self.path.startswith("/redir-cross"):
            # Hops to the *other* origin (host string AND port differ), which
            # is what urllib3's host-string comparison and aiohttp both let
            # through unfiltered.
            return self._redirect(_State.cross)
        if self.path.startswith("/redir-same"):
            return self._redirect(f"http://{self.headers['Host']}/land")
        return self._reply(200, b"direct")

    def _redirect(self, target):
        _State.landed.append(
            {k.lower(): v for k, v in self.headers.items()})
        self.send_response(302)
        self.send_header("Location", target)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _reply(self, code, body):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def pair():
    """Two distinct origins: ``localhost:P1`` and ``127.0.0.1:P2``."""
    if not loopback_healthy():
        pytest.skip("loopback degraded on this host")
    _State.landed.clear()
    _State.visits.clear()
    edge = HTTPServer(("localhost", 0), _Handler)
    land = HTTPServer(("127.0.0.1", 0), _Handler)
    _State.cross = f"http://127.0.0.1:{land.server_address[1]}/land"
    for srv in (edge, land):
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield (f"http://localhost:{edge.server_address[1]}",
               f"http://127.0.0.1:{land.server_address[1]}")
    finally:
        _State.landed.clear()
        _State.visits.clear()
        edge.shutdown()
        edge.server_close()
        land.shutdown()
        land.server_close()


# ---------------------------------------------------------------------------
# the origin comparison itself
# ---------------------------------------------------------------------------
def test_default_ports_normalize():
    assert origin("http://a.example/x") == origin("http://a.example:80/x")
    assert origin("https://a.example") == ("https", "a.example", 443)
    assert not same_origin("http://a.example", "https://a.example")


def test_host_string_differs_even_for_the_same_machine():
    """Mirrors urllib3: localhost and 127.0.0.1 are different origins."""
    assert not same_origin("http://localhost:8080/x", "http://127.0.0.1:8080/x")


def test_same_host_different_port_is_a_different_origin():
    """Where urllib3's host-string check is too weak -- the guard is not."""
    assert not same_origin("http://h:8080/a", "http://h:9090/a")


def test_unparseable_target_does_not_strip_credentials():
    """Scrubbing on "unknown" would be a false-negative generator."""
    assert same_origin("/just/a/path", "http://h/x")


# ---------------------------------------------------------------------------
# the policy
# ---------------------------------------------------------------------------
def test_operator_custom_headers_are_secrets_but_browser_shapes_are_not():
    pol = EgressPolicy(operator_headers={"X-Tenant": "t", "User-Agent": "u"})
    pol.note("http://start.example/")
    hdrs = {"X-Tenant": "t", "User-Agent": "u", "Cookie": "sid=v",
            "Content-Type": "application/json"}
    removed = pol.scrub(hdrs, "http://elsewhere.example/x")
    assert "X-Tenant" in removed and "Cookie" in removed
    assert hdrs == {"User-Agent": "u", "Content-Type": "application/json"}


def test_named_origin_keeps_everything():
    pol = EgressPolicy(operator_headers={"X-Tenant": "t"})
    pol.note("http://start.example/")
    hdrs = {"X-Tenant": "t", "Authorization": "Bearer x"}
    assert pol.scrub(hdrs, "http://start.example/deep/path") == []
    assert hdrs == {"X-Tenant": "t", "Authorization": "Bearer x"}


# ---------------------------------------------------------------------------
# sync engine, on the wire
# ---------------------------------------------------------------------------
def _requester():
    return Requester(timeout=5, headers=dict(SENTINELS),
                     cookies={"sid": "COOKIE-VALUE"})


def test_sync_top_level_request_carries_credentials(pair):
    edge, _land = pair
    req = _requester()
    req.get(edge + "/land", cache_get=False)
    seen = _landing_headers()
    assert seen["x-api-key"] == SENTINELS["x-api-key"]
    assert "sid=COOKIE-VALUE" in seen.get("cookie", "")


def test_sync_cross_origin_redirect_arrives_naked(pair):
    edge, _land = pair
    req = _requester()
    resp = req.get(edge + "/redir-cross", cache_get=False)
    assert resp.status_code == 200, "the redirect is still followed"
    assert b"landed" in resp.content, "and its body still scanned"
    seen = _landing_headers()
    leaked = {k: v for k, v in SENTINELS.items() if seen.get(k) == v}
    assert not leaked, f"credentials followed the page's redirect: {leaked}"
    assert "sid=COOKIE-VALUE" not in seen.get("cookie", ""), seen.get("cookie")
    assert seen.get("user-agent"), "stealth must survive: no UA is a scanner tell"
    assert req.egress.blocks == 1


def test_sync_same_origin_redirect_keeps_credentials(pair):
    edge, _land = pair
    req = _requester()
    req.get(edge + "/redir-same", cache_get=False)
    seen = _landing_headers()
    assert seen.get("x-api-key") == SENTINELS["x-api-key"], (
        "apps redirect within themselves constantly; that must stay authed")


def test_clones_share_one_block_counter(pair):
    edge, _land = pair
    req = _requester()
    req.clone().get(edge + "/redir-cross?a=1", cache_get=False)
    req.clone().get(edge + "/redir-cross?b=2", cache_get=False)
    assert req.egress.blocks == 2


# ---------------------------------------------------------------------------
# the opt-in authorization boundary (--stop-at-cross-origin)
# ---------------------------------------------------------------------------
def _guarded_requester():
    """Requester with the authorization boundary ON.

    Only the edge origin is ever named here, and the fixture's landing server
    is a different origin (host string and port both), so the boundary has
    something real to refuse.
    """
    return Requester(timeout=5, headers=dict(SENTINELS),
                     stop_at_cross_origin=True)


def test_boundary_refuses_the_cross_origin_hop(pair):
    edge, land = pair
    req = _guarded_requester()
    resp = req.get(edge + "/redir-cross", cache_get=False)
    assert resp.status_code == 302, "the 3xx itself is what the caller gets"
    assert _State.visits == ["/redir-cross"], (
        f"the off-origin hop must never be requested: {_State.visits}")
    assert req.egress.boundary_stops == [land + "/land"], req.egress.boundary_stops


def test_boundary_still_follows_same_origin_redirects(pair):
    edge, land = pair
    req = _guarded_requester()
    resp = req.get(edge + "/redir-same", cache_get=False)
    assert resp.status_code == 200 and b"landed" in resp.content, (
        "same-origin hops are not a boundary violation")
    assert req.egress.boundary_stops == []
    # Apps redirect inside themselves constantly; that stays authenticated.
    assert _landing_headers().get("x-api-key") == SENTINELS["x-api-key"]


def test_boundary_off_is_the_ordinary_following_path(pair):
    edge, _land = pair
    req = _requester()                      # stop_at_cross_origin defaults False
    resp = req.get(edge + "/redir-cross", cache_get=False)
    assert resp.status_code == 200 and b"landed" in resp.content
    assert req.egress.boundary_stops == []
    assert req.egress.blocks == 1, "credentials still withheld even when following"


# ---------------------------------------------------------------------------
# async engine, on the wire
# ---------------------------------------------------------------------------
def _async_kwargs(scanner_url, headers, cookies):
    """Real production wiring: AsyncScanner._session_kwargs(url).

    Called from inside the coroutine, exactly as ``_scan_raw`` calls it --
    aiohttp 3.13's CookieJar binds itself to the running loop at construction.
    """
    import aiohttp
    from xssentinel.core.async_scanner import AsyncScanner

    scanner = AsyncScanner(headers=headers, cookies=cookies)
    return aiohttp, scanner._session_kwargs(scanner_url), scanner


def test_async_cross_origin_redirect_arrives_naked(pair):
    import asyncio
    holder = {}

    async def go():
        aiohttp, kwargs, scanner = _async_kwargs(
            pair[0] + "/redir-cross", dict(SENTINELS), {"sid": "COOKIE-VALUE"})
        holder["scanner"] = scanner
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout, **kwargs) as sess:
            async with sess.get(pair[0] + "/redir-cross", timeout=timeout,
                                headers=SENTINELS) as resp:
                return await resp.text()

    assert "landed" in asyncio.run(go()), "the redirect is still followed"
    seen = _landing_headers()
    assert not any(seen.get(k) == v for k, v in SENTINELS.items()), seen
    # The jar is the part a header scrub cannot reach: aiohttp applies it
    # while building the hop, after on_request_redirect has already fired.
    assert "sid=COOKIE-VALUE" not in seen.get("cookie", ""), seen.get("cookie")
    assert holder["scanner"]._egress().blocks >= 1


def test_async_same_origin_redirect_keeps_credentials(pair):
    import asyncio

    async def go():
        aiohttp, kwargs, _scanner = _async_kwargs(
            pair[0] + "/redir-same", dict(SENTINELS), {"sid": "COOKIE-VALUE"})
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout, **kwargs) as sess:
            async with sess.get(pair[0] + "/redir-same", timeout=timeout,
                                headers=SENTINELS) as resp:
                return await resp.text()

    assert "landed" in asyncio.run(go())
    seen = _landing_headers()
    assert seen.get("x-api-key") == SENTINELS["x-api-key"]
    assert "sid=COOKIE-VALUE" in seen.get("cookie", "")
