"""Phase 86: async budget/circuit stops + transform-chain parity.

Two P1 defects found by the multi-agent audit, each proved by a test that
FAILS on the pre-fix code (not by the mere presence of the new code):

1. Budget/circuit stops were swallowed.  ``_throttle()`` raises
   ``BudgetExhausted`` / ``CircuitOpen``, but every ``_probe_param`` /
   ``_scan_*_async`` handler used ``except Exception: continue/return``, so
   --max-requests / --max-requests-per-endpoint / --breaker-threshold did
   nothing in async L1 and in all page-level layers: the scan kept probing
   every param on every layer and returned normally.  ``budget_exhausted_
   reason`` was set but never read.  These tests assert the request count is
   actually capped, that the exception is no longer swallowed, and that the
   findings collected before the stop are still returned.

2. ``self.max_transforms`` was stored but never used: the async L1 fired two
   variants per payload (bare marked + one polyglot) and none of the
   WAF/filter evasion chains the sync ``_try_payload`` tries.  The test builds
   a fixture that only reflects the payload once it has been encoded, and
   asserts async detects it -- while the identical fixture is NOT detected
   when the transform ladder is capped to the bare payload.

Runs without pytest-asyncio: async drivers are wrapped in asyncio.run() from
plain test functions.  The AsyncScanner must be constructed INSIDE the
running loop (Python 3.9 binds asyncio.Lock to the current loop).
"""
from __future__ import annotations
import asyncio
import html
import os
import sys
import types
import urllib.parse

# Make xssentinel importable when run from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from tests.conftest import SOCKETPAIR_OK
from xssentinel.core import async_scanner as asc_mod
from xssentinel.core.async_scanner import AsyncScanner
from xssentinel.core.budget import BudgetExhausted

# asyncio.run() needs a working loopback socketpair (see conftest.py);
# skip instead of hanging when the environment throttles it.

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _Resp:
    """Minimal aiohttp response (same shape tests/test_async_pipeline uses)."""

    def __init__(self, text, headers=None):
        self._t = text
        self.headers = dict(headers or {})
        self.status = 200

    async def text(self):
        return self._t

    async def read(self):
        return self._t.encode()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _Session:
    """Fake aiohttp session.

    mode="echo"     -- reflects the value verbatim (vulnerable app).
    mode="escape"   -- HTML-escapes the value (patched app, never confirms).
    mode="naivewaf" -- blocks any value carrying a raw '<' (naive string
                       filter), otherwise URL-decodes and reflects it.  Only an
                       ENCODED payload can slip through, so detection is proof
                       that the transform ladder ran.
    """

    def __init__(self, mode="echo", headers=None):
        self.mode = mode
        self.calls = []
        self.headers = dict(headers or {})

    def _render(self, val: str) -> str:
        if self.mode == "naivewaf" and "<" in val:
            return "request blocked by filter"
        if self.mode == "escape":
            val = html.escape(val, quote=True)
        elif self.mode == "naivewaf":
            val = urllib.parse.unquote(val)
        return f"<html><body><div>{val}</div></body></html>"

    def request(self, method, url, params=None, data=None, headers=None,
                proxy=None, **kw):
        self.calls.append({"method": method, "url": url,
                           "params": dict(params or {}),
                           "data": dict(data or {}) if data else {}})
        val = (params or {}).get("q", "") + (data or {}).get("q", "")
        return _Resp(self._render(val), self.headers)

    def get(self, url, params=None, headers=None, proxy=None, **kw):
        return self.request("GET", url, params=params, headers=headers,
                            proxy=proxy, **kw)


class _FakeAiohttp(types.ModuleType):
    """Stand-in for the ``aiohttp`` module so ``scan()`` can be driven offline.

    scan() builds a real ClientSession; patching sys.modules lets the whole
    scan pipeline (baseline -> page layers -> L1 -> graceful stop) run
    against the fake session above without touching the loopback stack.

    Phase 192: ``_session_kwargs`` unconditionally subclasses
    ``aiohttp.CookieJar`` (Phase 189 egress guard) and constructs a
    ``TraceConfig`` -- both missing here, which made every test reaching
    ``_session_kwargs`` die on ``module 'aiohttp' has no attribute
    'CookieJar'`` whenever no earlier test had already cached the real jar
    class (test-order-dependent: the Phase 191 lesson, in this file's own
    stub).  The egress SEMANTICS stay measured against the genuine aiohttp
    in ``tests/test_egress_guard.py``.
    """

    def __init__(self, mode="echo", headers=None):
        super().__init__("aiohttp")
        self.session_factory = lambda **kw: _Session(mode=mode,
                                                     headers=headers)
        self.ClientTimeout = lambda **kw: kw
        self.TCPConnector = lambda **kw: kw

        class _FakeCookieJar:
            # Enough of aiohttp.CookieJar for the egress subclass: the
            # subclass calls super().filter_cookies() and type(jar)() on
            # the result, so both must really work.
            def __init__(self, **kwargs):
                self._cookies = {}

            def update_cookies(self, cookies, request_url=None):
                self._cookies.update(dict(cookies))

            def filter_cookies(self, request_url=None):
                return dict(self._cookies)

        class _FakeTraceConfig:
            # _session_kwargs appends to both hook lists.
            def __init__(self, **kwargs):
                self.on_request_start = []
                self.on_request_redirect = []

        self.CookieJar = _FakeCookieJar
        self.TraceConfig = _FakeTraceConfig

    def ClientSession(self, **kw):
        session = self.session_factory(**kw)

        class _CM:
            async def __aenter__(_self):
                return session

            async def __aexit__(_self, *a):
                return False

        return _CM()


_JAR_SAVED = None


def _fake_aiohttp(mode="echo", headers=None):
    """Install the fake aiohttp module; returns the real one for restore."""
    global _JAR_SAVED
    real = sys.modules.get("aiohttp")
    sys.modules["aiohttp"] = _FakeAiohttp(mode=mode, headers=headers)
    # Isolate the `_EGRESS_JAR` class cache for the fake window (same
    # contract as test_async_hidden_param_mining): results must not depend
    # on whether some earlier test already cached the genuine class.
    from xssentinel.core import async_scanner_common as _asc_mod
    _JAR_SAVED = _asc_mod._EGRESS_JAR
    _asc_mod._EGRESS_JAR = None
    return real


def _restore_aiohttp(real):
    global _JAR_SAVED
    from xssentinel.core import async_scanner_common as _asc_mod
    if _JAR_SAVED is not None:
        _asc_mod._EGRESS_JAR = _JAR_SAVED
    _JAR_SAVED = None
    if real is None:
        sys.modules.pop("aiohttp", None)
    else:
        sys.modules["aiohttp"] = real


def _probe(params, mode="echo", max_transforms=8, max_requests=None, **kw):
    """Drive _probe_param inside a fresh loop. Returns (findings, session)."""

    async def run():
        scanner = AsyncScanner(max_concurrent=2, per_host_delay=0, jitter=0,
                               max_payloads=10, max_transforms=max_transforms,
                               max_requests=max_requests, timeout=5,
                               advanced_layers=False, **kw)
        scanner._semaphore = asyncio.Semaphore(2)
        session = _Session(mode=mode)
        out = []
        async for f in scanner._probe_param(
                session, "http://t/x", "GET", "q", params, {},
                False, "baseline"):
            out.append(f)
        return out, session, scanner

    return asyncio.run(run())


def _scan(url="http://t/x", params=None, mode="echo", headers=None, **kw):
    """Drive a full scan() against the fake aiohttp. Returns (findings, asc)."""

    async def run():
        real = _fake_aiohttp(mode=mode, headers=headers)
        try:
            scanner = AsyncScanner(max_concurrent=2, per_host_delay=0,
                                   jitter=0, timeout=5, **kw)
            out = []
            async for f in scanner.scan(url, params=params or {"q": "probe"}):
                out.append(f)
            return out, scanner
        finally:
            _restore_aiohttp(real)

    return asyncio.run(run())


# ===========================================================================
# Task 1 -- budget / circuit stops are no longer swallowed
# ===========================================================================

class TestBudgetStopPropagates:
    """The stop must reach scan() instead of being counted as 'one failed
    request' by the per-probe ``except Exception`` handlers."""

    @pytest.mark.skipif(not SOCKETPAIR_OK,
                        reason="needs loopback (moved down from the file-level gate)")
    def test_probe_param_reraises_budget_exhausted(self):
        """One request allowed: the marker probe spends it, the very next
        probe (the sandwich/profile probe) must raise -- pre-fix it was
        swallowed by ``except Exception: prof = None`` and the scan kept
        firing payloads."""
        async def run():
            scanner = AsyncScanner(max_concurrent=2, per_host_delay=0,
                                   jitter=0, max_payloads=10,
                                   max_transforms=1,
                                   max_requests=1, timeout=5,
                                   advanced_layers=False)
            scanner._semaphore = asyncio.Semaphore(2)
            session = _Session(mode="echo")
            out = []
            async for _f in scanner._probe_param(
                    session, "http://t/x", "GET", "q", {"q": "probe"}, {},
                    False, "baseline"):
                out.append(_f)
            return scanner, session

        with pytest.raises(BudgetExhausted):
            asyncio.run(run())

    @pytest.mark.skipif(not SOCKETPAIR_OK,
                        reason="needs loopback (moved down from the file-level gate)")
    def test_scan_stops_at_request_budget(self):
        """A non-confirming endpoint with a 10-payload budget would fire
        ~15 requests per param (payloads + position shift).  With
        max_requests=5 the scan must stop at exactly 5 and return normally."""
        findings, scanner = _scan(
            mode="escape", max_requests=5, max_payloads=10,
            max_transforms=1, advanced_layers=False)
        assert findings == []
        # Capped, and demonstrably NOT an early exit for another reason:
        # the scan kept probing until the cap itself refused the next request.
        assert scanner.requests_made == 5, scanner.requests_made
        # Phase 86: the reason is recorded and reported, not left dangling.
        assert scanner.budget_exhausted_reason

    @pytest.mark.skipif(not SOCKETPAIR_OK,
                        reason="needs loopback (moved down from the file-level gate)")
    def test_scan_survives_without_cap(self):
        """Control: the same non-confirming endpoint with NO budget burns
        far more than 5 requests -- proves the cap above is what stopped it."""
        _findings, scanner = _scan(
            mode="escape", max_payloads=10, max_transforms=1,
            advanced_layers=False)
        assert scanner.requests_made > 5, scanner.requests_made
        assert scanner.budget_exhausted_reason is None

    @pytest.mark.skipif(not SOCKETPAIR_OK,
                        reason="needs loopback (moved down from the file-level gate)")
    def test_scan_keeps_findings_collected_before_the_stop(self):
        """A finding that cost no requests (bypassable CSP, header-only) must
        still be yielded when the budget cuts the scan short -- pre-fix the
        stop never happened, post-fix it must not cost us the finding."""
        findings, scanner = _scan(
            mode="escape", max_requests=3, max_payloads=10,
            max_transforms=1,
            headers={"Content-Security-Policy":
                     "default-src 'self'; script-src 'unsafe-inline'"})
        types_found = [f.data.get("type") for f in findings]
        assert "csp_bypass" in types_found, types_found
        assert scanner.requests_made <= 3, scanner.requests_made
        assert scanner.budget_exhausted_reason
        # The finding is also retained on the scanner for report generation.
        assert any(f.data.get("type") == "csp_bypass"
                   for f in scanner.findings)

    @pytest.mark.skipif(not SOCKETPAIR_OK,
                        reason="needs loopback (moved down from the file-level gate)")
    def test_scan_returns_normally_on_confirming_endpoint(self):
        """A vulnerable endpoint must still yield its reflected finding and
        must NOT be mistaken for a budget stop.

        ``polyglot_reflection`` counts as a confirmed reflection here: the
        async L1 appends a polyglot fallback per payload (sync has no such
        inline fallback), and with this budget the first corpus payload --
        a sanitizer-bypass shape that is correctly non-executable on an
        unfiltered echo -- reaches that fallback before the classic
        payloads.  Measured on a live echo target (sync ``reflected/high``
        vs async ``polyglot_reflection/medium``): an engine-grading
        divergence the parity phase must settle; the contract THIS test
        pins is "a live reflection is confirmed, no budget stop".
        """
        findings, scanner = _scan(mode="echo", max_requests=20,
                                  max_payloads=4, max_transforms=2,
                                  advanced_layers=False)
        assert any(f.data.get("type") in ("reflected", "polyglot_reflection")
                  for f in findings), [f.data.get("type") for f in findings]
        assert scanner.budget_exhausted_reason is None

    @pytest.mark.skipif(not SOCKETPAIR_OK,
                        reason="needs loopback (moved down from the file-level gate)")
    def test_circuit_breaker_stops_the_scan(self):
        """breaker_threshold=2: two 5xx responses trip the breaker and the
        scan must stop instead of hammering a dead target."""
        class _5xxSession(_Session):
            """Dead target: 500s, but it still echoes the probe value (a
            breaker test needs the layer to keep requesting)."""

            def request(self, method, url, params=None, data=None,
                        headers=None, proxy=None, **kw):
                self.calls.append({})
                val = (params or {}).get("q", "") + (data or {}).get("q", "")
                r = _Resp(f"<html><body><div>{val}</div></body></html>")
                r.status = 500
                return r

        async def run():
            scanner = AsyncScanner(max_concurrent=2, per_host_delay=0,
                                   jitter=0, max_payloads=6,
                                   max_transforms=1, breaker_threshold=2,
                                   timeout=5, advanced_layers=False)
            scanner._semaphore = asyncio.Semaphore(2)
            session = _5xxSession(mode="echo")
            out = []
            async for _f in scanner._probe_param(
                    session, "http://t/x", "GET", "q", {"q": "probe"}, {},
                    False, "baseline"):
                out.append(_f)
            return scanner

        from xssentinel.core.budget import CircuitOpen
        with pytest.raises(CircuitOpen):
            asyncio.run(run())


# ===========================================================================
# Task 2 -- transform chain parity with the sync scanner
# ===========================================================================

class TestTransformChainParity:
    """max_transforms was dead config: async fired the bare payload plus one
    polyglot and nothing else, so every filtered target was a false negative."""

    @pytest.mark.skipif(not SOCKETPAIR_OK,
                        reason="needs loopback (moved down from the file-level gate)")
    def test_transform_chain_detects_filtered_reflection(self):
        """The fixture blocks any value carrying a raw '<' and URL-decodes
        the rest.  Only a transformed (percent-encoded) payload can reflect
        executably -- so a finding here proves the ladder ran."""
        findings, _session, _scanner = _probe({"q": "probe"}, mode="naivewaf",
                                              max_transforms=8)
        assert findings, "transform chain did not defeat the naive filter"
        assert findings[0].data["type"] == "reflected"
        chain = findings[0].data.get("transform") or []
        assert chain, "finding carries no transform attribution"
        assert "url_encode_selective" in chain, chain
        # Attribution kept: the marker survived the transform chain.
        assert findings[0].data["param"] == "q"

    @pytest.mark.skipif(not SOCKETPAIR_OK,
                        reason="needs loopback (moved down from the file-level gate)")
    def test_bare_payload_misses_the_same_fixture(self):
        """Control on the SAME fixture: with the ladder capped to the bare
        payload (max_transforms=1 -> only the [] chain) nothing confirms, so
        the detection above can only come from the transform chain."""
        findings, _session, _scanner = _probe({"q": "probe"}, mode="naivewaf",
                                              max_transforms=1)
        assert findings == [], findings

    @pytest.mark.skipif(not SOCKETPAIR_OK,
                        reason="needs loopback (moved down from the file-level gate)")
    def test_build_variants_respects_max_transforms(self):
        """The ladder is capped at max_transforms and leads with the bare
        payload (cheapest first), like the sync _try_payload."""
        async def run():
            scanner = AsyncScanner(max_concurrent=2, per_host_delay=0,
                                   jitter=0, max_transforms=3)
            return scanner._build_variants(
                "<script>alert('tok123')</script>", "html_element", "tok123")
        variants = asyncio.run(run())
        assert 1 <= len(variants) <= 3, variants
        chains, first = variants[0]
        assert chains == [] and first == "<script>alert('tok123')</script>"

    @pytest.mark.skipif(not SOCKETPAIR_OK,
                        reason="needs loopback (moved down from the file-level gate)")
    def test_build_variants_keeps_the_marker(self):
        """Attribution: the base variant must still carry the verifier token
        untouched (transforms are applied to the whole marked payload)."""
        async def run():
            scanner = AsyncScanner(max_concurrent=2, per_host_delay=0,
                                   jitter=0, max_transforms=4)
            return scanner._build_variants(
                "<img src=x onerror=alert('xsstok01')>", "html_element",
                "xsstok01")
        variants = asyncio.run(run())
        assert "xsstok01" in variants[0][1]

    @pytest.mark.skipif(not SOCKETPAIR_OK,
                        reason="needs loopback (moved down from the file-level gate)")
    def test_drain_agen_does_not_swallow_the_stop(self):
        """_drain_agen isolates per-layer errors -- it must NOT isolate a
        budget stop, or scan() can never see it."""
        async def run():
            async def agen():
                raise BudgetExhausted("stopped")
                yield  # pragma: no cover
            sink = []
            await asc_mod._drain_agen(agen(), sink)
        with pytest.raises(BudgetExhausted):
            asyncio.run(run())


# ===========================================================================
# Phase 208 -- the hermeticity gate follows the TRANSPORT, not the block
# ===========================================================================

class TestSyncLayersStayOffline:
    """The sync layers may only speak HTTP when a real transport exists.

    ``_get_sync_requester`` refuses real traffic unless
    ``_sync_layers_online`` is set; ``scan()`` sets it on entering
    ``async with aiohttp.ClientSession(...)``.  Entering the block only
    proves the block was entered -- with ``sys.modules["aiohttp"]``
    replaced, nothing speaks HTTP at all, yet the flag read True and the
    layers kept a real ``requests`` session.

    Consequence, measured (dev/_hang_probe.py): ``_scan_cookie_tossing``
    and ``_scan_header_xss`` called ``req.get()`` against the stub
    session's host and parked in ``getaddrinfo`` forever.  That wedged the
    whole suite at 2% and is the same path that left a range3 case
    hanging long past its runner timeout.
    """

    @pytest.mark.skipif(not SOCKETPAIR_OK,
                        reason="needs loopback (moved down from the file-level gate)")
    def test_stubbed_aiohttp_keeps_the_sync_requester_offline(self):
        """Over the fake transport the sync requester must hold the
        refusing stub -- the observation a leak would change."""
        from xssentinel.core.async_scanner_crawl import _OfflineSession

        async def run():
            real = _fake_aiohttp(mode="escape")
            try:
                scanner = AsyncScanner(max_concurrent=2, per_host_delay=0,
                                       jitter=0, timeout=5,
                                       advanced_layers=False)
                async for _f in scanner.scan("http://t/x",
                                             params={"q": "probe"}):
                    pass
                return scanner._get_sync_requester()
            finally:
                _restore_aiohttp(real)

        req = asyncio.run(run())
        session = getattr(req, "session", None)
        assert session is not None, "sync requester has no session at all"
        assert isinstance(session, _OfflineSession), (
            "sync layers would reach the real network behind a stub "
            f"transport: session is {type(session).__name__}")

    @pytest.mark.skipif(not SOCKETPAIR_OK,
                        reason="needs loopback (moved down from the file-level gate)")
    def test_stub_transport_is_reported_offline(self):
        """The decision itself: a stand-in module is not a transport."""
        import types as _types
        stub = _types.ModuleType("aiohttp")

        class _AnySession:
            pass

        stub.ClientSession = _AnySession
        assert AsyncScanner._transport_is_real(stub, _AnySession()) is False

    @pytest.mark.skipif(not SOCKETPAIR_OK,
                        reason="needs loopback (moved down from the file-level gate)")
    def test_genuine_transport_is_reported_online(self):
        """Control: the real aiohttp session must still unlock the layers,
        or this fix has silently turned offline-by-default."""
        aiohttp = pytest.importorskip("aiohttp")

        async def run():
            # aiohttp's ClientSession binds to the running loop.
            session = aiohttp.ClientSession()
            try:
                return AsyncScanner._transport_is_real(aiohttp, session)
            finally:
                await session.close()

        assert asyncio.run(run()) is True

    @pytest.mark.skipif(not SOCKETPAIR_OK,
                        reason="needs loopback (moved down from the file-level gate)")
    def test_unknown_transport_is_treated_as_offline(self):
        """An unrecognised session is not granted the network.

        A wrongly-offline layer degrades to its own ``except Exception``
        (one missed probe); a wrongly-online layer sends operator
        credentials to a host a test named.  Only one of those two
        mistakes is recoverable.
        """
        import aiohttp
        assert AsyncScanner._transport_is_real(
            aiohttp, object()) is False
