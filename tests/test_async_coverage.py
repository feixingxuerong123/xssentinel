"""Phase 290: the async engine's coverage instrumentation.

Before this phase every --async report's coverage section read
"0 endpoints / 0% layers / 0 requests" for scans that had just produced
findings: AsyncScanner had no CoverageTracker at all, the report is built
from a sync Scanner shim with its own EMPTY tracker, and the sync
sub-layers' 58 touch_layer calls landed in the shim's memory-only
_NullCoverage.  Measured on a two-page fixture: async found 4 findings and
reported zero coverage; sync reported 3 endpoints / 26 layers / 83
requests for the same target.

These tests pin the wiring without a browser or a network:
  * AsyncScanner constructs a real tracker;
  * the shim's coverage facade forwards to it (and keeps `touched`);
  * _CountingSession counts the verb / request paths but RETURNS the
    session's own object -- aiohttp's _RequestContextManager is both
    awaitable and an async CM, so an `async def` wrapper would break every
    `async with session.get(...)` site (measured: async dropped from 4
    findings to 0 before this was fixed);
  * request counting attributes to the CURRENT ENDPOINT, not the probe URL
    (the path/error layers inject into the URL, which invented 17 extra
    endpoint rows), and falls back to the probe URL when no endpoint is set;
  * _add_finding feeds the tracker's per-endpoint finding counter.
"""
from __future__ import annotations

import asyncio

import pytest

from xssentinel.core import async_scanner as a
from xssentinel.core.async_scanner_common import _AsyncScannerShim
from xssentinel.core.coverage import CoverageTracker
from xssentinel.core.findings import Finding


class _FakeSession:
    """Records verb calls; returns a sentinel object (not a coroutine)."""

    def __init__(self):
        self.calls = []
        self.sentinel = object()

    def request(self, method, url, **kw):
        self.calls.append(("request", method, url))
        return self.sentinel

    def get(self, url, **kw):
        self.calls.append(("get", "GET", url))
        return self.sentinel

    def post(self, url, **kw):
        self.calls.append(("post", "POST", url))
        return self.sentinel

    def close(self):
        pass


def test_async_scanner_constructs_a_real_tracker():
    sc = a.AsyncScanner()
    assert isinstance(sc.coverage, CoverageTracker)


def test_counting_session_delegates_and_counts():
    sess = _FakeSession()
    cov = CoverageTracker()
    wrapped = a._CountingSession(sess, cov)
    a._set_current_scan_url("http://t/page")
    try:
        got = wrapped.get("http://t/page?q=1")
        # the ORIGINAL object must come back -- awaiting it here would have
        # built a coroutine and broken `async with` at the call sites
        assert got is sess.sentinel
        assert wrapped.request("POST", "http://t/page") is sess.sentinel
        assert wrapped.close is not None       # delegation via __getattr__
        total = cov.to_json_dict()["totals"]
        assert total["requests"] == 2
        # Both requests were attributed to the ENDPOINT (not the probe url
        # with its query).  The tracker keys rows by (method, url), so
        # GET + POST on that endpoint are two rows -- same as sync.
        assert total["endpoints"] == 2
        urls = {e["url"] for e in cov.to_json_dict()["endpoints"]}
        assert urls == {"http://t/page"}
    finally:
        a._set_current_scan_url(None)


def test_request_attribution_falls_back_to_probe_url():
    assert a._attributed_url("http://t/probe?x=1") == "http://t/probe?x=1"
    a._set_current_scan_url("http://t/endpoint")
    try:
        assert a._attributed_url("http://t/probe?x=1") == "http://t/endpoint"
    finally:
        a._set_current_scan_url(None)


def test_shim_coverage_facade_forwards_and_keeps_touched():
    sc = a.AsyncScanner()
    shim = _AsyncScannerShim(sc)
    shim.coverage.touch_layer("http://t/e", "L8_postmessage", "GET", "d")
    assert shim.coverage.touched == [("http://t/e", "L8_postmessage",
                                      "GET", "d")]
    cov = sc.coverage.to_json_dict()
    assert cov["layer_coverage"]["L8_postmessage"] == 1
    assert cov["totals"]["endpoints"] == 1
    # record_layer(status="failed") keeps the failure row
    shim.coverage.record_layer("http://t/e", "L8_request",
                               status="failed", detail="boom")
    ep = sc.coverage.to_json_dict()["endpoints"][0]
    row = ep["layers"].get("L8_request")
    assert isinstance(row, dict) and row.get("status") == "failed", row


def test_add_finding_feeds_the_tracker():
    sc = a.AsyncScanner()

    async def _go():
        await sc._add_finding(
            Finding(url="http://t/sink", method="GET", param=None,
                    type="dom_dynamic", context="dom_sink",
                    payload="<svg/onload=alert(1)>", severity="high",
                    confidence="high", detail="x", evidence_class="browser-executed"))

    asyncio.run(_go())
    cov = sc.coverage.to_json_dict()
    assert cov["totals"]["findings"] == 1
    assert len(sc.findings) == 1
