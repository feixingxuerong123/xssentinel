"""Regression: an aborted SPA browser crawl must still fall back.

Defect (Phase 200 attribution, measured): once any earlier scan started
the shared Playwright sync browser, this thread keeps a running asyncio
loop (dom_engine.get_shared_browser -> sync_playwright().start()).  Every
later SpaCrawler.crawl then dies immediately with

    "It looks like you are using Playwright Sync API inside the asyncio
     loop."

which spa_crawler.py caught and turned into `return endpoints` -- the
partial, usually EMPTY, list -- WITHOUT consulting the fallback crawler.
Effect measured on a live fixture: crawl contributed 0 endpoints
(40 requests / 0.1s, no discovered routes) instead of 9-10
(427 requests, 16 findings).  Crawl capability disappeared silently: the
caller could not distinguish "this SPA has no routes" from "the browser
could not start".

These tests pin the contract without needing a browser or a network:
the loop message is the exact string Chromium/Playwright raise, and the
fallback must be used even when the browser already registered
something, merging rather than dropping.
"""
from __future__ import annotations

import sys

import pytest

sys.path.insert(0, "xssentinel/core")
sys.path.insert(0, "xssentinel")

from core import spa_crawler as spa  # noqa: E402

LOOP_MSG = ("It looks like you are using Playwright Sync API inside the "
            "asyncio loop.")


def _crawler(verbose: bool = False):
    return spa.SpaCrawler(max_depth=1, scope=None, timeout=1,
                          headless=True, per_page_budget_s=0.01,
                          max_total_pages=1, max_clicks_per_page=0,
                          verbose=verbose)


def _fake_start(monkeypatch, exc: Exception):
    """Make the ``with sync_playwright()`` block raise.

    This is where the measured wedge actually surfaces: Playwright IS
    importable and available() returns True, but entering the sync-API
    context in a thread that already runs an asyncio loop raises from the
    ``with`` statement itself.  Failing at the import instead would
    exercise a different (already-covered) branch, so the stub stands in
    for the context manager.
    """
    import playwright.sync_api as psa

    class _FakeSyncPw:
        def __call__(self, *a, **k):
            return self

        def __enter__(self):
            raise exc

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(psa, "sync_playwright", _FakeSyncPw())


# --- the failing case -------------------------------------------------------

def test_browser_abort_falls_back_to_static_crawler(monkeypatch):
    """The measured wedge: crawl must return the static result, not []."""
    _fake_start(monkeypatch, RuntimeError(LOOP_MSG))
    seen = []

    def fallback(url):
        seen.append(url)
        return [("http://h/static", "GET", {"q": "xss"}, {})]

    out = _crawler().crawl("http://h/app", fallback_crawler=fallback)

    assert seen == ["http://h/app"], "fallback must be consulted"
    assert out == [("http://h/static", "GET", {"q": "xss"}, {})], (
        "an aborted browser crawl must yield the static crawler's "
        "endpoints, not an empty list")


def test_partial_browser_endpoints_are_merged_not_dropped():
    """Browser work already done is kept alongside the static fallback.

    Pinned on the merge helper directly: crawl() rebuilds `endpoints`
    from empty on entry, so the only way a partial browser list meets the
    fallback is inside the except branch, and the rule there is
    "fallback result, with browser endpoints kept when any exist".
    """
    partial = [("http://h/from-browser", "GET", {}, {})]
    static = [("http://h/static", "GET", {"q": "xss"}, {})]
    assert spa._merge_endpoints(partial, static) == partial + static


# --- no fallback given: keep partial, do not fabricate ---------------------

def test_no_fallback_keeps_partial_endpoints(monkeypatch):
    _fake_start(monkeypatch, RuntimeError(LOOP_MSG))
    out = _crawler().crawl("http://h/app", fallback_crawler=None)
    assert out == [], "with no fallback there is nothing to merge in"


# --- the merge helper's own contract ---------------------------------------

class TestMergeEndpoints:
    def test_dedups_on_url_method_params_and_data(self):
        a = [("http://h/p", "GET", {"q": "1"}, {})]
        b = [("http://h/p", "GET", {"q": "1"}, {})]
        assert spa._merge_endpoints(a, b) == a

    def test_keeps_param_shape_differences(self):
        a = [("http://h/p", "GET", {"q": "1"}, {})]
        b = [("http://h/p", "GET", {}, {})]
        assert spa._merge_endpoints(a, b) == a + b

    def test_keeps_data_shape_differences(self):
        a = [("http://h/s", "POST", {}, {"q": "hi"})]
        b = [("http://h/s", "POST", {}, {"user": "bob"})]
        assert len(spa._merge_endpoints(a, b)) == 2

    def test_primary_order_wins(self):
        a = [("http://h/1", "GET", {}, {})]
        b = [("http://h/2", "GET", {}, {})]
        assert spa._merge_endpoints(a, b) == a + b

    def test_tolerates_none_and_empty(self):
        assert spa._merge_endpoints(None, None) == []
        assert spa._merge_endpoints([], []) == []

    def test_passes_through_malformed_entries(self):
        assert spa._merge_endpoints([("bad",)], []) == [("bad",)]


# --- the fallback message is loud, not silent ------------------------------

def test_abort_is_reported_even_though_it_recovers(capsys, monkeypatch):
    """Silent degradation is the actual defect; recovery must be visible."""
    _fake_start(monkeypatch, RuntimeError(LOOP_MSG))
    out = _crawler(verbose=True).crawl(
        "http://h/app",
        fallback_crawler=lambda u: [("http://h/s", "GET", {}, {})])
    printed = capsys.readouterr().out
    assert "crawl aborted" in printed
    assert "falling back" in printed
    assert out, "recovery still has to return endpoints"


# --- mutation control ------------------------------------------------------
# The project's rule: a guard that cannot fail proves nothing.  This test
# re-implements the PRE-Phase-200 except branch (abort -> return partial,
# never consult the fallback) against the SAME wedged input and asserts
# it LOSES the endpoints.  If both shapes returned the same thing, the
# guard would not be load-bearing and the headline test would be vacuous.

def test_pre_fix_shape_actually_loses_the_endpoints(monkeypatch):
    _fake_start(monkeypatch, RuntimeError(LOOP_MSG))

    def pre_fix_crawl(crawler, start_url, fallback_crawler=None):
        """The old body: swallow, return the partial list, no fallback."""
        endpoints: list = []
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright():
                raise AssertionError("unreachable with the stub in place")
        except Exception:
            return endpoints
        return endpoints

    out = pre_fix_crawl(_crawler(), "http://h/app",
                        fallback_crawler=lambda u: [("http://h/static",
                                                    "GET", {"q": "xss"}, {})])
    assert out == [], "pre-fix shape yields nothing; that is the measured bug"

    fixed = _crawler().crawl(
        "http://h/app",
        fallback_crawler=lambda u: [("http://h/static", "GET", {"q": "xss"}, {})])
    assert fixed == [("http://h/static", "GET", {"q": "xss"}, {})], (
        "the fixed shape must differ from the pre-fix shape, otherwise "
        "the guard proves nothing")


# --- availability still selects the path -----------------------------------

@pytest.mark.parametrize("available", [True, False])
def test_availability_still_controls_static_fallback(available, monkeypatch):
    """Playwright missing -> straight to fallback (unchanged contract)."""
    monkeypatch.setattr(spa, "_playwright_available", lambda: available)
    if available:
        _fake_start(monkeypatch, RuntimeError(LOOP_MSG))
    seen = []
    out = _crawler().crawl("http://h/app", fallback_crawler=lambda u: seen.append(u) or [])
    assert seen == ["http://h/app"]
    assert out == []
