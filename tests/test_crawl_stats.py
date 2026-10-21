"""Phase 298: the crawl artifact must say WHY it ended where it did.

Measured history: the same command produced 18-22 endpoints from the
static fallback and 70-74 from the browser crawl; within the browser path
the width can still vary because of three silent endings --

  * the max_total_pages cap stops the loop and DROPS whatever is queued
    (no record);
  * the per-page budget gives up before networkidle, so link extraction
    may be partial (the except: pass swallowed it);
  * a failed goto skips the page (verbose print only).

These tests drive the real crawl loop with a fake Playwright and assert
the counters that now reach the report (crawl_stats).
"""
from __future__ import annotations

import pytest

from xssentinel.core import spa_crawler as spa


class _Store:
    def __init__(self, links=None, slow=(), fail=()):
        self.links = links or {}
        self.slow = set(slow)
        self.fail = set(fail)


class _FakePage:
    def __init__(self, store: _Store):
        self.store = store
        self.current = None

    def add_init_script(self, js):
        pass

    def on(self, ev, handler):
        pass

    def goto(self, url, timeout=None, wait_until=None):
        if url in self.store.fail:
            raise RuntimeError("net::ERR_CONNECTION_REFUSED")
        self.current = url

    def wait_for_load_state(self, state, timeout=None):
        if self.current in self.store.slow:
            raise RuntimeError("Timeout exceeded")

    def evaluate(self, js):
        if "querySelectorAll('a[href]')" in js:
            return self.store.links.get(self.current, [])
        return []


class _FakeContext:
    def __init__(self, store):
        self.store = store

    def on(self, ev, handler):
        pass

    def add_cookies(self, c):
        pass

    def set_extra_http_headers(self, h):
        pass

    def new_page(self):
        return _FakePage(self.store)

    def close(self):
        pass


class _FakeBrowser:
    def __init__(self, store):
        self.store = store

    def new_context(self, **kw):
        return _FakeContext(self.store)

    def close(self):
        pass


class _FakeChromium:
    def __init__(self, store):
        self.store = store

    def launch(self, **kw):
        return _FakeBrowser(self.store)


class _FakePW:
    def __init__(self, store):
        self.store = store

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    @property
    def chromium(self):
        return _FakeChromium(self.store)


def _drive(monkeypatch, store, **kw):
    import playwright.sync_api as psa
    monkeypatch.setattr(spa, "_playwright_available", lambda: True)
    monkeypatch.setattr(psa, "sync_playwright", lambda: _FakePW(store))
    c = spa.SpaCrawler(verbose=False, **kw)
    # the helpers below need a real page API; this test is about the counters
    c._register_forms = lambda *a, **k: None
    c._auto_click = lambda *a, **k: None
    eps = c.crawl("http://t/", fallback_crawler=None)
    return c, eps


def test_cap_hit_is_counted_as_dropped(monkeypatch):
    store = _Store(links={"http://t/": ["/a", "/b", "/c", "/d", "/e"]})
    c, eps = _drive(monkeypatch, store, max_total_pages=3, max_depth=2)
    st = c.stats
    assert st["pages_crawled"] == 3, st
    assert st["pages_dropped_by_cap"] >= 1, st
    assert st["max_total_pages"] == 3


def test_budget_truncation_is_counted(monkeypatch):
    store = _Store(links={"http://t/": []}, slow={"http://t/"})
    c, eps = _drive(monkeypatch, store, max_total_pages=10)
    assert c.stats["pages_budget_truncated"] == 1, c.stats
    assert c.stats["pages_crawled"] == 1


def test_goto_failure_is_counted(monkeypatch):
    store = _Store(links={"http://t/": ["/dead"]}, fail={"http://t/dead"})
    c, eps = _drive(monkeypatch, store, max_total_pages=10)
    assert c.stats["pages_goto_failed"] == 1, c.stats


def test_clean_crawl_reports_zero_problems(monkeypatch):
    store = _Store(links={"http://t/": ["/a"]})
    c, eps = _drive(monkeypatch, store, max_total_pages=10)
    st = c.stats
    assert st["pages_crawled"] == 2
    assert st["pages_goto_failed"] == 0
    assert st["pages_budget_truncated"] == 0
    assert st["pages_dropped_by_cap"] == 0


def test_html_renders_the_stats_suffix():
    from xssentinel.core.report import build_html
    h = build_html([], "http://t/", {
        "generated": "x", "requests": 1, "scan_status": "completed",
        "crawl_engine": "spa",
        "crawl_stats": {"pages_crawled": 12, "pages_goto_failed": 1,
                        "pages_budget_truncated": 3,
                        "pages_dropped_by_cap": 40, "max_total_pages": 50}})
    assert "12 pages" in h
    assert "1 failed" in h
    assert "3 truncated" in h
    assert "40 dropped (cap 50)" in h
