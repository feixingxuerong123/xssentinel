"""Phase 293: a degraded crawl must be visible, and the loop wedge is
repairable.

Measured on OWASP Juice Shop 20.2.0 with one command:
  * fresh process, browser crawl works  -> 70-74 endpoints
  * shared sync browser already alive   -> crawl aborts, static fallback
                                           -> 18-22 endpoints
The number varied 4x with no signal in the artifact saying why.  The
abort itself is the Phase 200 loop wedge: dom_engine's shared sync
browser leaves the thread's asyncio loop running, and the crawler's own
`sync_playwright()` then refuses to start.  Measured directly: 0
endpoints in 0.0s with the shared browser alive, 13 endpoints in 30.5s
after ``shutdown_thread_browser()``.

These tests pin:
  * the wedge is detected and repaired once (shutdown + retry) instead
    of degrading immediately;
  * every fallback path names itself (``engine_used`` /
    ``fallback_reason``) and logs a warning -- no more verbose-only print;
  * a non-wedge abort does not retry;
  * Scanner._crawl_spa publishes the state for the report.
"""
from __future__ import annotations

import sys
import types

import pytest

from xssentinel.core import spa_crawler as spa


def _fake_pw_module(exc: BaseException | None = None):
    mod = types.ModuleType("playwright.sync_api")

    def sync_playwright():
        if exc is not None:
            raise exc
        raise AssertionError("test did not expect a real browser")

    mod.sync_playwright = sync_playwright
    return mod


def _install_pw(monkeypatch, exc):
    monkeypatch.setitem(sys.modules, "playwright.sync_api", _fake_pw_module(exc))
    monkeypatch.setattr(spa, "_playwright_available", lambda: True)


WEDGE = RuntimeError(
    "It looks like you are using Playwright Sync API inside the asyncio loop.")


def test_wedge_marker_recognised():
    assert spa._looks_like_loop_wedge(WEDGE)
    assert not spa._looks_like_loop_wedge(ValueError("boom"))
    assert not spa._looks_like_loop_wedge(RuntimeError("net::ERR_FAILED"))


def test_unavailable_is_named_not_just_printed(monkeypatch):
    monkeypatch.setattr(spa, "_playwright_available", lambda: False)
    crawled = []

    def fallback(url):
        crawled.append(url)
        return [("http://t/x", "GET", {}, {})]

    c = spa.SpaCrawler(verbose=False)
    out = c.crawl("http://t/", fallback_crawler=fallback)
    assert len(out) == 1 and crawled == ["http://t/"]
    assert c.engine_used == "static-fallback"
    assert c.fallback_reason == "playwright-unavailable"


def test_wedge_is_repaired_once_before_falling_back(monkeypatch):
    _install_pw(monkeypatch, WEDGE)
    shutdown = []
    monkeypatch.setattr(
        "xssentinel.core.dom_engine.shutdown_thread_browser",
        lambda: shutdown.append(True))
    crawled = []

    def fallback(url):
        crawled.append(url)
        return [("http://t/x", "GET", {}, {})]

    c = spa.SpaCrawler(verbose=False)
    out = c.crawl("http://t/", fallback_crawler=fallback)
    # one shutdown + one retry, then the second wedge degrades visibly
    assert shutdown == [True]
    assert len(out) == 1 and crawled == ["http://t/"]
    assert c.engine_used == "static-fallback"
    assert c.fallback_reason.startswith("browser-crawl-aborted:")
    assert "asyncio loop" in c.fallback_reason


def test_non_wedge_abort_does_not_retry(monkeypatch):
    _install_pw(monkeypatch, ValueError("net::ERR_CONNECTION_REFUSED"))
    shutdown = []
    monkeypatch.setattr(
        "xssentinel.core.dom_engine.shutdown_thread_browser",
        lambda: shutdown.append(True))
    crawled = []

    def fallback(url):
        crawled.append(url)
        return [("http://t/x", "GET", {}, {})]

    c = spa.SpaCrawler(verbose=False)
    out = c.crawl("http://t/", fallback_crawler=fallback)
    assert shutdown == []                      # not a wedge -> no retry
    assert len(out) == 1
    assert c.engine_used == "static-fallback"
    assert "ERR_CONNECTION_REFUSED" in c.fallback_reason


def test_scanner_publishes_the_engine_state():
    from xssentinel.core.scanner import Scanner
    sc = Scanner(requester=None)
    assert sc.crawl_engine_used is None
    # the attribute pair the report reads must exist on every Scanner
    assert hasattr(sc, "crawl_fallback_reason")


# --- Phase 297: the human deliverable must say it too ---------------------

def _html(meta):
    from xssentinel.core.report import build_html
    base = {"generated": "2026-10-21 22:00", "requests": 1,
            "scan_status": "completed"}
    return build_html([], "http://t/", {**base, **meta})


def test_html_names_a_degraded_crawl():
    h = _html({"crawl_engine": "static-fallback",
               "crawl_fallback_reason": "browser-crawl-aborted: Error: loop"})
    assert "DEGRADED CRAWL" in h
    assert "static-fallback" in h
    assert "partial" in h


def test_html_prints_the_engine_when_healthy():
    h = _html({"crawl_engine": "spa"})
    assert "Crawl: spa" in h
    assert "DEGRADED CRAWL" not in h


def test_html_says_nothing_when_no_crawl_ran():
    h = _html({})
    assert "Crawl:" not in h
    assert "DEGRADED CRAWL" not in h
