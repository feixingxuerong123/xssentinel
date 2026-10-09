# -*- coding: utf-8 -*-
"""A failed goto must not hand a provisional page to the next evaluate.

Phase 200 -- measured chain (dev/_silent_nav_probe.py, three branches
against a server that accepts and never responds):

  A  goto(wait_until="commit", timeout=2s) raises after 2.02s, then
     page.evaluate blocks **763s** -- Chromium keeps the navigation
     provisional; Playwright waits for an execution context that never
     arrives.  This was the field wedge: scan_endpoint('/evt') stalled
     436s on the fixture's starved server, faulthandler showed only
     Playwright's greenlet frames (useless), and the fixture's own
     timeout message blamed "a host that kills loopback connections".
  B  after the same failed goto, goto("about:blank") returns in 0.02s
     and the evaluate in 0.0s.
  C  control evaluate, no dangling navigation: 0.0s.

The fix lives in dom_engine._recover_nav, called from _bounded_goto and
harvest.  Pinned here at three levels:

  1. contract (FakePage): a goto that raises must be followed by an
     about:blank navigation BEFORE control returns -- no browser needed,
     runs everywhere;
  2. mutation control: with _recover_nav neutered the FakePage STILL
     reports the provisional state, so the contract test provably reads
     the fix and would go red without it;
  3. live (real Chromium + silent socket): goto fails, _recover_nav,
     evaluate completes -- a hard wall-clock bound.  Skipped when
     playwright/chromium is unavailable.

Why the fix cannot cost findings (the Phase-141 tension): under
wait_until="commit" a raised goto means the target document never
committed, so its scripts never ran -- there are no NEW sink hits.  Hits
from the previous probe's document were already read at the end of that
probe iteration (analyze reads window.__xss_dom_hits after every probe,
failed ones included), so recovery discards only consumed state.
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import dom_engine  # noqa: E402
from xssentinel.core.dom_engine import (  # noqa: E402
    DynamicDomAnalyzer, _recover_nav)


# ---------------------------------------------------------------------------
# 1. contract: FakePage, no browser
# ---------------------------------------------------------------------------

class FakePage:
    """Mimics the only Playwright behaviour this fix depends on.

    ``goto`` to a real URL leaves the navigation PROVISIONAL and raises
    (what Chromium does when the server never answers); ``goto`` to
    about:blank commits and clears the provisional flag; ``evaluate``
    while provisional is the 763s block -- reported here as a sentinel
    exception instead of a hang, so the test fails fast and loudly.
    """

    def __init__(self, fail_goto: bool = True):
        self.fail_goto = fail_goto
        self.provisional = False
        self.navigations: list = []
        self.recoveries = 0

    # Signatures match the real Playwright sync API (verified by
    # dev/_double_fidelity_probe.py for the sibling double in
    # test_spa_crawler_nav_recovery.py): keyword-only timeout/wait_until
    # on goto, positional expression + optional arg on evaluate.  Looser
    # **kwargs versions would accept calls the real code cannot make.
    def goto(self, url, timeout=None, wait_until=None):
        self.navigations.append(url)
        if url == "about:blank":
            self.provisional = False
            self.recoveries += 1
            return None
        if self.fail_goto:
            self.provisional = True
            raise TimeoutError("Page.goto: Timeout 2000ms exceeded")
        self.provisional = False
        return None

    def evaluate(self, expression, arg=None):
        if self.provisional:
            raise RuntimeError(
                "EVALUATE_ON_PROVISIONAL (live cost measured at 763s)")
        return None

    def wait_for_timeout(self, ms):
        return None


def _analyzer() -> DynamicDomAnalyzer:
    return DynamicDomAnalyzer(timeout=1)


def test_bounded_goto_recovers_after_failed_navigation():
    page = FakePage(fail_goto=True)
    _analyzer()._bounded_goto(page, "http://127.0.0.1:1/evt",
                              time.monotonic() + 5)
    # The goto raised internally -- control must not return with the page
    # still provisional, or the caller's next evaluate pays 763s.
    assert page.recoveries == 1, (
        "failed goto did not trigger about:blank recovery: navigations="
        f"{page.navigations}")
    assert page.provisional is False
    # And the caller's pattern (goto -> settle -> evaluate) now works.
    page.wait_for_timeout(0)
    page.evaluate("window.__xss_dom_harness = 1;")


def test_bounded_goto_no_recovery_when_goto_succeeds():
    """Recovery is for failures only -- a healthy path must not navigate
    away from the page it just loaded (that would discard real hits)."""
    page = FakePage(fail_goto=False)
    _analyzer()._bounded_goto(page, "http://127.0.0.1:1/evt",
                              time.monotonic() + 5)
    assert page.recoveries == 0, "recovery fired on a SUCCESSFUL goto"
    assert page.navigations == ["http://127.0.0.1:1/evt"]


def test_mutation_control_neutered_recovery_is_detected():
    """Mutation control: stub _recover_nav out and the contract test's
    assertions MUST fail -- otherwise those assertions read nothing."""
    page = FakePage(fail_goto=True)
    original = dom_engine._recover_nav
    dom_engine._recover_nav = lambda p: None
    try:
        _analyzer()._bounded_goto(page, "http://127.0.0.1:1/evt",
                                  time.monotonic() + 5)
    finally:
        dom_engine._recover_nav = original
    # With recovery neutered the page is STILL provisional -- exactly the
    # state the contract test asserts away.
    assert page.recoveries == 0 and page.provisional is True
    with pytest.raises(RuntimeError, match="EVALUATE_ON_PROVISIONAL"):
        page.evaluate("should not get here on a wedged page")


def test_recover_nav_is_best_effort():
    """Recovery failure must not raise: the caller already handles the
    original goto failure; a crashing recovery would turn one handled
    error into an unhandled one."""
    class ExplodingPage:
        def goto(self, url, **kw):
            raise RuntimeError("browser is wedged too")

    _recover_nav(ExplodingPage())  # must not raise


def test_recover_nav_only_accepts_about_blank():
    """Scope guard: recovery must navigate to about:blank and nothing
    else -- recovering to the ORIGINAL url would re-enter the loop this
    fix exists to break (and could hammer an unresponsive target)."""
    class RecordingPage:
        def __init__(self):
            self.urls = []
        def goto(self, url, **kw):
            self.urls.append(url)
            return None

    p = RecordingPage()
    _recover_nav(p)
    assert p.urls == ["about:blank"]


# ---------------------------------------------------------------------------
# 2. harvest (--discover) has the same shape
# ---------------------------------------------------------------------------

class HarvestFakePage(FakePage):
    """A Page double, plus the two members `harvest()` also needs.

    `new_page` used to live here, commented "only used if someone calls
    browser.new_page".  It was never called -- `new_page` belongs to
    Browser, not Page (real call sites: dom_engine.py:1051 and :1302,
    both `browser.new_page(...)`), so having it on the Page double let a
    test pass against a call the real code cannot make.  Removed by
    dev/_doubles_audit.py; the browser double below owns it.
    """

    def __init__(self, fail_goto=True):
        super().__init__(fail_goto=fail_goto)
        self._init_scripts = []

    def add_init_script(self, script=None, path=None):
        self._init_scripts.append(script)

    def evaluate(self, expr, arg=None):
        if self.provisional:
            raise RuntimeError("EVALUATE_ON_PROVISIONAL")
        return {"names": ["q", "search"], "urls": []}


class HarvestFakeBrowser:
    """`get_shared_browser()` returns a Browser; `new_page` belongs here."""

    def __init__(self, page):
        self._page = page
        self.new_page_calls: list = []

    def new_page(self, **_k):
        self.new_page_calls.append(True)
        return self._page

    def close(self):
        return None


def test_harvest_recovers_after_failed_navigation(monkeypatch):
    page = HarvestFakePage(fail_goto=True)
    fake_browser = HarvestFakeBrowser(page)

    monkeypatch.setattr(dom_engine, "get_shared_browser",
                        lambda: fake_browser)
    monkeypatch.setattr(DynamicDomAnalyzer, "available",
                        staticmethod(lambda: True))
    out = DynamicDomAnalyzer(timeout=1).harvest("http://127.0.0.1:1/app")
    assert page.recoveries == 1, (
        "harvest's failed goto did not recover -- its page.evaluate would "
        "block 763s live")
    assert fake_browser.new_page_calls, (
        "harvest must have obtained its page from browser.new_page(); if "
        "this is empty the double is answering a call the real code "
        "never makes")
    # evaluate ran AFTER recovery, so harvest degrades honestly to an
    # empty render instead of hanging (names come from the fake's
    # post-recovery evaluate).
    assert isinstance(out, dict)


def test_harvest_mutation_control(monkeypatch):
    """Same mutation control for harvest: neutered recovery leaves the
    page provisional and the evaluate sentinel fires."""
    page = HarvestFakePage(fail_goto=True)
    fake_browser = HarvestFakeBrowser(page)
    monkeypatch.setattr(dom_engine, "get_shared_browser",
                        lambda: fake_browser)
    monkeypatch.setattr(DynamicDomAnalyzer, "available",
                        staticmethod(lambda: True))
    monkeypatch.setattr(dom_engine, "_recover_nav", lambda p: None)
    # harvest swallows evaluate failures (best-effort contract) and
    # returns the empty dict -- so assert the STATE that proves the page
    # was left wedged, not an exception.
    out = DynamicDomAnalyzer(timeout=1).harvest("http://127.0.0.1:1/app")
    assert page.recoveries == 0 and page.provisional is True
    assert out == {"names": [], "resource_urls": [], "routes": []}


# ---------------------------------------------------------------------------
# 3. live: real Chromium, silent server, hard wall-clock bound
# ---------------------------------------------------------------------------

def _silent_server():
    """Accept connections, never respond -- the wire shape of a server
    whose single thread is parked on someone else's keep-alive."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    done = threading.Event()
    held = []

    def loop():
        while not done.is_set():
            try:
                srv.settimeout(0.3)
                c, _ = srv.accept()
                held.append(c)   # never read, never write
            except socket.timeout:
                continue
            except OSError:
                break
        for c in held:
            try:
                c.close()
            except Exception:
                pass
        try:
            srv.close()
        except Exception:
            pass

    threading.Thread(target=loop, daemon=True).start()
    return port, done


@pytest.mark.skipif(not DynamicDomAnalyzer.available(),
                    reason="playwright/chromium not available")
def test_live_failed_goto_then_evaluate_within_bound():
    """Level 3: the real browser, the real fix, a hard bound.

    Without recovery this is the 763s branch (probe A).  With it, goto
    costs its 1s budget, recovery ~0.02s, evaluate ~0s -- the whole test
    must finish well inside LIVE_BOUND, which is 60x below the unfixed
    cost.  The bound is deliberately loose (CI machines vary); the
    unfixed behaviour cannot come anywhere near it.
    """
    port, done = _silent_server()
    try:
        from xssentinel.core.dom_engine import get_shared_browser
        browser = get_shared_browser()
        page = browser.new_page()
        try:
            t0 = time.monotonic()
            with pytest.raises(Exception):
                page.goto(f"http://127.0.0.1:{port}/evt",
                          wait_until="commit", timeout=1000)
            _recover_nav(page)
            page.evaluate("1 + 1")   # the call that cost 763s unfixed
            elapsed = time.monotonic() - t0
            assert elapsed < 60, (
                f"goto-fail -> recover -> evaluate took {elapsed:.1f}s "
                f"(measured fixed cost: ~1.02s; unfixed: ~765s)")
        finally:
            try:
                page.close()
            except Exception:
                pass
    finally:
        done.set()
