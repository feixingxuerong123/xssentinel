# -*- coding: utf-8 -*-
"""Shared-browser lifecycle: a crashed instance must not silence the rest
of the process (Phase 224).

The failure this locks down was measured, not theorised: in the 13h
single-process suite run, ``test_range5``'s live Lit pair failed with
``all findings: []``.  ``dev/_stale_browser_probe.py`` reproduces the
mechanism deterministically -- when Chromium dies without going through
``shutdown_thread_browser()``, the thread-local entry stays behind with
playwright's greenlet loop still parked in the thread, so the next
``get_shared_browser()`` raises ``RuntimeError``, and ``analyze()``'s
catch-all turned that into a silent empty result for every later caller
in the process.  Silent-FN direction: the worst one.

These tests need no real Chromium -- the launch path is driven through an
injected fake ``playwright.sync_api`` module, and the stale state is
injected into ``dom_engine._TLS`` directly.  What is asserted is the
lifecycle contract, not the browser:

  1. a DEAD thread-local browser is unwound (its playwright stopped) and
     a fresh instance launched -- not a RuntimeError;
  2. a HEALTHY instance is returned as-is, with its playwright never
     stopped (the reverse guard: an over-eager unwind would pay a ~1-2s
     relaunch on every call);
  3. ``analyze()`` logs a WARNING naming the URL and the exception when
     the browser path fails -- "no findings" and "no browser" must never
     look the same in the logs again.
"""
from __future__ import annotations

import logging
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import dom_engine  # noqa: E402


# --------------------------------------------------------------------------
# fakes
# --------------------------------------------------------------------------

class _FakeBrowser:
    def __init__(self, connected: bool = True):
        self._connected = connected
        self.closed = False

    def is_connected(self) -> bool:
        return self._connected

    def close(self) -> None:            # a "crash": TLS is NOT cleared
        self._connected = False
        self.closed = True


class _FakeChromium:
    def __init__(self, browser: _FakeBrowser):
        self._browser = browser
        self.launches = 0

    def launch(self, args=None):
        self.launches += 1
        return self._browser


class _FakePlaywright:
    def __init__(self, browser: _FakeBrowser):
        self.chromium = _FakeChromium(browser)
        self.stopped = 0

    def start(self) -> "_FakePlaywright":
        return self

    def stop(self) -> None:
        self.stopped += 1


def _install_fake_playwright(monkeypatch, browser: _FakeBrowser):
    """Make the function-local ``from playwright.sync_api import
    sync_playwright`` inside get_shared_browser() resolve to a fake."""
    fake_mod = types.ModuleType("playwright.sync_api")
    pw = _FakePlaywright(browser)

    def _sync_playwright():
        return pw

    fake_mod.sync_playwright = _sync_playwright
    monkeypatch.setitem(sys.modules, "playwright.sync_api", fake_mod)
    return pw


def _clear_tls():
    for attr in ("browser", "pw"):
        if hasattr(dom_engine._TLS, attr):
            try:
                delattr(dom_engine._TLS, attr)
            except AttributeError:
                pass


@pytest.fixture
def clean_tls():
    _clear_tls()
    yield
    _clear_tls()


# --------------------------------------------------------------------------
# 1 + 2: the lifecycle contract
# --------------------------------------------------------------------------

def test_dead_instance_is_unwound_then_relaunched(monkeypatch, clean_tls):
    """A crashed browser must cost one relaunch, not a permanent
    RuntimeError for the rest of the thread's life."""
    stale = _FakeBrowser(connected=False)       # already dead in TLS
    stale_pw = _FakePlaywright(stale)
    dom_engine._TLS.browser = stale
    dom_engine._TLS.pw = stale_pw

    fresh = _FakeBrowser(connected=True)
    new_pw = _install_fake_playwright(monkeypatch, fresh)

    got = dom_engine.get_shared_browser()

    assert got is fresh, "a dead instance must not be handed back"
    assert stale_pw.stopped == 1, (
        "the stale playwright was not unwound -- its greenlet loop would "
        "still be parked in this thread and the relaunch refused")
    assert new_pw.chromium.launches == 1
    assert dom_engine._TLS.browser is fresh
    assert dom_engine._TLS.pw is new_pw


def test_healthy_instance_is_reused_without_unwind(monkeypatch, clean_tls):
    """Reverse guard: a live browser is returned untouched.  Unwinding on
    every call would pay a fresh Chromium launch (~1-2s) per analyze()."""
    live = _FakeBrowser(connected=True)
    live_pw = _FakePlaywright(live)
    dom_engine._TLS.browser = live
    dom_engine._TLS.pw = live_pw

    _install_fake_playwright(monkeypatch, _FakeBrowser(connected=True))

    got = dom_engine.get_shared_browser()

    assert got is live
    assert live_pw.stopped == 0, "a healthy instance was stopped anyway"
    assert live_pw.chromium.launches == 0, "a healthy instance was relaunched"


# --------------------------------------------------------------------------
# 3: never-silent rule
# --------------------------------------------------------------------------

@pytest.mark.skipif(not dom_engine.DynamicDomAnalyzer.available(),
                    reason="playwright not installed")
def test_analyze_warns_when_browser_path_fails(monkeypatch, caplog, clean_tls):
    """analyze() must not turn "the browser could not run" into a silent
    empty list -- that is the shape that hid the range5 flake."""
    url = "http://127.0.0.1:1/unsafe"

    def _boom():
        raise RuntimeError("cannot start Playwright sync API: this thread "
                           "already has a running event loop")

    monkeypatch.setattr(dom_engine, "get_shared_browser", _boom)
    with caplog.at_level(logging.WARNING):
        out = dom_engine.DynamicDomAnalyzer().analyze(url, marker="probe")

    assert out == [], "a failed browser path must still degrade, not raise"
    warns = [r for r in caplog.records
             if r.levelno == logging.WARNING and "browser analysis failed"
             in r.getMessage()]
    assert warns, (
        "analyze() swallowed a dead browser path silently -- 'no findings' "
        "and 'no browser' are indistinguishable in the logs")
    msg = warns[0].getMessage()
    assert url in msg and "RuntimeError" in msg
