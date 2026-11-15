"""Phase 397: ``dom_engine="off"`` must disable the browser on BOTH engines.

Root cause of the pos-sri-01 parity divergence (measured in
``benchmark/results/phase397_bisect_20261115.json``): 7 of 8 arms -- including
one where ALL FOUR product files changed since 2.1.0 were restored -- diverged
identically, while the eighth arm (``off_fixed``, adding an ``off`` branch to
both ``_resolve_dom_engine`` methods) converged. ``off`` is a documented MCP input
value ("off disables the DOM layer") and AsyncScanner's own default; both
resolvers previously fell through and constructed a real DynamicDomAnalyzer
whenever Playwright was importable.

Guards use a sentinel analyzer so "was a browser engine constructed?" is
measurable WITHOUT depending on whether Chromium happens to be installed.
The sentinel is only ever constructed or not -- no scan is run through it.
"""
from __future__ import annotations

import inspect

import pytest

from xssentinel.core import dom_engine as de_mod
from xssentinel.core.async_scanner import AsyncScanner
from xssentinel.core.async_scanner_layers import AsyncDetectionLayersMixin
from xssentinel.core.requester import Requester
from xssentinel.core.scanner import Scanner


class _SentinelAnalyzer:
    def __init__(self, **kw):
        self.kw = kw

    @staticmethod
    def available() -> bool:
        return True


@pytest.fixture
def sentinel(monkeypatch):
    monkeypatch.setattr(de_mod, "DynamicDomAnalyzer", _SentinelAnalyzer)
    return _SentinelAnalyzer


def test_sync_off_disables_browser_engine(sentinel):
    sc = Scanner(requester=Requester(timeout=5), dom_engine="off")
    assert sc._dom_engine is None
    assert sc._resolve_dom_engine() is None


def test_async_off_disables_browser_engine(sentinel):
    asc = AsyncScanner(dom_engine="off")
    assert asc._resolve_dom_engine() is None


def test_auto_still_builds_engine_on_both_sides(sentinel):
    """The fix must not silently turn off the default CLI/MCP mode."""
    sc = Scanner(requester=Requester(timeout=5), dom_engine="auto")
    assert isinstance(sc._dom_engine, sentinel)
    asc = AsyncScanner(dom_engine="auto")
    assert isinstance(asc._resolve_dom_engine(), sentinel)


def test_static_and_playwright_unchanged(sentinel):
    sc = Scanner(requester=Requester(timeout=5), dom_engine="static")
    assert sc._dom_engine is None
    asc = AsyncScanner(dom_engine="static")
    assert asc._resolve_dom_engine() is None
    # 'playwright' is the force-on mode; neither resolver may treat it as off.
    asc2 = AsyncScanner(dom_engine="playwright")
    assert isinstance(asc2._resolve_dom_engine(), sentinel)


def test_source_contract_off_branch_exists_on_both_resolvers():
    """Phase 394 lesson: a function body does not rot, its call sites do.

    Pin BOTH hand-written copies of the same contract; the mutation script
    proves a guard goes red when either copy loses its ``off`` branch.
    """
    for owner in (Scanner, AsyncDetectionLayersMixin):
        src = inspect.getsource(owner._resolve_dom_engine)
        assert src.count('if de == "off":') == 1, owner.__name__
        assert src.index('if de == "off":') < src.index('if de == "static":'), \
            owner.__name__
        # The branch must return, not just be present.
        assert 'if de == "off":\n            return None' in src, owner.__name__


def test_dom_delivery_guards_request_the_engine_explicitly():
    """The full batched gate caught 3 real regressions in this round.

    These guards assert browser-executed ``dom_dynamic`` findings but used to
    construct ``AsyncScanner`` without ``dom_engine`` -- i.e. the default
    ``off``.  They only passed because ``off`` was silently ignored before
    Phase 397.  An A/B arm that removed the ``off`` branches turned all 14
    green again, so the fix was to request ``auto`` at each call site, NOT to
    loosen an assertion.  Pin the call sites so the same drift cannot return.
    """
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    rel_paths = (
        "tests/test_phase215_crawl_mined_layers.py",
        "tests/test_phase209_spa_route_delivery.py",
        "tests/test_phase214_crawl_page_layers.py",
    )
    for rel in rel_paths:
        src = (root / rel).read_text(encoding="utf-8")
        assert "AsyncScanner(crawl=True" in src, rel
        assert 'dom_engine="auto"' in src, (
            f"{rel} must request the DOM engine explicitly; AsyncScanner's "
            f"default 'off' now really disables Chromium")
