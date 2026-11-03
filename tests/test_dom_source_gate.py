# -*- coding: utf-8 -*-
"""Phase 352: DOM source-probe budget gate.

The browser probe set is the DOM layer's cost multiplier.  A page that never
reads a URL/cookie/referrer source cannot receive attacker data through that
channel, so the probe is pure cost.  These pure tests lock:
  * no source read -> no probe (and analyze() can skip the browser),
  * cookie-only page -> cookie probe only,
  * external bundle -> hash+search retained (its router read is invisible),
  * XSS_DOM_SOURCE_GATE=0 -> the historical full set, byte-for-byte.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import dom_engine  # noqa: E402
from xssentinel.core.dom_engine import DynamicDomAnalyzer  # noqa: E402


def _analyzer(html: str) -> DynamicDomAnalyzer:
    a = DynamicDomAnalyzer.__new__(DynamicDomAnalyzer)
    a._caller_page_text = html
    return a


def _sources(probes) -> set:
    return {p.get("source") for p in probes}


def test_no_source_read_emits_no_probes():
    html = "<html><body><div id='x'></div><script>var a=1;</script></body></html>"
    assert _analyzer(html)._probes("http://h/p?q=1", "MK") == []


def test_cookie_only_page_gets_cookie_probe_only():
    html = "<script>var s=document.cookie;</script>"
    probes = _analyzer(html)._probes("http://h/p?q=1", "MK")
    assert _sources(probes) == set(["document.cookie"]), probes


def test_external_bundle_keeps_hash_and_search():
    html = "<html><script src='/app.js'></script></html>"
    probes = _analyzer(html)._probes("http://h/#/search?q=1", "MK")
    sources = _sources(probes)
    assert "location.hash" in sources and "location.search" in sources, probes
    assert "document.cookie" not in sources, probes


def test_generic_location_keeps_conservative_location_probes():
    html = "<script>var u = location + '';</script>"
    sources = _sources(_analyzer(html)._probes("http://h/p", "MK"))
    assert "location.hash" in sources and "location.search" in sources, sources


def test_env_switch_restores_the_historical_full_set(monkeypatch):
    monkeypatch.setenv("XSS_DOM_SOURCE_GATE", "0")
    html = "<script>var a=1;</script>"
    sources = _sources(_analyzer(html)._probes("http://h/p?q=1", "MK"))
    assert {"location.hash", "location.search", "location.href",
            "location.pathname", "document.referrer", "document.cookie",
            "window.name", "postMessage"} <= sources, sources


def test_no_page_text_keeps_the_historical_full_set():
    # Pure probe-URL callers (tests, and any caller without a body) must not
    # silently shrink -- that would be a recall change disguised as speed.
    a = DynamicDomAnalyzer.__new__(DynamicDomAnalyzer)
    sources = _sources(a._probes("http://h/p?q=1", "MK"))
    assert "document.cookie" in sources and "window.name" in sources, sources


def test_page_source_hints_shape():
    hints = dom_engine.page_source_hints(
        "<script>document.cookie; location.hash; addEventListener('message')</script>")
    assert hints["cookie"] and hints["hash"] and hints["postmessage"]
    assert not hints["path"] and not hints["referrer"]
