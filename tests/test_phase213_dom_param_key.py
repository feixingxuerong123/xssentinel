# -*- coding: utf-8 -*-
"""Phase 213: the DOM engine's delivered KEY rides back on the finding.

Before this phase every ``dom_dynamic`` Finding carried ``param=None`` even
when the engine knew exactly which key it had delivered the marker through
(``_probes()`` builds ``?q=`` and ``#/search?q=`` delivery URLs).  Measured
consequences on a real target (Phase 210b): the report's param column was
empty on the strongest evidence class, ``verify_fix`` could only fall back to
the ``params["_"]`` probe slot, and the fixer could not tell which key to
escape.

The contract this file pins:

* Every probe that injects the marker into a KEYED position carries
  ``param``: a real query key (``q``), the generic search key (``__xss__``),
  or a fragment key in source-qualified form (``q@hash`` -- qualified
  because no HTTP request ever sees it, so consumers must not treat it as
  one).
* Probes without a key position (raw fragment, href, pathname, referrer,
  cookie, window.name, postMessage) carry NO ``param`` key.  Pinned in both
  directions: a future probe cannot grow a fake key silently and a keyed
  probe cannot lose its key silently.
* ``@hash``-suffixed params are treated as keyless by every HTTP-replay
  consumer (poc curl, verify_fix replay, nuclei template): replaying
  ``?q@hash=`` at a server would reproduce nothing and could be read as
  "fixed" -- the worst direction for a fix report.
* The dom dedup group key stays param-blind (same sink on the same page is
  one issue; the remediation is the sink), so finding counts do not move.
"""
from __future__ import annotations

import asyncio
import os
import sys
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssentinel.core.dom_engine import DynamicDomAnalyzer  # noqa: E402
from xssentinel.core.findings import Finding  # noqa: E402

ROUTE_URL = "http://h/p?a=1&b=2#/r?q=3"
DOM_POC_PAYLOAD = "<img src=x onerror=alert(document.domain)>"


# ---------------------------------------------------------------------------
# The probe contract (pure, no browser)
# ---------------------------------------------------------------------------

def _probes(url: str = ROUTE_URL, marker: str = "MK") -> list:
    return DynamicDomAnalyzer()._probes(url, marker)


def test_keyed_probes_carry_the_delivered_key():
    keyed = {(p["source"], p["param"]) for p in _probes() if "param" in p}
    assert ("location.search", "a") in keyed
    assert ("location.search", "b") in keyed
    assert ("location.search", "__xss__") in keyed
    assert ("location.hash", "q@hash") in keyed


def test_keyless_probes_carry_no_param_key():
    """The exact keyless set, pinned so it can only move deliberately."""
    keyless = [p["source"] for p in _probes() if "param" not in p]
    assert sorted(keyless) == sorted([
        "location.hash",        # raw fragment -- the payload IS the fragment
        "location.href",
        "location.pathname",
        "document.referrer",
        "document.cookie",
        "window.name",
        "postMessage",
    ]), keyless


def test_hash_keys_are_source_qualified_and_search_keys_are_not():
    for p in _probes():
        if "param" not in p:
            continue
        if p["source"] == "location.hash":
            assert p["param"].endswith("@hash")
        else:
            assert not p["param"].endswith("@hash")


def test_delivery_url_matches_the_recorded_key():
    """The recorded key must be the key the probe URL actually carries."""
    for p in _probes():
        if p.get("param") == "q@hash":
            assert "q=MK" in p["url"], p["url"]
        if p.get("param") == "a":
            assert "a=MK" in p["url"], p["url"]


# ---------------------------------------------------------------------------
# Propagation into Findings (no browser: canned engine)
# ---------------------------------------------------------------------------

class _FakeResp:
    status_code = 200
    headers: dict = {}
    text = ("<html><body><script>"
            "document.getElementById('out').innerHTML = location.hash;"
            "</script></body></html>")


class _FakeReq:
    def get(self, url, **kw):
        return _FakeResp()

    def request(self, *a, **kw):
        return _FakeResp()


class _FakeEngine:
    def __init__(self, findings):
        self._f = findings

    def analyze(self, url, marker=None, dialog_token=None,
                page_text=None):
        return self._f


def _canned_dyn(param):
    return [{"type": "dom_dynamic", "sink": "Element.innerHTML",
             "source": "location.hash", "param": param,
             "snippet": "SNIP", "confidence": "high", "detail": "d"}]


def test_sync_dom_dynamic_finding_carries_param():
    from xssentinel.core.scanner import Scanner
    s = Scanner(use_headless=False)
    s._dom_engine = _FakeEngine(_canned_dyn("q@hash"))
    s._scan_dom(_FakeReq(), "http://h/#/r?q=x")
    dyn = [f for f in s.findings if f.data.get("type") == "dom_dynamic"]
    assert dyn, "canned engine hit did not reach a Finding"
    assert dyn[0].data["param"] == "q@hash"


def test_sync_keyless_hit_keeps_param_none():
    from xssentinel.core.scanner import Scanner
    s = Scanner(use_headless=False)
    s._dom_engine = _FakeEngine(_canned_dyn(None))
    s._scan_dom(_FakeReq(), "http://h/p")
    dyn = [f for f in s.findings if f.data.get("type") == "dom_dynamic"]
    assert dyn and dyn[0].data["param"] is None


def test_async_dom_dynamic_finding_carries_param():
    from xssentinel.core.async_scanner import AsyncScanner
    asc = AsyncScanner(max_concurrent=2, per_host_delay=0, jitter=0,
                       dom_engine="static")
    asc._resolve_dom_engine = lambda: _FakeEngine(_canned_dyn("q@hash"))

    async def run():
        out = []
        async for f in asc._scan_dom_async(
                "http://h/#/r?q=x", _FakeResp.text, "GET", {"q": "x"}):
            out.append(f)
        return out

    fs = asyncio.run(run())
    dyn = [f for f in fs if f.data.get("type") == "dom_dynamic"]
    assert dyn, "canned engine hit did not reach an async Finding"
    assert dyn[0].data["param"] == "q@hash"


# ---------------------------------------------------------------------------
# Dedup: the dom group key stays param-blind (counts do not move)
# ---------------------------------------------------------------------------

def _dom_finding(param):
    return Finding(url="http://h/p", method="GET", param=param,
                   type="dom_dynamic", context="Element.innerHTML",
                   payload="MK", transform=[], severity="high",
                   confidence="high", detail="d",
                   evidence_class="browser-executed")


def test_same_sink_via_two_keys_still_merges_to_one_finding():
    from xssentinel.core.scanner import Scanner
    s = Scanner(use_headless=False)
    s.findings = [_dom_finding("q"), _dom_finding("q@hash")]
    s.dedup()
    assert len(s.findings) == 1, (
        "the delivered key split a same-sink DOM group: the remediation is "
        "the sink, so the key must not be part of the group identity")


def test_non_dom_findings_still_dedupe_by_param():
    from xssentinel.core.scanner import Scanner
    s = Scanner(use_headless=False)

    def refl(p):
        return Finding(url="http://h/p", method="GET", param=p,
                       type="reflected", context="html_element",
                       payload="MK", transform=[], severity="high",
                       confidence="high", detail="d",
                       evidence_class="browser-executed")

    s.findings = [refl("q"), refl("other")]
    s.dedup()
    assert len(s.findings) == 2, (
        "non-dom findings must keep param in the group key")


# ---------------------------------------------------------------------------
# Consumers: @hash is never an HTTP carrier
# ---------------------------------------------------------------------------

def _dom_dict(param, url):
    return {"url": url, "method": "GET", "param": param,
            "type": "dom_dynamic", "context": "Element.innerHTML",
            "payload": "MK", "severity": "high", "confidence": "high",
            "detail": "d"}


def test_poc_fragment_key_never_becomes_a_query_curl():
    from xssentinel.core.poc import build_poc
    poc = build_poc(_dom_dict("q@hash", "http://h/#/search?q=x"))
    assert poc["curl"].startswith("#"), poc["curl"]
    assert "q@hash" not in poc["curl"], poc["curl"]
    # The HTML PoC navigates the fragment key, route path intact.
    expected = "#/search?q=" + urllib.parse.quote_plus(DOM_POC_PAYLOAD)
    assert expected in poc["html"], poc["html"]


def test_poc_query_key_replays_as_a_query():
    from xssentinel.core.poc import build_poc
    poc = build_poc(_dom_dict("q", "http://h/p?a=1"))
    assert poc["curl"].startswith("curl"), poc["curl"]
    assert "q=" + urllib.parse.quote_plus(DOM_POC_PAYLOAD) in poc["curl"]
    # The HTML embeds the target in an attribute: & is escaped to &amp;.
    assert "p?a=1&amp;q=" in poc["html"], poc["html"]


def test_poc_keyless_dom_keeps_the_legacy_raw_shapes():
    from xssentinel.core.poc import build_poc
    poc = build_poc(_dom_dict(None, "http://h/p"))
    assert poc["curl"].startswith("#"), poc["curl"]
    assert urllib.parse.quote(DOM_POC_PAYLOAD, safe="") in poc["html"]


class _Jar:
    def __init__(self):
        self._d: dict = {}

    def get(self, k, default=None):
        return self._d.get(k, default)

    def set(self, k, v):
        self._d[k] = v


class _RecordingRequester:
    """Records where the payload went; makes no request (carrier-test idiom
    from test_verify_carriers_live.py: the point is WHICH SLOT carried the
    payload, and a live echo can only show the end result)."""

    def __init__(self):
        self.session = type("S", (), {"cookies": _Jar(), "headers": {}})()
        self.calls: list = []

    def request(self, method, url, params=None, data=None, cache_get=None,
                **kw):
        self.calls.append({"method": method, "url": url,
                           "params": dict(params or {}),
                           "data": dict(data or {})})
        return _FakeResp()

    def close(self):
        pass


def test_replay_treats_hash_key_as_keyless():
    from xssentinel.core.verify_fix import _replay_request
    rq = _RecordingRequester()
    # Payload carries an alert() call: mark() injects the vfix_ token into
    # it (documented semantics -- a marker-less payload replays unmarked).
    _replay_request(rq, _dom_dict("q@hash", "http://h/#/search?q=x"),
                    "alert(document.domain)")
    assert rq.calls, "replay made no request"
    sent = rq.calls[0]
    assert "q@hash" not in sent["params"], sent
    assert set(sent["params"]) == {"_"}, sent
    assert "vfix_" in sent["params"]["_"], (
        "the probe-slot fallback must carry the freshly tokenized payload")


def test_replay_of_a_query_key_uses_the_real_slot():
    from xssentinel.core.verify_fix import _replay_request
    rq = _RecordingRequester()
    _replay_request(rq, _dom_dict("q", "http://h/p?a=1"),
                    "alert(document.domain)")
    sent = rq.calls[0]
    assert set(sent["params"]) == {"a", "q"}, sent
    assert "vfix_" in sent["params"]["q"], sent
    assert sent["url"] == "http://h/p", (
        "the URL query must move into params, not ride alongside them")


def test_nuclei_template_treats_hash_key_as_keyless():
    from xssentinel.core.report import _nuclei_template
    t = _nuclei_template(_dom_dict("q@hash", "http://h/#/search?q=x"),
                         "http://h")
    assert t["yaml"] and "q@hash" not in t["yaml"]
