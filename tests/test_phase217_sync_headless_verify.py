# -*- coding: utf-8 -*-
"""Phase 217: sync confirms bypass findings headlessly -- the mirror of the
async wrapper.

The asymmetry this closes (measured 2026-10-11, same lab target, both
engines, ``--headless``): sync's L8 request carriers (header / path /
cookie / error) are ``_add``ed directly and bypassed ``_record``'s
per-finding confirmation, so they stayed browser-unavailable/no-proof
while the async engine's scan()-level wrapper (Phase 183) confirmed the
very same shapes browser-executed.  Same scan, same target, different
evidence vocabulary -- and the prerequisite the 1.5-② severity cap is
waiting on (capping "no browser evidence + no proof" highs while the
confirmation paths differed would have broken engine severity parity).

The guards mirror ``_headless_verify_finding`` verbatim; the token
extraction is now ONE shared function (``findings.extract_replay_token``)
-- two copies of a carrier contract is the Phase 207 drift shape.

Run: pytest tests/test_phase217_sync_headless_verify.py -q
"""
from __future__ import annotations

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssentinel.core.findings import (  # noqa: E402
    EVIDENCE_OOB, Finding, extract_replay_token)
from xssentinel.core.scanner import Scanner  # noqa: E402

MARKED = "alert('xssp_q_2813')"


class _Session:
    headers: dict = {}


class _Req:
    session = _Session()


def _bypass_finding(**over) -> Finding:
    d = {"url": "http://h/p%2Fbench", "method": "GET",
         "param": "(path)", "type": "path_xss", "context": "url_path",
         "payload": MARKED, "transform": [], "severity": "high",
         "confidence": "high", "detail": "d",
         "evidence_class": "browser-unavailable",
         "headless": None, "proof": None}
    d.update(over)
    return Finding(**d)


@pytest.fixture()
def scanner(monkeypatch):
    s = Scanner(use_headless=True)
    s.req = _Req()
    calls: list = []

    def _fake_verify(url, method, params, data, headers, token, timeout=20):
        calls.append({"url": url, "params": params, "token": token})
        return {"available": True, "confirmed": True, "outcome": "fired",
                "detail": "dialog fired"}

    monkeypatch.setattr("xssentinel.core.verifier.verify_headless",
                        _fake_verify)
    s._verify_calls = calls
    return s


def test_bypass_finding_gets_browser_evidence(scanner):
    scanner._add(_bypass_finding())
    d = scanner.findings[0].data
    assert d["headless"]["confirmed"] is True
    assert d["evidence_class"] == "browser-executed"
    assert scanner._verify_calls, "the mirror never called verify_headless"
    # The replay must carry the finding's token for attribution.
    assert scanner._verify_calls[0]["token"] == "xssp_q_2813"


def test_refuted_replay_downgrades_like_the_async_wrapper(scanner, monkeypatch):
    monkeypatch.setattr("xssentinel.core.verifier.verify_headless",
                        lambda *a, **k: {"available": True,
                                         "confirmed": False,
                                         "outcome": "not-fired",
                                         "detail": "no dialog"})
    scanner._add(_bypass_finding())
    d = scanner.findings[0].data
    assert d["evidence_class"] == "browser-refuted"
    assert d["confidence"] == "low"


def test_record_findings_are_never_reverified(scanner):
    """A finding that already carries a headless dict (the _record path,
    including its explicit skip shapes) must pass through untouched."""
    d0 = {"url": "http://h/p", "method": "GET", "param": "q",
          "type": "reflected", "context": "html_element",
          "payload": MARKED, "transform": [], "severity": "high",
          "confidence": "high", "detail": "d",
          "evidence_class": "browser-unavailable",
          "headless": {"available": False, "confirmed": False,
                       "detail": "json carrier; headless replay skipped"},
          "proof": None}
    scanner._add(Finding(**d0))
    assert scanner._verify_calls == [], (
        "the mirror re-verified a finding that already carries a headless "
        "verdict -- double confirmation, and the skip-reason is overwritten")


def test_oob_and_placeholder_and_unattributable_are_skipped(scanner):
    oob = _bypass_finding(type="blind", evidence_class=EVIDENCE_OOB,
                          payload="xssp_q_2813")
    scanner._add(oob)
    placeholder = _bypass_finding(payload="(audit placeholder)")
    scanner._add(placeholder)
    unattributable = _bypass_finding(payload="no marker here at all")
    scanner._add(unattributable)
    assert scanner._verify_calls == [], (
        "OOB / placeholder / unattributable findings must skip the replay "
        "(the async wrapper's guards, mirrored)")


def test_replay_dedup_on_url_param_payload(scanner):
    scanner._add(_bypass_finding())
    scanner._add(_bypass_finding())
    assert len(scanner._verify_calls) == 1, (
        "identical replays must verify once (the async wrapper's dedup)")


def test_headless_off_never_verifies(monkeypatch):
    s = Scanner(use_headless=False)
    s.req = _Req()
    monkeypatch.setattr("xssentinel.core.verifier.verify_headless",
                        lambda *a, **k: pytest.fail(
                            "verify_headless called with --headless off"))
    s._add(_bypass_finding())
    assert s.findings[0].data["headless"] is None


def test_token_extraction_is_one_shared_contract():
    """The async wrapper delegates to the shared function; both engines
    must answer identically.  The inputs are the shapes verifier.mark
    actually emits (including the real concat stamp, whose token rides
    the fallback run -- a token without an ``xss`` run is unattributable
    BY CONTRACT, first measured 2026-10-11 against verifier.mark's own
    output)."""
    from xssentinel.core import verifier
    from xssentinel.core.async_scanner_verify import AsyncHeadlessVerifyMixin
    concat = verifier.mark("alert(1)", "xssp_q_2813", style="concat")
    for payload, want in [
        ("alert('xssp_q_2813')", "xssp_q_2813"),
        ("alert`xssp_q_2813`", "xssp_q_2813"),
        (concat, "xssp_q_2813"),
        ("plain text", None),
        # The documented boundary: the fallback requires an ``xss`` token
        # run, so a foreign-token concat stamp stays unattributable and
        # the replay is SKIPPED rather than risk a false refutation.
        (verifier.mark("alert(1)", "tok1234", style="concat"), None),
    ]:
        assert extract_replay_token(payload) == want, payload
        assert AsyncHeadlessVerifyMixin._probe_token(payload) == want, payload


# ---------------------------------------------------------------------------
# The TOCTOU the mirror exposed in the L8 error-page dedup (measured:
# clean tree stably 1 error finding per host; mirror tree stably 3 --
# the check-then-emit race on scanner.findings, widened ~1000x by the
# ~1-2s replay inside _add).  Fixed with an atomic per-host claim set.
# ---------------------------------------------------------------------------

class _ErrResp:
    def __init__(self, url: str):
        from urllib.parse import unquote
        self.status_code = 404
        self.headers = {"Content-Type": "text/html"}
        self.text = (f"<html><head><title>404</title></head><body>"
                     f"Not found: {unquote(url)}</body></html>")


class _ErrReq:
    def get(self, url, **kw):
        return _ErrResp(url)


class _ErrScanner:
    def __init__(self):
        import threading
        self._lock = threading.Lock()
        self.findings: list = []
        self.verbose = False
        self.use_headless = False
        self.req = _ErrReq()

        class _Cov:
            def touch_layer(self, *a, **k):
                pass

            def record_request(self, *a, **k):
                pass
        self.coverage = _Cov()

    def _add(self, f):
        self.findings.append(f)

    def _bump(self):
        pass


def test_error_page_host_claim_survives_finding_removal():
    """The per-host dedup must be a claim-set membership under the lock,
    not a scan of the findings list: a removed finding must NOT re-arm the
    probe for the same host."""
    from xssentinel.core.layers.transport_layers import _scan_error_xss
    s = _ErrScanner()
    _scan_error_xss(s, s.req, "http://h/echo")
    assert len(s.findings) == 1, "the reflected 404 probe must confirm"
    s.findings.clear()          # the finding left the list (dedup's old eyes)
    _scan_error_xss(s, s.req, "http://h/script")
    assert s.findings == [], (
        "the host claim must not re-arm after the finding left the list -- "
        "this is exactly the window the headless-confirmation mirror "
        "widened (measured: 1 -> 3 per-host findings)")
    _scan_error_xss(s, s.req, "http://other/echo")
    assert len(s.findings) == 1, "a different host claims its own probe"
