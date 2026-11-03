# -*- coding: utf-8 -*-
"""Phase 355: the transport-layer evidence canaries, both directions.

The Phase 353 prescreens sampled the probe list (3 of 19 headers, 2 of 5
cookies).  ``tests/test_redteam_independent.py`` refuted the premise on its
first full-suite run: /api/reflect echoes ONLY ``Referer`` (declared entry
7), so the sampled canary turned a confirmed finding into a false negative.
Phase 355 replaces sampling with coverage: ONE request carrying EVERY name
the probe loop would pay for, each with its own plain token.  The skip now
fires only when NOTHING probeable reflects -- sound by construction, and
one request cheaper than the sample.

These gates pin, per layer (header / cookie / path):

  * skip case  -- non-reflecting target: exactly the canary request, the
    skip is RECORDED with its reason (never a silent no-op),
  * pass-through -- canary hit: the full probe list still goes out,
  * selective echo -- a target reflecting exactly ONE late/unsampled name
    is NOT skipped and its finding lands (the redteam lesson, pinned),
  * XSS_ADAPTIVE_LAYERS=0 / XSS_BUDGET_V2=0 -- the historical full set.

Pure stand-ins, no loopback: the canary only reads ``resp.text``.  Echoes
are wrapped in an HTML comment so reflections count for the canary but
never reach ``confirmed`` in the probe loop (verified against the real
analyzer + verifier before this file was written).
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from xssentinel.core import cookie_xss as cookie_mod
from xssentinel.core import header_xss as header_mod
from xssentinel.core import path_xss as path_mod
from xssentinel.core.layers import transport_layers


class _Resp:
    def __init__(self, text: str = ""):
        self.text = text
        self.headers = {}
        self.status_code = 200


class _StubRequester:
    """Answers every request with a body built by ``_body``.

    ``_body(sent_headers, url)`` lets each test decide what "the server
    echoes".  Every request is recorded for the count assertions.
    """

    def __init__(self, body_fn):
        self.sent_headers: list[dict] = []
        self.urls: list[str] = []
        self._body_fn = body_fn

    def get(self, url, headers=None, **kw):
        self.sent_headers.append(dict(headers or {}))
        self.urls.append(url)
        return _Resp(self._body_fn(dict(headers or {}), url))

    def request(self, method, url, params=None, data=None, headers=None):
        return self.get(url, headers=headers)


class _FakeCoverage:
    def __init__(self):
        self.layers: list[tuple] = []

    def touch_layer(self, *a, **k):
        pass

    def record_request(self, *a, **k):
        pass

    def record_layer(self, url, layer_id, method="GET",
                     status="ran", detail=""):
        self.layers.append((layer_id, status, detail))


class _FakeScanner:
    def __init__(self):
        self.coverage = _FakeCoverage()
        self.verbose = False
        self.requests_made = 0
        self.findings: list = []

    def _bump(self):
        self.requests_made += 1

    def _add(self, finding):
        self.findings.append(finding)


def _skips(sc, layer_id):
    return [e for e in sc.coverage.layers
            if e[0] == layer_id and e[1] == "skipped"]


_NO_ECHO = lambda hdrs, url: "<html><body>static</body></html>"  # noqa: E731


def _comment_echo(hdrs, url):
    parts = [f"<!-- {v} -->" for v in hdrs.values()]
    parts.append(f"<!-- {url} -->")
    return "<html><body>" + "".join(parts) + "</body></html>"


def _only_header(name):
    def _body(hdrs, url):
        v = hdrs.get(name, "")
        # RAW echo: the canary's plain token cannot confirm anything, but
        # the probe loop's payload must land in an executable context for
        # the finding to be confirmed.
        return f"<html><body>{v}</body></html>" if v \
            else "<html><body>static</body></html>"
    return _body


# ---------------------------------------------------------------- header ---

class TestHeaderCanary:

    def test_authenticated_session_keeps_cookie_out_of_the_probe_list(self):
        """Cookie: <canary> replaces the operator's session cookie and makes
        every response 401 (self-hosted /header FN).  Cookie XSS has its own
        layer; the header layer must not destroy the session it audits."""
        class _Session:
            cookies = {"sid": "operator-session"}

        class _Req:
            session = _Session()

        names = transport_layers._header_probe_names(_FakeScanner(), _Req())
        assert "Cookie" not in names
        assert "User-Agent" in names

    def test_anonymous_session_keeps_cookie_in_the_probe_list(self):
        names = transport_layers._header_probe_names(_FakeScanner(),
                                                      _StubRequester(_NO_ECHO))
        assert "Cookie" in names

    def test_skip_when_nothing_reflects(self):
        sc = _FakeScanner()
        req = _StubRequester(_NO_ECHO)
        transport_layers._scan_header_xss(sc, req, "http://t.invalid/x")
        assert len(req.sent_headers) == 1, (
            f"canary must cost exactly one request, sent {len(req.sent_headers)}")
        assert len(_skips(sc, "L8_header")) == 1
        assert "canary" in _skips(sc, "L8_header")[0][2]
        assert sc.findings == []

    def test_pass_through_sends_the_whole_list(self):
        sc = _FakeScanner()
        req = _StubRequester(_comment_echo)
        transport_layers._scan_header_xss(sc, req, "http://t.invalid/x")
        sent = set()
        for one in req.sent_headers:
            sent.update(one.keys())
        missing = [h for h in header_mod.INJECTABLE_HEADERS if h not in sent]
        assert not missing, f"canary hit must still probe the whole list: {missing}"
        assert not _skips(sc, "L8_header")

    def test_selective_late_echo_is_not_skipped_and_lands(self):
        """The redteam lesson: a server echoing ONLY a declared-late header
        must get its finding.  The Phase 353 3-canary sample skipped this
        server; the all-header canary must not."""
        late = header_mod.INJECTABLE_HEADERS[6]
        assert late == "True-Client-IP", (
            "the pin below rides on the list order; re-pin if it moved")
        sc = _FakeScanner()
        req = _StubRequester(_only_header(late))
        transport_layers._scan_header_xss(sc, req, "http://t.invalid/x")
        assert not _skips(sc, "L8_header")
        params = [f.data.get("param") for f in sc.findings
                  if f.data.get("type") == "header_xss"]
        assert f"(header:{late})" in params, (
            f"selective echo of the late header was not confirmed: {params}")

    @pytest.mark.parametrize("env", ["XSS_ADAPTIVE_LAYERS", "XSS_BUDGET_V2"])
    def test_env_off_restores_the_full_set(self, env, monkeypatch):
        monkeypatch.setenv(env, "0")
        sc = _FakeScanner()
        req = _StubRequester(_NO_ECHO)
        transport_layers._scan_header_xss(sc, req, "http://t.invalid/x")
        assert not _skips(sc, "L8_header")
        sent = set()
        for one in req.sent_headers:
            sent.update(one.keys())
        assert set(header_mod.INJECTABLE_HEADERS) <= sent


# ---------------------------------------------------------------- cookie ---

class TestCookieCanary:

    def test_skip_when_nothing_reflects(self):
        sc = _FakeScanner()
        req = _StubRequester(_NO_ECHO)
        transport_layers._scan_cookie_xss(sc, req, "http://t.invalid/x")
        assert len(req.sent_headers) == 1
        assert len(_skips(sc, "L8_cookie")) == 1
        assert "canary" in _skips(sc, "L8_cookie")[0][2]
        assert sc.findings == []

    def test_pass_through_sends_top5(self):
        sc = _FakeScanner()
        req = _StubRequester(_comment_echo)
        transport_layers._scan_cookie_xss(sc, req, "http://t.invalid/x")
        assert len(req.sent_headers) >= 1 + 5
        assert not _skips(sc, "L8_cookie")

    def test_selective_unsampled_echo_is_not_skipped_and_lands(self):
        """Echo ONLY candidate #3 -- the name the Phase 353 2-of-5 sample
        never sent.  The finding must still land."""
        third = cookie_mod.candidate_cookies()[2]
        sc = _FakeScanner()
        req = _StubRequester(_only_cookie(third))
        transport_layers._scan_cookie_xss(sc, req, "http://t.invalid/x")
        assert not _skips(sc, "L8_cookie")
        params = [f.data.get("param") for f in sc.findings
                  if f.data.get("type") == "cookie_xss"]
        assert any(third in (p or "") for p in params), (
            f"selective echo of unsampled candidate {third!r} was not "
            f"confirmed: {params}")

    @pytest.mark.parametrize("env", ["XSS_ADAPTIVE_LAYERS", "XSS_BUDGET_V2"])
    def test_env_off_restores_the_full_set(self, env, monkeypatch):
        monkeypatch.setenv(env, "0")
        sc = _FakeScanner()
        req = _StubRequester(_NO_ECHO)
        transport_layers._scan_cookie_xss(sc, req, "http://t.invalid/x")
        assert not _skips(sc, "L8_cookie")
        assert len(req.sent_headers) == 5


def _only_cookie(name):
    def _body(hdrs, url):
        raw = hdrs.get("Cookie", "")
        keep = [pair for pair in raw.split("; ") if pair.startswith(
            name + "=")]
        if not keep:
            return "<html><body>static</body></html>"
        # RAW echo (see _only_header): plain canary tokens are harmless,
        # the probe payload needs an executable context to confirm.
        return f"<html><body>{keep[0].split('=', 1)[1]}</body></html>"
    return _body


# ------------------------------------------------------------------ path ---

class TestPathCanary:

    def test_skip_when_segment_not_reflected(self):
        sc = _FakeScanner()
        req = _StubRequester(_NO_ECHO)
        transport_layers._scan_path_xss(sc, req, "http://t.invalid/app/route")
        assert len(req.urls) == 1
        assert len(_skips(sc, "L8_path")) == 1
        assert "bare marker" in _skips(sc, "L8_path")[0][2]
        assert sc.findings == []

    def test_pass_through_sends_the_payload_shapes(self):
        sc = _FakeScanner()
        req = _StubRequester(lambda hdrs, url: f"<html>{url}</html>")
        transport_layers._scan_path_xss(sc, req, "http://t.invalid/app/route")
        expected = len([p for p in path_mod.path_payloads()
                        if p != "xssentinel"])
        assert len(req.urls) == 1 + expected, (
            f"canary hit must run the full payload ladder: "
            f"{len(req.urls)} != 1 + {expected}")
        assert not _skips(sc, "L8_path")

    @pytest.mark.parametrize("env", ["XSS_ADAPTIVE_LAYERS", "XSS_BUDGET_V2"])
    def test_env_off_restores_the_full_set(self, env, monkeypatch):
        monkeypatch.setenv(env, "0")
        sc = _FakeScanner()
        req = _StubRequester(_NO_ECHO)
        transport_layers._scan_path_xss(sc, req, "http://t.invalid/app/route")
        assert not _skips(sc, "L8_path")
        expected = len([p for p in path_mod.path_payloads()
                        if p != "xssentinel"])
        assert len(req.urls) == expected
