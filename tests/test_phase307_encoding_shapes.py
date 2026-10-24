# -*- coding: utf-8 -*-
"""Phase 307: the encoding-first retry also covers reflected-marker pages.

Phase 306 added a bounded encoded pass for endpoints that decode the parameter
*before* echoing it, so the plain marker never comes back.  Phase 307 extends
the same pass to the sibling shape measured on XSSMaze: the plain marker IS
reflected, raw tags are rejected, and only a fully encoded value survives the
application's decode chain.  The static ladder cannot reach these shapes --
the Phase 157 guard skips every transform that rewrites the token -- so the
retry runs after the payload loop fails.

Each fixture endpoint accepts exactly one shape and rejects the others, which
is what makes the assertions load-bearing: the safe twin decodes correctly but
escapes the result, and the mutation controls disable the retry to prove the
finding disappears.  The budget is pinned in both directions: at most six
requests when nothing matches, and the loop stops at the first match.
"""
import asyncio
import base64
import html
import os
import re
import sys
import threading
import time
import unicodedata
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from xssentinel.core import transform, verifier  # noqa: E402
from xssentinel.core.async_scanner_layers import (  # noqa: E402
    AsyncDetectionLayersMixin,
)
from xssentinel.core.budget import BudgetExhausted, CircuitOpen  # noqa: E402
from xssentinel.core.requester import Requester  # noqa: E402
from xssentinel.core.scanner import Scanner  # noqa: E402

_ENTITY_TABLE = (
    ("&lt;", "<"),
    ("&gt;", ">"),
    ("&quot;", '"'),
    ("&#x27;", "'"),
    ("&#39;", "'"),
    ("&amp;", "&"),
)

# What each fixture endpoint decodes; the finding must name the same transform.
EXPECTED_TRANSFORM = {
    "/b64x2": "double_base64",
    "/u2": "double_url_encode",
    "/u3": "triple_url_encode",
    "/entities": "html_escape",
    "/fullwidth": "fullwidth",
}


def _decode_entities_once(value):
    for entity, char in _ENTITY_TABLE:
        value = value.replace(entity, char)
    return value


def _page(markup):
    return f"<html><body><div>{markup}</div></body></html>"


_MARKER_ONLY = re.compile(r"^[A-Za-z0-9_]+$")
_RAW_DANGEROUS = ('<', '>', '"', "'", '`')


def _reject():
    """A fixed page with NO input echoed.

    The Phase 307 shape reflects the plain marker (taking the reflected path)
    but answers anything with raw markup with a fixed page.  Echoing the
    escaped input instead would make the Phase 95 sandwich profile report
    "every critical character encoded" and set ``marker_escaped`` -- the
    post-reflection retry is deliberately gated off on those, so the fixture
    would never exercise the feature it is meant to test.
    """
    return _page("rejected")


def _marker_or_reject(value):
    if _MARKER_ONLY.match(value):
        return _page(html.escape(value, quote=False))
    return _reject()


def _b64_twice(value):
    first = base64.b64decode(value, validate=True)
    return base64.b64decode(first, validate=True).decode("utf-8")


def _u2(value):
    first = unquote(value)
    if "%3C" not in first.upper():
        return None
    return unquote(first)


def _u3(value):
    if "%2525" not in value.upper():
        return None
    out = value
    for _ in range(3):
        out = unquote(out)
    return out


def _entities(value):
    if "<" in value or ">" in value:
        return None
    out = value
    for _ in range(2):
        out = _decode_entities_once(out)
    return out


def _fullwidth(value):
    if not value or not all(ord(c) > 0xFF for c in value):
        return None
    return unicodedata.normalize("NFKC", value)


_APPLY = {
    "/b64x2": _b64_twice,
    "/u2": _u2,
    "/u3": _u3,
    "/entities": _entities,
    "/fullwidth": _fullwidth,
}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, body, headers=None, status=200):
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        parts = urlsplit(self.path)
        path = parts.path
        value = (parse_qs(parts.query).get("q") or [""])[0]

        if path == "/nothing":
            # Reflects the marker and nothing executable.  Used to measure
            # the bounded pass's exact cost.
            return self._send(_marker_or_reject(value))

        if path == "/csp":
            # Same shape with a strict inline CSP.  The post-reflection retry
            # is pointless here (the browser will not run inline script) and
            # must not fire.
            return self._send(
                _marker_or_reject(value),
                headers={"Content-Security-Policy":
                         "default-src 'self'; script-src 'self'"})

        safe = path.endswith("-safe")
        base = path[:-5] if safe else path
        decoder = _APPLY.get(base)
        if decoder is None:
            return self._send(_page("unknown path"), status=404)
        if _MARKER_ONLY.match(value):
            return self._send(_page(html.escape(value, quote=False)))
        if any(c in value for c in _RAW_DANGEROUS):
            return self._send(_reject())
        try:
            decoded = decoder(value)
        except Exception:
            decoded = None
        if decoded is None or "<script>" not in decoded:
            return self._send(_reject())
        return self._send(_page(html.escape(decoded) if safe else decoded))


@pytest.fixture(scope="module")
def base():
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        srv.shutdown()


def _scan(base, path):
    sc = Scanner(requester=Requester(timeout=8), max_payloads=4,
                 max_transforms=4, dom_engine="static",
                 advanced_layers=False)
    sc.scan_target(base + path, method="GET", params={"q": "a"}, data={},
                   oob_collect=False)
    sc.dedup()
    return [f.data for f in sc.findings]


def _scan_async(base, path):
    from xssentinel.core.async_scanner import AsyncScanner

    async def _run():
        asc = AsyncScanner(max_concurrent=2, per_host_delay=0, jitter=0,
                           timeout=8, dom_engine="static",
                           advanced_layers=False, max_payloads=4,
                           max_transforms=4)
        return [f.data async for f in asc.scan(
            base + path, method="GET", params={"q": "a"})]

    # The host's loopback is shared with other sessions and stalls
    # intermittently (Phases 187/200/201).  A stalled scan must fail fast and
    # be retried by pytest-rerunfailures instead of hanging the whole file.
    try:
        return asyncio.run(asyncio.wait_for(_run(), timeout=90))
    except asyncio.TimeoutError:
        pytest.fail(f"async scan of {path} did not finish within 90s")


def _reflected(rows):
    return [r for r in rows if r.get("type") == "reflected"]


# ---------------------------------------------------------------------------
# Transform contracts
# ---------------------------------------------------------------------------
def test_the_three_new_transforms_round_trip():
    marked = "<script>alert('xssv_dead')</script>"

    doubled = transform.apply("double_base64", marked)
    assert base64.b64decode(
        base64.b64decode(doubled.encode())).decode() == marked

    escaped = transform.apply("html_escape", marked)
    assert "&#x27;" in escaped and "(" in escaped
    assert "&apos;" not in escaped and "&#40;" not in escaped
    assert html.unescape(escaped) == marked

    wide = transform.apply("fullwidth", marked)
    assert all(ord(c) > 0xFF for c in wide)
    assert unicodedata.normalize("NFKC", wide) == marked


def test_html_escape_survives_a_custom_double_decoder_while_named_does_not():
    """The discriminator that made `html_escape` a new transform: the
    measured double decoder restores `&#x27;` but leaves `&apos;`/`&#40;`
    alone, so the ladder's `html_entity_named` variant is not a substitute."""
    token = "xssv_deadbeef"
    marked = verifier.mark("<script>alert(1)</script>", token)

    def decoded(text):
        for _ in range(2):
            text = _decode_entities_once(text)
        return text

    escaped = decoded(transform.apply("html_escape", marked))
    named = decoded(transform.apply("html_entity_named", marked))

    assert "<script>alert('" in escaped
    assert verifier.verify_semantic(_page(escaped), token).get("confirmed")
    assert not verifier.verify_semantic(_page(named), token).get("confirmed")


# ---------------------------------------------------------------------------
# End-to-end: each shape confirms through the new post-reflection retry
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("path", sorted(EXPECTED_TRANSFORM))
def test_sync_confirms_each_phase307_shape(base, path):
    rows = _scan(base, path)
    hits = _reflected(rows)
    assert hits, rows
    assert hits[0].get("transform") == [EXPECTED_TRANSFORM[path]], hits[0]


@pytest.mark.parametrize("path", sorted(EXPECTED_TRANSFORM))
def test_sync_safe_twins_stay_silent(base, path):
    rows = _scan(base, path + "-safe")
    assert not rows, rows


@pytest.mark.parametrize("path", sorted(EXPECTED_TRANSFORM))
def test_async_confirms_each_phase307_shape(base, path):
    rows = _scan_async(base, path)
    hits = _reflected(rows)
    assert hits, rows
    assert hits[0].get("transform") == [EXPECTED_TRANSFORM[path]], hits[0]


@pytest.mark.parametrize("path", ["/entities-safe", "/fullwidth-safe"])
def test_async_safe_twin_stays_silent(base, path):
    rows = _scan_async(base, path)
    assert not rows, rows


# ---------------------------------------------------------------------------
# Mutation controls: disable the retry, the finding must disappear
# ---------------------------------------------------------------------------
def test_sync_bounded_pass_is_load_bearing(base, monkeypatch):
    monkeypatch.setattr(Scanner, "_try_encoding_first",
                        lambda *args, **kwargs: False)
    rows = _scan(base, "/entities")
    assert not rows, rows


def test_async_bounded_pass_is_load_bearing(base, monkeypatch):
    async def _empty(self, *args, **kwargs):
        if False:  # pragma: no cover - makes this an async generator
            yield None

    monkeypatch.setattr(AsyncDetectionLayersMixin,
                        "_try_encoding_first_async", _empty)
    rows = _scan_async(base, "/entities")
    assert not rows, rows


# ---------------------------------------------------------------------------
# Cost: at most six, and stop at the first match
# ---------------------------------------------------------------------------
class _CountingReq:
    def __init__(self, inner, counter):
        self.inner = inner
        self.counter = counter

    def request(self, *args, **kwargs):
        self.counter["n"] += 1
        return self.inner.request(*args, **kwargs)


class _CountingSession:
    def __init__(self, inner, counter):
        self.inner = inner
        self.counter = counter

    def request(self, *args, **kwargs):
        self.counter["n"] += 1
        return self.inner.request(*args, **kwargs)


@pytest.mark.parametrize("path,expected", [
    ("/nothing", 6),   # no shape matches: the full bounded budget
    ("/u2", 3),        # double URL is the third shape
    ("/entities", 5),  # html_escape is the fifth shape
])
def test_sync_retry_cost_is_bounded(base, monkeypatch, path, expected):
    counter = {"n": 0}
    original = Scanner._try_encoding_first

    def counted(self, req, *args, **kwargs):
        return original(self, _CountingReq(req, counter), *args, **kwargs)

    monkeypatch.setattr(Scanner, "_try_encoding_first", counted)
    rows = _scan(base, path)
    if path == "/nothing":
        assert not rows, rows
    else:
        assert _reflected(rows), rows
    assert counter["n"] == expected


@pytest.mark.parametrize("path,expected", [
    ("/nothing", 6),
    ("/u2", 3),
    ("/entities", 5),
])
def test_async_retry_cost_is_bounded(base, monkeypatch, path, expected):
    counter = {"n": 0}
    original = AsyncDetectionLayersMixin._try_encoding_first_async

    async def counted(self, session, *args, **kwargs):
        async for finding in original(self, _CountingSession(session, counter),
                                      *args, **kwargs):
            yield finding

    monkeypatch.setattr(AsyncDetectionLayersMixin,
                        "_try_encoding_first_async", counted)
    rows = _scan_async(base, path)
    if path == "/nothing":
        assert not rows, rows
    else:
        assert _reflected(rows), rows
    assert counter["n"] == expected


# ---------------------------------------------------------------------------
# Unit contracts: gates, budget, skip-param, budget/circuit propagation
# ---------------------------------------------------------------------------
class _Resp:
    def __init__(self, text="", headers=None):
        self.text = text
        self.headers = headers or {}


class _FakeReq:
    def __init__(self, response=None, error=None):
        self.response = response or _Resp()
        self.error = error
        self.calls = []

    def request(self, method, url, params=None, data=None, headers=None):
        self.calls.append({"method": method, "url": url,
                           "params": dict(params or {}),
                           "data": dict(data or {})})
        if self.error is not None:
            raise self.error
        return self.response


class _Coverage:
    def __init__(self):
        self.requests = 0
        self.layers = []
        self.params = []
        self.findings = 0

    def record_request(self, *args, **kwargs):
        self.requests += 1

    def touch_layer(self, url, layer, method, detail=None):
        self.layers.append((layer, detail))

    def record_param(self, *args, **kwargs):
        self.params.append(kwargs)

    def record_finding(self, *args, **kwargs):
        self.findings += 1


def _bare_scanner(skip=None):
    sc = Scanner.__new__(Scanner)
    sc.coverage = _Coverage()
    sc.skip_params = set(skip or ())
    sc._bump = lambda: None
    sc._record = lambda *args, **kwargs: None
    return sc


def _fake_verify(monkeypatch, confirm_on=None):
    calls = {"n": 0}

    def fake(text, token, **kwargs):
        calls["n"] += 1
        return {"confirmed": (confirm_on is not None
                              and calls["n"] == confirm_on),
                "context": "script_block", "detail": "probe"}

    monkeypatch.setattr(verifier, "verify_semantic", fake)
    return calls


def _html_resp():
    return _Resp("", {"Content-Type": "text/html; charset=utf-8"})


def test_sync_bounded_pass_gates(monkeypatch):
    req = _FakeReq(_html_resp())
    sc = _bare_scanner()
    _fake_verify(monkeypatch)

    assert sc._try_encoding_first(
        req, "http://h/p", "GET", {"q": "a"}, {}, "q", True,
        _html_resp()) is False
    assert req.calls == []

    assert sc._try_encoding_first(
        req, "http://h/p", "GET", {"q": "a"}, {}, "q", False,
        _Resp("", {"Content-Type": "application/json"})) is False
    assert req.calls == []


def test_sync_bounded_pass_is_six_and_stops_early(monkeypatch):
    req = _FakeReq(_html_resp())
    sc = _bare_scanner()
    calls = _fake_verify(monkeypatch)

    assert sc._try_encoding_first(
        req, "http://h/p", "GET", {"q": "a"}, {}, "q", False,
        _html_resp()) is False
    assert calls["n"] == 6 == len(req.calls)
    assert sc.coverage.requests == 6

    req = _FakeReq(_html_resp())
    sc = _bare_scanner()
    recorded = []
    sc._record = lambda *args, **kwargs: recorded.append(args[8])
    calls = _fake_verify(monkeypatch, confirm_on=4)
    assert sc._try_encoding_first(
        req, "http://h/p", "GET", {"q": "a"}, {}, "q", False,
        _html_resp()) is True
    assert len(req.calls) == 4
    assert recorded == [["triple_url_encode"]]
    assert ("L1_pre_encoded",
            "encoding-first:triple_url_encode") in sc.coverage.layers


def test_sync_bounded_pass_honours_skip_params(monkeypatch):
    req = _FakeReq(_html_resp())
    sc = _bare_scanner(skip={"track"})
    _fake_verify(monkeypatch)

    sc._try_encoding_first(
        req, "http://h/p", "GET", {"q": "a", "track": "secret"}, {},
        "q", False, _html_resp())

    assert req.calls
    assert all("track" not in call["params"] for call in req.calls)
    assert all("q" in call["params"] for call in req.calls)

    # Control: without a skip set the same probe DOES carry "track", so the
    # assertion above is about the filter rather than about the parameter
    # never being sent.
    req2 = _FakeReq(_html_resp())
    sc2 = _bare_scanner()
    sc2._try_encoding_first(
        req2, "http://h/p", "GET", {"q": "a", "track": "secret"}, {},
        "q", False, _html_resp())
    assert req2.calls
    assert all("track" in call["params"] for call in req2.calls)


@pytest.mark.parametrize("error", [BudgetExhausted("spent"),
                                   CircuitOpen("tripped")])
def test_sync_bounded_pass_propagates_budget_and_circuit(monkeypatch, error):
    req = _FakeReq(error=error)
    sc = _bare_scanner()
    _fake_verify(monkeypatch)

    with pytest.raises(type(error)):
        sc._try_encoding_first(
            req, "http://h/p", "GET", {"q": "a"}, {}, "q", False,
            _html_resp())


def test_sync_strict_csp_skips_the_post_reflection_retry(base, monkeypatch):
    from xssentinel.core import csp

    header = "default-src 'self'; script-src 'self'"
    assert csp.is_strict_inline(header)  # premise: the gate is meaningful

    calls = []
    monkeypatch.setattr(Scanner, "_try_encoding_first",
                        lambda *args, **kwargs: calls.append(args) or False)
    _scan(base, "/csp")
    assert calls == []
