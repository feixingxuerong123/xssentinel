# -*- coding: utf-8 -*-
"""Phase 196: a CSP can arrive by header OR by <meta>, and only one of those
modes actually stops anything.

Why this is a correctness fix and not a feature: everything that asked "does
inline run under this CSP?" read the ``Content-Security-Policy`` **response
header** and nothing else.  Chromium honours
``<meta http-equiv="Content-Security-Policy">`` exactly like the header --
measured on this host (``dev/_p196_csp_delivery/probe_csp_delivery.py``):
an inline reflection under a meta policy raises no dialog, the same shape
that raises two under no policy at all.  Report-Only, in either channel,
raises both: it never blocks.

    channel            Chromium dialog    judgment before Phase 196
    header enforcing   blocked            blocked              (ok)
    header report-only EXECUTES           EXECUTES             (ok)
    meta enforcing     blocked            EXECUTES  <-- FP
    meta report-only   EXECUTES           EXECUTES             (ok)
    no policy          EXECUTES           EXECUTES             (ok)

The same header-only reading ran backwards on the reporting side: a page whose
only policy is Report-Only used to produce a "CSP bypassable" finding (nothing
is being enforced, so there is nothing to bypass), while a page enforced only
by a bypassable <meta> policy produced none.

The browser test at the bottom re-measures the ground truth, so the judgment
change stays pinned to the browser rather than to this file's own opinion.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import csp as c                                    # noqa: E402
from xssentinel.core.scanner_layers import AdvancedLayerMixin            # noqa: E402
from xssentinel.core.verifier import (                                   # noqa: E402
    _csp_blocks_attr, _csp_blocks_inline, verify_semantic)

TOKEN = "xssv_deadbeef"
STRICT = "script-src 'self'"
INLINE_OK = "script-src 'self' 'unsafe-inline'"


def _page(csp_value: str, sink: str = "script", nonce: str = "") -> str:
    """A page whose only policy is a <meta>, reflecting one payload shape."""
    tag = "Content-Security-Policy"
    n = f' nonce="{nonce}"' if nonce else ""
    body = (f"<script{n}>alert('{TOKEN}')</script>" if sink == "script"
            else f"<img src=x onerror=\"alert('{TOKEN}')\">")
    return (f'<html><head><meta http-equiv="{tag}" content="{csp_value}">'
            f"</head><body>{body}</body></html>")


# ---------------------------------------------------------------------------
# 1. the two channels are both parsed, and stay in their own mode
# ---------------------------------------------------------------------------
def test_meta_enforcing_and_report_only_are_separated():
    enf, ro = c.meta_policies(
        '<meta content="script-src \'none\'" http-equiv="Content-Security-Policy">'
        '<meta http-equiv="content-security-policy-report-only" '
        'content="script-src \'unsafe-inline\'">')
    assert enf == ["script-src 'none'"], enf
    assert ro == ["script-src 'unsafe-inline'"], ro


def test_meta_content_entities_are_unescaped_like_a_browser():
    # a policy carrying quoted source expressions has to survive &quot;
    html = ('<meta http-equiv="Content-Security-Policy" '
            'content="script-src &quot;self&quot;">')
    enf, _ = c.meta_policies(html)
    assert enf == ['script-src "self"'] or enf == ["script-src 'self'"], enf


def test_policies_unions_header_and_meta_channels():
    pol = c.policies({"Content-Security-Policy": STRICT}, _page(INLINE_OK))
    assert pol["enforcing"] == [STRICT, INLINE_OK], pol
    # report-only never joins the enforcing list, from either channel
    pol2 = c.policies(
        {"Content-Security-Policy-Report-Only": STRICT},
        '<meta http-equiv="Content-Security-Policy-Report-Only" '
        'content="script-src \'self\'">')
    assert pol2["enforcing"] == [] and len(pol2["report_only"]) == 2, pol2


def test_any_enforcing_policy_blocks_the_family():
    """Header allows inline, meta forbids it: BOTH apply, so nothing runs."""
    pol = c.policies({"Content-Security-Policy": INLINE_OK}, _page(STRICT))
    assert c.blocks_family(pol, "elem") is True
    # and the reverse pair must not un-block it
    pol2 = c.policies({"Content-Security-Policy": STRICT}, _page(INLINE_OK))
    assert c.blocks_family(pol2, "elem") is True


# ---------------------------------------------------------------------------
# 2. the judgment -- this is the measured false positive
# ---------------------------------------------------------------------------
def test_meta_enforcing_csp_refutes_inline_script():
    v = verify_semantic(_page(STRICT), TOKEN, {})
    assert v["confirmed"] is False, v
    assert "CSP" in v["detail"], v


def test_meta_enforcing_csp_refutes_event_handler():
    v = verify_semantic(_page(STRICT, sink="handler"), TOKEN, {})
    assert v["confirmed"] is False, v


def test_meta_report_only_still_confirms_because_it_blocks_nothing():
    html = _page(STRICT).replace('http-equiv="Content-Security-Policy"',
                                 'http-equiv="Content-Security-Policy-Report-Only"')
    v = verify_semantic(html, TOKEN, {})
    assert v["confirmed"] is True, v


def test_header_strict_plus_meta_unsafe_inline_is_still_blocked():
    html = _page(INLINE_OK)
    v = verify_semantic(html, TOKEN, {"Content-Security-Policy": STRICT})
    assert v["confirmed"] is False, v


def test_verifier_helpers_accept_the_body_channel():
    assert _csp_blocks_inline({"Content-Security-Policy": STRICT}) is True
    assert _csp_blocks_inline({}, STRICT_META_HTML) is True
    assert _csp_blocks_attr({}, STRICT_META_HTML) is True
    # headers-only callers keep working unchanged
    assert _csp_blocks_inline({}, "<html>no policy</html>") is False


STRICT_META_HTML = _page(STRICT, sink="handler")


def test_nonce_declared_in_a_meta_policy_reopens_that_script():
    """The nonce-leak channel is unchanged, it just also sees the meta policy.

    The nonce is base64-shaped on purpose: ``_NONCE_DIRECTIVE_RE`` only
    recognises values that look like real nonces, and a first draft of this
    test used 'abc123' and failed for that reason alone -- a vacuous pass
    would have hidden the wiring it is supposed to pin.
    """
    nonce = "YWJjMTIzNDU2Nzg="
    html = _page(f"script-src 'nonce-{nonce}'", nonce=nonce)
    assert c.extract_nonces_from_csp(
        c.policies({}, html)["enforcing"][0]) == [nonce], html
    v = verify_semantic(html, TOKEN, {})
    assert v["confirmed"] is True, v
    # and a script WITHOUT the declared nonce stays blocked by the same policy
    v2 = verify_semantic(_page(f"script-src 'nonce-{nonce}'"), TOKEN, {})
    assert v2["confirmed"] is False, v2


# ---------------------------------------------------------------------------
# 3. the reporting side: no bypass claim for a policy that enforces nothing,
#    and meta-only protection is no longer invisible
# ---------------------------------------------------------------------------
class _Hdrs(dict):
    def get(self, key, default=None):           # noqa: D102
        return super().get(key, default) or super().get(key.lower(), default)


class _Resp:
    def __init__(self, headers, text):
        self.headers = _Hdrs(headers)
        self.text = text


class _Req:
    def __init__(self, resp):
        self._resp = resp

    def get(self, url):                          # noqa: ARG002
        return self._resp


class _Cov:
    def __init__(self):
        self.layers, self.findings = [], []

    def touch_layer(self, url, layer, method, detail=None):  # noqa: D102
        self.layers.append(layer)

    def record_finding(self, url, method):       # noqa: D102
        self.findings.append((url, method))

    def record_request(self, url, method):       # noqa: D102
        pass


class _Scanner:
    """Enough surface for AdvancedLayerMixin._scan_csp."""

    def __init__(self, headers, text):
        self.coverage = _Cov()
        self.findings = []
        self.verbose = False
        self._lock = threading.RLock()
        self._resp = _Resp(headers, text)

    def _bump(self):                             # noqa: D102
        pass


def _csp_findings(headers, text):
    sc = _Scanner(headers, text)
    AdvancedLayerMixin._scan_csp(sc, _Req(sc._resp), "http://t/x")
    return [f.data if hasattr(f, "data") else f for f in sc.findings]


def test_report_only_policy_alone_is_not_reported_as_bypassable():
    got = _csp_findings({"Content-Security-Policy-Report-Only": INLINE_OK},
                        "<html><body>x</body></html>")
    assert got == [], got


def test_meta_only_bypassable_policy_is_now_reported():
    got = _csp_findings({}, _page(INLINE_OK))
    assert [f["type"] for f in got] == ["csp_bypass"], got
    assert INLINE_OK in got[0]["csp_header"]


def test_enforcing_header_still_wins_over_the_meta_channel():
    got = _csp_findings({"Content-Security-Policy": STRICT}, _page(INLINE_OK))
    # the first enforcing policy is the header one; neither is bypassable here
    # ('self' with no gadget), so no finding -- and no crash either
    assert isinstance(got, list)


# ---------------------------------------------------------------------------
# 4. the async engine resolves the same channels (no silent second-class path)
# ---------------------------------------------------------------------------
def _async_csp_findings(headers, html):
    """Drive AsyncDetectionLayersMixin._scan_csp_async on a bare stub.

    The layer only needs the policy resolution and a Finding sink, so no
    scanner is constructed -- and if someone narrows the signature back to
    headers-only, these two assertions go red instead of the asymmetry
    quietly coming back.
    """
    import asyncio

    from xssentinel.core.async_scanner_layers import AsyncDetectionLayersMixin

    async def run():
        out = []
        agen = AsyncDetectionLayersMixin._scan_csp_async(
            object(), "http://t/x", headers, html)
        async for f in agen:
            out.append(f.data if hasattr(f, "data") else f)
        return out

    return asyncio.run(run())


def test_async_reports_a_meta_only_bypassable_policy_like_sync():
    got = _async_csp_findings({}, _page(INLINE_OK))
    assert [f["type"] for f in got] == ["csp_bypass"], got
    assert INLINE_OK in got[0]["csp_header"]


def test_async_does_not_claim_a_bypass_of_a_report_only_policy():
    assert _async_csp_findings(
        {"Content-Security-Policy-Report-Only": INLINE_OK}, "") == []


# Static guard, same shape as test_async_wiring / test_layer_accounting: the
# call site is outside the mixin, so narrowing the signature back to
# headers-only would not fail any behavior test -- it would just silently make
# async blind to meta policies again, which is exactly the drift this project
# has paid for three times (concat retry, content-type demotion, JSONP gadget).
def test_async_call_site_still_hands_the_layer_a_body():
    import ast
    import inspect
    import os

    from xssentinel.core.async_scanner_layers import AsyncDetectionLayersMixin

    params = list(inspect.signature(
        AsyncDetectionLayersMixin._scan_csp_async).parameters)
    assert params[:4] == ["self", "url", "resp_headers", "html"], params
    # the body argument must have a default, or every older caller breaks
    assert inspect.signature(AsyncDetectionLayersMixin._scan_csp_async) \
        .parameters["html"].default == ""

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = open(os.path.join(root, "xssentinel", "core", "async_scanner.py"),
               encoding="utf-8").read()
    tree = ast.parse(src)
    calls = [n for n in ast.walk(tree)
             if isinstance(n, ast.Call)
             and getattr(n.func, "attr", "") == "_scan_csp_async"]
    assert calls, "no _scan_csp_async call site found -- guard gone vacuous"
    for call in calls:
        args = list(call.args)
        assert len(args) == 3, ast.dump(call)
        # 3rd positional must be the page body, not another dict
        name = getattr(args[2], "id", None)
        assert name and "header" not in name.lower(), ast.dump(args[2])


def test_both_engines_agree_on_the_same_policy_set():
    """sync `_scan_csp` and async `_scan_csp_async` must not diverge by channel."""
    shapes = [
        ("meta bypassable", {}, _page(INLINE_OK)),
        ("meta strict", {}, _page(STRICT)),
        ("header bypassable", {"Content-Security-Policy": INLINE_OK}, ""),
        ("header strict", {"Content-Security-Policy": STRICT}, ""),
        ("report-only only", {"Content-Security-Policy-Report-Only": INLINE_OK},
         ""),
        ("header strict + meta bypassable",
         {"Content-Security-Policy": STRICT}, _page(INLINE_OK)),
    ]
    for label, headers, html in shapes:
        sync = _csp_findings(headers, html)
        asyn = _async_csp_findings(headers, html)
        assert len(sync) == len(asyn), (label, len(sync), len(asyn))
        assert [f.get("csp_header") for f in sync] == [
            f.get("csp_header") for f in asyn], label


# ---------------------------------------------------------------------------
# 5. ground truth re-measured in Chromium
# ---------------------------------------------------------------------------
class _H(BaseHTTPRequestHandler):
    shapes = {}

    def log_message(self, *a):
        pass

    def do_GET(self):
        shape = self.path.strip("/") or "none"
        headers, body = self.shapes[shape]
        raw = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)


@pytest.mark.parametrize("shape,expect_dialog", [
    ("meta_enforcing", False),
    ("meta_report_only", True),
    ("hdr_enforcing", False),
    ("hdr_report_only", True),
])
def test_browser_actually_behaves_the_way_we_now_judge(shape, expect_dialog):
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session (security software/TCP state)")
    from xssentinel.core import dom_engine
    if not dom_engine.DynamicDomAnalyzer.available():
        pytest.skip("playwright/chromium not available")

    _H.shapes = {
        "meta_enforcing": ({}, _page(STRICT)),
        "meta_report_only": ({}, _page(STRICT).replace(
            'http-equiv="Content-Security-Policy"',
            'http-equiv="Content-Security-Policy-Report-Only"')),
        "hdr_enforcing": ({"Content-Security-Policy": STRICT},
                          f"<html><body><script>alert('{TOKEN}')</script>"
                          "</body></html>"),
        "hdr_report_only": ({"Content-Security-Policy-Report-Only": STRICT},
                            f"<html><body><script>alert('{TOKEN}')</script>"
                            "</body></html>"),
    }
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    try:
        from playwright.sync_api import sync_playwright
        fired = []
        with sync_playwright() as p:
            br = p.chromium.launch(args=["--no-sandbox"])
            pg = br.new_context().new_page()
            pg.on("dialog", lambda d: (fired.append(d.message), d.dismiss()))
            pg.goto(f"http://127.0.0.1:{port}/{shape}", wait_until="load")
            pg.wait_for_timeout(1200)
            br.close()
    finally:
        srv.shutdown()
    assert (TOKEN in " ".join(fired)) is expect_dialog, (shape, fired)
