# -*- coding: utf-8 -*-
"""Phase 323: "CSP bypassable" must mean EVERY enforcing policy is
bypassable, not just the first one.

A browser runs a script only when every enforcing policy in force allows
it (multiple Content-Security-Policy policies intersect).  Both engines
resolved the full policy list correctly through ``csp.policies()`` -- the
verifier's inline gate even iterated it -- but the ``csp_bypass`` FINDING
layer took the first entry and analyzed only that:

    header: script-src 'self' 'unsafe-inline'   <- bypassable (analyzed)
    <meta>: script-src 'self'                    <- strict, never analyzed

reported "CSP bypassable", a claim the page's own second policy refutes.
dalfox v3.2.4 shipped the same fix upstream ("CSP analysis merges every
enforcing policy (multiple headers and <meta>)"); this file pins the
behavior for both engines plus the third instance of the class -- the
joined policy string handed to the Trusted Types / nonce layers must
carry ALL policies, because their nonce/directive regexes scan it.
"""
from __future__ import annotations

import asyncio
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import csp as c                                   # noqa: E402
from xssentinel.core.async_scanner_layers import (                    # noqa: E402
    AsyncDetectionLayersMixin)
from xssentinel.core.scanner_layers import AdvancedLayerMixin          # noqa: E402
from xssentinel.core import trusted_types as tt                        # noqa: E402

STRICT = "script-src 'self'"
INLINE_OK = "script-src 'self' 'unsafe-inline'"
# second bypassable policy with a DIFFERENT governing directive, so the
# aggregated evidence proves both were analyzed rather than one twice.
INLINE_OK_META = "default-src 'self' 'unsafe-inline'"


def _page(csp_value: str) -> str:
    return ('<html><head><meta http-equiv="Content-Security-Policy" '
            f'content="{csp_value}"></head><body>x</body></html>')


# ---------------------------------------------------------------------------
# harness (same shape as test_phase196_csp_delivery, which stays the
# authority for the channel/behaviour contract)
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


class _AsyncLayerStub(AsyncDetectionLayersMixin):
    verbose = False


def _async_csp_findings(headers, html):
    async def run():
        out = []
        agen = AsyncDetectionLayersMixin._scan_csp_async(
            _AsyncLayerStub(), "http://t/x", headers, html)
        async for f in agen:
            out.append(f.data if hasattr(f, "data") else f)
        return out

    return asyncio.run(run())


# ---------------------------------------------------------------------------
# 1. the false-positive class: first policy bypassable, second strict
# ---------------------------------------------------------------------------
def test_sync_strict_second_policy_suppresses_the_finding():
    got = _csp_findings({"Content-Security-Policy": INLINE_OK}, _page(STRICT))
    assert got == [], got


def test_async_strict_second_policy_suppresses_the_finding():
    got = _async_csp_findings({"Content-Security-Policy": INLINE_OK},
                              _page(STRICT))
    assert got == [], got


def test_sync_strict_first_policy_suppresses_too():
    # order must not matter: strict header + bypassable meta is equally
    # NOT a bypass (the old code only looked at the header here -- and
    # got this direction right; pin it so the all() semantics cannot be
    # "fixed" into any() later)
    got = _csp_findings({"Content-Security-Policy": STRICT}, _page(INLINE_OK))
    assert got == [], got


def test_async_strict_first_policy_suppresses_too():
    got = _async_csp_findings({"Content-Security-Policy": STRICT},
                              _page(INLINE_OK))
    assert got == [], got


# ---------------------------------------------------------------------------
# 2. single-policy behavior is byte-identical (no regression seam)
# ---------------------------------------------------------------------------
def test_sync_single_bypassable_policy_keeps_the_finding_shape():
    got = _csp_findings({"Content-Security-Policy": INLINE_OK},
                        "<html><body>x</body></html>")
    assert [f["type"] for f in got] == ["csp_bypass"], got
    assert got[0]["severity"] == "medium"
    assert got[0]["confidence"] == "medium"
    assert got[0]["csp_header"] == INLINE_OK, got[0]["csp_header"]
    assert got[0]["evidence"], "aggregation must not empty single-policy weak"


def test_async_single_bypassable_policy_keeps_the_finding_shape():
    got = _async_csp_findings({"Content-Security-Policy": INLINE_OK}, "")
    assert [f["type"] for f in got] == ["csp_bypass"], got
    assert got[0]["csp_header"] == INLINE_OK, got[0]["csp_header"]


# ---------------------------------------------------------------------------
# 3. all-bypassable: the finding carries EVERY policy and the union evidence
# ---------------------------------------------------------------------------
def test_sync_all_bypassable_joins_header_and_meta():
    got = _csp_findings({"Content-Security-Policy": INLINE_OK},
                        _page(INLINE_OK_META))
    assert [f["type"] for f in got] == ["csp_bypass"], got
    joined = got[0]["csp_header"]
    assert INLINE_OK in joined and INLINE_OK_META in joined, joined
    assert " || " in joined, joined
    # evidence aggregates BOTH analyses: one script-src line, one
    # default-src line
    assert "script-src" in got[0]["evidence"]
    assert "default-src" in got[0]["evidence"], got[0]["evidence"]


def test_async_all_bypassable_joins_header_and_meta():
    got = _async_csp_findings({"Content-Security-Policy": INLINE_OK},
                              _page(INLINE_OK_META))
    assert [f["type"] for f in got] == ["csp_bypass"], got
    assert INLINE_OK in got[0]["csp_header"]
    assert INLINE_OK_META in got[0]["csp_header"]
    assert "default-src" in got[0]["evidence"], got[0]["evidence"]


# ---------------------------------------------------------------------------
# 4. the joined policy string feeds the TT / nonce regex consumers
# ---------------------------------------------------------------------------
def test_joined_policies_reach_the_nonce_regex_consumer():
    """A nonce declared only in the SECOND policy must stay visible through
    the joined string advanced_layers hands to the nonce-reuse layer."""
    nonce = "YWJjMTIzNDU2Nzg="           # base64-shaped, like real nonces
    joined = " || ".join([
        "script-src 'self'",
        f"script-src 'nonce-{nonce}'",
    ])
    assert c.extract_nonces_from_csp(joined) == [nonce], joined
    html = f'<script nonce="{nonce}">alert(1)</script>'
    result = c.analyze_nonce_reuse(joined, html)
    assert result["nonce_count_in_html"] == 1, result


def test_joined_policies_reach_the_trusted_types_consumer():
    # the enforcement directive is require-trusted-types-FOR 'script'
    # (REQUIRE_TT_RE), the whitelist directive is trusted-types 'name'
    # (TRUSTED_TYPES_DIRECTIVE_RE) -- both must survive the join
    joined = " || ".join([
        "script-src 'self'",
        "require-trusted-types-for 'script'; trusted-types 'default'",
    ])
    assert tt.has_trusted_types_csp(joined) is True
    assert tt.get_trusted_types_policy_names(joined) == ["default"]


# ---------------------------------------------------------------------------
# 5. source guards: the break-on-first shape cannot quietly come back
# ---------------------------------------------------------------------------
def test_no_break_on_first_left_in_either_csp_layer():
    """A narrowed backport (``for p in ...: take p; break``) would not fail
    any single-policy test -- only the multi-policy ones above, which a
    refactor could delete as "dupes".  The source shape itself is pinned,
    same discipline as the async call-site guards in phase 196/215."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for rel in ("scanner_layers.py", "async_scanner_layers.py"):
        path = os.path.join(root, "xssentinel", "core", rel)
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        # the dispatch table + loop form; a literal `break` inside the
        # enforcing-policy loop is the regression we are fencing out.
        assert "for policy in enforcing:" in src, (rel, "loop shape changed")
    # and advanced_layers must JOIN, not pick the first
    adv = os.path.join(root, "xssentinel", "core", "advanced_layers.py")
    with open(adv, encoding="utf-8") as fh:
        src = fh.read()
    assert "csp_header = \" || \".join(_enf)" in src, "join lost"
    assert "_enf[0]" not in src, "break-on-first is back"
