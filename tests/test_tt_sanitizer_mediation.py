# -*- coding: utf-8 -*-
"""Phase 225: TT findings are graded by sanitizer mediation.

Range6's safe twin -- the canonical correct usage (current DOMPurify,
output to innerHTML) -- was measured to carry TWO medium TT claims whose
exploitability reading is unbacked: the mXSS payload is provably stripped
(no live element, no dialog; dev/_r6_mxss_premise.py), yet the report
said "concrete DOM-XSS" (tt_taint_flow) and "trivially exploitable"
(tt_no_policy).  The project had dodged this shape twice rather than
grading it (benchmark/server.py m_sanitizer_safe: textContent; Phase
128b: DOMParser instead of innerHTML) -- and the dodges are what kept it
invisible.

What is graded (and what is not):

  * a recognized sanitizer between source and sink does NOT drop the
    flow -- the write is still TT-unprotected, which is this layer's
    subject -- it downgrades the DOM-XSS reading to a defense-in-depth
    note (low);
  * `policy.createHTML` between source and sink still drops the flow
    entirely (unchanged: it IS the TT mitigation);
  * an unmediated flow keeps its severity (medium via the Phase 218 cap);
  * `tt_no_policy` drops to low only when EVERY detected flow is
    sanitizer-mediated -- one raw write path keeps the medium claim.

The vocabulary is imported from the sanitizer layer (one definition,
Phase 207 lesson), so the two layers cannot drift on what a sanitizer
call looks like.
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssentinel.core import trusted_types as tt  # noqa: E402
from xssentinel.core.layers import content_layers  # noqa: E402


# The range6 shell, byte-for-byte in shape: the param never touches the
# server side; the app reads it client-side and sanitizes before the sink.
SAFE_TWIN = """
<div id="out"></div>
<script src="/vendor/dompurify/3.4.17/purify.min.js"></script>
<script>
var q = new URLSearchParams(location.search).get('q') || '';
var clean = DOMPurify.sanitize(q);
document.getElementById('out').innerHTML = clean;
</script>
"""

# No sanitizer anywhere: the layer's original subject.
UNMEDIATED = """
<div id="out"></div>
<script>
var h = location.hash.substring(1);
document.getElementById('out').innerHTML = h;
</script>
"""

# One sanitized write AND one raw write: the raw path keeps the claim.
PARTIAL = """
<div id="out"></div>
<script src="/vendor/dompurify/3.4.17/purify.min.js"></script>
<script>
var q = new URLSearchParams(location.search).get('q') || '';
document.getElementById('a').innerHTML = DOMPurify.sanitize(q);
document.getElementById('b').innerHTML = location.hash;
</script>
"""

# The TT mitigation proper: wrapped in a policy call -- flow dropped.
POLICY_WRAPPED = """
<div id="out"></div>
<script>
var policy = trustedTypes.createPolicy('p', {createHTML: (s) => s});
document.getElementById('out').innerHTML =
    policy.createHTML(location.hash.substring(1));
</script>
"""


def _by_type(html):
    return {v["type"]: v
            for v in tt.analyze_page(html)["violations"]}


# --------------------------------------------------------------------------
# the graded shapes
# --------------------------------------------------------------------------

def test_sanitizer_mediated_flow_is_a_defense_in_depth_note():
    v = _by_type(SAFE_TWIN)
    flow = v["tt_taint_flow"]
    assert flow["severity"] == "low", flow
    assert flow["sanitizer_mediated"] is True
    assert "DOMPurify.sanitize" in flow["title"], flow["title"]
    assert "not established" in flow["title"], flow["title"]
    # ... and the page-level claim degrades with it, since EVERY flow is
    # mediated here.
    assert v["tt_no_policy"]["severity"] == "low", v["tt_no_policy"]


def test_unmediated_flow_keeps_its_severity():
    v = _by_type(UNMEDIATED)
    assert v["tt_taint_flow"]["severity"] == "high", v["tt_taint_flow"]
    assert v["tt_taint_flow"]["sanitizer_mediated"] is False
    assert v["tt_no_policy"]["severity"] == "medium", v["tt_no_policy"]


def test_one_raw_write_path_keeps_the_page_level_claim_medium():
    """Reverse guard: the demotion must not fire while ANY detected flow
    is unmediated -- a partially-sanitized page still has a raw path."""
    v = _by_type(PARTIAL)
    flows = tt.analyze_page(PARTIAL)["taint_flows"]
    assert any(f["sanitizer_mediated"] for f in flows), flows
    assert any(not f["sanitizer_mediated"] for f in flows), flows
    assert v["tt_no_policy"]["severity"] == "medium", v["tt_no_policy"]
    # the raw flow itself must be the one carrying the concrete claim
    assert v["tt_taint_flow"]["sanitizer_mediated"] is False


def test_policy_call_still_drops_the_flow_entirely():
    """The TT mitigation proper is unchanged: a policy-wrapped write is
    not a flow at all (no taint_flow violation, no mediated note)."""
    v = _by_type(POLICY_WRAPPED)
    assert "tt_taint_flow" not in v, v


def test_static_write_alone_does_not_gain_a_flow():
    """No taint source near the sink -> no flow -> the no_policy claim
    keeps its status quo (medium); this change must not invent flows."""
    v = _by_type('<script>document.body.innerHTML = "static";</script>')
    assert "tt_taint_flow" not in v, v
    assert v["tt_no_policy"]["severity"] == "medium", v["tt_no_policy"]


# --------------------------------------------------------------------------
# the severity reaches the finding (integration through the layer)
# --------------------------------------------------------------------------

def _fake_scanner():
    class _Cov:
        def touch_layer(self, *a, **k):
            pass

        def record_finding(self, *a, **k):
            pass

    class _S:
        verbose = False
        requests_made = 0

        def __init__(self):
            self.added = []
            self.coverage = _Cov()

        def _add(self, f):
            self.added.append(f)

        def _bump(self, *a, **k):
            pass

    return _S()


def test_layer_reports_the_graded_severities():
    sc = _fake_scanner()
    content_layers._scan_trusted_types(
        sc, "http://h/", SAFE_TWIN, "", "text/html")
    sev = {f.data.get("type"): f.data.get("severity") for f in sc.added}
    assert sev.get("trusted_types_taint_flow") == "low", sev
    assert sev.get("trusted_types_no_policy") == "low", sev


def test_layer_keeps_medium_on_the_unmediated_shape():
    """The same wiring on the unmediated page: the ungraded severity must
    survive the trip through the layer, or the grading above would prove
    nothing.  At the layer this is "high" (innerHTML's table severity);
    the Phase 218 evidence-shape cap lowers it to medium downstream --
    what matters here is that the sanitizer grading did NOT touch it."""
    sc = _fake_scanner()
    content_layers._scan_trusted_types(
        sc, "http://h/", UNMEDIATED, "", "text/html")
    sev = {f.data.get("type"): f.data.get("severity") for f in sc.added}
    assert sev.get("trusted_types_taint_flow") == "high", sev
    assert sev.get("trusted_types_no_policy") == "medium", sev
