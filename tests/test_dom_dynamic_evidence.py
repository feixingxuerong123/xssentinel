# -*- coding: utf-8 -*-
"""Phase 260: the DOM-dynamic emit contract has exactly one definition.

`DynamicDomAnalyzer.analyze` hands back a row per flagged endpoint, and since
Phase 226 that row carries ``executed`` -- the engine's own statement of what
the browser did.  The two engine wrappers each used to translate that row into
a finding by hand, and the parity gate measured the cost: given byte-identical
rows (``confidence=medium``, ``executed=False``) sync emitted
browser-executed/high (it hard-coded ``outcome="fired"``, which MASKED the
engine's ``executed=False`` and claimed an execution nobody observed) while
async emitted the row's raw ``medium``.  Same input, two claims.

The fix is one function, ``findings.dom_dynamic_evidence``, called by both
sites.  These tests pin the contract itself and pin that both sites still go
through it -- the second half is the half that matters, because "one
definition" is exactly the kind of invariant that decays silently when a later
phase touches only one engine.

No browser and no network: the engine row is plain data, so the contract is
checkable offline.

Run:  pytest tests/test_dom_dynamic_evidence.py
"""
from __future__ import annotations

import json
import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssentinel.core.findings import (  # noqa: E402
    DOM_DELIVERY_TYPE,
    EVIDENCE_BROWSER_EXECUTED,
    dom_dynamic_evidence,
    dom_dynamic_finding,
)

_CORE = os.path.join(ROOT, "xssentinel", "core")
# The two sites this contract exists to unify.
_SITES = {
    "sync": os.path.join(_CORE, "scanner_layers.py"),
    "async": os.path.join(_CORE, "async_scanner_layers.py"),
}


def _src(which: str) -> str:
    with open(_SITES[which], encoding="utf-8") as fh:
        return fh.read()


# --- what the contract states ----------------------------------------------


class TestContractStates:
    """One row in, and the finding must say exactly what the browser said."""

    def test_executed_row_claims_execution(self):
        ev = dom_dynamic_evidence({"executed": True, "confidence": "medium",
                                   "detail": "location.search -> innerHTML"})
        assert ev["evidence_class"] == EVIDENCE_BROWSER_EXECUTED
        assert ev["confidence"] == "high"
        assert ev["headless"]["outcome"] == "fired"
        assert ev["headless"]["confirmed"] is True

    def test_delivered_row_does_not_claim_execution(self):
        """The defect this function exists to prevent.

        ``executed=False`` means the source REACHED the sink and no execution
        was observed.  Stating that as "fired" is a claim the browser did not
        make; stating it as refuted-and-maybe-fine is a claim nobody made
        either, so the detail has to carry the "not proof of absence" clause.
        """
        ev = dom_dynamic_evidence({"executed": False, "confidence": "medium",
                                   "detail": "location.hash -> innerHTML"})
        assert ev["evidence_class"] == "browser-refuted"
        assert ev["confidence"] == "low"
        assert ev["headless"]["outcome"] == "not-fired"
        assert ev["headless"]["confirmed"] is False
        assert "not proof of absence" in ev["detail"]

    def test_engine_detail_survives_into_the_finding(self):
        """A grade that drops the engine's own words loses the evidence."""
        ev = dom_dynamic_evidence({"executed": False, "confidence": "medium",
                                   "detail": "carrier=html via location.hash"})
        assert "carrier=html via location.hash" in ev["detail"]

    def test_contract_carries_no_severity(self):
        """Severity is what benchmark/runner.py reads as "was this detected".

        Expressing doubt through it would turn true positives into silent
        false negatives, so the contract must not even offer the key --
        callers keep their own ``severity="high"``.
        """
        ev = dom_dynamic_evidence({"executed": False, "confidence": "medium"})
        assert set(ev) == {"headless", "evidence_class", "confidence", "detail"}
        assert "severity" not in ev


class TestFindingClass:
    """Phase 265: execution versus delivery is a CLASS distinction.

    A delivery-only row used to be a high `dom_dynamic` with a low confidence
    and a bare marker in `proof`; range6 measured the canonical safe pattern
    (DOMPurify 3.4.17 -> innerHTML) as a high false positive because of it.
    The class chooser is now one function, so neither engine can drift back.
    """

    def test_executed_row_is_high_dom_dynamic_with_proof(self):
        got = dom_dynamic_finding({
            "executed": True, "confidence": "medium",
            "detail": "carrier=html", "snippet": "xssentinel_dom_abcd"})
        assert got["type"] == "dom_dynamic"
        assert got["severity"] == "high"
        assert got["proof"] == "xssentinel_dom_abcd"
        assert got["evidence_class"] == EVIDENCE_BROWSER_EXECUTED

    def test_delivery_only_is_low_reachability_without_proof(self):
        got = dom_dynamic_finding({
            "executed": False, "confidence": "medium",
            "detail": "carrier=none", "snippet": "xssentinel_dom_abcd"})
        assert got["type"] == DOM_DELIVERY_TYPE == "dom_sink_reachability"
        assert got["severity"] == "low"
        assert got["proof"] is None, \
            "a bare probe marker must not masquerade as execution proof"
        assert got["confidence"] == "low"
        assert got["evidence_class"] == "browser-refuted"

    def test_legacy_high_row_keeps_the_confirmed_class(self):
        got = dom_dynamic_finding({"confidence": "high", "snippet": "M"})
        assert got["type"] == "dom_dynamic"
        assert got["severity"] == "high"
        assert got["proof"] == "M"

    def test_legacy_medium_row_becomes_reachability(self):
        got = dom_dynamic_finding({"confidence": "medium", "snippet": "M"})
        assert got["type"] == DOM_DELIVERY_TYPE
        assert got["severity"] == "low"
        assert got["proof"] is None


class TestDeliveryTypeIsWired:
    """A new finding type is only honest if its delivery surfaces agree.

    Phase 207's lesson: type_rule / type_name / interop / fix_advice /
    compliance are separate tables, and a type missing from one of them
    renders as a generic slug or an error-level finding.  Pin the new class
    at the same time as the class itself.
    """

    def test_api_accepts_the_type(self):
        from xssentinel.api.validation import _VALID_TYPES
        assert DOM_DELIVERY_TYPE in _VALID_TYPES

    def test_sarif_has_a_distinct_note_rule(self):
        from xssentinel.core.report import build_sarif
        doc = json.loads(build_sarif([{
            "type": DOM_DELIVERY_TYPE, "severity": "low",
            "confidence": "low", "url": "http://h/p", "method": "GET",
            "param": "q", "context": "innerHTML", "payload": "marker",
            "detail": "delivery evidence only",
        }], "http://h", {}))
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        assert any(r["id"] == "XSSENTINEL-DOM-SINK-REACHABILITY"
                   for r in rules), [r.get("id") for r in rules]
        assert doc["runs"][0]["results"][0]["level"] == "note"

    def test_fix_advice_and_compliance_have_entries(self):
        from xssentinel.core.fix_advice import get_advice
        adv = get_advice(DOM_DELIVERY_TYPE)
        assert adv and "Verify" in adv["headline"]
        with open(os.path.join(ROOT, "xssentinel", "data",
                               "compliance.json"), encoding="utf-8") as fh:
            comp = json.load(fh)
        entries = comp["finding_type_map"][DOM_DELIVERY_TYPE]
        assert entries and all(len(e) == 4 for e in entries)

    def test_delivery_type_gets_no_active_poc(self):
        from xssentinel.core.poc import build_poc
        p = build_poc({"type": DOM_DELIVERY_TYPE, "url": "http://h/p",
                       "param": "q", "payload": "marker"})
        assert p == {"curl": "", "url": "", "html": ""}

    def test_mxss_carrier_is_the_measured_range6_shape(self):
        """range6's positive page only regains browser-executed evidence
        because this carrier survives DOMPurify 2.0.7.  A later cleanup that
        drops it must fail here, not in a distant gate."""
        from xssentinel.core.dom_engine import _CARRIER_SHAPES
        shapes = dict(_CARRIER_SHAPES)
        assert "mxss" in shapes
        assert "mglyph" in shapes["mxss"]
        assert "alert(%d)" in shapes["mxss"]


class TestCarrierNeedsNoNetwork:
    """Phase 341: execution must not wait on a round trip.

    ``<img src=x onerror=...>`` writes its sink hit synchronously but fires
    its dialog only once the image request FAILS -- a real HTTP round trip.
    The engine reads the dialog channel a fixed settle (``_DOM_SETTLE_MS``)
    after navigation, so on a slow or contended target the execution was
    read as absent and a browser-confirmed positive silently degraded to
    ``dom_sink_reachability`` / not-fired.  Measured on range5's Lit page,
    real Chromium (dev/_carrier_sync_probe.py):

        404 round trip     html carrier fires at     svg carrier fires at
             0ms                  60ms                     49ms
          1100ms                1162ms                     50ms

    So at least one carrier shape must execute on element INSERTION rather
    than on a network outcome.  Dropping it re-opens a silent FN under load,
    which no local green run would ever show.
    """

    def test_a_shape_is_network_independent(self):
        from xssentinel.core.dom_engine import _CARRIER_SHAPES
        shapes = dict(_CARRIER_SHAPES)
        assert "svg" in shapes, \
            "the network-independent carrier is what keeps a slow target from "\
            "reading as delivery-only; see dev/_carrier_sync_probe.py"
        assert shapes["svg"].startswith("<svg"), shapes["svg"]
        assert "onload" in shapes["svg"]
        assert "src=" not in shapes["svg"], \
            "a src= would make it wait on a round trip again, which is the "\
            "exact defect this shape exists to avoid"
        assert "alert(%d)" in shapes["svg"]

    def test_the_network_dependent_shape_is_still_there(self):
        """The svg shape ADDS a fallback; it must not replace the incumbent.

        ``html`` is the shape that survives the broadest set of sinks
        (innerHTML/document.write/jQuery family) and it is the one the
        benchmark matrix is calibrated against -- removing it would trade
        one silent FN for another.
        """
        from xssentinel.core.dom_engine import _CARRIER_SHAPES
        shapes = dict(_CARRIER_SHAPES)
        assert "html" in shapes and "onerror" in shapes["html"]

    def test_html_is_tried_before_svg(self):
        """Order is the cost contract: when html already fires, svg is never
        paid for.  Reversing them adds a navigation-side effect to every
        page whose html carrier works, for no measured gain."""
        from xssentinel.core.dom_engine import _CARRIER_SHAPES
        names = [n for n, _ in _CARRIER_SHAPES]
        assert names.index("html") < names.index("svg"), names


class TestLegacyRows:
    """A row without ``executed`` (pre-Phase 226, or hand-built).

    Absence must fall back to the row's own confidence, because that is what
    the flag was split out of -- "high" there MEANT the sink fired.  Reading
    absence as "not executed" would silently demote every legacy row to
    browser-refuted.
    """

    def test_legacy_high_row_is_read_as_fired(self):
        ev = dom_dynamic_evidence({"confidence": "high"})
        assert ev["evidence_class"] == EVIDENCE_BROWSER_EXECUTED
        assert ev["headless"]["outcome"] == "fired"

    def test_legacy_medium_row_is_read_as_delivered_only(self):
        ev = dom_dynamic_evidence({"confidence": "medium"})
        assert ev["evidence_class"] == "browser-refuted"
        assert ev["headless"]["outcome"] == "not-fired"

    def test_bare_row_defaults_to_delivered_only(self):
        """No flag and no confidence: the honest answer is "we do not know it
        fired", never "it fired"."""
        ev = dom_dynamic_evidence({})
        assert ev["evidence_class"] == "browser-refuted"
        assert ev["headless"]["confirmed"] is False


# --- both engines still go through the one definition ----------------------


class TestOneDefinition:
    """The invariant that decays: one site drifting back to a hand-rolled
    emit re-creates the parity divergence without touching this function."""

    @pytest.mark.parametrize("which", sorted(_SITES))
    def test_site_calls_the_shared_class_chooser(self, which):
        assert "dom_dynamic_finding(d)" in _src(which)

    @pytest.mark.parametrize("which", sorted(_SITES))
    def test_site_reads_the_contract_not_a_literal(self, which):
        """The emission must take its class/evidence from the contract, not
        from constants written at the call site."""
        src = _src(which)
        assert '_emit["evidence_class"]' in src
        assert '_emit["type"]' in src
        assert '_emit["severity"]' in src
        assert '"type": "dom_dynamic"' not in src
        assert '"severity": "high", "confidence": _emit' not in src

    @pytest.mark.parametrize("which", sorted(_SITES))
    def test_site_hard_codes_no_fired_outcome(self, which):
        assert re.search(r'"outcome"\s*:\s*"fired"', _src(which)) is None

    def test_the_two_sites_emit_identically(self):
        """The parity gate's actual question, answered without a browser:
        the same engine row cannot become two different findings."""
        row = {"executed": False, "confidence": "medium",
               "detail": "location.hash -> innerHTML", "sink": "innerHTML",
               "snippet": "#<img src=x onerror=alert(1)>"}
        assert dom_dynamic_evidence(row) == dom_dynamic_evidence(dict(row))
        assert dom_dynamic_finding(row) == dom_dynamic_finding(dict(row))
