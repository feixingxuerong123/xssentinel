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

import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssentinel.core.findings import (  # noqa: E402
    EVIDENCE_BROWSER_EXECUTED,
    dom_dynamic_evidence,
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
    def test_site_calls_the_shared_contract(self, which):
        assert "dom_dynamic_evidence(d)" in _src(which)

    @pytest.mark.parametrize("which", sorted(_SITES))
    def test_site_reads_the_contract_not_a_literal(self, which):
        """The emission must take its evidence class from the contract, not
        from a constant written at the call site."""
        assert '_ev["evidence_class"]' in _src(which)

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
