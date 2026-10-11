# -*- coding: utf-8 -*-
"""Phase 218: the evidence-shape severity cap (1.5-②) + its sink wiring.

The rule the 210b record asked for, landed on the measured population: a
HIGH/CRITICAL claim with neither browser evidence (browser-executed class,
OOB callback, confirmed headless replay) nor a verifiable ``proof`` payload
is capped to MEDIUM at the engine's FINAL evidence state.  Severity only --
the scoring denominator does not move (medium still counts as detected),
confidence is untouched, and since Phase 217 both engines reach this point
with the same evidence vocabulary, so the cap hits the same findings on
both sides.

The wiring is pinned where the evidence state is final:
  * sync: ``Scanner._add``, AFTER the Phase 217 headless mirror (a
    just-confirmed finding keeps its high shelf);
  * async: BOTH final yield branches of ``scan()`` (headless off = direct;
    headless on = after ``_headless_verify_finding``'s in-place upgrade --
    capping in ``_add_finding`` would fire BEFORE the upgrade and strand a
    browser-confirmed finding on the medium shelf).

Run: pytest tests/test_phase218_evidence_cap.py -q
"""
from __future__ import annotations

import ast
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssentinel.core.findings import (  # noqa: E402
    EVIDENCE_OOB, Finding, cap_unverified_severity)
from xssentinel.core.scanner import Scanner  # noqa: E402

CAP_NOTE = "severity capped to medium"


def _d(**over) -> dict:
    d = {"url": "http://h/p", "method": "GET", "param": None,
         "type": "trusted_types_taint_flow", "context": "tt_sink",
         "payload": "snippet", "transform": [], "severity": "high",
         "confidence": "high", "detail": "d",
         "evidence_class": "browser-unavailable",
         "headless": None, "proof": None}
    d.update(over)
    return d


# ---------------------------------------------------------------------------
# the cap itself (pure)
# ---------------------------------------------------------------------------

def test_high_unverified_is_capped_to_medium():
    d = _d()
    assert cap_unverified_severity(d) is True
    assert d["severity"] == "medium"
    assert CAP_NOTE in d["detail"]


def test_critical_is_capped_too():
    d = _d(severity="critical")
    assert cap_unverified_severity(d) is True
    assert d["severity"] == "medium"


def test_cap_is_idempotent():
    d = _d()
    assert cap_unverified_severity(d) is True
    assert cap_unverified_severity(d) is False
    assert d["severity"] == "medium"
    assert d["detail"].count(CAP_NOTE) == 1


@pytest.mark.parametrize("over", [
    {"proof": {"status": 200, "snippet": "x"}},
    {"evidence_class": "browser-executed"},
    {"evidence_class": EVIDENCE_OOB},
    {"headless": {"available": True, "confirmed": True, "outcome": "fired"}},
    {"severity": "medium"},
    {"severity": "low"},
    # The engine-symmetry exemption: async encodes a judged reflection's
    # excerpt in `evidence` with NO proof field (sync uses `proof`) -- a
    # proof-only check capped async's entire reflected family while sync's
    # stayed high (caught on paper before the first matrix run: 69 vs 63).
    {"evidence_class": "model-judged",
     "evidence": "...<script>alert('xssp_q_2813')</script>..."},
])
def test_backed_claims_keep_their_shelf(over):
    d = _d(**over)
    assert cap_unverified_severity(d) is False
    assert d["severity"] == over.get("severity", "high")


def test_static_hint_without_excerpt_is_the_cap_target():
    """The measured shape of the population this rule exists for
    (trusted_types_taint_flow on the lab): browser-unavailable, no proof,
    NO evidence key -- nothing in the report backs the high shelf."""
    d = _d(evidence_class="browser-unavailable")
    d.pop("evidence", None)
    assert cap_unverified_severity(d) is True
    assert d["severity"] == "medium"


# ---------------------------------------------------------------------------
# the sync sink (behavioral)
# ---------------------------------------------------------------------------

def test_sync_add_caps_the_unverified_high():
    s = Scanner(use_headless=False)
    s._add(Finding(**_d()))
    assert s.findings[0].data["severity"] == "medium"
    assert CAP_NOTE in s.findings[0].data["detail"]


def test_sync_add_leaves_proof_bearing_highs_alone():
    s = Scanner(use_headless=False)
    s._add(Finding(**_d(proof={"status": 200, "snippet": "x"})))
    assert s.findings[0].data["severity"] == "high"


# ---------------------------------------------------------------------------
# the wiring (static -- both engines, at the final evidence state)
# ---------------------------------------------------------------------------

def test_both_sinks_wire_the_cap_at_their_final_evidence_state():
    sync_src = open(os.path.join(ROOT, "xssentinel/core/scanner.py"),
                    encoding="utf-8").read()
    async_src = open(os.path.join(ROOT, "xssentinel/core/async_scanner.py"),
                     encoding="utf-8").read()
    # sync: inside _add, and AFTER the Phase 217 mirror hook
    add_fn = next(n for n in ast.walk(ast.parse(sync_src))
                  if isinstance(n, ast.FunctionDef) and n.name == "_add")
    add_src = ast.get_source_segment(sync_src, add_fn)
    assert "cap_unverified_severity(finding.data)" in add_src
    assert add_src.index("_maybe_headless_verify(finding)") \
        < add_src.index("cap_unverified_severity"), (
        "the cap must run AFTER the headless mirror, or a just-confirmed "
        "finding is capped on its pre-verification shape")
    # async: BOTH final yield branches of scan() carry the cap
    scan_fn = next(n for n in ast.walk(ast.parse(async_src))
                   if isinstance(n, ast.AsyncFunctionDef) and n.name == "scan")
    scan_src = ast.get_source_segment(async_src, scan_fn)
    assert scan_src.count("cap_unverified_severity(f.data)") == 2, (
        "both final yield branches (headless off / on) must cap -- the "
        "off branch is the only cap site for unheadless scans, the on "
        "branch must run after the in-place evidence upgrade")
