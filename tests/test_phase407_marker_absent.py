# -*- coding: utf-8 -*-
"""Phase 407: marker-absence convergence is DECOUPLED from marker-escaped.

Background
----------
async spent ~245 requests on a parameter whose probe marker never reflected;
sync skips that ladder outright (`scanner.py` "not reflected -> skip").  The
first convergence attempt folded `marker_absent` into `marker_escaped` and
regressed reflected positives (pos-elem-01 / neg-filter-01 -> FN, 35->28
requests): `marker_escaped` is a multi-stage master switch in async (sandwich/
generative probe, quote probe, transform cap 12->2, concat-stamp, tail
fallbacks).  The fix is a SEPARATE signal that narrows ONLY the corpus
candidate budget.

Guards:
  * behaviour -- marker_absent=True yields <=3 corpus candidates while
    marker_escaped stays False (proving no folded-in master switch);
  * reflected case (absent=False) keeps the full budget;
  * source pin -- marker_absent appears ONLY at the budget decision and the
    param plumbing, NEVER in a `not marker_escaped` gate (the regression).
"""
import asyncio
import inspect
from pathlib import Path

from xssentinel.core.async_scanner import AsyncScanner
from xssentinel.core.async_scanner_layers import AsyncDetectionLayersMixin

_ROOT = Path(__file__).resolve().parents[1]


def _bare_scanner(cap=14):
    # __new__ avoids __init__ (no session/network); only max_payloads is read
    # by _build_probe_candidates for the budget.
    sc = AsyncScanner.__new__(AsyncScanner)
    sc.max_payloads = cap
    sc.max_transforms = 12
    # _build_probe_candidates reads a few optional knobs via getattr/attr
    sc.waf_name = None
    sc._custom_payloads = None
    return sc


def _cands(absent, escaped=False, cap=14):
    sc = _bare_scanner(cap)
    return asyncio.get_event_loop().run_until_complete(
        sc._build_probe_candidates(
            None, "http://x/", "GET", "q", {"q": "v"}, {}, False,
            "html_element", "marker", escaped, [], marker_absent=absent))


def test_absent_narrows_budget_without_touching_escaped():
    cands, escaped_out, _prof, _families = _cands(absent=True, escaped=False,
                                                  cap=14)
    # only the corpus budget narrowed
    assert len(cands) <= 3, cands
    # the returned master switch was NOT flipped by absence
    assert escaped_out is False


def test_reflected_keeps_full_budget():
    cands, escaped_out, _prof, _families = _cands(absent=False, escaped=False,
                                                  cap=14)
    assert len(cands) > 3, len(cands)
    assert escaped_out is False


def test_escaped_still_narrows_budget():
    # pre-existing Phase 93 contract must survive the new parameter
    cands, _escaped_out, _prof, _families = _cands(absent=False, escaped=True,
                                                   cap=14)
    assert len(cands) <= 3, cands


def test_source_pins_decoupling():
    fn = inspect.getsource(AsyncDetectionLayersMixin._build_probe_candidates)
    # budget decision uses the decoupled signal
    assert "marker_absent" in fn
    assert "marker_escaped or marker_absent" in fn.replace("\n", " ")
    # CRITICAL: absence must NOT be OR'd into any downstream master-switch
    # gate.  The one place both appear together is the budget line only.
    for line in fn.splitlines():
        if "marker_absent" in line:
            assert "not marker_escaped" not in line, line
    assert "cand_budget" in fn


def test_prefix_encoded_fallback_is_zero_request_and_present():
    """Phase 407 parity: async restores a prefix-encoded marker from the
    already-captured text (context.find_prefix_encoded_marker), zero requests.
    """
    from xssentinel.core import context as ctx
    marker = "xssentinel_async_q_ab12"
    # first 6 letters entity-encoded, tail literal -- the level4 shape
    encoded = "".join(f"&#x{ord(c):x};" for c in marker[:6]) + marker[6:]
    text = f"<div>Parameters: {encoded}</div>"
    assert ctx.find_prefix_encoded_marker(text, marker) is not None
    # and async_scanner calls it in the no-reflection branch
    scan_src = (_ROOT / "xssentinel" / "core" /
                "async_scanner.py").read_text(encoding="utf-8")
    assert "find_prefix_encoded_marker" in scan_src
