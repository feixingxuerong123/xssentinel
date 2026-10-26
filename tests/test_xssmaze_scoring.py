"""Phase 322: the XSSMaze xsleak scoring contract (versioned module).

Pins the upstream v0.3.0 rule so no aggregate view we write around the
official runner can count correct silence as a false negative.  Pure
functions, no lab, no network.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "benchmark"))

from xssmaze_scoring import (NO_DETECTION_EXPECTED_PREFIXES,  # noqa: E402
                             CORRECT_SILENCE, FN_CANDIDATE, NEEDS_REVIEW,
                             TP, category_of, contract_mismatches,
                             detection_expected, outcome)

_LAB = "http://127.0.0.1:3001"


class TestContract:
    def test_prefix_set_is_closed_and_explicit(self):
        # widening this tuple is a contract change: it must stay a literal
        # someone consciously edits next to the upstream quote
        assert NO_DETECTION_EXPECTED_PREFIXES == ("xsleak",)

    def test_xsleak_silence_is_correct_not_fn(self):
        url = f"{_LAB}/xsleak/redirect?q=admin"
        assert detection_expected(url) is False
        assert outcome(url, 0) == CORRECT_SILENCE

    def test_xsleak_finding_is_needs_review_not_tp(self):
        url = f"{_LAB}/xsleak/avatar.gif?q=admin"
        assert outcome(url, 2) == NEEDS_REVIEW

    def test_regular_levels_keep_runner_classification(self):
        assert outcome(f"{_LAB}/attr/level2?q=x", 1) == TP
        assert outcome(f"{_LAB}/attr/level2?q=x", 0) == FN_CANDIDATE
        assert detection_expected(f"{_LAB}/csp-bypass/level3") is True

    def test_category_extraction(self):
        assert category_of(f"{_LAB}/xsleak/redirect?q=a") == "xsleak"
        assert category_of(f"{_LAB}/") == ""
        assert category_of("not a url") == ""

    def test_prefix_match_is_category_exact(self):
        # a hypothetical future category 'xsleaks2' must not silently
        # inherit the not-XSS exemption
        assert detection_expected(f"{_LAB}/xsleaks2/level1") is True


class TestRunnerCrossCheck:
    def test_consistent_runner_output_has_no_mismatch(self):
        assert contract_mismatches(
            fns=[f"{_LAB}/attr/level5"], detected_controls=["xsleak"]) == []

    def test_xsleak_in_runner_fn_list_is_loud(self):
        bad = contract_mismatches(fns=[f"{_LAB}/xsleak/redirect?q=admin"],
                                  detected_controls=[])
        assert bad and "reclassified" in bad[0]
