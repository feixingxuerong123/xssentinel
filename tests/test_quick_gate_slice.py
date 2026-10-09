# -*- coding: utf-8 -*-
"""Phase 190: the push-gate accuracy slice must actually span the detection surface.

Why this file exists
--------------------
CI's per-push accuracy gate runs ``benchmark.runner --quick``.  For a long time
that slice was built by ``_quick_subset(cases, per_class=5)``, whose round-robin
over contexts stopped **mid-cycle in alphabetical order** -- so it re-measured the
same handful of families on every build while the biggest family in the matrix was
never measured at all:

    html_element: 48 vulnerable + 34 safe cases = 43% of the 192-case matrix,
                  0 of them in the push slice.

Worse, the *documented* size of that slice was wrong everywhere it was written
down (ci.yml, CONTRIBUTING.md, docs/OPTIMIZATION.md all said "98 cases"; the
archive reports said 10).  At 10 cases the gate thresholds (``FPR > 20%`` /
``recall < 50%``, benchmark/runner.py) tolerated **1 false positive and 2 false
negatives per push** and still printed green -- a gate that passes on a broken
layer is not a gate.

So these tests lock two things:

1. **Coverage** -- every ``(ground_truth, context)`` pair in the manifest has a
   representative in the quick slice, deterministically.
2. **Self-consistency of the docs** -- the number CI/contributor docs quote for
   the slice is the number the code actually produces, and the stale claims that
   hid this bug may not come back.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from benchmark.runner import _quick_subset  # noqa: E402

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_MANIFEST = os.path.join(_ROOT, "benchmark", "manifest.json")

# Claims that were true at some point and then rotted.  Re-introducing one of
# these means the doc and the code disagree again -- fix the doc, don't re-add
# the string.
_BANNED_STALE_CLAIMS = (
    "98 例快速精度矩阵",
    "98-case quick slice",
    "(98 例)",
    "Quick mode (10 cases)",
    # Present-tense claims about the MATRIX size.  Dated historical rows that
    # say "98 例" (README's 2026-09-06 / Phase 96 baselines) are legitimate
    # records -- what must not come back is a sentence asserting the matrix
    # IS 98 cases today.
    "同一 98 用例矩阵",
)

# Files that state how big the push slice is.  A file belongs here only if it
# really makes that claim: `run_benchmark_batched.py` drives the FULL 192-case
# matrix and has no reason to mention 64, so adding it made the guard assert
# something false about a correct file.
_CLAIMING_FILES = (
    os.path.join(".github", "workflows", "ci.yml"),
    "CONTRIBUTING.md",
    "README.md",
    os.path.join("docs", "OPTIMIZATION.md"),
    os.path.join("benchmark", "run_benchmark.py"),
    os.path.join("benchmark", "runner.py"),
)


def _cases():
    with open(_MANIFEST, encoding="utf-8") as fh:
        return json.load(fh)["cases"]


def _pairs(cases):
    return {(c.get("ground_truth"), c.get("context") or "unknown") for c in cases}


def test_quick_slice_covers_every_ground_truth_context_pair():
    """No context family may be invisible to a per-push gate."""
    cases = _cases()
    missing = _pairs(cases) - _pairs(_quick_subset(cases))
    assert not missing, f"contexts never measured on push: {sorted(missing)}"


def test_quick_slice_is_exactly_one_representative_per_pair():
    """Default cap = full context coverage, and nothing is duplicated."""
    cases = _cases()
    subset = _quick_subset(cases)
    assert len(subset) == len(_pairs(cases))
    assert _pairs(subset) == _pairs(cases), "slice picked a pair twice or skipped one"
    assert len({c["id"] for c in subset}) == len(subset), "duplicate case in slice"


def test_biggest_context_family_is_in_the_push_slice():
    """The regression that motivated this file: html_element was never sampled."""
    html_element = [c for c in _cases() if c.get("context") == "html_element"]
    assert len(html_element) > 40, "manifest shape changed; this test needs re-reading"
    picked = {c["id"] for c in _quick_subset(_cases())}
    assert any(c["id"] in picked for c in html_element)


def test_quick_slice_is_deterministic():
    """Two builds must be comparable, so the pick cannot depend on dict order."""
    cases = _cases()
    assert [c["id"] for c in _quick_subset(cases)] == [c["id"] for c in _quick_subset(cases)]


def test_explicit_cap_still_spreads_across_contexts():
    """A smaller slice must still take distinct contexts, not one context x N."""
    subset = _quick_subset(_cases(), per_class=3)
    by_gt = {gt: [c for c in subset if c.get("ground_truth") == gt]
             for gt in ("vulnerable", "safe")}
    for gt, picked in by_gt.items():
        assert len(picked) == 3, f"{gt}: expected 3 cases, got {len(picked)}"
        assert len({c.get("context") for c in picked}) == 3, f"{gt}: contexts repeated"


def test_documented_slice_size_matches_the_code():
    """The number quoted in CI / contributor docs is the number produced."""
    n = len(_quick_subset(_cases()))
    assert n >= 40, (
        f"push slice is only {n} cases -- below the thresholds in "
        "benchmark/runner.py this gate cannot see a single FP or FN"
    )
    for rel in _CLAIMING_FILES:
        with open(os.path.join(_ROOT, rel), encoding="utf-8") as fh:
            text = fh.read()
        assert str(n) in text, f"{rel} does not state the current slice size ({n})"
        for stale in _BANNED_STALE_CLAIMS:
            assert stale not in text, f"{rel} still claims the stale slice size: {stale!r}"
