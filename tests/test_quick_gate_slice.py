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


# ---------------------------------------------------------------------------
# Rotation (`--quick-offset`): determinism is what makes two builds comparable,
# but it also means the same 64 of 194 cases are the ONLY ones a push measures.
# After hundreds of rounds those 64 are the ones every fix was validated
# against; the other 130 are covered only by the nightly full run, so a
# regression there costs up to a day to notice.  Rotation keeps "comparable
# within a window" while the window changes.
# ---------------------------------------------------------------------------
def _family_sizes(cases):
    """Largest (ground_truth, context) family -- how many offsets are needed."""
    counts = {}
    for c in cases:
        key = (c.get("ground_truth"), c.get("context") or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return max(counts.values())


def test_offset_zero_is_the_historical_slice():
    """The default must be byte-identical to the pre-rotation behaviour."""
    cases = _cases()
    assert ([c["id"] for c in _quick_subset(cases)]
            == [c["id"] for c in _quick_subset(cases, offset=0)])


def test_offset_rotates_the_representative():
    """offset=1 must actually pick different cases, or it is a no-op flag."""
    cases = _cases()
    base = {c["id"] for c in _quick_subset(cases)}
    rotated = {c["id"] for c in _quick_subset(cases, offset=1)}
    assert base != rotated, "rotation changed nothing -- the flag is inert"
    # ... and it must still be a slice of the same shape, not a superset.
    assert len(base) == len(rotated)


def test_offset_keeps_one_representative_per_pair():
    """Rotation changes WHICH case, never HOW MANY pairs are covered."""
    cases = _cases()
    for off in (0, 1, 7, 23):
        subset = _quick_subset(cases, offset=off)
        assert _pairs(subset) == _pairs(cases), f"offset {off} lost a context"
        assert len({c["id"] for c in subset}) == len(subset), \
            f"offset {off} picked the same case twice"


def test_offset_is_deterministic():
    """A rotated slice must still be reproducible locally (that is the point)."""
    cases = _cases()
    assert ([c["id"] for c in _quick_subset(cases, offset=5)]
            == [c["id"] for c in _quick_subset(cases, offset=5)])


def test_offsets_cover_the_whole_manifest():
    """The claim that justifies the flag: N rotations measure ALL 194 cases.

    Without rotation the fixed slice needs 194 pushes to touch every case; with
    it, `max family size` rotations suffice.  This is the measurement, not the
    argument -- if the modulo ever stopped enumerating a family, this fails.
    """
    cases = _cases()
    need = _family_sizes(cases)
    seen = set()
    for off in range(need):
        seen |= {c["id"] for c in _quick_subset(cases, offset=off)}
    assert seen == {c["id"] for c in cases}, (
        f"{need} rotations did not reach every case; "
        f"missed: {sorted({c['id'] for c in cases} - seen)[:5]}")


def test_offsets_are_cheap_relative_to_the_full_matrix():
    """The rotation must beat the status quo, not just differ from it."""
    cases = _cases()
    need = _family_sizes(cases)
    assert need < len(cases) // 2, (
        f"rotating {need} times to cover {len(cases)} cases is no cheaper than "
        "running the full matrix -- the family distribution changed shape")


def test_cli_exposes_quick_offset():
    """The flag has to be reachable, or the rotation is library-only."""
    import subprocess
    out = subprocess.run(
        [sys.executable, os.path.join(_ROOT, "benchmark", "runner.py"), "--help"],
        capture_output=True, text=True, timeout=120)
    assert "--quick-offset" in out.stdout


# ---------------------------------------------------------------------------
# The same rot, one level up: the MATRIX size.  192 was true for a while and
# then the manifest grew to 194; the slice-size guard above did not catch it
# because both numbers contain "19"... no, because nobody wrote a guard for it.
# History rows ("Phase 265 的 192 例", docs/OPTIMIZATION.md's dated entries) are
# records and must stay -- only present-tense claims are banned.
# ---------------------------------------------------------------------------
_BANNED_MATRIX_CLAIMS = (
    "完整 192 例双引擎矩阵",
    "Full 192-case drill",
    "this 192-case run",
)

_MATRIX_CLAIMING_FILES = (
    os.path.join(".github", "workflows", "ci.yml"),
    "CONTRIBUTING.md",
)


def test_documented_matrix_size_matches_the_manifest():
    """A doc that says the matrix is 192 cases while it is 194 is the same bug
    the slice guard exists for -- just harder to notice, because a 2-case gap
    looks like rounding."""
    n = len(_cases())
    for rel in _MATRIX_CLAIMING_FILES:
        with open(os.path.join(_ROOT, rel), encoding="utf-8") as fh:
            text = fh.read()
        assert str(n) in text, f"{rel} does not state the current matrix size ({n})"
        for stale in _BANNED_MATRIX_CLAIMS:
            assert stale not in text, (
                f"{rel} still claims the stale matrix size: {stale!r}")
