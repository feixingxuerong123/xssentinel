"""XSSMaze scoring contract, versioned (Phase 322).

Upstream rule (hahwul/xssmaze v0.3.0 README): "The whole xsleak category
is cross-site leaks, not XSS -- a scanner that reports nothing there is
correct."  In our 2026-10-22 lab runs the xsleak URLs rode the CONTROLS
batch, so upstream scores them on the FP side: silence is correct, a
finding is a control violation.

The OFFICIAL runner (``scripts/benchmark.py``, per-URL ``--detect-json``
mode) is the authoritative scorer -- this module does NOT re-score.  What
it does is pin the expectation so every aggregate/attribution view we
write AROUND the runner (dev/_xssmaze/*) classifies xsleak the same way
upstream does, and a future upstream reclassification surfaces as a loud
contract mismatch instead of silently shifting our FN denominator.

Rules, once, in code:

  * an xsleak-category URL with ZERO findings is ``correct_silence`` --
    it must never be counted as a false negative anywhere;
  * an xsleak-category URL WITH findings is ``needs_review`` -- not an
    auto-TP (the category is not XSS) and not silently dropped either;
  * every other category keeps the runner's own TP/FN classification.
"""
from __future__ import annotations

from urllib.parse import urlparse

#: Category prefixes upstream documents as "not XSS".  Deliberately a
#: closed tuple -- widening it is a contract change that belongs in a
#: reviewed edit with the upstream quote updated, not a config tweak.
NO_DETECTION_EXPECTED_PREFIXES = ("xsleak",)

CORRECT_SILENCE = "correct_silence"
NEEDS_REVIEW = "needs_review"
TP = "tp"
FN_CANDIDATE = "fn_candidate"


def category_of(url: str) -> str:
    """First path segment of a lab URL (…/<category>/levelN?…).

    Non-URL garbage has no category (''), so it can never accidentally
    match an exemption prefix.
    """
    try:
        p = urlparse(url)
    except ValueError:
        return ""
    if not p.scheme or not p.netloc:
        return ""
    seg = p.path.lstrip("/").split("/")
    return seg[0] if seg else ""


def detection_expected(url: str) -> bool:
    """False for categories upstream documents as not-XSS."""
    cat = category_of(url).lower()
    return not any(cat == p.lower() or cat.startswith(p.lower() + "-")
                   for p in NO_DETECTION_EXPECTED_PREFIXES)


def outcome(url: str, finding_count: int) -> str:
    """Classify one (URL, findings) pair under the upstream contract."""
    if not detection_expected(url):
        return CORRECT_SILENCE if finding_count == 0 else NEEDS_REVIEW
    return TP if finding_count > 0 else FN_CANDIDATE


def contract_mismatches(fns: list[str], detected_controls: list[str]) -> list[str]:
    """Cross-check official runner output against this contract.

    Returns human-readable mismatch lines (empty list = consistent):
    the runner's FN list must contain NO xsleak URL (upstream counts them
    as controls), and its detected-controls list SHOULD carry the xsleak
    name only when we actually fired there.  Any mismatch means upstream
    reclassified the category and this module -- plus every aggregate
    built on it -- needs a reviewed update, not a silent reinterpretation.
    """
    bad: list[str] = []
    for u in fns:
        if not detection_expected(u):
            bad.append(f"runner counts {u} as FN but the category is "
                       "documented not-XSS (correct silence) -- upstream "
                       "reclassified?")
    return bad
