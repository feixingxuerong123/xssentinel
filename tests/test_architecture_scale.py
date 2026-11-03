# -*- coding: utf-8 -*-
"""Phase 347: the "don't pile it back into the main file" rule, measured.

Why budgets instead of exact counts
-----------------------------------
AGENTS.md stated the Mixin split as a dated measurement (2026-10-05: core
1869 / layers 769 / crawl 406 / stored 579 / findings 216) and derived a rule
from it: new capability goes into the matching Mixin.  Four weeks later the
real numbers were 2246 / 936 / 483 / 982 / 377 -- the core grew 20% and
``scanner_stored`` grew 70% -- and nothing failed, because a number in prose
is not an instrument.  Pinning the *exact* count would be worse: every
one-line edit would break the build, the gate would be disabled within a
week, and a disabled gate is indistinguishable from no gate.

So the pinned quantity is the **ceiling**.  Exceeding it is not forbidden, it
is *deliberate*: split the file, or raise the budget in the same commit and
say why.  Both are reviewable; drift is not.

Why both directions are checked
-------------------------------
A budget table can fail in two ways, and only one of them looks like a
failure.  A file over budget is loud.  A *new* Mixin that nobody budgeted is
silent -- it is simply not in the table, so nothing measures it, which is the
same "the set itself can grow without an alarm" shape this project has been
caught by before.  ``test_every_mixin_has_a_budget`` closes that direction.
"""
import os
import re

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CORE = os.path.join(_ROOT, "xssentinel", "core")

#: file name -> ceiling in physical lines (``wc -l``).
#: 2026-11-01 measured values are in AGENTS.md; the ceiling is that value plus
#: ~10%, which is roughly one feature's worth of headroom before a decision.
BUDGETS = {
    # Phase 356 (2026-11-03) raise: marker-form fan-out is interleaved inside
    # _try_payload and _detect_quote_escaping sits next to its sibling probe
    # _probe_reflection_profile -- the reflection path already lives in this
    # file, so the ceiling follows the table convention (measured + ~10%)
    # instead of splitting half a method into another file.  Measured at
    # raise time: 2438 / 1107.
    "scanner.py": 2650,
    "scanner_layers.py": 1050,
    "scanner_crawl.py": 550,
    "scanner_stored.py": 1200,
    # Phase 352: stored auto-discovery is its own Mixin (125 lines measured)
    # so the stored round-trip file stays under its ceiling.
    "scanner_stored_auto.py": 150,
    "findings.py": 450,
    "async_scanner.py": 1600,
    "async_scanner_layers.py": 2350,
    "async_scanner_crawl.py": 650,
    "async_scanner_common.py": 520,
    "async_scanner_verify.py": 145,
}

#: Every file the two pipelines are split into.  Listed explicitly (not
#: globbed) so a new Mixin shows up as a test failure, not as a file the
#: budget table silently never covered.
_MIXIN_FAMILY = set(BUDGETS)


def _line_count(path: str) -> int:
    with open(path, "rb") as fh:
        return fh.read().count(b"\n")


def test_every_mixin_has_a_budget():
    """Both directions: no unbudgeted Mixin, no budget for a missing file."""
    on_disk = {name for name in os.listdir(_CORE)
               if re.match(r"^(async_)?scanner(_[a-z_]+)?\.py$", name)
               or name == "findings.py"}
    missing_budget = on_disk - _MIXIN_FAMILY
    assert not missing_budget, (
        "these Mixin files have no line budget, so nothing measures them: "
        f"{sorted(missing_budget)} -- add them to BUDGETS")
    vanished = _MIXIN_FAMILY - on_disk
    assert not vanished, (
        f"BUDGETS names files that no longer exist: {sorted(vanished)} -- "
        "a stale budget is a measurement of nothing")


def test_no_mixin_exceeds_its_budget():
    over = []
    for name, budget in sorted(BUDGETS.items()):
        actual = _line_count(os.path.join(_CORE, name))
        if actual > budget:
            over.append(f"{name}: {actual} > {budget} (+{actual - budget})")
    assert not over, (
        "Mixin over budget -- split it, or raise the ceiling in this commit "
        "and say why in the message:\n  " + "\n  ".join(over))


def test_budget_has_headroom_but_is_not_decorative():
    """A ceiling set 3x above reality measures nothing.

    The other failure mode of a ratchet: budgets raised "to be safe" until
    they can never fire.  Headroom is capped at 25% so the table keeps
    describing the architecture instead of blessing any future size.
    """
    loose = []
    for name, budget in sorted(BUDGETS.items()):
        actual = _line_count(os.path.join(_CORE, name))
        if actual and budget > actual * 1.25:
            loose.append(f"{name}: budget {budget} vs actual {actual}")
    assert not loose, (
        "budget headroom above 25% makes the ceiling unfalsifiable:\n  "
        + "\n  ".join(loose))


def test_doc_points_at_this_gate():
    """A rule whose gate is not discoverable from the rule does not get run."""
    with open(os.path.join(_ROOT, "AGENTS.md"), encoding="utf-8") as fh:
        doc = fh.read()
    assert "tests/test_architecture_scale.py" in doc, (
        "AGENTS.md must name the gate that enforces its own architecture rule")
