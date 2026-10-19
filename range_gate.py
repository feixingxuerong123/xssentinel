# -*- coding: utf-8 -*-
"""Shared gate rules for the range runners (range3/4/5).

Why this module exists.  Each runner grew its own verdict filter, and the
filter only ever looked at TP/FP/TN/FN.  But range4 and range5 do not
measure "did a static pattern match" -- they measure "did a REAL browser
execute this payload".  Their positives print `browser-confirmed=N` and
the gate ignored it, so a run where Chromium never started scored TP on
every positive and passed:

    PLAYWRIGHT_BROWSERS_PATH=<empty dir> python range4/runner.py --engine sync
      [sync] r4-pos-react-dsi  TP  top: reflected/high/script_string_sq/errored
                                   browser-confirmed=0
      => TP2 FP0 TN2 FN0 ERR0
      [*] Range4 gate: every case scored as ground truth requires
      EXIT=0                      # <- the range measured nothing

That is the Phase 266 lesson one level up: a gate that cannot see the
thing the range exists to measure is decoration.  The project also has a
documented silent-degradation path for the headless verifier, so
"outcome=errored / confirmed=0" is a shape that actually occurs.

One definition, both call sites (Phase 259's lesson): the rules live here
and the runners call them; a hand-kept copy per runner is how the two
engines' emit contracts drifted in the first place.
"""
from __future__ import annotations


def failing_rows(rows: list[dict]) -> list[dict]:
    """Rows whose verdict is a defect.  SKIP is not a defect: it means the
    manifest declared the case inapplicable to that engine."""
    return [r for r in rows if r.get("verdict") in ("FN", "FP", "ERROR")]


def evidence_gaps(rows: list[dict],
                  cases_by_id: dict[str, dict]) -> list[tuple[str, str]]:
    """Positives that scored TP without a single browser-executed finding.

    A positive counts as measured only when the manifest says the case
    needs a browser AND the report carries at least one finding whose
    headless outcome is `fired`.  A missing `confirmed` key counts as
    zero: no recorded evidence is not evidence.

    Cases the manifest scores statically (headless=False, e.g. range6's
    sanitizer pair) are exempt by construction, not by exception.
    """
    gaps: list[tuple[str, str]] = []
    for r in rows:
        case = cases_by_id.get(r.get("case_id"))
        if not case or not case.get("headless"):
            continue
        if case.get("gt") != "vulnerable":
            continue
        if r.get("verdict") == "TP" and not r.get("confirmed"):
            gaps.append((r.get("engine", "?"), r.get("case_id", "?")))
    return gaps
