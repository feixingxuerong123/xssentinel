# -*- coding: utf-8 -*-
"""Phase 401: pin the ADJUDICATION of Phase 391's onstart "evidence conflict".

Phase 391 refused to settle 11 verifier-confirmed / browser-inert onstart
shapes, claiming Phase 362's "live" on XSSMaze level5 came from a page with
its own scripts and scoring -- a different口径 from bare HTML, so the two
could not refute each other.

Phase 401 obtained the real XSSMaze source (commit 2976f2e; level5 logic
unchanged since c7a0a83) and adjudicated with a VALID interaction oracle:

  1. level5 page is a PURE STATIC `<div {query}>Event Handler Test :: ...`
     -- no <script>, no dispatch.  Phase 391's "different口径" premise is
     false: the real page IS bare HTML.
  2. Phase 362's finding is evidence_class=browser-unavailable,
     headless=None, "execution unverified" -- never a browser-confirmed
     live.  There was no "target says live" evidence to conflict with.
  3. Real Chromium load+hover (XSSMaze client口径): official answer fires,
     negative control inert, all onstart shapes inert while verifier still
     confirms.  controls_valid=True.

This guard pins the adjudication WITHOUT changing the product verdict:
INERT_HANDLER_PAIRS and Phase 389's `<div marquee onstart>` boundary stay
exactly as-is (expanding the pair is a separate, full-192 round).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from xssentinel.core import sandbox as S  # noqa: E402
from xssentinel.core import verifier as V  # noqa: E402

_ART = (_ROOT / "benchmark" / "results" /
        "phase401_onstart_level5_adjudication_20261118.json")
_SRC = (_ROOT / "benchmark" / "results" /
        "phase401_xssmaze_level5_source_snapshot_20261118.json")
_P362 = _ROOT / "dev" / "_xssmaze" / "_p362b_post" / "eventhandler-level5.json"
_OPT = _ROOT / "docs" / "OPTIMIZATION.md"
_TOKEN = "xssv_PHASE401"
_HEADERS = {"Content-Type": "text/html; charset=utf-8"}


def _art() -> dict:
    return json.loads(_ART.read_text(encoding="utf-8"))


def _src() -> dict:
    return json.loads(_SRC.read_text(encoding="utf-8"))


def test_controls_valid_and_verdict_is_adjudicated():
    art = _art()
    assert art["controls_valid"] is True, "first probe had invalid controls"
    assert art["verdict"].startswith("adjudicated"), art["verdict"]


def test_real_page_is_bare_html_no_script():
    """The premise that killed Phase 391's settlement is false."""
    src = _src()
    assert src["facts"]["page_has_script"] is False
    assert "<div #{query}>" in src["build_html_crystal"]
    assert "Filters.strip_angles" in src["build_html_crystal"]
    assert src["facts"]["onstart_in_denylist"] is False
    # a source snapshot that silently flips to "has script" must be caught
    assert "no <script>" in src["facts"]["page_is"]


def test_phase362_evidence_was_never_browser_execution():
    """Phase 362's 'live' was an unverified reflection, not browser evidence."""
    snap = _src()["phase362_evidence"]
    assert snap["evidence_class"] == "browser-unavailable"
    assert snap["headless"] is None
    assert "unverified" in snap["detail"]
    # cross-check against the actual historical artifact, not just the copy
    p362 = json.loads(_P362.read_text(encoding="utf-8"))
    finding = next(f for f in p362["findings"]
                   if "onstart" in (f.get("payload") or ""))
    assert finding["evidence_class"] == "browser-unavailable"
    assert finding.get("headless") is None


def test_onstart_shapes_inert_in_browser_but_confirmed_by_verifier():
    art = _art()
    rows = {r["case"]: r for r in art["rows"]}
    assert rows["control_positive_official_answer"]["browser_dialog"] is True
    assert rows["control_negative_plain"]["browser_dialog"] is False
    for case in ("phase362_marquee_onstart", "phase391_div_onstart",
                 "onstart_nested_bypass"):
        assert rows[case]["browser_dialog"] is False, case
        assert rows[case]["verifier_confirmed"] is True, case


def test_this_round_did_not_change_product_verdict():
    """Adjudication != repair: Phase 389's narrow pair is untouched."""
    assert S.INERT_HANDLER_PAIRS == frozenset({("marquee", "onstart")})
    html = ("<!doctype html><html><body>"
            f"<div marquee onstart=\"alert('{_TOKEN}')\">x</div>"
            "</body></html>")
    v = V.verify_semantic(html, _TOKEN, _HEADERS)
    assert v["confirmed"] is True, v
    assert "8.32" in _OPT.read_text(encoding="utf-8"), (
        "the adjudication record must be in OPTIMIZATION section 8.32")
