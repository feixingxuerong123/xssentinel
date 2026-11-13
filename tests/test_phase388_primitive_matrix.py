# -*- coding: utf-8 -*-
"""Phase 388: the fn_net "2 real FPs" verdict is refuted by a shape matrix.

§8.17 concluded (from hand-written nearby browser cases) that L7 polyglot
should be downgraded under the quote-encoding profile.  The deterministic
matrix measures the product's OWN nine executor primitives through the REAL
/fuzz/render fixture with a real Chromium dialog: eight of nine are live,
only one (marquee onstart) is verifier-only.  A whole-layer downgrade would
therefore manufacture false negatives.  This guard pins that fact table and
the tools/documents that carry it.

The FP arm of fn_net is a CANDIDATE generator, not a verdict; this is the
"candidate != verdict" rule made into a measured artifact.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from xssentinel.core import polyglot as POLY  # noqa: E402

_ART = (_ROOT / "benchmark" / "results" /
        "phase388_primitive_matrix_20261113.json")
_SCRIPT = _ROOT / "dev" / "phase388_primitive_matrix.py"
_ADJUDICATOR = _ROOT / "dev" / "fn_net_adjudicate.py"
_OPT = _ROOT / "docs" / "OPTIMIZATION.md"
_CHANGELOG = _ROOT / "CHANGELOG.md"


def _art() -> dict:
    return json.loads(_ART.read_text(encoding="utf-8"))


def test_matrix_enumerates_the_product_corpus_exactly():
    a = _art()
    product = {p for p, _why in POLY._EXEC_PRIMITIVES}
    assert {r["primitive"] for r in a["rows"]} == product
    expected = (len(product) * len(a["meta"]["sinks"])
                * len(a["meta"]["escs"]))
    assert a["summary"]["shapes"] == len(product)
    assert a["summary"]["arms"] == len(a["rows"]) == expected
    combos = [(r["primitive"], r["esc"], r["sink"]) for r in a["rows"]]
    assert len(combos) == len(set(combos)), "duplicate or missing arm"
    assert set(a["meta"]["escs"]) == {"encode_quotes", "raw", "html",
                                      "encode_angles"}
    assert set(a["meta"]["sinks"]) == {"none", "dom"}


def test_controls_are_load_bearing():
    """A browser oracle that cannot see an execution proves nothing."""
    a = _art()
    assert a["meta"]["controls_valid"] is True
    assert a["summary"]["controls_valid"] is True
    assert any(r["browser_dialog"] for r in a["rows"] if r["esc"] == "raw")
    for esc in ("html", "encode_angles"):
        arm = [r for r in a["rows"] if r["esc"] == esc]
        assert arm and not any(r["browser_dialog"] for r in arm), esc
        assert not any(r["verifier_confirmed"] for r in arm), esc


def test_summary_is_recomputed_from_rows():
    a = _art()
    rows = a["rows"]
    live, verifier_only = [], []
    for prim in {r["primitive"] for r in rows}:
        same = [r for r in rows if r["primitive"] == prim
                and r["esc"] == "encode_quotes"]
        assert len(same) == len(a["meta"]["sinks"])
        if all(r["verifier_confirmed"] and r["browser_dialog"]
               for r in same):
            live.append(prim)
        elif all(r["verifier_confirmed"] and not r["browser_dialog"]
                 for r in same):
            verifier_only.append(prim)
    assert set(a["summary"]["true_detection"]) == set(live)
    assert set(a["summary"]["verifier_only"]) == set(verifier_only)
    assert len(live) + len(verifier_only) == len(
        {r["primitive"] for r in rows})


def test_the_narrow_defect_is_the_marquee_shape():
    """2026-11-13 Chromium fact table: 8 live, 1 verifier-only."""
    a = _art()
    assert len(a["summary"]["true_detection"]) == 8
    assert len(a["summary"]["verifier_only"]) == 1
    assert "marquee" in a["summary"]["verifier_only"][0]
    # The two fn_net candidates are NOT rejected by the browser in general:
    # only this one primitive is.  "Downgrade L7 under encode_quotes" would
    # suppress the eight live shapes.
    assert a["summary"]["true_detection"]


def test_matrix_script_uses_product_corpus_and_real_fixture():
    src = _SCRIPT.read_text(encoding="utf-8")
    for token in ("POLY._EXEC_PRIMITIVES", "build_multi_stage_polyglot",
                  "/fuzz/render?ctx=", "esc={esc}", "sink={sink}",
                  'page.on("dialog"', "verify_semantic"):
        assert token in src, token
    # No reconstructed "nearby" shapes: that is exactly how §8.17 erred.
    assert "&lt;/script&gt;" not in src
    assert "marquee" not in src


def test_adjudicator_uses_the_findings_own_payload():
    src = _ADJUDICATOR.read_text(encoding="utf-8")
    for token in ("_invoke_scanner", "V.mark", 'f.get("payload")',
                  "/fuzz/render?ctx={ctx}&esc={esc}", "sink={sink}",
                  'page.on("dialog"', "controls_valid"):
        assert token in src, token
    assert "&lt;/script&gt;" not in src


def test_documents_carry_the_correction_and_keep_history():
    changelog = _CHANGELOG.read_text(encoding="utf-8")
    unreleased = changelog.split("## [2.0.1]", 1)[0]
    assert "勘误" in unreleased and "真阳性" in unreleased
    # One exact sentence, so deleting a single word from the erratum is
    # caught even though the generic word appears elsewhere in the section.
    assert "8/9 形状 verifier 与浏览器一致确认(真阳性)" in unreleased
    assert "phase388_primitive_matrix_20261113.json" in unreleased
    # A dated released entry is a historical record: corrected by an
    # erratum, never silently rewritten.
    released = changelog.split("## [2.0.1]", 1)[1].split("## [2.0.0]", 1)[0]
    assert "L7 polyglot 层转义画像降档列为下轮候选" in released
    opt = _OPT.read_text(encoding="utf-8")
    assert "新候选(实测记账,未修)" in opt  # §8.17 original preserved
    assert "### 8.19" in opt
    section = opt.split("### 8.19", 1)[1]
    assert "真阳性" in section and "marquee" in section
