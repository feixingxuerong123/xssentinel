# -*- coding: utf-8 -*-
"""Phase 391: pin the onstart shape fact table AND the decision not to act.

The fact table says: in bare HTML, Chromium 148 does not execute ``onstart``
on ANY measured element (including Phase 362's ``<div marquee onstart>``),
even when a ``start`` event is dispatched by hand.  That is NOT a repair
order.  Phase 362's "live" evidence came from the XSSMaze level5 page, a
different oracle with its own scripts and scoring.  Until that conflict is
adjudicated in the real page, Phase 389's narrow pair stays exactly as it
is.  These guards make both halves of that decision explicit.
"""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from xssentinel.core import sandbox as S  # noqa: E402
from xssentinel.core import verifier as V  # noqa: E402

_ART = (_ROOT / "benchmark" / "results" /
        "phase391_onstart_shapes_20261114.json")
_PROBE = _ROOT / "dev" / "phase391_onstart_shapes.py"
_OPT = _ROOT / "docs" / "OPTIMIZATION.md"
_CHANGELOG = _ROOT / "CHANGELOG.md"

_ELEMENTS = ("marquee", "div", "span", "p", "section", "a", "img", "svg",
             "table", "input")
_VERIFIER_ONLY = frozenset({
    "<div onstart>", "<span onstart>", "<p onstart>",
    "<section onstart>", "<a onstart>", "<img onstart>", "<svg onstart>",
    "<table onstart>", "<input onstart>", "<div marquee onstart>",
    "<div onstart + dispatch start>",
})
_TOKEN = "xssv_p391"
_HEADERS = {"Content-Type": "text/html; charset=utf-8"}


def _art() -> dict:
    return json.loads(_ART.read_text(encoding="utf-8"))


def _rows() -> dict:
    return {r["shape"]: r for r in _art()["rows"]}


def test_controls_and_baseline_are_measured():
    art = _art()
    rows = _rows()
    assert art["meta"]["controls_valid"] is True
    assert art["summary"]["controls_valid"] is True
    assert art["summary"]["arms"] == len(art["rows"]) == 15, (
        "the summary no longer describes the rows -- a fact table whose "
        "counts drifted is not evidence")
    assert rows["control_positive_onerror"]["browser_dialog"] is True
    assert rows["control_negative_onclick"]["browser_dialog"] is False
    assert rows["<marquee onstart>"]["browser_dialog"] is False
    assert rows["<marquee onstart>"]["verifier_confirmed"] is False
    assert rows["<marquee onstart + start()>"]["browser_dialog"] is False
    assert art["summary"]["live"] == []


def test_every_measured_onstart_shape_is_verifier_only():
    art = _art()
    rows = _rows()
    for shape in sorted(_VERIFIER_ONLY):
        assert shape in rows, shape
        assert rows[shape]["verifier_confirmed"] is True, shape
        assert rows[shape]["browser_dialog"] is False, shape
    assert set(art["summary"]["verifier_only"]) == _VERIFIER_ONLY, (
        "the summary's verifier_only set no longer matches the measured "
        "shapes -- re-run the probe instead of editing the list")
    assert len(_VERIFIER_ONLY) == 11


def test_shapes_come_from_the_probe_scripts_own_corpus():
    """AST, not a hand-typed list: guard against 'measured what I wrote'."""
    art = _art()
    rows = _rows()
    tree = ast.parse(_PROBE.read_text(encoding="utf-8"))
    corpus = None
    for node in tree.body:
        if isinstance(node, ast.Assign) \
                and any(isinstance(t, ast.Name) and t.id == "ELEMENTS"
                        for t in node.targets):
            corpus = [e.value for e in node.value.elts]
    assert corpus, "ELEMENTS not found in the probe -- guard matched nothing"
    assert tuple(corpus) == _ELEMENTS == tuple(art["meta"]["elements"])
    for el in corpus:
        assert f"<{el} onstart>" in rows, el


def test_this_round_did_not_change_the_product_verdict():
    """The measured conflict is NOT settled; Phase 389's boundary survives."""
    assert S.INERT_HANDLER_PAIRS == frozenset({("marquee", "onstart")}), (
        "the inert pair changed without an XSSMaze level5 browser remeasure")
    html = ("<!doctype html><html><body>"
            f"<div marquee onstart=\"alert('{_TOKEN}')\">x</div>"
            "</body></html>")
    v = V.verify_semantic(html, _TOKEN, _HEADERS)
    assert v["confirmed"] is True, v
    assert "8.22" in _OPT.read_text(encoding="utf-8")


def test_documents_record_the_open_conflict():
    opt = _OPT.read_text(encoding="utf-8")
    changelog = _CHANGELOG.read_text(encoding="utf-8")
    assert "Phase 391" in opt and "Phase 391" in changelog
    assert "XSSMaze" in opt and "证据冲突未定谳" in opt, (
        "the documents must say the conflict is OPEN, not claim a fix")
