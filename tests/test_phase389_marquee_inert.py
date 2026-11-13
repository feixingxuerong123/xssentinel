# -*- coding: utf-8 -*-
"""Phase 389: the marquee/onstart verifier-only FP is closed, nothing else moves.

The 388 shape matrix measured 9 product polyglot executors in real Chromium:
8 fire, ``<marquee onstart=...>`` never does while the verifier confirmed it.
This fix makes the HTML sandbox's fact table say ``inert`` for that ONE
(element, handler) pair so the existing Phase 169 veto retracts the
``event_handler`` confirmation.  The guards below pin the narrowness:

* the pair is a PAIR, not a handler-name blacklist (Phase 362 measured
  ``onstart`` as a live attribute on a non-marquee host element);
* all 8 live primitives stay confirmed;
* a before/after 72-arm matrix shows the browser facts did not change and
  only marquee's verifier bit flipped.
"""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from xssentinel.core import polyglot as P  # noqa: E402
from xssentinel.core import sandbox as S  # noqa: E402
from xssentinel.core import verifier as V  # noqa: E402

_ART388 = (_ROOT / "benchmark" / "results" /
           "phase388_primitive_matrix_20261113.json")
_ART389 = (_ROOT / "benchmark" / "results" /
           "phase389_primitive_matrix_20261113.json")
_SANDBOX = _ROOT / "xssentinel" / "core" / "sandbox.py"
_OPT = _ROOT / "docs" / "OPTIMIZATION.md"
_CHANGELOG = _ROOT / "CHANGELOG.md"
TOKEN = "xssv_p389"
MSG = "xss_poly_389fixed"
_HEADERS = {"Content-Type": "text/html; charset=utf-8"}


def _verify(body: str) -> dict:
    return V.verify_semantic(body, TOKEN, _HEADERS)


def _art(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_marquee_onstart_is_refused_with_sandbox_attribution():
    html = ("<!doctype html><html><body>"
            f"<marquee onstart=\"alert('{TOKEN}')\">x</marquee>"
            "</body></html>")
    v = _verify(html)
    assert v["confirmed"] is False, v
    assert v["detail"].startswith("sandbox:"), v
    assert v["sandbox_state"] == "inert", v
    assert S.judge(html, TOKEN, sink="parser").state == "inert"


def test_eight_live_primitives_stay_confirmed():
    """The narrow veto must not suppress the shapes Chromium really fires."""
    saved = list(P._EXEC_PRIMITIVES)
    try:
        for primitive, why in saved:
            P._EXEC_PRIMITIVES = [(primitive, why)]
            payload = P.build_multi_stage_polyglot("389fixed")
            html = ("<!doctype html><html><body>" + payload
                    + "</body></html>")
            v = V.verify_semantic(html, MSG, _HEADERS)
            expected = "marquee" not in primitive
            assert bool(v.get("confirmed")) is expected, (primitive, v)
    finally:
        P._EXEC_PRIMITIVES = saved


def test_phase362_attribute_shape_is_not_banned():
    """Angle-bracket stripping leaves onstart on the HOST element, not on a
    <marquee>; Phase 362 measured that as live.  A name blacklist would kill
    it, so the rule must be an (element, attribute) pair."""
    v = _verify("<!doctype html><html><body>"
                f"<div marquee onstart=\"alert('{TOKEN}')\">x</div>"
                "</body></html>")
    assert v["confirmed"] is True, v


def test_rule_is_a_pair_and_lives_in_handler_state():
    assert S.INERT_HANDLER_PAIRS == frozenset({("marquee", "onstart")})
    src = _SANDBOX.read_text(encoding="utf-8")
    fn = next(n for n in ast.parse(src).body
              if isinstance(n, ast.FunctionDef)
              and n.name == "_handler_state")
    seg = ast.get_source_segment(src, fn) or ""
    assert "if (name, ev) in INERT_HANDLER_PAIRS:" in seg
    assert "measured no-exec in Chromium" in seg


def test_before_after_fact_tables_differ_only_in_the_verifier_bit():
    before, after = _art(_ART388), _art(_ART389)
    prims = {r["primitive"] for r in before["rows"]}
    assert prims == {r["primitive"] for r in after["rows"]}
    assert len(before["rows"]) == len(after["rows"]) == 72
    assert len(before["summary"]["verifier_only"]) == 1
    assert after["summary"]["verifier_only"] == []
    assert len(after["summary"]["true_detection"]) == 8
    assert before["meta"]["controls_valid"] is True
    assert after["meta"]["controls_valid"] is True
    # The summary repeats the same measured flag; a guard that reads only one
    # copy would let the other rot.
    assert before["summary"]["controls_valid"] is True
    assert after["summary"]["controls_valid"] is True

    def arm(a, prim):
        return [r for r in a["rows"] if r["primitive"] == prim
                and r["esc"] == "encode_quotes"]

    for prim in prims:
        b, a = arm(before, prim), arm(after, prim)
        assert len(b) == len(a) == 2
        # The browser is the same Chromium on the same fixture: its facts
        # must be byte-identical across the fix.
        assert {r["browser_dialog"] for r in b} == {
            r["browser_dialog"] for r in a}, prim
        v_before = {r["verifier_confirmed"] for r in b}
        v_after = {r["verifier_confirmed"] for r in a}
        if "marquee" in prim:
            assert v_before == {True} and v_after == {False}, prim
        else:
            assert v_before == v_after == {True}, prim


def test_documents_record_the_narrow_fix():
    unreleased = _CHANGELOG.read_text(encoding="utf-8").split(
        "## [2.0.1]", 1)[0]
    assert "Phase 389" in unreleased and "marquee" in unreleased
    assert "phase389_primitive_matrix_20261113.json" in unreleased
    assert "### 8.20" in _OPT.read_text(encoding="utf-8")
