# -*- coding: utf-8 -*-
"""Phase 382: the independent-browser FACT TABLE must stay a fact table.

Phase 381 stopped at DELIVERY ("a stored string in a JSON field is not a
rendered XSS").  This runner closes that gap with an INDEPENDENT Playwright
Chromium: a real ``dialog`` event is execution evidence, each payload arm has
a matched clean control, and a dialog in the CONTROL arm means contamination.

What this guard refuses to let rot:

* no confusion-matrix / rate fields may creep back in (there is no denominator);
* counts must be recomputable from the rows, not hand-written;
* the two cases and two arms are pinned explicitly, so a silently shrinking
  set cannot pass;
* the verdict must be derivable from the real dialog evidence;
* the runner must still listen for ``dialog`` events and still have the
  ``control_contaminated`` branch -- checked on the AST of the real function,
  not on a comment in the report;
* the Markdown must be byte-identical to ``to_markdown(json)`` (real entry
  point, not a "looks similar" substring check);
* the tree is attributed: no silent ``unknown``.

Measured on tree ``edfe91d``.  These artifacts are external-validity evidence,
NOT a score for the 1.5.0 delivery tree.
"""
import ast
import collections
import json
import os
import pathlib
import re
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_JSON = "benchmark/results/juice_render_20261110.json"
_MD = "benchmark/results/juice_render_20261110.md"
_RUNNER = "benchmark/run_juice_render.py"

_EXPECTED_CASES = ("httpHeaderXssChallenge", "restfulXssChallenge")
_EXPECTED_ARMS = ("payload", "control")
_BANNED_FIELDS = {
    "tp", "fp", "tn", "fn", "precision", "recall", "f1", "f1_score",
    "accuracy", "true_positive", "false_positive", "score", "detected",
}


def _read(rel):
    return (pathlib.Path(_ROOT) / rel).read_text(encoding="utf-8")


def _data():
    return json.loads(_read(_JSON))


def _all_keys(obj):
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield str(key)
            yield from _all_keys(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from _all_keys(item)


def test_no_confusion_matrix_or_rate_fields():
    data = _data()
    leaked = {k.lower() for k in _all_keys(data)} & _BANNED_FIELDS
    assert not leaked, f"事实表里混入了评分字段: {sorted(leaked)}"
    assert "no TP/FP/TN/FN" in data["scoring_policy"]
    assert "## Why no score" in _read(_MD), "MD 丢了「为什么不给分」的口径"


def test_counts_are_recomputed_from_rows():
    data = _data()
    recomputed = dict(collections.Counter(r["verdict"] for r in data["rows"]))
    assert data["counts"] == recomputed, "counts 不是由 rows 重算出来的"


def test_cases_and_arms_are_explicit_and_matched():
    data = _data()
    assert tuple(data["cases"]) == _EXPECTED_CASES, "官方挑战集合被悄悄改动"
    assert tuple(data["arms"]) == _EXPECTED_ARMS, "payload/control 配对被改动"
    assert len(data["rows"]) == len(_EXPECTED_CASES) * len(_EXPECTED_ARMS)
    for case in _EXPECTED_CASES:
        arms = {r["arm"] for r in data["rows"] if r["key"] == case}
        assert arms == set(_EXPECTED_ARMS), f"{case} 缺 matched control 臂"


def test_execution_verdict_follows_the_real_dialog_evidence():
    for row in _data()["rows"]:
        fired = bool(row["dialogs"])
        if row["arm"] == "payload":
            expected = "browser_executed" if fired else "not_executed"
            assert row["verdict"] == expected, (
                f"{row['key']}/payload 的 verdict 与 dialog 证据不符")
            if fired:
                assert row["dialogs"] == ["xss"], "执行证据必须来自真实 dialog 事件"
                assert row["server_has_payload"] is True
        else:
            assert not fired, "control 臂出现 dialog 只能记污染,不能记命中"
            assert row["verdict"] == "not_executed"
            assert row["server_has_payload"] is False


def test_runner_uses_dialog_listener_and_contamination_branch():
    """AST 反查真实函数:注释里写「用 dialog」不算数。"""
    tree = ast.parse(_read(_RUNNER))
    functions = {
        n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    # ``ast.unparse`` normalises string quotes, so match the AST node itself:
    # a call to ``<page>.on("dialog", handler)``.
    listeners = [
        node for node in ast.walk(functions["_browser_probe"])
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "on"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == "dialog"
    ]
    assert listeners, (
        "_browser_probe 不再监听真实 dialog 事件(不要退化成 DOM iframe 判定)")
    run_body = ast.unparse(functions["run"])
    assert "control_contaminated" in run_body, "control 臂污染分支不见了"
    assert "dialogs" in run_body, "verdict 不再由 dialogs 推导"


def test_markdown_is_byte_identical_to_the_real_generator():
    if _ROOT not in sys.path:
        sys.path.insert(0, _ROOT)
    try:
        from benchmark.run_juice_render import to_markdown
    except ImportError as exc:  # a red gate, never a silent skip
        import pytest
        pytest.fail(f"无法 import 真实事实表生成器(依赖面缺 playwright?): {exc}")
    assert to_markdown(_data()) == _read(_MD), (
        "MD 与 JSON 不再由 to_markdown 同源生成")


def test_tree_is_attributed_and_echoed_in_markdown():
    tree = _data()["tree"]
    assert re.fullmatch(r"[0-9a-f]{7,40}", tree), (
        f"tree 归属缺失或写了 unknown: {tree!r}")
    assert tree in _read(_MD), "MD 没有记录测量当时的树"


def test_official_payload_and_clean_controls_are_internally_consistent():
    data = _data()
    payload = data["official_payload"]
    assert payload.startswith("<iframe"), "官方 payload 形状变了"
    assert set(data["clean_control_values"].values()) == {
        "203.0.113.7", "The all-time classic."}
    for row in data["rows"]:
        if row["arm"] == "payload":
            assert row["server_echo"] == payload
        else:
            assert row["server_echo"] in data["clean_control_values"].values()
