# -*- coding: utf-8 -*-
"""Phase 380: the real-application cross-tool table stays a FACT TABLE.

Why this guard exists
---------------------
On OWASP Juice Shop v20.2.0 the positive XSS cases live on Angular hash
routes: the injection point sits in the URL fragment, which no HTTP request
can carry.  dalfox / nuclei are request-shaped tools, so their "0 findings"
on those rows is NOT MEASURED, not a miss.  The two rows every tool can reach
are true negatives (REST search does not reflect; /redirect HTML-escapes), so
there is no server-deliverable positive and no denominator for recall.  Any
TP/FP/F1 computed from this table would be fabricated precision -- exactly the
failure mode this repo's gate rules forbid ("a gate that passes on a broken
measurement is not a gate").

The published artifacts are therefore locked on five axes:

1. the scoring policy and summary carry no score columns;
2. delivery shape comes from the URL via the REAL runner function, never from
   a tool-name allowlist (AST check on the function body);
3. cases come from the target's own answer key or a measured control, and the
   ``pos-derived`` supplementary row stays OUT of any denominator;
4. the summary is recomputed from the per-case rows;
5. the Markdown is byte-identical to rendering the JSON through
   ``to_markdown`` -- no hand-edited scorecard can be slipped in later.

Mutation evidence: ``dev/phase380_mutations.py`` (7 anchored mutations, each
run against ONE named test so a red cannot come from a different assertion).
"""
import ast
import json
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from benchmark.run_juice_cross_tool import (  # noqa: E402
    CASES,
    _delivery_shape,
    to_markdown,
)

_JSON = _ROOT / "benchmark" / "results" / "juice_cross_tool_20261110.json"
_MD = _ROOT / "benchmark" / "results" / "juice_cross_tool_20261110.md"
_RUNNER = _ROOT / "benchmark" / "run_juice_cross_tool.py"

_TOOLS = frozenset({"XSSentinel", "dalfox", "nuclei-dast-xss"})
_SUMMARY_KEYS = frozenset({
    "cases", "detected", "errors", "wall_s",
    "detected_on_fragment", "detected_on_server",
})
_SCORE_WORDS = frozenset({"tp", "fp", "tn", "fn", "f1", "precision", "recall"})


@pytest.fixture(scope="module")
def fact():
    return json.loads(_JSON.read_text(encoding="utf-8"))


_EXPECTED_POLICY = (
    "FACT TABLE ONLY. No TP/FP/TN/FN or F1: delivery reachability differs "
    "per tool and there is no server-deliverable positive."
)


def test_scoring_policy_forbids_scores(fact):
    # Pin the whole sentence: any edit that turns this into a scorecard --
    # including a quoted F1/precision value -- must fail the guard.
    assert fact["scoring_policy"] == _EXPECTED_POLICY


def test_summary_has_no_score_columns(fact):
    assert set(fact["summary"]) == _TOOLS
    for tool, summary in fact["summary"].items():
        assert set(summary) == _SUMMARY_KEYS, tool
        assert not (set(map(str.lower, summary)) & _SCORE_WORDS), tool
    md = _MD.read_text(encoding="utf-8")
    assert "## Counts (NOT a confusion matrix)" in md
    assert "## Why no score" in md
    assert "| precision |" not in md.lower()
    assert "| recall |" not in md.lower()


def test_delivery_shape_is_url_derived(fact):
    # Every row must agree with the runner's own URL-derived verdict.
    for row in fact["rows"]:
        shape = _delivery_shape(row["url"])
        assert row["fragment_only"] == shape["fragment_only"], row["case_id"]
        assert row["http_path"] == shape["http_path"], row["case_id"]
        assert row["http_query"] == shape["http_query"], row["case_id"]
        assert row["note"] == shape["note"], row["case_id"]
        if row["fragment_only"]:
            assert row["http_query"] == "" and row["http_path"] == "/"
        else:
            assert row["http_query"]
    # ...and that function may not consult a tool-name allowlist to decide
    # reachability: the fact would then be a belief, not a measurement.
    tree = ast.parse(_RUNNER.read_text(encoding="utf-8"))
    fn = next(n for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name == "_delivery_shape")
    tokens = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
    tokens |= {n.value for n in ast.walk(fn)
               if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    for tool in ("dalfox", "nuclei", "xssentinel"):
        assert not any(tool in str(tok).lower() for tok in tokens), tool


def test_denominator_is_not_inflated(fact):
    by_id = {c["id"]: c for c in fact["cases"]}
    assert len(by_id) == 5
    excluded = [c for c in fact["cases"] if not c["in_denominator"]]
    assert [c["id"] for c in excluded] == ["js-dom-search-result"]
    assert excluded[0]["ground_truth"] == "pos-derived"
    assert excluded[0]["answer_key"] is None
    for case in fact["cases"]:
        if case["in_denominator"]:
            assert case["answer_key"] is not None
            assert case["ground_truth"] in ("pos", "neg")
    for row in fact["rows"]:
        case = by_id[row["case_id"]]
        assert row["in_denominator"] == case["in_denominator"]
        assert row["answer_key"] == case["answer_key"]
        if not row["fragment_only"]:
            # A server-reachable positive would create a legal denominator;
            # this table has none, which is WHY it publishes no score.
            assert row["ground_truth"] == "neg"


def test_cases_match_runner_and_answer_key(fact):
    assert fact["cases"] == CASES
    assert fact["answer_key_file"].endswith("data/static/challenges.yml")
    keys = {c["answer_key"] for c in fact["cases"] if c["answer_key"]}
    assert any(k.startswith("localXssChallenge") for k in keys)
    assert any(k.startswith("reflectedXssChallenge") for k in keys)
    assert sum(k.startswith("measured control") for k in keys) == 2
    assert fact["target_app"].startswith("OWASP Juice Shop v20.2.0")
    assert fact["target"] == "http://127.0.0.1:18900"


def test_summary_is_recomputed_from_rows(fact):
    assert set(fact["tools"]) == _TOOLS
    assert len(fact["rows"]) == len(fact["tools"]) * len(fact["cases"]) == 15
    pairs = [(r["tool"], r["case_id"]) for r in fact["rows"]]
    assert len(set(pairs)) == len(pairs)
    for tool in fact["tools"]:
        rows = [r for r in fact["rows"] if r["tool"] == tool]
        s = fact["summary"][tool]
        assert s["cases"] == len(rows)
        assert s["detected"] == sum(bool(r["detected"]) for r in rows)
        assert s["errors"] == sum(bool(r["error"]) for r in rows)
        assert s["wall_s"] == round(sum(r["time_s"] for r in rows), 2)
        assert s["detected_on_fragment"] == sum(
            bool(r["detected"]) and r["fragment_only"] for r in rows)
        assert s["detected_on_server"] == sum(
            bool(r["detected"]) and not r["fragment_only"] for r in rows)
    assert fact["tree"] in fact["tool_versions"]["XSSentinel"]
    assert set(fact["tool_versions"]) == _TOOLS | {"nuclei templates"}


def test_markdown_is_byte_identical_to_rendered_json(fact):
    assert to_markdown(fact) == _MD.read_text(encoding="utf-8")
