# -*- coding: utf-8 -*-
"""Phase 381: the per-challenge delivery table stays a FACT TABLE.

Why this guard exists
---------------------
The 2026-11-09 external run covered only 2 of the 9 XSS challenges in the
target's own ``challenges.yml``.  This table measures whether the other 7 can
even be delivered on this deployment.  It must NOT become a scorecard:

  * seven challenges are not seven comparable cases (authenticated writes,
    a hash-route fragment, and a blocked 6-star prerequisite are mixed);
  * a stored string in a JSON field is not a rendered XSS;
  * a row that was never sent must stay ``blocked`` with a reason and never
    enter any denominator.

The most dangerous failure mode here is measurement contamination: an earlier
run persists a payload into the app, and a later run "reads it back" as if it
had just delivered it.  The verdict is therefore locked to THIS request's own
decoded response field; list endpoints and JWT snapshots are supplementary
only.  The ``_carries`` comparison is AST-checked so nobody can quietly turn
it into a constant ``True``.

Mutation evidence: ``dev/phase381_mutations.py`` (8 anchored mutations, each
run against ONE named test node so a red cannot come from another assertion).
"""
import ast
import json
import re
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from benchmark.run_juice_challenges import (  # noqa: E402
    ALREADY_COVERED,
    OFFICIAL_PAYLOAD,
    PLANS,
    SCORING_POLICY,
    to_markdown,
)

_JSON = _ROOT / "benchmark" / "results" / "juice_challenges_20261110.json"
_MD = _ROOT / "benchmark" / "results" / "juice_challenges_20261110.md"
_RUNNER = _ROOT / "benchmark" / "run_juice_challenges.py"

#: The nine official XSS keys, copied from the target's own answer key.
#: Pinned here so the guard needs NO ignored ``dev/_juiceshop`` files (those
#: are gitignored and absent on other machines).
_OFFICIAL_XSS_KEYS = frozenset({
    "restfulXssChallenge", "usernameXssChallenge",
    "persistedXssUserChallenge", "localXssChallenge",
    "httpHeaderXssChallenge", "reflectedXssChallenge",
    "persistedXssFeedbackChallenge", "videoXssChallenge",
    "xssBonusChallenge",
})
_VERDICTS = frozenset({
    "delivered", "accepted_not_reflected", "blocked",
    "fragment_only", "error",
})
_SCORE_WORDS = frozenset({"tp", "fp", "tn", "fn", "f1", "precision",
                          "recall", "accuracy"})


@pytest.fixture(scope="module")
def fact():
    return json.loads(_JSON.read_text(encoding="utf-8"))


def test_scoring_policy_forbids_scores(fact):
    assert fact["scoring_policy"] == SCORING_POLICY
    assert not (set(map(str.lower, fact["counts"])) & _SCORE_WORDS)
    md = _MD.read_text(encoding="utf-8")
    assert "## Counts (NOT a confusion matrix)" in md
    assert "## Why no score" in md
    assert "| precision |" not in md.lower()
    assert "| recall |" not in md.lower()


def test_cases_come_from_official_answer_key(fact):
    rows = fact["rows"]
    keys = {r["key"] for r in rows}
    assert len(rows) == len(keys) == 7
    assert keys | set(fact["already_covered"]) == _OFFICIAL_XSS_KEYS
    assert not (keys & set(fact["already_covered"]))
    assert set(fact["already_covered"]) == set(ALREADY_COVERED)
    assert fact["official_xss_challenge_count"] == len(_OFFICIAL_XSS_KEYS) == 9
    assert fact["uncovered_measured"] == len(rows)
    assert {p[0] for p in PLANS} == keys
    assert fact["official_payload"] == OFFICIAL_PAYLOAD
    assert fact["answer_key_file"].endswith("data/static/challenges.yml")
    bonus = fact["bonus_payload_from_answer_key"]
    assert bonus.startswith("<iframe") and bonus.endswith("</iframe>")
    assert "soundcloud" in bonus.lower()


def test_delivery_shape_is_objective(fact):
    for row in fact["rows"]:
        assert row["http_reachable"] == row["delivery_shape"].startswith("http_")
        assert row["verdict"] in _VERDICTS
        assert row["reason"], row["key"]
        assert row["name"] and isinstance(row["difficulty"], int)
        if row["delivery_shape"] == "not_attempted":
            assert row["http_request_sent"] is False
            assert row["request_status"] is None
            assert row["verdict"] == "blocked"
    bonus = next(r for r in fact["rows"] if r["key"] == "xssBonusChallenge")
    assert bonus["delivery_shape"] == "url_fragment"
    assert bonus["http_reachable"] is False
    assert bonus["http_request_sent"] is False
    assert bonus["verdict"] == "fragment_only"


def test_verdict_uses_only_this_requests_response(fact):
    for row in fact["rows"]:
        if row["verdict"] == "delivered":
            assert row["payload_in_response"] is True, row["key"]
            assert row["server_echo_value"] == OFFICIAL_PAYLOAD, row["key"]
            assert 200 <= row["request_status"] < 300, row["key"]
        elif row["verdict"] == "accepted_not_reflected":
            assert row["payload_in_response"] is False, row["key"]
            assert 200 <= row["request_status"] < 300, row["key"]
        elif row["verdict"] == "blocked":
            assert row["http_request_sent"] is False, row["key"]
    # The user-list endpoint holds users written by earlier runs; using it as
    # readback would be contamination, so it must stay out of the evidence.
    user = next(r for r in fact["rows"]
                if r["key"] == "persistedXssUserChallenge")
    assert user["payload_in_view"] is None
    assert "NOT used as readback" in user["note"]
    header = next(r for r in fact["rows"]
                  if r["key"] == "httpHeaderXssChallenge")
    assert header["jwt_snapshot_contains_payload"] in (True, False)


def test_counts_are_recomputed_from_rows(fact):
    recomputed: dict[str, int] = {}
    for row in fact["rows"]:
        recomputed[row["verdict"]] = recomputed.get(row["verdict"], 0) + 1
    assert fact["counts"] == recomputed
    assert sum(fact["counts"].values()) == len(fact["rows"]) == 7
    assert re.fullmatch(r"[0-9a-f]{7,40}", fact["tree"]), (
        "tree must be a real git short hash, so evidence has provenance")


def test_carries_compares_decoded_value():
    """The verdict must come from a decoded field, not a raw substring."""
    tree = ast.parse(_RUNNER.read_text(encoding="utf-8"))
    fns = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    body = ast.unparse(fns["_carries"])
    assert "value == payload" in body
    assert "_json_field(" in body
    assert "json.loads" in ast.unparse(fns["_json_field"])


def test_git_head_refuses_unknown():
    """An unavailable git must ABORT; evidence without provenance is not
    evidence (the sandbox blocks git from a Python child with WinError 5).
    """
    tree = ast.parse(_RUNNER.read_text(encoding="utf-8"))
    fns = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    body = ast.unparse(fns["_git_head"])
    assert 'return "unknown"' not in body
    assert "refusing to publish a fake tree" in body
    assert "RuntimeError" in body


def test_markdown_is_byte_identical_to_rendered_json(fact):
    assert to_markdown(fact) == _MD.read_text(encoding="utf-8")


def test_bonus_cli_is_a_fact_not_a_score(fact):
    bonus = next(r for r in fact["rows"] if r["key"] == "xssBonusChallenge")
    cli = bonus["xssentinel"]
    assert set(cli) == {"url", "rc", "secs", "finding_types", "stdout_head"}
    assert isinstance(cli["finding_types"], list)
    assert "/#/search?q=" in cli["url"]
    assert not (set(cli) & _SCORE_WORDS)
