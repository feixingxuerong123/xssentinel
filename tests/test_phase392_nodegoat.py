# -*- coding: utf-8 -*-
"""Phase 392 / M3: the NodeGoat fact table stays a fact table.

Why this guard exists
---------------------
NodeGoat is the one real third-party APPLICATION this round could run natively
(no Docker / no WSL / Java 8 only / no PHP).  Its answer key here is the
official source (server.js autoescape:false, profile.html render points,
profile.js FIXME + error path, memos.html marked pipeline) AND a real
Chromium load per delivery.  Guarded failure modes:

  * expectation drift: the KEY ids and their expected shapes are pinned, and
    V7 (href javascript:) must stay an activation shape -- it can never
    honestly read ``exec`` on load, and must never be counted as a miss.
  * oracle contamination: a run without the session cookie 'measures' the
    login page; the first run of this round did exactly that and was
    discarded.  The committed evidence must show controls inert AND the
    stored shapes consistent with the source citations.
  * score-creep: third-party tool rows are facts only (Phase 380 rule).

Mutation evidence: ``dev/phase392_mutations.py``.
"""
import json
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from benchmark.run_nodegoat import (  # noqa: E402
    BENIGN,
    KEY,
    RESULT_STEM,
    SEED_PASS,
    SEED_USER,
    to_markdown,
)

_JSON = _ROOT / "benchmark" / "results" / f"{RESULT_STEM}.json"
_MD = _ROOT / "benchmark" / "results" / f"{RESULT_STEM}.md"
_SCORE_WORDS = frozenset({"tp", "fp", "tn", "fn", "f1", "precision",
                          "recall", "accuracy"})


def test_answer_key_is_pinned_to_official_source():
    ids = [k[0] for k in KEY]
    assert len(ids) == len(set(ids)) == 7
    expect = {k[0]: k[5] for k in KEY}
    assert expect["V1-lastname-attr-breakout"] == "exec"
    assert expect["V2-ssn-attr-breakout"] == "exec"
    assert expect["V3-bankacc-attr-breakout"] == "exec"
    assert expect["V4-address-attr-breakout"] == "exec"
    assert expect["V5-updateerror-reflection"] == "exec"
    assert expect["V6-memos-marked"] == "adjudicate"
    assert expect["V7-firstname-href-jsuri"] == "activation-load-inert"
    for _kid, _page, _field, _payload, citation, _expect in KEY:
        assert citation and ("/" in citation or "server.js" in citation)


def test_seed_credentials_come_from_the_official_seed():
    assert SEED_USER == "admin"
    assert SEED_PASS == "Admin_123"
    assert BENIGN["bankRouting"].endswith("#"), \
        "benign profile must pass the bankRouting regex gate or every POST \
takes the error path"


@pytest.fixture(scope="module")
def fact():
    return json.loads(_JSON.read_text(encoding="utf-8"))


def test_verdicts_only_from_oracle_field(fact):
    allowed = {"exec", "inert"}
    rows = {r["id"]: r for r in fact["oracle_rows"]}
    assert set(rows) == {k[0] for k in KEY}
    for kid, r in rows.items():
        assert r["oracle"] in allowed
        assert r["citation"]
    # V7 is an activation shape: load-time Chromium can never see it fire
    assert rows["V7-firstname-href-jsuri"]["oracle"] == "inert"


def test_published_controls_are_inert(fact):
    for c in fact["control_rows"]:
        assert c["oracle"] == "inert", c["id"]


def test_no_score_vocabulary(fact):
    words = set()
    for section in ("oracle_rows", "control_rows"):
        for row in fact[section]:
            words |= {str(k).lower() for k in row}
    assert not (words & _SCORE_WORDS)
    md = _MD.read_text(encoding="utf-8")
    assert "| precision |" not in md.lower()
    assert "| recall |" not in md.lower()


def test_third_party_rows_are_facts_only(fact):
    tools = fact.get("tools")
    if not tools:
        pytest.skip("本轮证据未包含 tools 部分")
    assert "FACT TABLE ONLY" in tools["note"]
    for r in tools["rows"]:
        assert set(r) >= {"tool", "page", "detected", "hits", "seconds",
                          "error"}


def test_md_is_generated_from_the_same_json(fact):
    md = _MD.read_text(encoding="utf-8")
    assert to_markdown(fact) == md
    assert fact["not_comparable"]
    assert any("XSSMaze" in line for line in fact["not_comparable"])
    assert any("memo" in line for line in fact["not_comparable"]), \
        "planted-state disclosure is part of the honesty contract"


def test_planted_state_disclosure_pinned_in_runner_source():
    # The memo row cannot be deleted once inserted, so every future run of
    # this table must keep disclosing the planted state (Phase 381 rule).
    # A committed-evidence check cannot see a future runner drifting, so the
    # disclosure is pinned in the source itself.
    src = (_ROOT / "benchmark" / "run_nodegoat.py").read_text(
        encoding="utf-8")
    assert "本轮向靶场写入 1 条 memo" in src
    assert "状态已披露" in src


def test_engine_findings_if_present_have_no_invented_severity(fact):
    engine = fact.get("engine")
    if not engine:
        pytest.skip("本轮证据未包含 engine 部分")
    assert engine["rc"] == 0
    for f in engine["findings"]:
        assert f["severity"] in ("high", "medium", "low", "critical",
                                 "info", "")
