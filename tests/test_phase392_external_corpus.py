# -*- coding: utf-8 -*-
"""Phase 392: the external-corpus fidelity table stays honest.

Why this guard exists
---------------------
This round feeds OTHER projects' vectors (PortSwigger 2026 cheat sheet,
SecLists, PayloadsAllTheThings, OWASP evasion cheat sheet, html5sec) through
the engine's own sandbox classifier and scores the verdicts against a real
Chromium load.  Two failure modes are guarded here:

  * score-creep: agreement percentages on third-party vectors are NOT scanner
    TP/FP/F1.  XSSMaze (official target + official scorer) stays the only F1
    source; any confusion-matrix vocabulary appearing in the fact table is a
    regression (external_validity_20261108.md §4/§6).
  * a broken oracle publishing numbers: the control pages must show
    exec+live (known-exec) and inert+inert (benign) in the committed
    evidence, or the whole measurement is void -- the runner already ABORTs
    on this, and the guard pins the published artifacts to the same rule.

The pure-function tests use synthetic fixtures so the guard needs NO ignored
``dev/_external_corpus`` files (those are gitignored and absent on other
machines).

Mutation evidence: ``dev/phase392_mutations.py``.
"""
import json
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from benchmark.run_external_corpus import (  # noqa: E402
    BENIGN_CONTROLS,
    BENIGN_EXPECTED_SANDBOX,
    CONTROLS_EXPECTED_SANDBOX,
    CORPORA,
    DIRECTIONS,
    ESCAPED_CONTEXTS,
    KNOWN_EXEC_CONTROLS,
    PS_NO_INTERACTION_CAP,
    PS_REQUIRES_INTERACTION_CAP,
    RAW_HOSTS,
    RESULT_STEM,
    aggregate,
    build_page,
    classify,
    keep_vector,
    to_markdown,
)

_JSON = _ROOT / "benchmark" / "results" / f"{RESULT_STEM}.json"
_MD = _ROOT / "benchmark" / "results" / f"{RESULT_STEM}.md"
_SCORE_WORDS = frozenset({"tp", "fp", "tn", "fn", "f1", "precision",
                          "recall", "accuracy", "confusion"})


# ---------------------------------------------------------------- constants

def test_corpus_table_shape():
    ids = [c[0] for c in CORPORA]
    assert len(ids) == len(set(ids)) == 12
    assert all(isinstance(c[3], int) and c[3] > 0 for c in CORPORA)
    assert PS_NO_INTERACTION_CAP == 45 and PS_REQUIRES_INTERACTION_CAP == 20


def test_context_plan_mirrors_sandbox_hosts_vocabulary():
    names = [name for name, _tpl in RAW_HOSTS]
    assert len(names) == 8 and len(set(names)) == 8
    assert set(ESCAPED_CONTEXTS) <= set(names)
    # the vocabulary must stay the one the engine's sandbox uses
    from xssentinel.core.sandbox import HOSTS
    assert set(names) <= set(HOSTS)


def test_controls_pin_the_oracle_contract():
    assert len(KNOWN_EXEC_CONTROLS) == 6
    assert len(BENIGN_CONTROLS) == 3
    for _cid, payload, ctx in KNOWN_EXEC_CONTROLS:
        assert "<" in payload or "onerror" in payload or "onload" in payload
    for _cid, payload, ctx in BENIGN_CONTROLS:
        assert "<svg" not in payload and "onerror" not in payload


# ------------------------------------------------------------ pure functions

def test_keep_vector_filters_prose_and_comments():
    assert keep_vector("<svg onload=alert(1)>")
    assert keep_vector("javascript:alert(1)")
    assert not keep_vector("# credit to rsnake")
    # the ONLY thing keeping this line out is the comment filter -- without
    # it the payload regex would match and the sample would drift
    assert not keep_vector("# <svg onload=alert(1)> banner")
    assert not keep_vector(">>> vectors()")
    assert not keep_vector("just some prose words here")
    assert not keep_vector("x" * 1001)
    assert not keep_vector("   ")
    # short non-payload line
    assert not keep_vector("hello")


def test_control_payloads_pinned_in_runner_source():
    # The committed evidence is frozen: weakening a control's payload in the
    # runner would not move it.  The oracle contract therefore pins the exact
    # canonical payloads in the source (same shape as the AST/source pins the
    # repo uses elsewhere).
    src = (_ROOT / "benchmark" / "run_external_corpus.py").read_text(
        encoding="utf-8")
    for payload in ("<svg onload=alert(911)>", "<img src=x onerror=alert(912)>",
                    "<script>alert(913)</script>",
                    "<input autofocus onfocus=alert(914)>",
                    'srcdoc="&lt;svg onload=alert(915)&gt;"',
                    '"><img src=x onerror=alert(916)>'):
        assert payload in src, payload


def test_build_page_verbatim_and_escaped_twins():
    vec = '<svg onload=alert(1)>'
    raw = build_page(vec, "text", escaped=False)
    assert "<div id=\"c\"><svg onload=alert(1)></div>" in raw
    esc = build_page(vec, "text", escaped=True)
    assert "<svg" not in esc and "&lt;svg" in esc
    # script_dq twin escapes for the JS-string context, not HTML
    js = build_page('x"onerror="y', "script_dq", escaped=True)
    assert 'var a = "x\\"onerror=\\"y";' in js


def test_classify_maps_every_direction():
    base = {"oracle": "exec", "sandbox": "live"}
    assert classify(base) == "agree_live"
    assert classify({"oracle": "exec", "sandbox": "inert"}) == "missed"
    assert classify({"oracle": "inert", "sandbox": "live"}) == "overstated"
    # activation semantics: href-javascript: can never fire a load-time
    # dialog; a live-with-activation verdict on an inert-on-load page is the
    # classifier being honest, not over-stating
    assert classify({"oracle": "inert", "sandbox": "live",
                     "activation": True}) == "activation_inert"
    assert classify({"oracle": "inert", "sandbox": "inert"}) == "agree_inert"
    assert classify({"oracle": "exec", "sandbox": "unknown"}) == \
        "unknown_on_exec"
    assert classify({"oracle": "inert", "sandbox": "unknown"}) == \
        "unknown_on_inert"
    assert classify({"oracle": "inert", "sandbox": "error"}) == \
        "sandbox_error"
    assert classify({"oracle": "nav-timeout", "sandbox": "inert"}) == \
        "oracle_error"


def test_aggregate_populations_and_rates():
    rows = [
        {"corpus": "a", "context": "text", "escaped": False,
         "direction": "agree_live"},
        {"corpus": "a", "context": "text", "escaped": False,
         "direction": "missed"},
        {"corpus": "a", "context": "text", "escaped": True,
         "direction": "agree_inert"},
        {"corpus": "a", "context": "text", "escaped": True,
         "direction": "overstated"},
        {"corpus": "a", "context": "text", "escaped": True,
         "direction": "activation_inert"},
        {"corpus": "b", "context": "text", "escaped": False,
         "direction": "oracle_error"},
    ]
    agg = aggregate(rows)
    ov = agg["overall"]
    assert ov["population"] == 6
    assert ov["oracle_exec_population"] == 2
    assert ov["oracle_inert_population"] == 2
    assert ov["activation_population"] == 1
    assert ov["understatement_rate"] == 0.5
    assert ov["overstatement_rate"] == 0.5
    assert ov["counts"]["oracle_error"] == 1
    assert agg["by_escaped"]["True"]["overstatement_rate"] == 0.5
    assert agg["by_escaped"]["True"]["oracle_exec_population"] == 0
    assert agg["by_escaped"]["True"]["understatement_rate"] is None


# ------------------------------------------------------------ evidence shape

@pytest.fixture(scope="module")
def fact():
    return json.loads(_JSON.read_text(encoding="utf-8"))


def test_evidence_exists_and_has_no_score_vocabulary(fact):
    flat_keys = set()
    for section in ("selection", "m1", "m2"):
        blob = fact.get(section)
        if not isinstance(blob, dict):
            continue
        for k in blob:
            flat_keys.add(str(k).lower())
    assert not (flat_keys & _SCORE_WORDS), \
        "confusion-matrix vocabulary must not appear in the fact table"
    counts = fact["m1"]["agreement"]["overall"]["counts"]
    assert set(counts) == set(DIRECTIONS)


def test_published_controls_are_sane(fact):
    ctl = {r["id"]: r for r in fact["m1"]["control_rows"]}
    for cid, _payload, _ctx in KNOWN_EXEC_CONTROLS:
        assert ctl[cid]["oracle"] == "exec", cid
        assert ctl[cid]["sandbox"] == CONTROLS_EXPECTED_SANDBOX[cid], cid
    for cid, _payload, _ctx in BENIGN_CONTROLS:
        assert ctl[cid]["oracle"] == "inert", cid
        assert ctl[cid]["sandbox"] == BENIGN_EXPECTED_SANDBOX[cid], cid


def test_selection_stats_match_caps(fact):
    stats = {c["corpus"]: c for c in fact["selection"]["corpora"]}
    assert set(stats) == {c[0] for c in CORPORA}
    for corpus_id, _file, _kind, cap in CORPORA:
        assert stats[corpus_id]["selected"] <= cap
    assert stats["ps-sheet-2026"]["selected"] == \
        PS_NO_INTERACTION_CAP + PS_REQUIRES_INTERACTION_CAP
    total = fact["m1"]["selected_vectors"] * fact["m1"]["contexts"]
    assert fact["m1"]["pages"] == total


def test_rows_are_complete_and_directioned(fact):
    rows = fact["m1"]["rows"]
    corpora = {c[0] for c in CORPORA}
    contexts = {n for n, _ in RAW_HOSTS} | set(ESCAPED_CONTEXTS)
    for r in rows:
        assert r["direction"] in DIRECTIONS
        assert r["corpus"] in corpora
        assert r["context"] in contexts
        assert r["oracle"] in ("exec", "inert")
        assert r["sandbox"] in ("live", "inert", "unknown", "error")


def test_md_is_generated_from_the_same_json(fact):
    md = _MD.read_text(encoding="utf-8")
    assert to_markdown(fact) == md
    assert "不与" in md and "XSSMaze" in md
    assert fact["not_comparable"], "must disclose what this table is NOT"
    assert len(fact["not_comparable"]) >= 4


def test_m2_third_party_rows_are_facts_only(fact):
    m2 = fact.get("m2")
    if not m2:
        pytest.skip("本轮证据未包含 m2 部分")
    for tool, blob in m2["tools"].items():
        assert "FACT TABLE ONLY" in blob["note"]
        for r in blob["rows"]:
            assert set(r) >= {"kind", "context", "detected", "hits",
                              "seconds", "rc", "error"}
            assert isinstance(r["detected"], bool)
    eng = m2["engine"]
    assert eng["vuln_twins_total"] >= 8
    assert eng["safe_twins_total"] >= 4


def test_safe_href_twin_defence_is_context_correct():
    # html.escape does NOT neutralise a javascript: URI in href (attribute
    # entities decode before URL parsing) -- the first M2 run's high verdict
    # on the naive-escaped href twin measured exactly that.  A URL-context
    # defence validates the scheme; pin the implementation, not just the row.
    src = (_ROOT / "benchmark" / "run_external_corpus.py").read_text(
        encoding="utf-8")
    assert 'return "#blocked"' in src
    assert "def safe_reflect" in src
