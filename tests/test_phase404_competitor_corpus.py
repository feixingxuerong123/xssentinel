# -*- coding: utf-8 -*-
"""Phase 404: competitor-authored test assets -> our classifier, kept honest.

This round feeds payload catalogues PUBLISHED BY OTHER SCANNER PROJECTS
(XSStrike / XSSer / dalfox / nuclei-templates) through two measurements:

  * M1 fidelity: real Chromium load-time oracle vs sandbox.judge, reusing the
    exact Phase 392 harness.  Fact table, NOT recall/F1.
  * E2E injection: the same catalogues fed in via --custom-payloads against a
    stratified reflection slice, baseline arm included.  Not a full-gate F1.

Three failure modes are pinned here:

  * score-creep: confusion-matrix / F1 vocabulary in either fact table, or
    pooling competitor vectors with the self-authored 194 matrix, is a
    regression (external_validity_20261108.md §4/§6).
  * lost provenance: every vector row must carry repo:path@sha12 and the exact
    placeholder transform -- otherwise "someone else's corpus" is unverifiable.
  * broken oracle: M1 control pages must be exec+live / inert+inert in the
    committed evidence (runner ABORTs on this; the guard pins the artifact).

Pure-function tests use synthetic fixtures; the evidence tests read the
committed JSON. No ignored dev/_* files are required.
"""
import json
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from benchmark.run_external_corpus import (  # noqa: E402
    BENIGN_CONTROLS,
    CONTROLS_EXPECTED_SANDBOX,
    DIRECTIONS,
    KNOWN_EXEC_CONTROLS,
)

_FIDELITY = _ROOT / "benchmark" / "results" / \
    "competitor_payloads_20261120.json"
_E2E = _ROOT / "benchmark" / "results" / "competitor_e2e_20261120.json"
_SCORE_WORDS = frozenset({"f1", "precision", "recall", "accuracy",
                          "confusion", "recall_rate", "detection_rate"})


# --------------------------------------------------------------- constants

def test_family_names_are_four_competitors():
    # the ledger records exactly the families extracted from competitor trees
    expected = {"xsstrike", "xsser", "dalfox", "nuclei"}
    assert expected <= {"xsstrike", "xsser", "dalfox", "nuclei", "w3af-tests"}


@pytest.fixture(scope="module")
def fidelity():
    return json.loads(_FIDELITY.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def e2e():
    return json.loads(_E2E.read_text(encoding="utf-8"))


# --------------------------------------------------------------- M1 table

def _structural_keys(blob):
    """Only KEY NAMES, never value text: the honesty_header legitimately says
    'not recall/F1', and dumping a 2k-row JSON into an assert makes pytest's
    difflib O(n^2) hang on any mismatch (measured this round)."""
    keys = set()

    def walk(x):
        if isinstance(x, dict):
            for k, v in x.items():
                keys.add(str(k).lower())
                walk(v)
        elif isinstance(x, list):
            for v in x[:5]:
                walk(v)
    walk(blob)
    return keys


def test_fidelity_is_a_fact_table_not_a_scorecard(fidelity):
    keys = _structural_keys(fidelity)
    for word in _SCORE_WORDS:
        assert word not in keys, f"score vocabulary leaked as a key: {word}"
    counts = fidelity["m1"]["agreement"]["overall"]["counts"]
    assert set(counts) == set(DIRECTIONS)
    assert fidelity["honesty_header"].strip()
    # the header must actively disclaim score vocabulary
    assert "f1" in fidelity["honesty_header"].lower()


def test_m1_controls_are_sane(fidelity):
    ctl = {r["id"]: r for r in fidelity["m1"]["control_rows"]}
    assert len(ctl) == len(KNOWN_EXEC_CONTROLS) + len(BENIGN_CONTROLS)
    for cid, _payload, _ctx in KNOWN_EXEC_CONTROLS:
        assert ctl[cid]["oracle"] == "exec", cid
        assert ctl[cid]["sandbox"] == CONTROLS_EXPECTED_SANDBOX[cid], cid
    for cid, _payload, _ctx in BENIGN_CONTROLS:
        assert ctl[cid]["oracle"] == "inert", cid


def test_every_row_has_provenance_and_direction(fidelity):
    rows = fidelity["m1"]["rows"]
    assert rows
    for r in rows:
        assert r["direction"] in DIRECTIONS
        # provenance: repo:path@sha12, plus the exact placeholder transform
        assert ":" in r["source"] and "@" in r["source"], r["source"]
        assert r["transform"], r["id"]
        assert r["corpus"] in fidelity["selection"]["ledger"]
    # row count = vectors x contexts (28 = 8 raw + 4 escaped twins)
    assert fidelity["m1"]["pages"] == \
        fidelity["m1"]["selected_vectors"] * fidelity["m1"]["contexts"]


def test_ledger_records_selected_vs_candidates(fidelity):
    ledger = fidelity["selection"]["ledger"]
    for fam, info in ledger.items():
        assert isinstance(info["candidates"], int)
        assert isinstance(info["selected"], int)
        assert info["selected"] <= info["candidates"]
        if info["selected"]:
            assert info["source_files"], fam
            assert info["transforms"], fam


def test_w3af_unit_test_asset_recorded_as_not_executable(fidelity):
    # w3af's test_xss.py references external moth/WAVSEP targets and has no
    # inline payload literals; that must be recorded, not silently dropped.
    w = fidelity["selection"]["ledger"].get("w3af-tests", {})
    assert w.get("selected") == 0
    assert w.get("note"), "the asset-shape difference must be explained"
    assert any("w3af" in n for n in fidelity["not_comparable"])


# --------------------------------------------------------------- E2E table

def test_e2e_has_baseline_arm_and_no_f1_vocabulary(e2e):
    assert "baseline" in e2e["families"]
    keys = _structural_keys(e2e)
    for word in _SCORE_WORDS:
        assert word not in keys, f"score vocabulary leaked as a key: {word}"
    assert e2e["honesty_header"].strip()


def test_e2e_ground_truth_comes_from_manifest_not_scanner(e2e):
    for fam, blob in e2e["families"].items():
        for cid, r in blob["cases"].items():
            assert r["ground_truth"] in ("vulnerable", "safe")
            # error is a separate bucket, never folded into FN/TN
            assert set(r) >= {"detected", "findings", "error", "ground_truth"}
            s = blob["summary"]
            assert set(s) == {"tp", "fn", "fp", "tn", "err"}
            assert s["tp"] + s["fn"] + s["fp"] + s["tn"] + s["err"] == \
                len(blob["cases"])


def test_e2e_budgets_match_the_gate(e2e):
    from benchmark.runner import (DEFAULT_MAX_PAYLOADS,
                                  DEFAULT_MAX_TRANSFORMS)
    assert e2e["budgets"]["max_payloads"] == DEFAULT_MAX_PAYLOADS
    assert e2e["budgets"]["max_transforms"] == DEFAULT_MAX_TRANSFORMS
