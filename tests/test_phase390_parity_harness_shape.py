# -*- coding: utf-8 -*-
"""Phase 390: pin the parity-full harness correction and its measurement.

The 2026-11-13 note called the 2/194 divergences "behavioural / a sync-side
potential mining FN".  A four-arm probe on the 2.1.0 final tree refuted that:
one was the harness inventing a visible parameter, the other did not
reproduce at all.  These guards keep the verdict tied to the artifact and
keep both engines fed from ONE params source.

Nothing here scans a target: the scanning evidence is the probe artifact,
which is re-read in full.  The gate's shape is checked through its real
``_gate_params`` function, not a copy of the rule.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "benchmark"))

_GATE = _ROOT / "tests" / "test_parity_full_matrix.py"
_ART = (_ROOT / "benchmark" / "results" /
        "phase390_parity_probe_20261114.json")
_MANIFEST = _ROOT / "benchmark" / "manifest.json"
_OPT = _ROOT / "docs" / "OPTIMIZATION.md"
_CHANGELOG = _ROOT / "CHANGELOG.md"

# Measured 2026-11-14 on this manifest.  A new param-less case changes the
# harness input set, so the guard must shout instead of quietly adapting.
_PARAM_LESS_IDS = frozenset({
    "pos-dom-01", "pos-dom-03", "pos-dom-04", "pos-dom-05", "pos-dom-06",
    "pos-pmmine-01", "neg-pmmine-01", "pos-cssi-01", "neg-cssi-01",
    "neg-cssi-02",
})
_ARMS = ("gate_shape", "runner_shape", "adaptive_off", "budget_v2_off")
_SRI = [["sri_missing_script", "medium", "high"]]
_REFLECTED = [["reflected", "high", "high"]]


def _load_gate():
    spec = importlib.util.spec_from_file_location("_p390_gate", _GATE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _cases() -> list:
    return json.loads(_MANIFEST.read_text(encoding="utf-8"))["cases"]


def _art() -> dict:
    return json.loads(_ART.read_text(encoding="utf-8"))


def test_param_less_cases_get_no_synthetic_param():
    """The real runner sends no known params for these cases."""
    gate = _load_gate()
    cases = _cases()
    empty = [c for c in cases if not c.get("param", "q")]
    assert {c["id"] for c in empty} == set(_PARAM_LESS_IDS), (
        "the param-less case set changed -- re-measure the harness shape "
        "before trusting the parity sweep")
    assert len(empty) == 10, len(empty)
    for c in empty:
        assert gate._gate_params(c) == {}, c["id"]


def test_paramful_cases_keep_the_historical_probe_dict():
    """The other 184 cases must be byte-for-byte untouched by the fix."""
    gate = _load_gate()
    cases = _cases()
    paramful = [c for c in cases if c.get("param", "q")]
    assert len(paramful) > 100, (
        "the param-ful set collapsed -- this guard would pass on an empty "
        "set and prove nothing")
    for c in paramful:
        assert gate._gate_params(c) == {c["param"]: "probe"}, c["id"]
    assert len(paramful) + len(_PARAM_LESS_IDS) == len(cases)


def test_both_runners_use_the_same_params_source():
    """AST guard that actually matches something (Phase 222's fake-green)."""
    src = _GATE.read_text(encoding="utf-8")
    tree = ast.parse(src)
    bodies = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.name in ("_run_sync", "_run_async"):
            bodies[node.name] = node
    assert set(bodies) == {"_run_sync", "_run_async"}, (
        "could not find both runners in the gate source")

    for name, fn in bodies.items():
        calls = [n for n in ast.walk(fn)
                 if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Name)
                 and n.func.id == "_gate_params"]
        assert calls, f"{name} no longer calls _gate_params -- the guard "
        "would otherwise match nothing"
        synthetic = [n for n in ast.walk(fn)
                     if isinstance(n, ast.Dict)
                     and any(isinstance(v, ast.Constant)
                             and v.value == "probe" for v in n.values)]
        assert not synthetic, (
            f"{name} builds a probe dict inline again -- the two engines "
            "can drift back to different harness inputs")


def test_fact_table_pins_the_harness_verdict():
    """Re-read the whole four-arm artifact, not a summary somebody wrote."""
    art = _art()
    assert "2.1.0" in art["tree"], art["tree"]
    assert tuple(art["arms"]) == _ARMS, list(art["arms"])
    assert art["budgets"] == {"max_payloads": 14, "max_transforms": 12}

    gate_shape = art["arms"]["gate_shape"]
    assert gate_shape["pos-pmmine-01"]["params"] == {"q": "probe"}
    assert gate_shape["pos-pmmine-01"]["sync"] == []
    assert gate_shape["pos-pmmine-01"]["async"] == _REFLECTED
    assert gate_shape["pos-pmmine-01"]["agree"] is False, (
        "the fake divergence disappeared from the BEFORE arm -- the "
        "harness correction has nothing left to explain")

    for arm in _ARMS:
        rows = art["arms"][arm]
        assert set(rows) == {"pos-sri-01", "pos-pmmine-01"}, (arm, list(rows))
        assert rows["pos-sri-01"]["sync"] == _SRI, arm
        assert rows["pos-sri-01"]["async"] == _SRI, arm
        assert rows["pos-sri-01"]["agree"] is True, arm
        if arm != "gate_shape":
            assert rows["pos-pmmine-01"]["sync"] == _REFLECTED, arm
            assert rows["pos-pmmine-01"]["async"] == _REFLECTED, arm
            assert rows["pos-pmmine-01"]["agree"] is True, arm
    assert art["arms"]["runner_shape"]["pos-pmmine-01"]["params"] == {}


def test_documents_record_the_correction():
    opt = _OPT.read_text(encoding="utf-8")
    changelog = _CHANGELOG.read_text(encoding="utf-8")
    assert "8.21" in opt
    assert "Phase 390" in opt
    assert "Phase 390" in changelog
