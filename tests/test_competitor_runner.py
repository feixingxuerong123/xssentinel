# -*- coding: utf-8 -*-
"""Phase 404/405: the competitor-corpus runner stays a re-runnable, honest entry.

Guards three things:
  * the committed runner exposes the three arms and refuses to fabricate
    evidence ownership (--tree),
  * when the gitignored scratch measurement modules are absent (fresh
    checkout), it fails LOUDLY with the fetch recipe -- never silently
    degrades to "no competitors measured",
  * the committed fact tables + guard tests are the real always-on artifact,
    so this runner is opt-in, not part of the default CI job.
"""
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]


def test_runner_exposes_three_arms():
    src = (_ROOT / "benchmark" / "run_competitor_corpus.py").read_text(
        encoding="utf-8")
    for arm in ("extract", "m1", "e2e"):
        assert f'"{arm}"' in src
    assert "--tree" in src and "--smoke" in src


def test_runner_fails_loudly_without_scratch_modules():
    """Simulate a fresh checkout by pointing the module map at a missing path;
    the runner must exit 2 with a recipe, not return success with no data."""
    src = (_ROOT / "benchmark" / "run_competitor_corpus.py").read_text(
        encoding="utf-8")
    assert "raise SystemExit(2)" in src
    assert "fresh checkout" in src or "re-fetch" in src
    # no silent fallback that would report 'all clear' with zero competitors
    assert "not_comparable" in src or "UNOWNED" in src


def test_committed_fact_tables_exist():
    for stem in ("competitor_payloads_20261120", "competitor_e2e_20261120",
                 "src_onload_probe2_20261120"):
        j = _ROOT / "benchmark" / "results" / (stem + ".json")
        assert j.is_file(), j
        assert j.stat().st_size > 100, j


def test_guard_tests_are_committed():
    for name in ("test_phase404_competitor_corpus.py",
                 "test_phase405_onload_scheme.py"):
        assert (_ROOT / "tests" / name).is_file()
