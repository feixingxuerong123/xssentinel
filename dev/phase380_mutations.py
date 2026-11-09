#!/usr/bin/env python3
"""Phase 380 mutation checks: green -> RED -> green on the FINAL tree.

Seven anchored mutations on the REAL artifacts, each verified with three real
pytest subprocess runs (baseline / mutated / restored) against ONE named test
node -- a red from a different assertion would be a false pass, which is the
"guard idling" failure mode this repo keeps getting bitten by.  All touched
bytes are restored in a ``finally`` block and compared afterwards.

The mutations target the ways a fact table can silently become a scorecard:
a scoring policy that quotes a number, an invented F1 column, a delivery
shape flipped by hand, a tool-name allowlist inside the URL-derived shape
function, an inflated denominator, a dropped official answer key, and a
hand-edited Markdown that no longer matches its JSON.

Usage: .venv/Scripts/python.exe dev/phase380_mutations.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUARD = "tests/test_phase380_juice_cross_tool.py"
JSON_FILE = ROOT / "benchmark" / "results" / "juice_cross_tool_20261110.json"
MD_FILE = ROOT / "benchmark" / "results" / "juice_cross_tool_20261110.md"
RUNNER_FILE = ROOT / "benchmark" / "run_juice_cross_tool.py"
PY = sys.executable


def _mutate_policy(data):
    data["scoring_policy"] = "Scorecard: XSSentinel wins, F1=1.00"


def _mutate_summary_score(data):
    data["summary"]["XSSentinel"]["f1"] = 1.0


def _mutate_fragment(data):
    rows = [r for r in data["rows"]
            if r["tool"] == "XSSentinel" and r["case_id"] == "js-dom-search"]
    assert len(rows) == 1, "ABORT: js-dom-search anchor missing"
    rows[0]["fragment_only"] = False


def _mutate_denominator(data):
    cases = [c for c in data["cases"] if c["id"] == "js-dom-search-result"]
    assert len(cases) == 1, "ABORT: pos-derived case anchor missing"
    cases[0]["in_denominator"] = True


def _mutate_answer_key(data):
    cases = [c for c in data["cases"] if c["id"] == "js-dom-search"]
    assert len(cases) == 1, "ABORT: official challenge anchor missing"
    cases[0]["answer_key"] = None


CASES = [
    ("policy must not promise a score", "test_scoring_policy_forbids_scores",
     "json", _mutate_policy),
    ("summary must have no invented score column",
     "test_summary_has_no_score_columns", "json", _mutate_summary_score),
    ("a row's delivery shape may not be flipped by hand",
     "test_delivery_shape_is_url_derived", "json", _mutate_fragment),
    ("delivery shape may not consult a tool allowlist",
     "test_delivery_shape_is_url_derived", "runner", None),
    ("the supplementary row stays out of the denominator",
     "test_denominator_is_not_inflated", "json", _mutate_denominator),
    ("official answer keys may not disappear",
     "test_cases_match_runner_and_answer_key", "json", _mutate_answer_key),
    ("markdown must be rendered from the json",
     "test_markdown_is_byte_identical_to_rendered_json", "md", None),
]

MD_ANCHOR = "## Counts (NOT a confusion matrix)"
MD_MUTATED = "## Counts (a confusion matrix)"
RUNNER_ANCHOR = "    parts = urlsplit(url)\n"
RUNNER_MUTATED = ("    parts = urlsplit(url)\n"
                  '    _tool_allowlist = {"dalfox", "nuclei"}\n')


def _run(node: str):
    env = dict(os.environ,
               PYTHONDONTWRITEBYTECODE="1",
               NO_PROXY="127.0.0.1,localhost",
               no_proxy="127.0.0.1,localhost")
    proc = subprocess.run(
        [PY, "-m", "pytest", "-q", "--no-header", f"{GUARD}::{node}"],
        cwd=str(ROOT), capture_output=True, text=True, timeout=300, env=env)
    return proc.returncode, (proc.stdout + proc.stderr)[-400:]


def _write_mutated(kind: str, mutate, originals: dict):
    if kind == "json":
        data = json.loads(originals["json"])
        mutate(data)
        JSON_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                             encoding="utf-8")
    elif kind == "md":
        text = originals["md"]
        if text.count(MD_ANCHOR) != 1:
            raise AssertionError("ABORT: md anchor not unique")
        MD_FILE.write_text(text.replace(MD_ANCHOR, MD_MUTATED, 1),
                           encoding="utf-8")
    elif kind == "runner":
        text = originals["runner"]
        if text.count(RUNNER_ANCHOR) != 1:
            raise AssertionError("ABORT: runner anchor not unique")
        RUNNER_FILE.write_text(text.replace(RUNNER_ANCHOR, RUNNER_MUTATED, 1),
                               encoding="utf-8")
    else:
        raise AssertionError(f"ABORT: unknown kind {kind}")


def _restore(originals: dict):
    JSON_FILE.write_text(originals["json"], encoding="utf-8")
    MD_FILE.write_text(originals["md"], encoding="utf-8")
    RUNNER_FILE.write_text(originals["runner"], encoding="utf-8")


def main() -> int:
    originals = {
        "json": JSON_FILE.read_text(encoding="utf-8"),
        "md": MD_FILE.read_text(encoding="utf-8"),
        "runner": RUNNER_FILE.read_text(encoding="utf-8"),
    }
    canonical = json.dumps(json.loads(originals["json"]), indent=2,
                           ensure_ascii=False)
    if canonical != originals["json"]:
        print("ABORT: json is not in the runner's canonical dump form")
        return 2

    all_ok = True
    for label, node, kind, mutate in CASES:
        base_rc, base_out = _run(node)
        if base_rc != 0:
            print(f"ABORT [{label}]: baseline is not green\n{base_out}")
            return 2
        try:
            _write_mutated(kind, mutate, originals)
            mut_rc, mut_out = _run(node)
        except AssertionError as exc:
            print(f"ABORT [{label}]: {exc}")
            _restore(originals)
            return 2
        finally:
            _restore(originals)
        rest_rc, rest_out = _run(node)
        ok = mut_rc != 0 and rest_rc == 0
        all_ok = all_ok and ok
        print(f"[{'PASS' if ok else 'FAIL'}] {label}: "
              f"baseline rc={base_rc}, mutated rc={mut_rc}, "
              f"restored rc={rest_rc}")
        if not ok:
            print(f"  mutated tail: {mut_out[-300:]}")
            print(f"  restored tail: {rest_out[-300:]}")

    if (JSON_FILE.read_text(encoding="utf-8") != originals["json"]
            or MD_FILE.read_text(encoding="utf-8") != originals["md"]
            or RUNNER_FILE.read_text(encoding="utf-8") != originals["runner"]):
        print("ABORT: artifacts were not restored byte-for-byte")
        return 2
    print(f"\nPhase 380 mutations: {len(CASES)} cases, "
          f"{'ALL PASS' if all_ok else 'FAILURES PRESENT'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
