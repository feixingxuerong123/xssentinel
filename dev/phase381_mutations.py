#!/usr/bin/env python3
"""Phase 381 mutation checks: green -> RED -> green on the FINAL tree.

Eleven anchored mutations on the REAL artifacts, each verified with three
real pytest subprocess runs (baseline / mutated / restored) against ONE named
test node -- a red from a different assertion would be a false pass.  All
touched bytes are restored in a ``finally`` block and compared afterwards.

The mutations target the ways this delivery table can lie: an invented score,
a fake denominator, a verdict promoted without this request's own echo, a
blocked row pretending to have been sent, contaminated readback from an
earlier run, a score smuggled into the CLI fact, a hand-edited Markdown, a
silently fabricated ``tree``, and a decoded-field comparison turned into a
constant True.

Usage: .venv/Scripts/python.exe dev/phase381_mutations.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUARD = "tests/test_phase381_juice_challenges.py"
JSON_FILE = ROOT / "benchmark" / "results" / "juice_challenges_20261110.json"
MD_FILE = ROOT / "benchmark" / "results" / "juice_challenges_20261110.md"
RUNNER_FILE = ROOT / "benchmark" / "run_juice_challenges.py"
PY = sys.executable


def _by_key(data, key):
    rows = [r for r in data["rows"] if r["key"] == key]
    assert len(rows) == 1, f"ABORT: {key} anchor missing"
    return rows[0]


def _m_policy(data):
    data["scoring_policy"] = "Scorecard: F1=1.00, precision=1.00"


def _m_counts_score(data):
    data["counts"]["f1"] = 1.0


def _m_counts_drift(data):
    data["counts"]["delivered"] = 5


def _m_answer_key_count(data):
    data["official_xss_challenge_count"] = 8


def _m_fake_delivered(data):
    row = _by_key(data, "restfulXssChallenge")
    row["payload_in_response"] = False
    row["verdict"] = "delivered"


def _m_fake_sent(data):
    row = _by_key(data, "videoXssChallenge")
    row["http_request_sent"] = True
    row["request_status"] = 200


def _m_contaminated_readback(data):
    row = _by_key(data, "persistedXssUserChallenge")
    row["payload_in_view"] = True
    row["verdict"] = "delivered"


def _m_cli_score(data):
    _by_key(data, "xssBonusChallenge")["xssentinel"]["f1"] = 1.0


MD_ANCHOR = "## Counts (NOT a confusion matrix)"
MD_MUTATED = "## Counts (a confusion matrix)"
RUNNER_FAKE_TREE = (
    '        raise RuntimeError(f"refusing to publish a fake tree: {tree!r}")',
    '        return "unknown"',
)
RUNNER_TRUE_CARRIES = (
    "            return value == payload, _head(value, 160)",
    "            return True, _head(value, 160)",
)

CASES = [
    ("policy must not promise a score", "test_scoring_policy_forbids_scores",
     "json", _m_policy),
    ("counts must have no invented score column",
     "test_scoring_policy_forbids_scores", "json", _m_counts_score),
    ("counts must be recomputed from rows",
     "test_counts_are_recomputed_from_rows", "json", _m_counts_drift),
    ("the nine official keys must not drift",
     "test_cases_come_from_official_answer_key", "json", _m_answer_key_count),
    ("delivered requires THIS request's own echo",
     "test_verdict_uses_only_this_requests_response", "json",
     _m_fake_delivered),
    ("a blocked row must never claim to have been sent",
     "test_delivery_shape_is_objective", "json", _m_fake_sent),
    ("an earlier run's user list may not become readback",
     "test_verdict_uses_only_this_requests_response", "json",
     _m_contaminated_readback),
    ("the CLI fact must not grow a score field",
     "test_bonus_cli_is_a_fact_not_a_score", "json", _m_cli_score),
    ("markdown must be rendered from the json",
     "test_markdown_is_byte_identical_to_rendered_json", "md",
     (MD_ANCHOR, MD_MUTATED)),
    ("an unavailable git must ABORT, not say unknown",
     "test_git_head_refuses_unknown", "runner", RUNNER_FAKE_TREE),
    ("the decoded echo comparison may not become True",
     "test_carries_compares_decoded_value", "runner", RUNNER_TRUE_CARRIES),
]


def _run(node: str):
    env = dict(os.environ,
               PYTHONDONTWRITEBYTECODE="1",
               NO_PROXY="127.0.0.1,localhost",
               no_proxy="127.0.0.1,localhost")
    proc = subprocess.run(
        [PY, "-m", "pytest", "-q", "--no-header", f"{GUARD}::{node}"],
        cwd=str(ROOT), capture_output=True, text=True, timeout=300, env=env)
    return proc.returncode, (proc.stdout + proc.stderr)[-400:]


def _write_mutated(kind: str, payload, originals: dict):
    if kind == "json":
        data = json.loads(originals["json"])
        payload(data)
        JSON_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                             encoding="utf-8")
        return
    text = originals["md" if kind == "md" else "runner"]
    anchor, replacement = payload
    if text.count(anchor) != 1:
        raise AssertionError(f"ABORT: {kind} anchor not unique")
    target = MD_FILE if kind == "md" else RUNNER_FILE
    target.write_text(text.replace(anchor, replacement, 1), encoding="utf-8")


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
    for label, node, kind, payload in CASES:
        base_rc, base_out = _run(node)
        if base_rc != 0:
            print(f"ABORT [{label}]: baseline is not green\n{base_out}")
            return 2
        try:
            _write_mutated(kind, payload, originals)
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
    print(f"\nPhase 381 mutations: {len(CASES)} cases, "
          f"{'ALL PASS' if all_ok else 'FAILURES PRESENT'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
