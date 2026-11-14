#!/usr/bin/env python3
"""Phase 392 mutation checks: green -> RED -> green on the final tree.

Eight anchored mutations across the two round runners, each verified with
three real pytest subprocess runs (baseline / mutated / restored) against ONE
named test node -- a red from a different assertion would be a false pass.
All touched bytes are restored in a ``finally`` block and compared afterwards.

The mutations target the ways this round's tables can lie:

  * a classifier verdict promoted/demoted by remapping ``overstated``;
  * a corpus filter that stops rejecting comment lines (sample drift);
  * an aggregation that quietly drops a direction from its own counts;
  * a control page weakened until the oracle contract is vacuous;
  * the honesty header stripped from the rendered markdown;
  * the NodeGoat answer key's activation shape flipped to ``exec``;
  * the official seed user replaced by a juice-shop-shaped guess;
  * the planted-state disclosure deleted from the markdown.

Usage: .venv/Scripts/python.exe dev/phase392_mutations.py
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable

GUARD_A = "tests/test_phase392_external_corpus.py"
RUNNER_A = ROOT / "benchmark" / "run_external_corpus.py"
GUARD_B = "tests/test_phase392_nodegoat.py"
RUNNER_B = ROOT / "benchmark" / "run_nodegoat.py"

CASES = [
    ("activation semantics may not be remapped to over-statement", GUARD_A,
     "test_classify_maps_every_direction", RUNNER_A,
     ('            if row.get("activation"):',
      '            if False:  # mutated')),
    ("corpus filter may not stop rejecting comment lines", GUARD_A,
     "test_keep_vector_filters_prose_and_comments", RUNNER_A,
     ('if s.startswith(("#", ">>>", "credit", "see:", "source:")):',
      'if s.startswith((">>>", "credit", "see:", "source:")):')),
    ("aggregation may not drop a direction from its own counts", GUARD_A,
     "test_aggregate_populations_and_rates", RUNNER_A,
     ('            counts[r["direction"]] += 1',
      '            if r["direction"] != "oracle_error":\n'
      '                counts[r["direction"]] += 1')),
    ("a known-exec control may not be weakened", GUARD_A,
     "test_control_payloads_pinned_in_runner_source", RUNNER_A,
     ('    ("ctl-script-plain", "<script>alert(913)</script>", "text"),',
      '    ("ctl-script-plain", "<p>nothing here</p>", "text"),')),
    ("the honesty header may not be stripped from the markdown", GUARD_A,
     "test_md_is_generated_from_the_same_json", RUNNER_A,
     ('    L.append(data["honesty_header"])', '    L.append("")')),
    ("the activation shape may not be re-labelled exec", GUARD_B,
     "test_answer_key_is_pinned_to_official_source", RUNNER_B,
     ('     "activation-load-inert"),', '     "exec"),')),
    ("the seed user may not be guessed from another app", GUARD_B,
     "test_seed_credentials_come_from_the_official_seed", RUNNER_B,
     ('SEED_USER = "admin"', 'SEED_USER = "admin@nodegoat.com"')),
    ("the planted-state disclosure may not be deleted", GUARD_B,
     "test_planted_state_disclosure_pinned_in_runner_source", RUNNER_B,
     ('            "本轮向靶场写入 1 条 memo(不可删)+ 多次 profile 覆写,'
      '状态已披露",',
      '            "",')),
]


def _run(node_guard: str, node: str):
    env = dict(os.environ,
               PYTHONDONTWRITEBYTECODE="1",
               NO_PROXY="127.0.0.1,localhost",
               no_proxy="127.0.0.1,localhost")
    proc = subprocess.run(
        [PY, "-m", "pytest", "-q", "--no-header", f"{node_guard}::{node}"],
        cwd=str(ROOT), capture_output=True, text=True, timeout=300, env=env)
    return proc.returncode, (proc.stdout + proc.stderr)[-400:]


def _apply(runner: Path, anchor: str, replacement: str):
    text = runner.read_text(encoding="utf-8")
    if text.count(anchor) != 1:
        raise AssertionError(f"ABORT: anchor not unique in {runner.name}: "
                             f"{anchor[:60]!r} (count={text.count(anchor)})")
    runner.write_text(text.replace(anchor, replacement, 1), encoding="utf-8")


def main() -> int:
    originals = {str(r): r.read_text(encoding="utf-8")
                 for r in {c[3] for c in CASES}}
    all_ok = True
    for label, guard, node, runner, (anchor, replacement) in CASES:
        base_rc, base_out = _run(guard, node)
        if base_rc != 0:
            print(f"ABORT [{label}]: baseline is not green\n{base_out}")
            return 2
        try:
            _apply(runner, anchor, replacement)
            mut_rc, mut_out = _run(guard, node)
        except AssertionError as exc:
            print(f"ABORT [{label}]: {exc}")
            return 2
        finally:
            runner.write_text(originals[str(runner)], encoding="utf-8")
        rest_rc, rest_out = _run(guard, node)
        ok = mut_rc != 0 and rest_rc == 0
        all_ok = all_ok and ok
        print(f"[{'PASS' if ok else 'FAIL'}] {label}: "
              f"baseline rc={base_rc}, mutated rc={mut_rc}, "
              f"restored rc={rest_rc}")
        if not ok:
            print(f"  mutated tail: {mut_out[-300:]}")
            print(f"  restored tail: {rest_out[-300:]}")

    for r, before in originals.items():
        if Path(r).read_text(encoding="utf-8") != before:
            print(f"ABORT: {r} was not restored byte-for-byte")
            return 2
    print(f"\nPhase 392 mutations: {len(CASES)} cases, "
          f"{'ALL PASS' if all_ok else 'FAILURES PRESENT'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
