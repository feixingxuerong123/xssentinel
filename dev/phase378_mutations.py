#!/usr/bin/env python3
"""Phase 378 mutation checks: green -> RED -> green on the FINAL tree.

Seven anchored mutations on the REAL source, each verified with three real
pytest subprocess runs (baseline / mutated / restored).  Source bytes are
restored in a ``finally`` block.  A missing or duplicated anchor ABORTS
rather than "running it to see" (project rule).

The mutations target the ways an idempotency cache can silently lie:
disabled without saying so, keys that miss identical calls, failures
replayed as if they were verdicts, a poll frozen by a stale hit, a hit
reported as a fresh scan, and the two channels disagreeing.

Usage: .venv/Scripts/python.exe dev/phase378_mutations.py
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "xssentinel" / "api" / "mcp_server.py"
GUARD = "tests/test_phase378_mcp_idempotency.py"
PY = sys.executable

CASES = [
    ("modern-only cache gate must stay open",
     "if modern and name not in _CACHE_EXCLUDED:",
     "if False and name not in _CACHE_EXCLUDED:"),
    ("an identical retry must actually look up the cache",
     "hit = _cache_lookup(cache_key, time.monotonic())",
     "hit = None"),
    ("only SUCCESS may be reused",
     'if cache_key is not None and not result.get("isError"):',
     "if cache_key is not None:"),
    ("a status poll must never be replayed",
     '_CACHE_EXCLUDED = frozenset({"xssentinel_scan_status"})',
     "_CACHE_EXCLUDED = frozenset()"),
    ("schema defaults must be filled before hashing",
     'value = arguments.get(key, prop.get("default"))',
     "value = arguments.get(key)"),
    ("a hit must be reported as a hit",
     "return _stamp_cache(cached_result, True, scope, ttl_ms)",
     "return _stamp_cache(cached_result, False, scope, ttl_ms)"),
    ("text and structuredContent must agree about the hit",
     'out["structuredContent"] = {**structured, **fields}',
     'out["structuredContent"] = structured'),
]


def _run():
    env = dict(os.environ,
               PYTHONDONTWRITEBYTECODE="1",
               NO_PROXY="127.0.0.1,localhost",
               no_proxy="127.0.0.1,localhost")
    proc = subprocess.run(
        [PY, "-m", "pytest", "-q", "--no-header", GUARD],
        cwd=str(ROOT), capture_output=True, text=True, timeout=300,
        env=env)
    return proc.returncode, (proc.stdout + proc.stderr)[-400:]


def main() -> int:
    all_ok = True
    original = SRC.read_bytes()
    text = original.decode("utf-8")
    for label, anchor, mutated in CASES:
        count = text.count(anchor)
        if count != 1:
            print(f"ABORT [{label}]: anchor found {count} times, expected 1")
            return 2
        base_rc, base_out = _run()
        if base_rc != 0:
            print(f"ABORT [{label}]: baseline is not green\n{base_out}")
            return 2
        try:
            SRC.write_bytes(text.replace(anchor, mutated, 1).encode("utf-8"))
            mut_rc, mut_out = _run()
        finally:
            SRC.write_bytes(original)
        rest_rc, rest_out = _run()
        ok = mut_rc != 0 and rest_rc == 0
        all_ok = all_ok and ok
        print(f"[{'PASS' if ok else 'FAIL'}] {label}: "
              f"baseline rc={base_rc}, mutated rc={mut_rc}, "
              f"restored rc={rest_rc}")
        if not ok:
            print(f"  mutated tail: {mut_out[-300:]}")
            print(f"  restored tail: {rest_out[-300:]}")
    print(f"\nPhase 378 mutations: {len(CASES)} cases, "
          f"{'ALL PASS' if all_ok else 'FAILURES PRESENT'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
