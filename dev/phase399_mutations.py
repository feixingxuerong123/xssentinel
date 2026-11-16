#!/usr/bin/env python3
"""Phase 399 mutation check: prove the guard catches the pre-fix behavior.

Three states: baseline (guard green) -> mutated (REST validation removed,
guard must go red) -> restored (byte-identical to baseline, guard green).
Uses the bytes-hash restore discipline from Phase 398's mutations.
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "xssentinel" / "api" / "server.py"
GUARD = "tests/test_phase399_rest_dom_engine_validation.py"
PY = sys.executable

MUTATION = '''    dom_engine = _normalize_dom_engine(body.get("dom_engine", "auto"))
    if dom_engine is None:
        return Response.error(400, "invalid_request",
                              f"dom_engine must be one of {_dom_engine_values()} "
                              f"(got {body.get('dom_engine')!r})")'''
REPLACEMENT = '''    dom_engine = body.get("dom_engine", "auto")  # MUTATED: no validation'''


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def run_guard():
    r = subprocess.run(
        [PY, "-m", "pytest", GUARD, "-q", "--no-header"],
        cwd=ROOT, capture_output=True, text=True,
        env={"PATH": __import__("os").environ.get("PATH", ""),
             "SYSTEMROOT": __import__("os").environ.get("SYSTEMROOT", ""),
             "TEMP": __import__("os").environ.get("TEMP", ""),
             "TMP": __import__("os").environ.get("TMP", "")},
    )
    tail = [line for line in r.stdout.splitlines()
            if "passed" in line or "failed" in line]
    return r.returncode, (tail[-1] if tail else r.stdout[-120:]).strip()


def main():
    original = TARGET.read_bytes()
    h0 = sha(original)
    text = original.decode("utf-8")
    assert MUTATION in text, "MUTATION anchor not found -- ABORT (no blind run)"
    assert REPLACEMENT not in text

    print("[baseline]", run_guard())

    TARGET.write_text(text.replace(MUTATION, REPLACEMENT, 1), encoding="utf-8")
    rc_mut, out_mut = run_guard()
    print("[mutated ]", (rc_mut, out_mut))

    TARGET.write_bytes(original)
    h1 = sha(TARGET.read_bytes())
    assert h0 == h1, "restore byte-hash mismatch"
    rc_res, out_res = run_guard()
    print("[restored]", (rc_res, out_res))

    ok = rc_mut != 0 and rc_res == 0
    print(f"[verdict] {'PASS' if ok else 'FAIL'} "
          f"(baseline rc=0, mutated rc={rc_mut}, restored rc={rc_res})")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
