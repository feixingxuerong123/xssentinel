"""Phase 400 mutation: remove the `not headers` guard from the cache WRITE.

baseline (shipped)      -> guard GREEN
mutated  (guard removed)-> guard RED   (poison returns)
restored (bytes restored)-> guard GREEN

Byte-level restore; asserts the exact anchor exists before mutating (Phase 201
lesson: assert-then-mutate, never "run and see").
"""
from __future__ import annotations

import subprocess
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
SRC = _ROOT / "xssentinel" / "core" / "requester.py"
ANCHOR = ("if cache_get and self._cache_size > 0 and not params \\\n"
          "                and not headers and 200 <= resp.status_code < 400:")
MUTATED = ("if cache_get and self._cache_size > 0 and not params \\\n"
           "                and 200 <= resp.status_code < 400:")
PY = _ROOT / ".venv" / "Scripts" / "python.exe"
TEST = "tests/test_phase400_cache_write_headers.py"


def run() -> int:
    return subprocess.run([str(PY), "-m", "pytest", "-q", TEST],
                          cwd=_ROOT, capture_output=True).returncode


def main() -> int:
    original = SRC.read_text(encoding="utf-8")
    assert ANCHOR in original, "ABORT: anchor not found -- refusing to mutate"
    assert original.count(ANCHOR) == 1, "ABORT: anchor not unique"
    rc_base = run()
    print(f"baseline: rc={rc_base} (expect 0)")
    try:
        SRC.write_text(original.replace(ANCHOR, MUTATED, 1), encoding="utf-8")
        rc_mut = run()
        print(f"mutated:  rc={rc_mut} (expect non-zero)")
    finally:
        SRC.write_text(original, encoding="utf-8")
    rc_rest = run()
    print(f"restored: rc={rc_rest} (expect 0)")
    assert SRC.read_text(encoding="utf-8") == original, "byte restore failed"
    ok = rc_base == 0 and rc_mut != 0 and rc_rest == 0
    print("MUTATION CONTRAST:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
