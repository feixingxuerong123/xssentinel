"""Phase 401 mutation: prove the adjudication guards are not vacuous.

Three mutations, each baseline-green -> mutated-red -> byte-restored-green:
  1. flip controls_valid True -> False  (guard must refuse to adjudicate)
  2. flip an onstart browser_dialog False -> True (guard must catch it)
  3. flip the source snapshot page_has_script False -> True (premise guard)

All restore by exact bytes; assert anchors exist before mutating.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
PY = _ROOT / ".venv" / "Scripts" / "python.exe"
TEST = "tests/test_phase401_onstart_adjudication.py"
ART = _ROOT / "benchmark" / "results" / "phase401_onstart_level5_adjudication_20261118.json"
SRC = _ROOT / "benchmark" / "results" / "phase401_xssmaze_level5_source_snapshot_20261118.json"


def run() -> int:
    return subprocess.run([str(PY), "-m", "pytest", "-q", TEST],
                          cwd=_ROOT, capture_output=True).returncode


def mutate_json(path: Path, fn) -> bytes:
    original = path.read_bytes()
    data = json.loads(original)
    fn(data)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2),
                    encoding="utf-8")
    return original


def main() -> int:
    ok = True
    for name, path, fn in [
        ("controls_valid -> False", ART,
         lambda d: d.__setitem__("controls_valid", False)),
        ("onstart browser_dialog -> True", ART,
         lambda d: next(r for r in d["rows"]
                        if r["case"] == "phase391_div_onstart")
         .__setitem__("browser_dialog", True)),
        ("level5 page_has_script -> True", SRC,
         lambda d: d["facts"].__setitem__("page_has_script", True)),
    ]:
        orig = path.read_bytes()
        rc0 = run()
        try:
            mutate_json(path, fn)
            rc1 = run()
        finally:
            path.write_bytes(orig)
        rc2 = run()
        assert path.read_bytes() == orig, f"byte restore failed: {name}"
        good = rc0 == 0 and rc1 != 0 and rc2 == 0
        ok = ok and good
        print(f"{name}: base={rc0} mut={rc1} restored={rc2} -> "
              f"{'PASS' if good else 'FAIL'}")
    print("MUTATION CONTRAST:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
