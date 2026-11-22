"""Phase 400 (headless auth cookies) mutation check: break each fix, prove
the guard goes red, restore byte-for-byte. Run with the project venv.

  .venv/Scripts/python.exe dev/phase400_headless_cookie_mutations.py
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST = "tests/test_phase400_headless_auth_cookies.py"

MUTATIONS = (
    ("context cookie install", "xssentinel/core/verifier.py",
     b"            page.context.add_cookies(browser_cookies)\n",
     b"            pass  # MUTANT: cookies never installed\n", 1),
    ("form carrier", "xssentinel/core/verifier.py",
     b"                    url, form=data or {}, params=params or {},\n",
     b"                    url, data=data or {}, params=params or {},\n", 1),
    ("async call site", "xssentinel/core/async_scanner_verify.py",
     b"cookies=self._verify_cookies()))",
     b"_mutated_cookies()))", 1),
    ("sync call site", "xssentinel/core/scanner.py",
     b"cookies=verifier.session_cookies(self.req.session))",
     b"_mutated_cookies(self.req.session))", 2),
)


def digest(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def pytest_red() -> bool:
    env = dict(os.environ)
    env["NO_PROXY"] = env["no_proxy"] = "127.0.0.1,localhost"
    env["TEMP"] = env["TMP"] = "C:/Users/Administrator/.cache/xssentinel/tmp"
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", TEST],
                       cwd=ROOT, env=env, capture_output=True, text=True)
    return r.returncode != 0


def main() -> None:
    originals = {}
    for _, rel, _, _, _ in MUTATIONS:
        p = ROOT / rel
        originals[rel] = (p.read_bytes(), digest(p))

    baseline = not pytest_red()
    print("baseline:", "GREEN" if baseline else "RED (abort)", flush=True)
    if not baseline:
        raise SystemExit(2)

    results = []
    try:
        for name, rel, old, new, expected in MUTATIONS:
            p = ROOT / rel
            raw = p.read_bytes()
            count = raw.count(old)
            if count != expected:
                raise SystemExit("ABORT: %s pattern count=%d expected=%d"
                                 % (name, count, expected))
            p.write_bytes(raw.replace(old, new))
            red = pytest_red()
            results.append((name, red))
            print("%-28s %s" % (name, "RED (good)" if red else "GREEN (BAD)"),
                  flush=True)
            p.write_bytes(raw)
    finally:
        for rel, (raw, expected) in originals.items():
            p = ROOT / rel
            p.write_bytes(raw)
            assert digest(p) == expected, "restore failed: " + rel

    after = not pytest_red()
    print("restored:", "GREEN" if after else "RED (BAD)", flush=True)
    ok = all(red for _, red in results) and after
    print("VERDICT:", "PASS" if ok else "FAIL")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
