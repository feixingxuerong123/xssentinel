#!/usr/bin/env python3
"""Phase 394 mutation checks: green -> RED -> green on the three fixes.

Each mutation is verified with three real pytest subprocess runs (baseline /
mutated / restored) against ONE named test node.  All touched bytes are
restored in a ``finally`` block and compared afterwards.

Usage: .venv/Scripts/python.exe dev/phase394_mutations.py
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable

SANDBOX = ROOT / "xssentinel" / "core" / "sandbox.py"
PARSER = ROOT / "xssentinel" / "core" / "sandbox_parser.py"
REQUESTER = ROOT / "xssentinel" / "core" / "requester.py"

CASES = [
    ("invalid-first-char may not swallow markup again",
     "tests/test_phase394_sandbox_tokenizer.py",
     "test_non_letter_lt_no_longer_swallows_following_markup",
     PARSER,
     ('                self.add_text("<", decode=not self.in_foreign())\n'
      '                self.i += 1\n'
      '                continue',
      '                k = s.find(">", self.i)\n'
      '                if k < 0:\n'
      '                    self.add_text(s[self.i:], decode=not self.in_foreign())\n'
      '                    return Doc(self.root, self.notes)\n'
      '                self.current().append(Node("text", s[self.i:k + 1]))\n'
      '                self.i = k + 1\n'
      '                continue')),
    ("iframe may not lose autofocus focusability again",
     "tests/test_phase394_sandbox_tokenizer.py",
     "test_iframe_is_focusable_for_autofocus_onfocus",
     SANDBOX,
     ('    "legend", "option", "optgroup", "slot",\n'
      '    # Phase 393 corpus, measured: `"autofocus/onfocus=alert(1)//` landing\n'
      '    # autofocus + onfocus on the HOST IFRAME (after a srcdoc="" quote\n'
      '    # breakout the rest of the tag text becomes the iframe\'s own attributes)\n'
      '    # fired in Chromium.  <frame> is deliberately absent -- unmeasured.\n'
      '    "iframe",\n'
      '})',
      '    "legend", "option", "optgroup", "slot",\n'
      '})')),
    ("operator cookies may not be re-asserted",
     "tests/test_phase394_auth_cookie_stickiness.py",
     "test_pinned_cookie_survives_probe_set_cookie",
     REQUESTER,
     ('        self._reassert_pinned_cookies()\n        return resp',
      '        return resp')),
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
    print(f"\nPhase 394 mutations: {len(CASES)} cases, "
          f"{'ALL PASS' if all_ok else 'FAILURES PRESENT'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
