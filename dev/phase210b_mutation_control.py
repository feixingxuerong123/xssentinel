"""Phase 210b mutation control: are the new guards load-bearing?

Four mutations, one per decision this round added:

  M1  redirect_xss._statement_end -> back to the fixed 200-char tail window
  M2  redirect_xss mask loop      -> mask only the current sink span
  M3  content_layers trusted-types-> drop the script-document filter
  M4  client_layers framework     -> drop the script-document demotion

Each must turn at least one test RED.  A guard that stays green with the
fix removed is not a guard (dev/_MUTATION_CONTROL_LESSON.md: the first
attempt here "passed" because the anchor never matched and the run used
the original code).  So this script aborts loudly when an anchor is
missing, and verifies byte-identical restore instead of trusting a backup.

Exit 0 only when: baseline green, every mutation red, every restore green,
and every file byte-identical to what it read.
"""
from __future__ import annotations

import subprocess
import sys

FILES = {
    "redirect": "xssentinel/core/redirect_xss.py",
    "content": "xssentinel/core/layers/content_layers.py",
    "client": "xssentinel/core/layers/client_layers.py",
    "advanced": "xssentinel/core/advanced_layers.py",
}

TESTS = {
    "redirect": ["tests/test_phase210_redirect_selfsource.py"],
    "content": ["tests/test_phase210b_script_documents.py"],
    "client": ["tests/test_phase210b_script_documents.py"],
    "advanced": ["tests/test_phase210b_script_documents.py"],
}

# (file key, anchor lines, replacement lines, what it proves)
MUTATIONS = [
    ("advanced",
     ['        content_type = next((v for k, v in _hdrs.items()',
      '                             if k.lower() == "content-type"), "")'],
     ['        content_type = _hdrs.get("Content-Type", "")  # MUTATED M5'],
     "M5 header-case-insensitive lookup"),
] + [
    ("redirect",
     ['    limit = min(len(block), m.end() + _JUDGMENT_WINDOW)',
      '    if m.group(0).rstrip().endswith("("):'],
     ['    limit = min(len(block), m.end() + _JUDGMENT_WINDOW)',
      '    return limit  # MUTATED M1: statement bound removed',
      '    if False:'],
     "M1 statement bound"),
    ("redirect",
     ['            for s, e in spans:',
      '                for i in range(max(s, start) - start, min(e, end) - start):',
      '                    if 0 <= i < len(chars):',
      '                        chars[i] = " "'],
     ['            s, e = spans[matches.index(m)]  # MUTATED M2: current sink only',
      '            for i in range(max(s, start) - start, min(e, end) - start):',
      '                if 0 <= i < len(chars):',
      '                    chars[i] = " "'],
     "M2 neighbour masking"),
    ("content",
     ['        candidates = [v for v in result["violations"]',
      '                      if not (_script_doc',
      '                              and v.get("type") == "tt_no_policy")]'],
     ['        candidates = [v for v in result["violations"]  # MUTATED M3',
      '                      if True]'],
     "M3 trusted-types filter"),
    ("client",
     ['            if _script_doc:',
      '                # Phase 210b: the pattern is real'],
     ['            if False:  # MUTATED M4: document kind ignored',
      '                # Phase 210b: the pattern is real'],
     "M4 framework demotion"),
]


def _read(path: str) -> tuple[str, str]:
    with open(path, encoding="utf-8", newline="") as fh:
        raw = fh.read()
    nl = "\r\n" if "\r\n" in raw else "\n"
    return raw, nl


def run(label: str, tests: list) -> int:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", *tests, "-q", "--timeout=180"],
        capture_output=True, text=True, errors="replace")
    tail = "\n".join(proc.stdout.strip().splitlines()[-2:])
    print(f"[{label}] rc={proc.returncode}  {tail}", flush=True)
    return proc.returncode


def main() -> int:
    originals = {k: _read(p) for k, p in FILES.items()}
    results = []

    for key in TESTS:
        if run(f"baseline {key}", TESTS[key]) != 0:
            print(f"ABORT: baseline is not green for {key}")
            return 2

    for key, anchor, repl, label in MUTATIONS:
        path = FILES[key]
        raw, nl = originals[key]
        a = nl.join(anchor)
        r = nl.join(repl)
        if a not in raw:
            print(f"MUTATION ABORTED ({label}): anchor not found in {path}.\n"
                  f"Looking for:\n{a}\nThe source drifted; a mutation run "
                  f"here would silently execute the ORIGINAL code and report "
                  f"green.")
            restore_all(originals)
            return 2
        mutated = raw.replace(a, r, 1)
        if mutated == raw:
            print(f"MUTATION ABORTED ({label}): replacement identical")
            restore_all(originals)
            return 2
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(mutated)
        red = run(f"{label} MUTATED", TESTS[key]) != 0
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(raw)
        green = run(f"{label} restored", TESTS[key]) == 0
        results.append((label, red, green))

    restore_all(originals)
    for key, path in FILES.items():
        now, _ = _read(path)
        if now != originals[key][0]:
            print(f"FAIL: {path} is not byte-identical to what this script read")
            return 2

    failed = [lbl for lbl, red, green in results if not (red and green)]
    for lbl, red, green in results:
        print(f"  {lbl:28s} mutated_red={red} restored_green={green}")
    if failed:
        print(f"RESULT guard_is_load_bearing=False ({failed})")
        return 1
    print("RESULT guard_is_load_bearing=True")
    return 0


def restore_all(originals) -> None:
    for key, path in FILES.items():
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(originals[key][0])


if __name__ == "__main__":
    raise SystemExit(main())
