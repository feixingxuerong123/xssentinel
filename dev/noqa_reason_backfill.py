#!/usr/bin/env python3
"""One-shot backfill: give every bare ``# noqa: F401`` in xssentinel/ a reason.

Why this exists
---------------
``pyproject.toml``'s ``[tool.ruff.lint.per-file-ignores]`` comment claims the
scanner Mixin imports "are now annotated with inline ``# noqa: F401`` comments
(with reasons)".  Measured 2026-10-01: 47 F401 suppressions, **36 of them
bare** (no reason at all).  The comment asserted a convention the code never
followed -- the same "docs drift ahead of reality" failure the project keeps
hitting.  This script closes the gap; ``tests/test_noqa_hygiene.py`` keeps it
closed.

Classification rule (do not simplify to indentation)
----------------------------------------------------
* line contains ``import`` and is at module level  -> Mixin runtime reference
* line does **not** contain ``import``             -> continuation line of a
  multi-line import statement; it inherits the classification of the statement
  it belongs to (always a module-level Mixin import here)
* line contains ``import`` and is indented         -> optional-dependency probe
  (``try: import x`` / ``-> flag = True``), the import *is* the use

Both reasons are written in the project's existing dialect, e.g.
``# noqa: F401  (re-export)``.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "xssentinel"

# A bare F401: the suppression is the last thing on the line (only whitespace
# after it).  Anything following it already counts as a reason.
BARE = re.compile(r"^(?P<head>.*?#\s*noqa:\s*F401)(?P<tail>\s*)$")

MIXIN = "  (Mixin 运行时引用:scanner 由 Mixin 组合,静态分析看不见)"
PROBE = "  (可选依赖可用性探测:导入即使用)"


def classify(line: str) -> str:
    """Return the reason suffix for a bare-F401 line."""
    stripped = line.lstrip()
    # A continuation line of a multi-line import has no `import` token of its
    # own -- it must inherit the module-level classification, not look indented.
    if not re.search(r"\bimport\b", stripped):
        return MIXIN
    if line[:1].isspace():
        return PROBE
    return MIXIN


def main() -> int:
    changed: list[Path] = []
    touched = 0
    for path in sorted(PKG.rglob("*.py")):
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError) as exc:  # pragma: no cover
            print(f"SKIP {path}: {exc}", file=sys.stderr)
            continue
        out: list[str] = []
        dirty = False
        for line in text.splitlines(keepends=True):
            body = line.rstrip("\r\n")
            eol = line[len(body):]
            m = BARE.match(body)
            if m:
                body = f"{m.group('head')}{classify(body)}"
                dirty = True
                touched += 1
            out.append(body + eol)
        if dirty:
            path.write_text("".join(out), encoding="utf-8")
            changed.append(path)
    for p in changed:
        print(f"updated {p.relative_to(ROOT)}")
    print(f"\n{touched} bare F401 suppressions annotated across {len(changed)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
