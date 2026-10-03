#!/usr/bin/env python3
"""Two-part noqa hygiene pass over ``xssentinel/`` (idempotent).

Part 1 -- give every bare ``# noqa: F401`` a reason.
    ``pyproject.toml``'s ``[tool.ruff.lint.per-file-ignores]`` comment claims the
    scanner Mixin imports "are now annotated with inline ``# noqa: F401`` comments
    (with reasons)".  Measured 2026-10-01: 47 F401 suppressions, **40 of them
    bare**.  The config comment asserted a convention the code never followed --
    the same "docs drift ahead of reality" failure this project keeps hitting.
    ``tests/test_noqa_hygiene.py`` keeps it closed from here on.

Part 2 -- strip ``# noqa: BLE001``.
    ``select = ["E", "F", "W"]`` means BLE001 (flake8-blind-except) is never
    evaluated, so those suppressions are dead comments that mislead readers into
    thinking blind-except is being governed.  Any trailing note (``- reaper never
    dies``) is kept as a plain comment; the dead noqa marker is dropped.

Classification rule for part 1 (do NOT simplify to indentation):
    * no ``import`` token on the line -> continuation of a multi-line import;
      it inherits the module-level (Mixin) classification despite being indented
    * indented **and** has ``import`` -> optional-dependency probe
      (``try: import x`` / flag set), where the import itself is the use
    * module level with ``import`` -> Mixin runtime reference
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "xssentinel"

# A bare F401: the suppression is the last thing on the line (only whitespace
# after it).  Anything following it already counts as a reason.
BARE_F401 = re.compile(r"^(?P<head>.*?#\s*noqa:\s*F401)(?P<tail>\s*)$")
# A dead ``noqa: BLE001`` suppression (hash omitted so ruff does not read this
# very line as a real directive) with an optional trailing note after a dash.
DEAD_BLE = re.compile(r"\s*#\s*noqa:\s*BLE001(?:\s*-\s*(?P<note>.*))?\s*$")

MIXIN = "  (Mixin 运行时引用:scanner 由 Mixin 组合,静态分析看不见)"
PROBE = "  (可选依赖可用性探测:导入即使用)"


def classify(line: str) -> str:
    """Return the reason suffix for a bare-F401 line."""
    stripped = line.lstrip()
    if not re.search(r"\bimport\b", stripped):
        return MIXIN
    if line[:1].isspace():
        return PROBE
    return MIXIN


def main() -> int:
    annotated = 0
    stripped = 0
    changed: list[Path] = []

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

            m = BARE_F401.match(body)
            if m:
                body = f"{m.group('head')}{classify(body)}"
                dirty = True
                annotated += 1
            else:
                d = DEAD_BLE.search(body)
                if d:
                    head = body[: d.start()].rstrip()
                    note = (d.group("note") or "").strip()
                    body = f"{head}  # {note}".rstrip() if note else head
                    dirty = True
                    stripped += 1

            out.append(body + eol)
        if dirty:
            path.write_text("".join(out), encoding="utf-8")
            changed.append(path)

    for p in changed:
        print(f"updated {p.relative_to(ROOT)}")
    print(f"\nF401 annotated: {annotated}   dead BLE001 stripped: {stripped}"
          f"   files: {len(changed)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
