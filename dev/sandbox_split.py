#!/usr/bin/env python3
"""First cut of docs 1.3: split core/sandbox.py into sibling modules.

Why siblings, not a package: the project already uses this shape
(scanner.py + scanner_crawl.py + scanner_layers.py, async_scanner_common.py),
and keeping sandbox.py a module leaves EVERY external import untouched --
including ``benchmark/probe_svg_case.py``'s direct import of the private names
``_SVG_ATTR_CASE, _MATHML_ATTR_CASE``, which a hand-written package
``__init__`` re-export table would silently forget.

Why a common layer: _Parser needs Node/Doc/VOID, which the judging half also
needs. Put them in either half and you get a cycle. Common keeps the graph
one-directional:  sandbox_common <- sandbox_parser <- sandbox

PURE MOVEMENT. If this script ever changes behaviour, it is wrong.
"""
from __future__ import annotations

import ast
import pathlib
import sys
from collections import defaultdict

ROOT = pathlib.Path(__file__).resolve().parent.parent
CORE = ROOT / "xssentinel" / "core"
SRC = CORE / "sandbox.py"
APPLY = "--apply" in sys.argv

COMMON_DOC = '''"""Structures shared by both halves of the sandbox.

Split out of ``core/sandbox.py`` (docs 1.3).  Holds only what both the parser
half and the judging half need, so neither has to import the other.  See
``sandbox.py``'s docstring for what this sandbox models and how its fidelity is
measured against Chromium.
"""

'''

PARSER_DOC = '''"""The tokeniser and tree-builder half of the sandbox.

Split out of ``core/sandbox.py`` (docs 1.3) as a pure move -- nothing here was
rewritten while moving.  Callers keep going through ``sandbox.parse()``.
"""

'''


def analyse(src_text):
    tree = ast.parse(src_text)
    defs, order = {}, []
    for n in tree.body:
        if isinstance(n, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            defs[n.name] = n
            order.append((n.lineno, n.end_lineno, n.name))
        elif isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    defs[t.id] = n
                    order.append((n.lineno, n.end_lineno, t.id))
    refs = defaultdict(set)
    for name, node in defs.items():
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in defs and sub.id != name:
                refs[name].add(sub.id)
    used_by = defaultdict(set)
    for a, ts in refs.items():
        for b in ts:
            used_by[b].add(a)
    header_end = min(s for s, _e, _n in order) - 1
    # Where the leading module docstring ends, so new files can start their own
    # docstring and still put `from __future__` first (SyntaxError otherwise),
    # while keeping the optional-import block that sits between them.
    doc_end = 0
    for n in tree.body:
        if (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)
                and isinstance(n.value.value, str)):
            doc_end = n.end_lineno
        else:
            break
    return tree, defs, order, refs, used_by, header_end, doc_end


def main() -> int:
    lines = SRC.read_text(encoding="utf-8").splitlines()
    _tree, defs, order, refs, used_by, header_end, doc_end = analyse("\n".join(lines))
    header = "\n".join(lines[:header_end]).rstrip() + "\n"
    # new files get their own docstring, so they start AFTER the original one
    header_body = "\n".join(lines[doc_end:header_end]).strip() + "\n"

    # closure of _Parser
    closure, stack = set(), ["_Parser"]
    while stack:
        n = stack.pop()
        if n in closure:
            continue
        closure.add(n)
        stack.extend(refs.get(n, ()))

    # A name belongs in COMMON only if the remaining (judging) half needs it.
    # Being used by a *public wrapper* (parse() -> _Parser) does NOT make a name
    # common -- that direction is solved by an import, not by hoisting. So seed
    # from names the remainder actually references, then take closure over the
    # seed's dependencies (pulling NO_ESCAPE_TEXT along with serialize_text,
    # which is what attempt #1 got wrong and attempt #2 over-corrected).
    remaining = {n for n in defs if n not in closure}
    seed = {n for n in closure if used_by.get(n, set()) & remaining}
    seed.discard("_Parser")
    seed |= {"Node", "Doc", "VOID", "MATHML_TEXT_INTEGRATION",
             "SVG_HTML_INTEGRATION", "serialize_text"}
    common_set = set(seed)
    changed = True
    while changed:
        changed = False
        for n in list(common_set):
            for d in refs.get(n, ()):
                if d not in common_set:
                    common_set.add(d)
                    changed = True
    parser_set = (closure - common_set) | {"_Parser"}

    # Hard self-checks.
    bad = {(n, d) for n in common_set for d in refs.get(n, ()) if d in parser_set}
    if bad:
        print("ABORT: common -> parser reverse dependency:", sorted(bad)[:10])
        return 1
    if len(parser_set) < 10:
        print("ABORT: parser partition collapsed (%d names) -- not a split" % len(parser_set))
        return 1

    def ownership():
        """Attach each top-level definition to the comment block above it.

        Ripping definitions out by their own line span alone silently dropped
        362 lines of `#:` attribute docs -- the ones saying WHERE a table came
        from ("MEASURED, not recalled from the spec",
        "benchmark/probe_breakout.py -> results/foreign_breakout.json").  Those
        lines are not decoration; they are the evidence trail that the whole
        project's "verdicts need measurements behind them" stance rests on.
        Every non-code line between two definitions belongs to the one below it.
        """
        owned, prev_end = [], header_end
        for s, e, name in sorted(order):
            lead, i = s, s - 1
            while i > prev_end:
                stripped = lines[i - 1].strip()
                if stripped == "" or stripped.startswith("#"):
                    lead, i = i, i - 1
                else:
                    break
            owned.append((lead, e, name))
            prev_end = e
        return owned

    owned = ownership()

    def render(names):
        out = []
        for lead, end, name in owned:
            if name in names:
                out.extend(lines[lead - 1:end])
                out.append("")
        return "\n".join(out)

    # The rest of sandbox.py keeps the original header, then re-imports the
    # moved names so that EVERY attribute that used to live here is still
    # reachable.  This matters beyond tidiness: benchmark/probe_svg_case.py
    # does `from xssentinel.core.sandbox import _SVG_ATTR_CASE` and
    # benchmark/probe_breakout.py reads sandbox.FOREIGN_BREAK -- neither is
    # referenced by the remainder, so a "what does the rest use?" import list
    # would drop them and break those probes silently.
    reexport = sorted(common_set | parser_set)

    def reexport_block(reason_comment):
        out = ["# Re-exported so every name that used to live in this module is",
               "# still reachable as `sandbox.<name>` -- external callers include",
               "# benchmark/probe_svg_case.py (_SVG_ATTR_CASE, _MATHML_ATTR_CASE)",
               "# and benchmark/probe_breakout.py (FOREIGN_BREAK).",
               "from .sandbox_common import ("]
        for n in reexport:
            if n in common_set:
                out.append("    %s,  %s" % (n, reason_comment))
        out.append(")")
        out.append("from .sandbox_parser import (")
        for n in reexport:
            if n in parser_set:
                out.append("    %s,  %s" % (n, reason_comment))
        out.append(")")
        return "\n".join(out) + "\n\n"

    needed_common = sorted({d for n in parser_set
                            for d in refs.get(n, ())} & common_set)

    REASON = "# noqa: F401  (re-export:外部按 sandbox.<name> 访问)"
    # Everything after the last definition must follow it into sandbox.py --
    # first attempt dropped `if __name__ == "__main__": raise SystemExit(main())`,
    # i.e. the `python -m xssentinel.core.sandbox` CLI, and no test noticed.
    tail_start = max(e for _lead, e, _n in owned)
    tail = "\n".join(lines[tail_start:])
    if tail.strip():
        tail = "\n" + tail.rstrip("\n") + "\n"
    kept_src = (header + "\n" + reexport_block(REASON)
                + render(set(defs) - parser_set - common_set) + tail)

    common_src = COMMON_DOC + header_body + "\n" + render(common_set)
    parser_src = (PARSER_DOC + header_body + "\n"
                  + "from .sandbox_common import (\n"
                  + "".join("    %s,\n" % n for n in needed_common)
                  + ")\n\n"
                  + render(parser_set))

    def linecount(text):
        return len(text.splitlines())

    print("sandbox_common.py : %2d names, %4d lines" % (len(common_set), linecount(common_src)))
    print("sandbox_parser.py : %2d names, %4d lines" % (len(parser_set), linecount(parser_src)))
    print("sandbox.py        : %2d names, %4d lines (was %d)"
          % (len(defs) - len(parser_set) - len(common_set) + len(parser_set) + len(common_set),
             linecount(kept_src), len(lines)))
    print()
    print("common:", ", ".join(sorted(common_set)))
    print()
    print("parser:", ", ".join(sorted(parser_set)))

    if APPLY:
        (CORE / "sandbox_common.py").write_text(common_src, encoding="utf-8")
        (CORE / "sandbox_parser.py").write_text(parser_src, encoding="utf-8")
        SRC.write_text(kept_src, encoding="utf-8")
        print("\nWRITTEN.  Roll back with:  git checkout -- xssentinel/core/sandbox.py"
              " && rm xssentinel/core/sandbox_common.py xssentinel/core/sandbox_parser.py")
    else:
        print("\nDRY RUN -- pass --apply to write")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
