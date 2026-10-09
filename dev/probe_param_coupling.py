"""Map the cross-stage coupling left inside _probe_param (Phase 211 round 2).

Round 1 moved the three self-contained tail stages out.  What remains is
the part where every stage reads and rewrites the same handful of locals,
which is exactly why it cannot be cut by eyeballing it.  This script
answers, per stage: which names does it WRITE, which does it READ, and
which of those are also touched by another stage.

Usage:

    python dev/probe_param_coupling.py

Names that are written in one stage and read in a later one are the state
that has to become explicit (a state object or explicit parameters) before
that stage can move.
"""
import ast
import os
import sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "xssentinel", "core", "async_scanner.py")

# Stage boundaries, identified by the leading comment that opens each one.
# Matched by substring so the script survives line drift.
STAGE_MARKERS = [
    ("A L1 probe", "Phase 100: keep this response's headers"),
    ("B1 pre-encode", "Phase 35: structured-param pre-encoding"),
    ("B2 candidates", "Phase 43: multi-corpus cross-context sampling"),
    ("B3 profile", "Phase 37: reflection profile + generative payloads"),
    ("B4 rcdata", "Phase 96: RCDATA breakout surfacing"),
    ("B5 waf bypass", "If WAF detected, prepend"),
    ("C variant loop", "Phase 132: ``return`` on the first confirmed"),
    ("D concat retry", "Phase 166 (sync parity, scanner._try_payload:1112)"),
    ("E position shift", "Phase 37: parameter position shift"),
    ("F tail (moved)", "Phase 211: the three tail stages below moved"),
    ("H L7 + time", "Phase 132: L7 parameter layers"),
]


def stage_of(lineno, starts):
    cur = "(preamble)"
    for name, line in starts:
        if lineno >= line:
            cur = name
    return cur


def main():
    src = open(SRC, encoding="utf-8").read()
    lines = src.splitlines()
    tree = ast.parse(src)

    fn = None
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "_probe_param":
            fn = node
    if fn is None:
        sys.exit("_probe_param not found")

    # Locate stage start lines by scanning the function body's comments.
    starts = []
    for marker in STAGE_MARKERS:
        name, text = marker
        hit = None
        for i in range(fn.lineno - 1, fn.end_lineno):
            if text in lines[i]:
                hit = i + 1
                break
        if hit:
            starts.append((name, hit))
    starts.sort(key=lambda x: x[1])

    writes = defaultdict(set)
    reads = defaultdict(set)

    for node in ast.walk(fn):
        if not isinstance(node, ast.Name):
            continue
        st = stage_of(node.lineno, starts)
        if isinstance(node.ctx, ast.Store):
            writes[st].add(node.id)
        else:
            reads[st].add(node.id)

    print(f"_probe_param: lines {fn.lineno}-{fn.end_lineno} "
          f"({fn.end_lineno - fn.lineno + 1})")
    print(f"stages found: {len(starts)}\n")

    stages = [s[0] for s in starts]
    order = ["(preamble)"] + stages
    all_names = sorted({n for s in order for n in writes[s] | reads[s]})
    shared = sorted(
        n for n in all_names
        if sum(1 for s in order if n in writes[s] or n in reads[s]) > 1
        and not n.startswith("_")
    )

    print("== cross-stage state (candidates for the state object) ==")
    for n in shared:
        w = [s for s in order if n in writes[s]]
        r = [s for s in order if n in reads[s]]
        if not w:
            continue
        print(f"  {n:<18} written={w}  read={r}")

    print("\n== per-stage size (statements) ==")
    bounds = [(s, ln) for s, ln in starts]
    for idx, (name, ln) in enumerate(bounds):
        end = bounds[idx + 1][1] if idx + 1 < len(bounds) else fn.end_lineno
        print(f"  {name:<18} lines {ln}-{end} ({end - ln})")


if __name__ == "__main__":
    main()
