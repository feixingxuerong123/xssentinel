# -*- coding: utf-8 -*-
"""Phase 360 mechanical rewrite: give every CLI print an explicit stream.

AST-located, BYTE-offset-accurate insertion of ``file=human()`` into bare
``print(...)`` calls in the three CLI modules.  Byte offsets matter twice
over here: this tree is CRLF with ``core.autocrlf=true`` (writing LF would
produce a whole-file fake diff), and ``ast`` col_offset counts UTF-8 BYTES,
not characters -- an em-dash earlier on the line shifts every later column.
Re-runnable: calls that already name a ``file=`` are skipped.  The real
guarantee is tests/test_phase360_cli_compat.py's AST gate plus e2e cases.
"""
from __future__ import annotations

import ast
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = ["xssentinel/__main__.py", "xssentinel/cli_runner.py",
         "xssentinel/cli_commands.py"]


def line_offsets(data: bytes):
    offs = [0]
    for line in data.splitlines(keepends=True):
        offs.append(offs[-1] + len(line))
    return offs


def main():
    total = 0
    for rel in FILES:
        path = os.path.join(ROOT, rel)
        data = open(path, "rb").read()
        tree = ast.parse(data)
        offs = line_offsets(data)
        edits = []
        for n in ast.walk(tree):
            if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                    and n.func.id == "print"):
                continue
            if any(k.arg == "file" for k in n.keywords):
                continue
            end = offs[n.end_lineno - 1] + n.end_col_offset
            assert data[end - 1:end] == b")", (rel, n.lineno,
                                               data[end - 8:end + 2])
            i = end - 2
            while i >= 0 and data[i:i + 1] in (b" ", b"\t", b"\r", b"\n"):
                i -= 1
            prev = data[i:i + 1]
            if prev == b"(":                    # print()
                ins = b"file=human()"
            elif prev == b",":                  # print(x,)
                ins = b" file=human()"
            else:                               # print(x) / print(x, flush=1)
                ins = b", file=human()"
            edits.append((end - 1, ins, n.lineno))
        for pos, ins, _lineno in sorted(edits, reverse=True):
            data = data[:pos] + ins + data[pos:]
        open(path, "wb").write(data)            # CRLF preserved byte-for-byte
        total += len(edits)
        print("%-34s %3d print(s) rewritten (lines %s)" %
              (rel, len(edits), [e[2] for e in edits]))
    print("total:", total)
    for rel in FILES:
        ast.parse(open(os.path.join(ROOT, rel), "rb").read())
    return 0


if __name__ == "__main__":
    sys.exit(main())
