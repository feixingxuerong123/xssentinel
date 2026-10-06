# -*- coding: utf-8 -*-
"""Rule audit: keep-alive handlers must be served by ThreadingHTTPServer.

Phase 200 -- why this file exists as a TEST and not just a rule:

PROJECT.md already codified "lab services must be ThreadingHTTPServer and
the handler must carry a timeout" -- written after benchmark/server.py
wedge in Phase 179.  The rule was never grepped repo-wide, so four
violators of the exact same shape survived it for twenty phases:

  * tests/vuln_server.py::__main__       (the --self-test wedge: held the
    whole suite over its 900s bound twice, then mis-blamed the host's
    loopback);
  * tests/benchmark.py::ensure_server    (same handler, same shape);
  * benchmark/run_benchmark.py           (compare-mode server);
  * benchmark/run_dalfox_only.py         (dalfox comparison server).

This is the "rules are not coverage" failure mode the project already
names for detection layers ("layer coverage != branch coverage",
176g) -- it just happened at the process layer.  A rule nobody greps for
decays into documentation; a test fails the build.  Same lesson as
test_quick_gate_slice.py pinning doc numbers to code numbers (Phase 190).

Static scan, two directions:

  1. every file DECLARING ``protocol_version = "HTTP/1.1"`` must also
     construct ThreadingHTTPServer and must not bare-instantiate
     HTTPServer( -- except lines explicitly tagged ``audit:`` (the
     mutation control in test_vuln_server_concurrency.py deliberately
     rebuilds the OLD shape to prove the starvation test can still fail);
  2. every bare ``= HTTPServer(``` instantiation must not pass a handler
     whose class is declared in an HTTP/1.1 file (cross-file violations
     like ``HTTPServer(..., vuln_server.H)`` -- the tests/benchmark.py
     shape).  String literals (assertions ABOUT the old shape) are not
     instantiations and do not match the assignment form.

Handler timeout is asserted for the two lab services directly (vuln_server.H
has its own behavioural test next door; BenchmarkHandler.timeout is checked
here because no other test owns it).
"""
from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SKIP_DIRS = {".git", "attic", "node_modules", ".venv", "__pycache__",
              ".venv312", ".qoder", ".trae", ".agenthub", ".workbuddy",
              ".mypy_cache", ".ruff_cache", ".pytest_cache", ".benchmarks"}
# Detection pairs RAW and CODE lines: the raw line carries the version
# literal (must be HTTP/1.1), the code line proves the occurrence is real
# code -- a docstring's copy of this very pattern is blanked to spaces and
# fails the second test, which is why quoting us in prose is harmless.
_KEEPALIVE_DECL = re.compile(r'protocol_version\s*=\s*["\']HTTP/1\.1')
# Assignment form: an instantiation, not a mention in a string/assert.
_ASSIGN_INST = re.compile(r"=\s*(?:[\w.]+\.)?HTTPServer\s*\(")
_ANY_INST = re.compile(r"(?<![\w.])HTTPServer\s*\(")


def _py_files() -> list:
    out = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if fn.endswith(".py"):
                out.append(os.path.join(dirpath, fn))
    return out


def _read(path: str) -> list:
    with open(path, encoding="utf-8", errors="ignore") as fh:
        return fh.read().splitlines()


def _code_lines(path: str) -> list:
    """File lines with comments/strings blanked out (tokenize-accurate).

    The audit's own docstring QUOTES both patterns it searches for
    (`protocol_version = "HTTP/1.1"`, `= HTTPServer(`) -- a naive text
    scan flags the auditor itself.  Blanking COMMENT/STRING token spans
    keeps code occurrences (class attributes, assignments) and drops
    prose occurrences, including multi-line docstrings, exactly.
    """
    import io as _io
    import tokenize
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        toks = list(tokenize.tokenize(_io.BytesIO(raw).readline))
    except (tokenize.TokenError, SyntaxError, IndentationError):
        return _read(path)  # unparseable: fall back to raw text
    lines = raw.decode("utf-8", errors="ignore").splitlines(keepends=True)
    blanked = list(lines)
    for tok in toks:
        if tok.type not in (tokenize.COMMENT, tokenize.STRING):
            continue
        (srow, scol), (erow, ecol) = tok.start, tok.end
        for row in range(srow, erow + 1):
            if row > len(blanked):
                break
            line = blanked[row - 1]
            start = scol if row == srow else 0
            end = ecol if row == erow else len(line)
            blanked[row - 1] = line[:start] + " " * (end - start) + line[end:]
    return [ln.rstrip("\n") for ln in blanked]


def _rel(path: str) -> str:
    return os.path.relpath(path, ROOT).replace("\\", "/")


def _keepalive_decl_lines(path: str) -> list:
    """1-based line numbers where REAL code declares HTTP/1.1 keep-alive."""
    raw = _read(path)
    code = _code_lines(path)
    # Raw line must carry the literal AND the `protocol_version` identifier
    # must SURVIVE blanking -- i.e. it is code, not a string/comment
    # mention (in `'protocol_version = "HTTP/1.1"' not in t` the identifier
    # lives inside the string, so the code view has it blanked away).
    return [i for i, (r, c) in enumerate(zip(raw, code), 1)
            if _KEEPALIVE_DECL.search(r) and "protocol_version" in c]


def _keepalive_handler_classes() -> dict:
    """class name -> declaring file (files that declare HTTP/1.1)."""
    classes: dict = {}
    for path in _py_files():
        if not _keepalive_decl_lines(path):
            continue
        for ln in _code_lines(path):
            m = re.match(r"class\s+(\w+)", ln)
            if m:
                classes[m.group(1)] = _rel(path)
    return classes


def test_keepalive_files_use_threading_server():
    """Direction 1: declaring file must construct the threading server."""
    offenders = []
    for path in _py_files():
        raw = _read(path)          # comments visible (audit: tags live here)
        code = _code_lines(path)   # prose invisible (docstrings quoting us)
        decl_lines = _keepalive_decl_lines(path)
        if not decl_lines:
            continue
        rel = _rel(path)
        src = "\n".join(code)
        if "ThreadingHTTPServer" not in src:
            offenders.append(
                f"{rel}: declares HTTP/1.1 keep-alive but never uses "
                f"ThreadingHTTPServer (line {decl_lines[0]}) -- a single "
                f"thread parks in readline on one idle connection and never "
                f"accepts another (the --self-test wedge)")
            continue
        # Bare instantiations in this file: each must be either the
        # threading server (name contains 'Threading') or explicitly tagged
        # as an intentional old-shape reconstruction.  Detection reads the
        # code line; the tag is a COMMENT, so it is read from the raw line.
        for i, ln in enumerate(code, 1):
            if not _ANY_INST.search(ln):
                continue
            if "ThreadingHTTPServer" in ln:
                continue
            if "audit:" in raw[i - 1]:
                continue  # tagged exception (mutation control)
            offenders.append(
                f"{rel}:{i}: bare HTTPServer( in a keep-alive file: "
                f"{raw[i - 1].strip()}")
    assert not offenders, "keep-alive handler / server shape violations:\n" + \
        "\n".join(offenders)


def test_bare_instantiation_never_gets_keepalive_handler():
    """Direction 2: cross-file -- bare HTTPServer( + HTTP/1.1 handler."""
    classes = _keepalive_handler_classes()
    assert classes, "no HTTP/1.1 handler classes found -- audit is broken"
    offenders = []
    for path in _py_files():
        raw = _read(path)
        code = _code_lines(path)
        rel = _rel(path)
        for i, ln in enumerate(code, 1):
            if not _ASSIGN_INST.search(ln):
                continue
            if "ThreadingHTTPServer" in ln:
                continue
            if "audit:" in raw[i - 1]:
                continue
            # Window spans the call (handlers may sit on the next lines).
            window = "\n".join(code[i - 1:i + 3])
            for hname, hfile in classes.items():
                if hname == "H":
                    # bare 'H' is ambiguous across files; require the
                    # vuln_server reference that makes it this H.
                    if "vuln_server" not in window and \
                            "vuln_server" not in rel:
                        continue
                if re.search(rf"\b{hname}\b", window):
                    offenders.append(
                        f"{rel}:{i}: bare HTTPServer( takes keep-alive "
                        f"handler {hname} (declared in {hfile})")
    assert not offenders, "cross-file keep-alive handler violations:\n" + \
        "\n".join(offenders)


def test_lab_service_handlers_carry_timeout():
    """The second half of the PROJECT.md rule, for both lab services.

    vuln_server.H's timeout has a behavioural test beside this file
    (test_vuln_server_concurrency.py::test_handler_carries_socket_timeout);
    BenchmarkHandler is asserted here because nothing else owns it.
    """
    import importlib
    server_mod = importlib.import_module("benchmark.server")
    assert getattr(server_mod.BenchmarkHandler, "timeout", None), (
        "benchmark.server.BenchmarkHandler must set a socket timeout: "
        "without it a half-open connection pins its thread forever")
