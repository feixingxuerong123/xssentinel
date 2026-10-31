# -*- coding: utf-8 -*-
"""Phase 347: a silent ``except Exception: pass`` may not spread.

Why this file exists
--------------------
The project already says the important thing about swallowed exceptions, in
``verifier.py``: *"a gate that throws silently is a gate that is off"*.  It
applies that rule in exactly one place -- ``SANDBOX_GATE_ERRORS`` is asserted
empty by ``tests/test_sandbox_gate.py`` -- and nowhere else.  Measured with an
AST walk (not grep: ``except Exception: pass`` on one line is invisible to
``grep -A1``): **110 broad swallows across 34 files**, 17 of them in
``dom_engine.py``.

Not all 110 are wrong.  Plenty are legitimate best-effort paths (a breaker
that cannot record, a coverage counter that must not break a scan).  The
problem is that nothing distinguishes "legitimate best-effort" from "the layer
silently stopped running", and the second one is how a scan reports zero
findings for a target it never examined.

So this is a ratchet, not a ban: the current count per file is the ceiling,
and the ceiling only moves down.  No big-bang refactor is asked for -- fix one
when you touch it, and lower the number in the same commit.

Why exact match instead of "at most"
------------------------------------
A ceiling that stays above reality stops measuring anything: fix five
swallows, leave the number at seventeen, and five new ones fit back in with no
alarm.  That is the same "budget raised until it can never fire" shape
``test_architecture_scale.py`` guards.  Exact match makes every change
deliberate in both directions -- growth is a regression, shrinkage is progress
that has to be locked in by editing one integer.

The detector is tested on snippets before it is trusted on the tree: a guard
that stops recognising what it guards passes forever.
"""
import ast
import os

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PKG = os.path.join(_ROOT, "xssentinel")

#: repo-relative path -> number of broad swallows, measured 2026-11-01.
#: This number may go down.  It may not go up, and it may not stay put while
#: the file changes -- see the module docstring.
CEILINGS = {
    "xssentinel/core/dom_engine.py": 17,
    "xssentinel/core/verifier.py": 10,
    "xssentinel/cli_runner.py": 8,
    "xssentinel/core/passive_proxy.py": 8,
    "xssentinel/cli_commands.py": 6,
    "xssentinel/core/async_scanner_layers.py": 5,
    "xssentinel/core/requester.py": 5,
    "xssentinel/api/server.py": 4,
    "xssentinel/core/scanner.py": 4,
    "xssentinel/core/spa_crawler.py": 4,
    "xssentinel/api/jobs.py": 3,
    "xssentinel/core/async_scanner_crawl.py": 3,
    "xssentinel/core/graphql_xss.py": 3,
    "xssentinel/core/sri_bypass.py": 3,
    "xssentinel/api/mcp_server.py": 2,
    "xssentinel/core/async_scanner.py": 2,
    "xssentinel/core/oob.py": 2,
    "xssentinel/core/pre_encode.py": 2,
    "xssentinel/core/session.py": 2,
    "xssentinel/core/verify_fix.py": 2,
    "xssentinel/desktop/shell.py": 2,
    "xssentinel/core/advanced_layers.py": 1,
    "xssentinel/core/bypass.py": 1,
    "xssentinel/core/fuzzer.py": 1,
    "xssentinel/core/import_map_xss.py": 1,
    "xssentinel/core/layers/content_layers.py": 1,
    "xssentinel/core/param_miner.py": 1,
    "xssentinel/core/polyglot.py": 1,
    "xssentinel/core/progress.py": 1,
    "xssentinel/core/report_ai.py": 1,
    "xssentinel/core/scanner_crawl.py": 1,
    "xssentinel/core/time_xss.py": 1,
    "xssentinel/core/upload_probe.py": 1,
    "xssentinel/desktop/app.py": 1,
}


# -- the detector ----------------------------------------------------------

_BROAD = ("Exception", "BaseException")


def _is_broad(handler: ast.ExceptHandler) -> bool:
    """Whether this handler catches everything (bare, Exception, BaseException)."""
    if handler.type is None:            # bare `except:`
        return True
    names = []
    if isinstance(handler.type, ast.Name):
        names = [handler.type.id]
    elif isinstance(handler.type, ast.Tuple):
        names = [e.id for e in handler.type.elts if isinstance(e, ast.Name)]
    return any(n in _BROAD for n in names)


def count_swallows(source: str, filename: str = "<snippet>") -> int:
    """Count ``except <broad>: pass`` handlers in ``source``.

    ``except ImportError: pass`` is not counted: a narrow catch around an
    optional dependency is a decision, not a swallowed failure.  Neither is a
    handler that does anything at all, even ``log()`` -- the smell is the
    *silence*, not the breadth alone.
    """
    tree = ast.parse(source, filename)
    n = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and _is_broad(node):
            if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                n += 1
    return n


def _scan_tree() -> dict:
    found = {}
    for dirpath, dirnames, filenames in os.walk(_PKG):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for name in filenames:
            if not name.endswith(".py"):
                continue
            path = os.path.join(dirpath, name)
            with open(path, encoding="utf-8") as fh:
                n = count_swallows(fh.read(), path)
            if n:
                rel = os.path.relpath(path, _ROOT).replace(os.sep, "/")
                found[rel] = n
    return found


# -- the detector is tested before it is trusted --------------------------

def test_detector_counts_a_bare_pass():
    assert count_swallows("try:\n    f()\nexcept Exception:\n    pass\n") == 1


def test_detector_counts_the_one_line_form():
    """The form grep cannot see -- the reason this test uses an AST."""
    assert count_swallows("try:\n    f()\nexcept Exception: pass\n") == 1


def test_detector_counts_bare_except_and_baseexception():
    src = ("try:\n    f()\nexcept:\n    pass\n"
           "try:\n    f()\nexcept BaseException:\n    pass\n")
    assert count_swallows(src) == 2


def test_detector_counts_a_tuple_containing_exception():
    assert count_swallows(
        "try:\n    f()\nexcept (ValueError, Exception):\n    pass\n") == 1


def test_detector_ignores_a_narrow_catch():
    """An optional-dependency guard is a decision, not a swallowed failure."""
    assert count_swallows(
        "try:\n    import x\nexcept ImportError:\n    pass\n") == 0


def test_detector_ignores_a_handler_that_does_something():
    assert count_swallows(
        "try:\n    f()\nexcept Exception:\n    log()\n") == 0


def test_detector_ignores_pass_plus_anything_else():
    assert count_swallows(
        "try:\n    f()\nexcept Exception:\n    pass\n    return None\n") == 0


def test_detector_sees_more_than_one_in_a_file():
    src = ("try:\n    f()\nexcept Exception: pass\n"
           "try:\n    g()\nexcept Exception:\n    pass\n")
    assert count_swallows(src) == 2


# -- the ratchet -----------------------------------------------------------

def test_no_file_exceeds_its_ceiling():
    found = _scan_tree()
    grew = {p: (CEILINGS.get(p, 0), n) for p, n in found.items()
            if n > CEILINGS.get(p, 0)}
    assert not grew, (
        "a new silent `except Exception: pass` appeared -- log it, count it, "
        "or re-raise it:\n  "
        + "\n  ".join(f"{p}: {old} -> {new}" for p, (old, new) in grew.items()))


def test_improvement_is_locked_in():
    """Shrinking is progress, but only if the ceiling comes down with it.

    Otherwise the freed headroom is silently reusable, and the table drifts
    above reality until it measures nothing.
    """
    found = _scan_tree()
    shrank = {p: (CEILINGS[p], found[p]) for p in CEILINGS
              if p in found and found[p] < CEILINGS[p]}
    assert not shrank, (
        "fewer swallows than the ceiling allows -- lower the number in "
        "CEILINGS to lock the improvement in:\n  "
        + "\n  ".join(f"{p}: {old} -> {new}" for p, (old, new) in shrank.items()))


def test_no_unlisted_file_has_swallows():
    """The other direction: a new module must not enter the table's blind spot."""
    found = _scan_tree()
    unlisted = sorted(p for p in found if p not in CEILINGS)
    assert not unlisted, (
        "these files have broad swallows but no ceiling, so nothing measures "
        f"them: {unlisted}")


def test_no_stale_ceiling():
    """A ceiling for a file that no longer swallows anything measures nothing."""
    found = _scan_tree()
    stale = sorted(p for p in CEILINGS if p not in found)
    assert not stale, (
        f"CEILINGS names files with no broad swallows (or no longer present): "
        f"{stale} -- remove the entry")


def test_total_matches_the_table():
    """One number to watch in the output, and it can only go down."""
    found = _scan_tree()
    assert sum(found.values()) == sum(CEILINGS.values())
