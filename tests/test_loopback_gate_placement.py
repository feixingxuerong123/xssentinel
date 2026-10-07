"""Static gate: the loopback gate must live on the test that needs loopback.

Invariant this locks
--------------------
A module-level ``pytestmark = pytest.mark.skipif(not SOCKETPAIR_OK, ...)``
skips *every* test in the file when the host's loopback is degraded --
including the tests that never touch the network.  Measured 2026-10-06 on
``test_verify_carriers_live.py``: with ``XSSENTINEL_FORCE_SOCKETPAIR=bad``
all 21 tests skipped, among them the six that pin the paramless-carrier
fallback through a stub.  Those are pure-placement assertions; they pass or
fail without a socket.  A degraded host silently lost them.

The failure mode is the nasty one because it is invisible on a healthy
host: the file reports green either way, and the coverage that disappears
is exactly the coverage nobody re-checks.  It is the same shape as the
pyflakes gate -- "a gate that can skip is not a gate".

It cannot be fixed by waiving the module-level mark per test (the mark
lives on the Module node, and ``skipif`` is evaluated for every item that
inherits it).  The only correct shape is to push the gate down to the
tests with the dependency, which is what this file enforces.

This gate itself is deliberately network-free: it parses source, so it
runs (and fails) on a throttled host too.
"""
from __future__ import annotations

import ast
import os
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS = os.path.join(ROOT, "tests")
CONFTEST = os.path.join(TESTS, "conftest.py")

#: Names whose presence in a module-level gate means "this gate is keyed on
#: loopback health" (as opposed to, say, "skip unless playwright is
#: installed", which is a legitimate module-level gate).
LOOPBACK_NAMES = ("SOCKETPAIR_OK", "loopback_healthy")


def module_level_loopback_gates(source: str):
    """Return ``(lineno, target)`` for every module-level loopback gate.

    A "module-level gate" is an assignment to ``pytestmark`` (or an
    augmented/annotated variant) whose value mentions a loopback-health
    name anywhere inside it -- a bare ``skipif`` or a list of marks.
    """
    tree = ast.parse(source)
    hits = []
    for node in tree.body:
        targets = []
        if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets = (node.targets if isinstance(node, ast.Assign)
                       else [node.target])
        if not targets:
            continue
        if not any(isinstance(t, ast.Name) and t.id == "pytestmark"
                   for t in targets):
            continue
        if _mentions_loopback(node):
            hits.append((node.lineno, "pytestmark"))
    return hits


def _mentions_loopback(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in LOOPBACK_NAMES:
            return True
        # ``not SOCKETPAIR_OK`` inside a stringified condition is not
        # walkable, but nobody writes these gates as strings; if they ever
        # do, the constant check below still catches the name.
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            if any(n in sub.value for n in LOOPBACK_NAMES):
                return True
    return False


def _test_files():
    return sorted(
        os.path.join(TESTS, n)
        for n in os.listdir(TESTS)
        if n.startswith("test_") and n.endswith(".py"))


# ---------------------------------------------------------------------------
# The invariant
# ---------------------------------------------------------------------------

def test_no_module_level_loopback_gate_in_any_test_file():
    """No test file may gate the whole module on loopback health."""
    offenders = []
    for path in _test_files():
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        for lineno, target in module_level_loopback_gates(src):
            offenders.append(f"{os.path.basename(path)}:{lineno} ({target})")
    assert not offenders, (
        "module-level loopback gates skip every test in the file on a "
        "degraded host, including the ones that need no network -- move the "
        "gate down to the tests that use loopback:\n  "
        + "\n  ".join(offenders))


def test_detector_actually_fires_on_a_real_violation():
    """Anti-vacuity: the gate above must be *capable* of failing.

    Worth stating why this exists: the whole point of the invariant is that
    a silent skip looks identical to a pass.  A gate that cannot fail has
    exactly the same problem, one level up.  (The same discipline was
    learned the hard way on the pyflakes gate -- see
    ``test_no_undefined_names.py``.)
    """
    violation = (
        "import pytest\n"
        "from tests.conftest import SOCKETPAIR_OK\n"
        "\n"
        "pytestmark = pytest.mark.skipif(\n"
        "    not SOCKETPAIR_OK, reason='loopback degraded')\n"
        "\n"
        "def test_uses_no_network():\n"
        "    assert True\n"
    )
    # Both shapes: the bare skipif and the list-of-marks form.
    list_form = (
        "import pytest\n"
        "from tests.conftest import SOCKETPAIR_OK, loopback_healthy\n"
        "\n"
        "pytestmark = [\n"
        "    pytest.mark.skipif(not SOCKETPAIR_OK, reason='x'),\n"
        "    pytest.mark.skipif(not loopback_healthy(), reason='y'),\n"
        "]\n"
    )
    with tempfile.TemporaryDirectory() as td:
        p1 = os.path.join(td, "a.py")
        p2 = os.path.join(td, "b.py")
        with open(p1, "w", encoding="utf-8") as fh:
            fh.write(violation)
        with open(p2, "w", encoding="utf-8") as fh:
            fh.write(list_form)
        assert module_level_loopback_gates(violation), (
            "detector missed a bare module-level skipif")
        assert module_level_loopback_gates(list_form), (
            "detector missed the list-of-marks form")
        with open(p1, encoding="utf-8") as fh:
            assert module_level_loopback_gates(fh.read())

    # ...and it must stay quiet on the shape we actually want: a gate
    # hanging off a named marker that tests opt into one at a time.
    good = (
        "import pytest\n"
        "from tests.conftest import SOCKETPAIR_OK\n"
        "\n"
        "requires_loopback = pytest.mark.skipif(\n"
        "    not SOCKETPAIR_OK, reason='loopback degraded')\n"
        "\n"
        "@requires_loopback\n"
        "def test_x():\n"
        "    assert True\n"
    )
    assert not module_level_loopback_gates(good), (
        "a per-test marker must not be mistaken for a module-level gate")


# ---------------------------------------------------------------------------
# The machinery the invariant depends on
# ---------------------------------------------------------------------------

def test_no_loopback_marker_is_registered():
    """``@pytest.mark.no_loopback`` must be a registered marker.

    An unregistered marker is only a warning, so a typo would make the
    waiver vanish silently -- and the marker is how a test declares "I
    make no network call", which is the claim the invariant rests on.
    """
    with open(CONFTEST, encoding="utf-8") as fh:
        src = fh.read()
    assert '"no_loopback:' in src or "'no_loopback:" in src, (
        "tests/conftest.py no longer registers the no_loopback marker in "
        "pytest_configure(); @pytest.mark.no_loopback would become a "
        "silently ignored typo")


def test_socketpair_probe_can_be_forced(monkeypatch):
    """The gate is only trustworthy if it can be exercised both ways.

    ``XSSENTINEL_FORCE_SOCKETPAIR`` is what makes the difference between
    "the suite is green" and "the suite is green because everything
    skipped" visible.  On a healthy host the forced-bad run is the only
    way to see what a degraded host would lose.
    """
    import importlib

    conftest = importlib.import_module("tests.conftest")
    probe = conftest._probe_socketpair
    monkeypatch.setenv("XSSENTINEL_FORCE_SOCKETPAIR", "bad")
    assert probe() is False, "forced-bad must make the probe report unhealthy"
    monkeypatch.setenv("XSSENTINEL_FORCE_SOCKETPAIR", "good")
    assert probe() is True, "forced-good must make the probe report healthy"


def test_at_least_one_file_uses_the_per_test_gate():
    """The per-test shape must exist somewhere, or the invariant is vacuous.

    If nobody ever wrote ``requires_loopback``/an in-body
    ``loopback_healthy()`` check, "no module-level gate" could be satisfied
    by simply having no gate at all -- which is the opposite of what we
    want on a host that really is degraded.
    """
    users = []
    for path in _test_files():
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        if "loopback_healthy" in src or "requires_loopback" in src:
            users.append(os.path.basename(path))
    assert len(users) >= 5, (
        "only %d test files apply a per-test loopback gate; a module-level "
        "ban with almost no per-test gates means the loopback-dependent "
        "tests are unprotected, not correctly gated: %s" % (len(users), users))


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
