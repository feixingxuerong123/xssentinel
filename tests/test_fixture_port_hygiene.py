"""Static gate: a loopback fixture must not gamble on a port number.

What this locks
---------------
`tests/test_xs_leaks.py` went red the moment its file-level loopback gate was
lifted -- two tests asserting the XS-Leak audit stays quiet on an origin that
sends Cross-Origin-Opener-Policy.  The origin *did* send it.  The client was
not talking to that origin:

    netstat -ano | findstr :9002
      TCP  127.0.0.1:9002  LISTENING     15668   <- python, started 2h earlier
      TCP  127.0.0.1:9002  ESTABLISHED           <- our own request

The fixture picked its port with `for port in range(9002, 9014)`.  Two things
combine into a silent disaster:

1. ``http.server.HTTPServer.allow_reuse_address = 1``.  On Windows
   ``SO_REUSEADDR`` lets a second socket bind a port another process is
   ALREADY listening on.  The bind *succeeds*, so ``except OSError: continue``
   never fires -- the fixture believes it owns the port.
2. Nothing then checks that the server answering IS our server.  The squatter
   replies, the fixture never learns, and every assertion is made about the
   wrong origin.

The size of the damage is the point: ``test_surface_found_when_opt_in`` in the
same file *expects* one finding, so it stayed green against the foreign
server -- for the wrong reason -- while the isolation test went red.  One
squatted port produced a false green and a false red simultaneously, and
neither said anything about the port.

The fix is not a better probe, it is no probe at all: bind
``("127.0.0.1", 0)``.  The OS hands back a port nothing else can hold, so
"squatted" is not a state that exists.  Nine fixtures were converted
(2026-10-07); this gate keeps them from drifting back.

A note on stale documentation: an earlier note in this repo records Windows
reserved ports as ``8810-9109`` and tells you to use 18xxx/19xxx instead.
``netsh`` no longer lists that range (measured 2026-10-07: 1101-1200, 5357,
21879+ ...).  The avoidance rule is still the right default, but the specific
numbers were never the mechanism -- SO_REUSEADDR was.  Ephemeral binding
removes the mechanism.

There is no exemption for a "safe-looking" fixed port.  An earlier draft of
this gate allowed the project's 18xxx/19xxx band, on the grounds that a
collision there is merely unlikely; that is the same argument that kept
9002-9013 in place, and the failure is silent either way.  The last in-band
fixture (``PORT = 18878`` in ``test_escape_invariant_fuzz.py``) was converted
with the others, so the rule is now simply: port 0, or nothing.

This gate parses source only, so it runs (and fails) on a throttled host.
"""
from __future__ import annotations

import ast
import os
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS = os.path.join(ROOT, "tests")

LOOPBACK = "127.0.0.1"


def _calls_range(node: ast.AST) -> bool:
    return (isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "range")


def _binds_a_server(node: ast.AST) -> bool:
    """True when the node constructs something named like a server.

    Needed because a ``for ... in range(...)`` over loopback is not always a
    port probe: two files use that shape to POLL for readiness
    (``HTTPConnection("127.0.0.1", port)`` inside ``for _ in range(20)``).
    Those are read loops, not bind loops -- flagging them would be noise, so
    the rule is "a range loop that also constructs a *Server".
    """
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call):
            continue
        fn = sub.func
        name = getattr(fn, "id", None) or getattr(fn, "attr", None) or ""
        if "server" in str(name).lower():
            return True
    return False


def _mentions_loopback(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and sub.value == LOOPBACK:
            return True
    return False


def _loopback_port_literals(tree: ast.AST):
    """(lineno, port) for every literal in the `("127.0.0.1", <int>)` slot.

    Deliberately narrow: only the second element of a 2-tuple whose first
    element is the loopback literal.  Walking a whole Call node for int
    constants picked up `timeout=10`, `range(1, ...)` and every other
    integer that merely shares a line -- 20 false positives on the first
    run, all noise.
    """
    out = []
    for sub in ast.walk(tree):
        if not isinstance(sub, ast.Tuple) or len(sub.elts) < 2:
            continue
        first, second = sub.elts[0], sub.elts[1]
        if (isinstance(first, ast.Constant) and first.value == LOOPBACK
                and isinstance(second, ast.Constant)
                and isinstance(second.value, int)
                and second.value != 0):
            out.append((sub.lineno, second.value))
    return out


def port_hygiene_offenders(source: str):
    """(kind, lineno, detail) for every violation in one module's source."""
    tree = ast.parse(source)
    hits = []
    for node in ast.walk(tree):
        # Rule A: a range() loop that picks a loopback port.
        if isinstance(node, ast.For) and _calls_range(node.iter):
            if _mentions_loopback(node) and _binds_a_server(node):
                hits.append(("port-probe-loop", node.lineno,
                             "range() loop binding a server on 127.0.0.1"))
    # Rule B: any hard-coded non-zero port on 127.0.0.1.  No "safe band":
    # a collision inside 18xxx is silent exactly like one inside 90xx.
    for lineno, port in _loopback_port_literals(tree):
        hits.append(("hard-coded-port", lineno, str(port)))
    # de-duplicate: walking a For node also walks its children.
    seen, uniq = set(), []
    for h in hits:
        if h in seen:
            continue
        seen.add(h)
        uniq.append(h)
    return uniq


def _test_files():
    return sorted(
        os.path.join(TESTS, n)
        for n in os.listdir(TESTS)
        if n.startswith("test_") and n.endswith(".py"))


# ---------------------------------------------------------------------------
# The invariant
# ---------------------------------------------------------------------------

def test_no_port_probe_loops_and_no_out_of_band_ports():
    """Every loopback fixture binds ephemeral (or an in-band fixed port)."""
    offenders = []
    for path in _test_files():
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        for kind, lineno, detail in port_hygiene_offenders(src):
            offenders.append(f"{os.path.basename(path)}:{lineno} {kind} {detail}")
    assert not offenders, (
        "a loopback fixture must bind ('127.0.0.1', 0) -- the OS then "
        "guarantees the port is free.  Probing or hard-coding a port lets a "
        "second bind (http.server sets SO_REUSEADDR, which on Windows "
        "succeeds even over a live listener) put the client on the WRONG "
        "server, and the fixture never finds out:\n  "
        + "\n  ".join(offenders))


# ---------------------------------------------------------------------------
# Anti-vacuity: the detector must be able to fail
# ---------------------------------------------------------------------------

def test_detector_catches_both_shapes():
    """A gate that cannot fail is the same bug one level up.

    The failure being guarded here was invisible precisely because nothing
    reported it; a detector that silently matches nothing would be a second
    instance of that, inside the guard.
    """
    probe = (
        "import threading\n"
        "from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer\n"
        "\n"
        "def start():\n"
        "    for port in range(9002, 9014):\n"
        "        try:\n"
        "            srv = ThreadingHTTPServer(('127.0.0.1', port), H)\n"
        "            break\n"
        "        except OSError:\n"
        "            continue\n"
        "    return srv\n"
    )
    fixed_bad = (
        "from http.server import ThreadingHTTPServer\n"
        "\n"
        "def start():\n"
        "    return ThreadingHTTPServer(('127.0.0.1', 18878), H)\n"
    )
    kinds_probe = {k for k, _l, _d in port_hygiene_offenders(probe)}
    kinds_fixed = {k for k, _l, _d in port_hygiene_offenders(fixed_bad)}
    assert "port-probe-loop" in kinds_probe, "missed the range() probe loop"
    assert "hard-coded-port" in kinds_fixed, "missed the fixed port"

    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "x.py")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(probe)
        with open(p, encoding="utf-8") as fh:
            assert port_hygiene_offenders(fh.read())

    # The shapes we want must stay quiet.
    good = (
        "from http.server import ThreadingHTTPServer\n"
        "\n"
        "def a():\n"
        "    srv = ThreadingHTTPServer(('127.0.0.1', 0), H)\n"
        "    return srv.server_address[1]\n"
        "\n"
        "def b():\n"
        "    import http.client\n"
        "    return http.client.HTTPConnection('127.0.0.1', 8899, timeout=1)\n"
    )
    assert not port_hygiene_offenders(good), (
        "ephemeral bind must be accepted, and a client CONNECT to a known "
        "port is not a bind -- it must not be flagged")


def test_ephemeral_binding_is_actually_used():
    """The invariant must not be satisfiable by having no servers at all.

    If nothing in tests/ bound 127.0.0.1, "no probe loops" would pass while
    the suite had simply stopped exercising anything over loopback -- the
    opposite of the intent.
    """
    users = []
    for path in _test_files():
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        if '"127.0.0.1", 0' in src or "'127.0.0.1', 0" in src:
            users.append(os.path.basename(path))
    assert len(users) >= 5, (
        f"only {len(users)} test files bind an ephemeral loopback port "
        f"({users}); the gate would pass on a suite that no longer starts "
        "any server, which is not the property being asserted")


def test_two_ephemeral_binds_never_collide():
    """Why port 0 and not a better probe -- measured, not asserted.

    The property the fix relies on is that an ephemeral bind is EXCLUSIVE:
    two of them cannot land on the same port, so "is someone else already
    listening here?" has no answer other than "no".  A probed port has no
    such property -- and, because ``http.server`` sets SO_REUSEADDR, the
    second bind does not even raise on Windows, which is precisely why the
    old ``except OSError: continue`` never fired.

    (That last claim is observable but host-dependent, so it is recorded in
    the module docstring instead of being asserted: on a host that DOES
    refuse the second bind, a probe loop would have been safe, and this
    gate would then be guarding against something that cannot happen.)
    """
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class _H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    a = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    try:
        b = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    finally:
        a.server_close()
    try:
        pa, pb = a.server_address[1], b.server_address[1]
        assert pa != pb, (
            f"two ephemeral binds got the same port ({pa}); the OS no longer "
            "guarantees exclusivity, so ephemeral binding would stop being "
            "the fix this gate assumes it is")
        assert pa != 0 and pb != 0
    finally:
        b.server_close()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
