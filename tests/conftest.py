"""Shared pytest fixtures / environment probes for the xssentinel suite.

Phase 38: on this Windows host, ``socket.socketpair()`` (which asyncio's
ProactorEventLoop needs for its self-pipe) can HANG indefinitely — the
loopback connect/accept is throttled by security software / TCP state.
Every test that calls ``asyncio.run()`` is affected.  We probe socketpair
ONCE at collection time and expose ``SOCKETPAIR_OK`` so affected tests can
skip themselves instead of hanging the whole session (they are re-run
automatically when the environment recovers).

Phase 43: the interference also degrades over a LONG test session — the
collection-time probe passes, but by the time HTTP-fixture tests run
(~1 min in), loopback connect/accept is throttled again and they FAIL
instead of skip.  ``loopback_healthy()`` is the RUNTIME probe: call it
inside fixtures/tests right before real loopback work and
``pytest.skip`` when the environment has degraded mid-session.
"""
from __future__ import annotations

import os
import socket as _socket
import sys
import tempfile
import threading

import pytest

# ---------------------------------------------------------------------------
# Phase 176: keep the suite off live model providers
# ---------------------------------------------------------------------------
# LLM pool discovery ends at the pool shipped INSIDE the package -- real
# vendors with real credentials.  So a test that forgets to pass an explicit
# pool path does not fail loudly; it makes a live HTTP call to a model
# provider.  That is slow, flaky, and ships whatever the test "scanned" to a
# third party.
#
# This happened for real: the API AI-report tests resolved jobs through
# JobManager directly (bypassing the handler that injects the pool path), so
# "no pool configured" quietly meant "use the shipped pool", and four tests
# spent 34s each talking to a live vendor.
#
# Pointing the env override at a path that does not exist makes any such
# mistake degrade to the deterministic template instead.  Tests that DO
# exercise the pool pass an explicit ``config_path``, which takes precedence
# over the environment -- so this does not weaken them.
#
# Escape hatch for a deliberate live-integration run:
#   XSSENTINEL_ALLOW_LIVE_LLM_IN_TESTS=1 pytest ...
if os.environ.get("XSSENTINEL_ALLOW_LIVE_LLM_IN_TESTS") != "1":
    os.environ["XSSENTINEL_LLM_CONFIG"] = os.path.join(
        tempfile.gettempdir(), "xssentinel-no-live-llm-in-tests.json")

SOCKETPAIR_OK = True


def _probe_socketpair(timeout: float = 3.0, rounds: int = 2) -> bool:
    """True only if socketpair succeeds `rounds` times in a row — the
    interference is intermittent, so a single lucky pass is not enough."""
    # Override so the gate can be TESTED, not only observed.  The
    # `no_loopback` waiver below cannot be demonstrated on a healthy host,
    # and a waiver nobody can demonstrate is a waiver nobody can trust.
    # Named XSSENTINEL_* so it reads as a test hook rather than an
    # environment knob production might consult.
    forced = os.environ.get("XSSENTINEL_FORCE_SOCKETPAIR", "").lower()
    if forced in ("bad", "0", "false", "degraded"):
        return False
    if forced in ("good", "1", "true", "healthy"):
        return True
    for _ in range(rounds):
        result = {"ok": False}

        def _try():
            try:
                a, b = _socket.socketpair()
                a.close()
                b.close()
                result["ok"] = True
            except Exception:
                pass

        th = threading.Thread(target=_try, daemon=True)
        th.start()
        th.join(timeout)
        if not result["ok"]:
            return False
    return True


SOCKETPAIR_OK = _probe_socketpair()


def loopback_healthy(timeout: float = 3.0) -> bool:
    """RUNTIME health probe: socketpair + a real loopback connect/accept.

    Call this inside a fixture/test right before loopback-dependent work;
    when False, ``pytest.skip`` instead of letting the test fail on a
    throttled connect.  Cheap (~ms when healthy).
    """
    if not _probe_socketpair(timeout=timeout, rounds=1):
        return False
    # Also verify a plain loopback bind/connect/accept round-trip — the
    # security software sometimes throttles connects but not socketpair.
    result = {"ok": False}

    def _try():
        try:
            srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            srv.settimeout(timeout)
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            port = srv.getsockname()[1]
            cli = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            cli.settimeout(timeout)
            cli.connect(("127.0.0.1", port))
            conn, _ = srv.accept()
            conn.close()
            cli.close()
            srv.close()
            result["ok"] = True
        except Exception:
            pass

    th = threading.Thread(target=_try, daemon=True)
    th.start()
    th.join(timeout * 2 + 1)
    return result["ok"]


# ---------------------------------------------------------------------------
# Loopback gate: measurement
# ---------------------------------------------------------------------------
# Several files carry a module-level
#     pytestmark = [pytest.mark.skipif(not SOCKETPAIR_OK, ...)]
# which is right for the live tests in them -- and wrong for the tests
# that need no network at all.  A file-level skipif lives on the Module
# node and CANNOT be waived by a marker on an individual test: the
# correct fix is to move the gate down to the tests that need it.
#
# That is not a speculative cleanup.  Measured 2026-10-06
# (test_verify_carriers_live.py): on a throttled host the whole file
# skipped -- 21 skipped -- including the paramless-carrier cases, which
# record the outgoing request through a stub and never touch the network.
# The branch they pin is the one a DOM-family finding depends on, so it
# is exactly the coverage that must not go quiet.
#
# XSSENTINEL_FORCE_SOCKETPAIR=bad|good (see _probe_socketpair) is what
# makes that measurable instead of accidental.  It earned its place here:
# the first attempt at the waiver was an `item.own_markers` filter in
# `pytest_collection_modifyitems`, which cannot reach a module-level
# skipif at all.  Run with the gate forced bad, it reported "21 passed"
# -- on a host whose gate happened to be healthy -- and only
# XSSENTINEL_FORCE_SOCKETPAIR=bad exposed it as 21 skipped.
#
# The lesson generalises past pytest: an override that only exists to
# test infrastructure is worth adding exactly when the infrastructure
# otherwise reports success by accident.
#
# Set this to verify a gate-related change, and unset it afterwards.


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "no_loopback: this test makes no network request, so a host whose "
        "loopback is degraded must not skip it")


# ---------------------------------------------------------------------------
# Event-loop isolation
# ---------------------------------------------------------------------------

def running_loop_present() -> bool:
    """True when this thread already has a *running* asyncio loop.

    ``asyncio.run()`` refuses to start when one is running ("cannot be called
    from a running event loop"), so this is exactly the precondition the
    sync tests that drive async code depend on.
    """
    import asyncio
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return False
    return True


@pytest.fixture(autouse=True)
def _isolate_event_loop(request):
    """Stop a leaked event loop from showing up as a bogus failure.

    Many tests here are plain ``def`` functions that drive the async scanner
    through ``asyncio.run()``.  In a full session an earlier test leaves a
    loop running in this thread, and every later ``asyncio.run()`` then raises
    ``RuntimeError`` -- the affected tests pass one at a time and fail only in
    the full run (observed: 7 async tests red on an otherwise green tree),
    which makes them useless as a regression signal.

    Three jobs:
    1. After each test, NAME the leak (test id goes to stderr) so the actual
       culprit is easy to find in CI logs.
    2. Try to UNWIND the most common leak (the dom_engine shared Playwright
       browser, whose sync API parks a running loop in this thread) by
       stopping that thread's browser.  Production embedders get
       ``dom_engine.shutdown_thread_browser()`` for the same purpose.
    3. Before each test, if a loop is still running, skip rather than fail.
       A skip says "environment", a failure says "we broke something".
    """
    leaked_before = running_loop_present()
    yield
    if not leaked_before and running_loop_present():
        print(f"\n[loop-leak] {request.node.nodeid} LEFT A RUNNING LOOP "
              "(likely Playwright sync API; see test_benchmark_fp.py notes)",
              file=sys.stderr)
        try:
            from xssentinel.core import dom_engine
            dom_engine.shutdown_thread_browser()
        except Exception:
            pass
        if running_loop_present():
            print("[loop-leak] unwind FAILED -- loop still running",
                  file=sys.stderr)
        else:
            print("[loop-leak] unwound via shutdown_thread_browser()",
                  file=sys.stderr)
    if leaked_before:
        pytest.skip(
            "a previous test left a running event loop in this thread")


# ---------------------------------------------------------------------------
# Logging isolation  (Phase 221c)
# ---------------------------------------------------------------------------
#
# Same failure SHAPE as the loop leak above, different mechanism, and it is
# the one that survived two full-suite runs because it reproduces only in
# a long session.
#
# `xssentinel.core.logger.configure_logging()` sets the level on the NAMED
# `xssentinel` logger and installs a StreamHandler on it, and nothing ever
# puts it back.  Any test that drives `__main__.main()` in-process with
# `--log-level error` therefore leaves `xssentinel` at ERROR for the rest
# of the session.  pytest's caplog installs its handler on the ROOT logger
# and at_level() sets the ROOT level -- but a named logger's OWN level wins
# over root's -- so every later caplog assertion collects nothing and fails
# with a message that reads like a product bug:
#
#   tests/test_layer_guard.py:65  "wiring error was not escalated to WARNING"
#
# Reproduced in 6 seconds (vs 40-66 minutes to notice it in a full run):
#
#   pytest tests/test_completeness_gate_robust.py tests/test_layer_guard.py
#   -> 3 failed, 12 passed
#
# The 73-file alphabetical bisect missed it because the poisoning file is
# `test_completeness_gate_robust.py`, whose own name sorts BEFORE the guard
# file but whose *content* is what matters.
#
# Fix: snapshot the logger's level + handlers around every test and restore
# them, so a test that configures logging cannot decide the outcome of one
# that asserts on it.

@pytest.fixture(autouse=True)
def _isolate_logging():
    """Undo any logging configuration a test performs.

    Scope note: only the ``xssentinel`` logger is restored, not the root.
    pytest itself owns root handlers (caplog lives there), and rewriting
    root mid-session is how you break the framework's own reporting.
    """
    import logging
    from xssentinel.core import logger as _logger_mod

    xs = logging.getLogger("xssentinel")
    saved_level = xs.level
    saved_handlers = list(xs.handlers)
    saved_configured = _logger_mod._configured
    yield
    for h in list(xs.handlers):
        if h not in saved_handlers:
            xs.removeHandler(h)
    for h in saved_handlers:
        if h not in xs.handlers:
            xs.addHandler(h)
    xs.setLevel(saved_level)
    _logger_mod._configured = saved_configured
