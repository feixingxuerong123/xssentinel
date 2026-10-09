"""Phase 208: async must grade a polyglot hit the way sync's polyglot layer does.

The 64-family representative slice (benchmark/parity_slice_measure.py) found
exactly one divergence, on /r/url03 (meta_refresh context):

    sync  = polyglot_reflection / medium / medium
    async = reflected           / high   / high

Replaying that endpoint alone showed both engines had identical evidence --
model-only, same context (event_handler), both polyglot hits.  Sync has a
dedicated polyglot emitter (``scanner_layers.py``); async only had the
polyglot PROBE (a variant in ``_probe_param``), so the hit fell through to
the generic reflected branch and came out harsher.

These tests lock the classification, not just the grading helper: a plain
reflected hit must still be high/high (test 3), otherwise the fix would
quietly downgrade every async finding.
"""
import asyncio
import os
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
sys.path.insert(0, os.path.join(ROOT, "benchmark"))

from server import run_server  # noqa: E402
from test_engine_parity_gate import _BUDGETS  # noqa: E402

from tests.conftest import loopback_healthy  # noqa: E402

from xssentinel.core.async_scanner import AsyncScanner  # noqa: E402
from xssentinel.core.async_scanner_common import _polyglot_grade  # noqa: E402
from xssentinel.core.requester import Requester  # noqa: E402
from xssentinel.core.scanner import Scanner  # noqa: E402


def _start_server():
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session (security software/TCP state)")
    holder = {"ready": threading.Event(), "server": None, "port": None}

    def on_ready(srv):
        holder["server"] = srv
        holder["port"] = srv.server_address[1]
        holder["ready"].set()

    threading.Thread(target=run_server, args=(0,),
                     kwargs={"ready_callback": on_ready}, daemon=True).start()
    assert holder["ready"].wait(15), "benchmark server did not start"
    return holder["server"], f"http://127.0.0.1:{holder['port']}"


def _sync_findings(base, path, param="q"):
    sc = Scanner(requester=Requester(timeout=8), dom_engine="off",
                 verbose=False, **_BUDGETS)
    sc.scan_endpoint(base + path, "GET", {param: "probe"}, {})
    return [f.data if hasattr(f, "data") else dict(f) for f in sc.findings]


def _async_findings(base, path, param="q"):
    """Run the async engine in a fresh thread.

    Phase 203: sync with dom_engine="auto" binds an asyncio loop to the
    calling thread, so asyncio.run() here would fail with "cannot be called
    from a running event loop".  A fresh thread side-steps it; dom_engine is
    "off" in this file anyway, but the isolation is free.
    """
    async def one():
        asc = AsyncScanner(max_concurrent=4, per_host_delay=0, jitter=0,
                           timeout=8, dom_engine="off",
                           advanced_layers=True, **_BUDGETS)
        got = []
        async for f in asc.scan(base + path, method="GET",
                                params={param: "probe"}):
            got.append(f.data if hasattr(f, "data") else dict(f))
        return got

    box = {}

    def target():
        box["out"] = asyncio.run(one())

    th = threading.Thread(target=target)
    th.start()
    th.join(180)
    return box.get("out", [])


def test_polyglot_grade_matches_the_sync_polyglot_layer():
    """Non-HTML only lowers severity; confidence stays medium (sync's model)."""
    assert _polyglot_grade({"Content-Type": "text/html"}) == ("medium", "medium")
    assert _polyglot_grade({"Content-Type": "application/json"}) == ("low", "medium")
    # Missing/garbage headers must not crash the scan path.
    assert _polyglot_grade(None) == ("medium", "medium")


def test_polyglot_hit_is_classified_like_sync():
    """The one divergence the slice found: /r/url03 must agree across engines."""
    srv, base = _start_server()
    try:
        s_finds = _sync_findings(base, "/r/url03")
        a_finds = _async_findings(base, "/r/url03")
    finally:
        srv.shutdown()

    assert s_finds, "sync reported nothing on /r/url03 -- fixture changed?"
    assert a_finds, "async reported nothing on /r/url03 -- fixture changed?"

    s_types = {f.get("type") for f in s_finds}
    a_types = {f.get("type") for f in a_finds}
    assert s_types == a_types, (
        f"engine divergence on /r/url03: sync={s_types} async={a_types}")

    for f in a_finds:
        if f.get("type") == "polyglot_reflection":
            assert f.get("severity") == "medium"
            assert f.get("confidence") == "medium"


def test_plain_reflected_hit_is_still_high():
    """Regression guard: the fix must not downgrade ordinary reflected hits."""
    srv, base = _start_server()
    try:
        a_finds = _async_findings(base, "/r/elem01")
    finally:
        srv.shutdown()

    reflected = [f for f in a_finds if f.get("type") == "reflected"]
    assert reflected, (
        f"no plain reflected finding on /r/elem01 (got "
        f"{[f.get('type') for f in a_finds]}) -- pick another case")
    assert reflected[0].get("severity") == "high"
    assert reflected[0].get("confidence") == "high"
