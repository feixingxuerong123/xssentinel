# -*- coding: utf-8 -*-
"""Async error taxonomy: what stops the scan vs what a param survives.

The async engine wraps every stage in ``except (BudgetExhausted,
CircuitOpen): raise`` followed by broader ``except Exception`` handlers
that skip-and-continue.  That taxonomy is the Phase 86 contract:

  * a deliberate scan stop (budget gone, circuit open) must PROPAGATE --
    swallowing it would turn "we spent the budget" into "this param had
    nothing", silently;
  * any other transport error must NOT kill the scan -- one dead
    connection is not a verdict.

These branches had no direct tests (the benchmark exercises the happy
path; a wedged file here hung the local gate for 2x540s instead).  All
tests are fake-session, no network, sub-second.
"""
from __future__ import annotations
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from tests.conftest import SOCKETPAIR_OK

from xssentinel.core.async_scanner import AsyncScanner
from xssentinel.core.budget import BudgetExhausted, CircuitOpen


class _Resp:
    def __init__(self, text, headers=None):
        self._t = text
        self.headers = headers or {}

    async def text(self):
        return self._t

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _ScriptedSession:
    """Each request pops the next behaviour: a str echoes it raw (a
    live reflection), an Exception instance is raised.  When the script
    runs out, ``default`` applies (echo, or a standing error)."""

    def __init__(self, script, default="echo"):
        self.script = list(script)
        self.default = default
        self.calls = 0

    def request(self, method, url, params=None, data=None,
                headers=None, proxy=None):
        self.calls += 1
        val = (params or {}).get("q", "") + (data or {}).get("q", "")
        item = self.script.pop(0) if self.script else self.default
        if isinstance(item, Exception):
            raise item
        body = item if item != "echo" else val
        return _Resp(f"<html><body><div>{body}</div></body></html>")


def _collect(session, params=None):
    """Drive _probe_param in a fresh loop; L7 hand-off stubbed."""
    original = AsyncScanner._scan_advanced_param_layers

    async def _noop(self, *a, **k):
        if False:                     # pragma: no cover -- keeps it a gen
            yield None

    AsyncScanner._scan_advanced_param_layers = _noop
    try:
        async def run():
            asc = AsyncScanner(max_concurrent=4, per_host_delay=0, jitter=0,
                               max_payloads=4, max_transforms=1)
            asc._semaphore = asyncio.Semaphore(4)
            out = []
            async for f in asc._probe_param(session, "http://t/x", "GET",
                                            "q", params or {"q": "x"}, {},
                                            False, "x"):
                out.append(f)
            return out

        return asyncio.run(run())
    finally:
        AsyncScanner._scan_advanced_param_layers = original


class TestBudgetStopsPropagate:
    @pytest.mark.skipif(not SOCKETPAIR_OK,
                        reason="needs loopback (moved down from the file-level gate)")
    def test_budget_exhaustion_on_the_marker_probe_propagates(self):
        s = _ScriptedSession([BudgetExhausted("requests: 500/500")])
        with pytest.raises(BudgetExhausted):
            _collect(s)
        assert s.calls == 1, "the stop must be immediate, not retried"

    @pytest.mark.skipif(not SOCKETPAIR_OK,
                        reason="needs loopback (moved down from the file-level gate)")
    def test_circuit_open_on_the_marker_probe_propagates(self):
        s = _ScriptedSession([CircuitOpen("target is dead")])
        with pytest.raises(CircuitOpen):
            _collect(s)

    @pytest.mark.skipif(not SOCKETPAIR_OK,
                        reason="needs loopback (moved down from the file-level gate)")
    def test_budget_exhaustion_mid_payload_loop_propagates(self):
        # call 1: marker reflected -> we proceed; call 2: sandwich probe;
        # call 3: the first payload variant hits the dead budget.  A
        # swallow here would read as "this param is safe" -- the exact
        # false negative Phase 86 forbids.
        s = _ScriptedSession(["echo", "echo",
                              BudgetExhausted("requests: 500/500")])
        with pytest.raises(BudgetExhausted):
            _collect(s)

    @pytest.mark.skipif(not SOCKETPAIR_OK,
                        reason="needs loopback (moved down from the file-level gate)")
    def test_circuit_open_mid_payload_loop_propagates(self):
        s = _ScriptedSession(["echo", "echo",
                              CircuitOpen("connection reset storm")])
        with pytest.raises(CircuitOpen):
            _collect(s)


class TestGenericErrorsDegrade:
    @pytest.mark.skipif(not SOCKETPAIR_OK,
                        reason="needs loopback (moved down from the file-level gate)")
    def test_transport_error_on_the_marker_probe_skips_the_param(self):
        s = _ScriptedSession([ConnectionError("reset by peer")])
        assert _collect(s) == [], "a dead probe is not a verdict"

    @pytest.mark.skipif(not SOCKETPAIR_OK,
                        reason="needs loopback (moved down from the file-level gate)")
    def test_transport_error_on_a_variant_tries_the_next_variant(self):
        # call 3 (first variant) dies, call 4 (the next variant) reflects
        # and confirms: one dead request must not cost the finding.
        # (Phase 309: call 4 used to be the per-payload build_polyglot
        # flavour -- that append is gone, the flavour now fires once after
        # the whole queue -- so call 4 is the next variant in the ladder
        # and grades like a context hit, not like a polyglot.)
        s = _ScriptedSession(["echo", "echo",
                              ConnectionError("reset by peer"),
                              "echo"])
        findings = _collect(s)
        assert findings, "a single failed variant must not cost the param"
        # Phase 221: the type is `polyglot_reflection`, not `reflected`.
        # Phase 208b ("async grades a polyglot hit like sync's polyglot
        # layer") made the async side emit the same type sync already used
        # (scanner_layers.py:774), and this assertion still carried the
        # pre-208b literal.  What the test is really about is the sentence
        # in the comment above -- a dead variant must not cost the finding
        # -- so it accepts either name rather than re-typing the grader's
        # vocabulary into a budget test.
        assert findings[0].data["type"] in ("reflected", "polyglot_reflection")
        # Phase 309: the confirming variant is a context-queue hit, graded
        # by _non_html_grade (high on this HTML echo) where it used to be
        # the appended polyglot flavour (graded medium by _polyglot_grade).
        # The grading itself has its own gate (Phase 208 file); what THIS
        # file pins is that the confirm is honestly graded, never None --
        # whichever variant survived the dead one.
        assert findings[0].data["confidence"] in ("high", "medium")
        assert findings[0].data["evidence_class"] == "model-only"
        assert findings[0].data.get("evidence"), \
            "a model-only claim must still show its evidence excerpt"
        # Phase 221: same evidence-shape cap as the two sibling files.
        # The budget contract under test is the finding's EXISTENCE; assert
        # the 1.5-① invariant (a high letter must carry a basis) instead of
        # re-asserting a severity the cap is allowed to move.
        assert findings[0].data["severity"] in ("high", "medium", "low")
        if findings[0].data["severity"] in ("high", "critical"):
            assert bool(findings[0].data.get("proof")
                        or findings[0].data.get("evidence")), \
                "a high claim must carry a checkable basis"

    @pytest.mark.skipif(not SOCKETPAIR_OK,
                        reason="needs loopback (moved down from the file-level gate)")
    def test_all_variants_failing_yields_nothing_and_does_not_raise(self):
        s = _ScriptedSession(["echo", "echo"],
                             default=ConnectionError("dead"))
        assert _collect(s) == []
