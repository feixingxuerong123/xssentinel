# -*- coding: utf-8 -*-
"""Phase 312: the evidence-shape invariant, measured across both engines.

OPTIMIZATION 3.6's "仍然待做 ①": every static layer's high claims must
carry a checkable basis -- one gate across the layers, not one guard per
incident.  Phase 218's ``cap_unverified_severity`` enforces the rule at
both engines' choke points (async ``scan()`` final yield, sync
``_record``); this gate MEASURES the invariant over a live server
population instead of trusting the wiring.

Arm 1 sweeps the cap's target families (trusted-types static hints,
prototype pollution, the reflected/safe twins) through both engines and
asserts zero violations.  Arm 2 is the mutation control: with the cap
monkeypatched out of BOTH engines, the same sweep must produce
violations -- measured: trusted_types_policy_bypass and
prototype_pollution go back to high with
evidence_class='browser-unavailable' and no proof/evidence.  A gate that
passes on a population with nothing to catch is decoration; arm 2 is
what proves arm 1 is load-bearing.

The FULL sweep (all 211 routes, ledger artifact) runs via
``python benchmark/evidence_shape_sweep.py`` -- machine time, kept out of
the suite the same way the Phase 222 full parity matrix is.
"""
import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))), "benchmark"))

from server import run_server as bench_run_server  # noqa: E402
from evidence_shape_sweep import (  # noqa: E402
    RESIDENT_ROUTES, invariant_violations, run_sweep)


@pytest.fixture(scope="module")
def bench_base():
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session (security software/TCP state)")
    holder = {}

    def on_ready(srv):
        holder["port"] = srv.server_address[1]
        holder["ready"].set()

    holder["ready"] = threading.Event()
    t = threading.Thread(target=bench_run_server, args=(0,),
                         kwargs={"ready_callback": on_ready}, daemon=True)
    t.start()
    assert holder["ready"].wait(15), "benchmark server did not start"
    time.sleep(0.2)
    yield f"http://127.0.0.1:{holder['port']}"


def test_invariant_holds_on_the_cap_target_families(bench_base):
    """Every high/critical finding carries a checkable basis."""
    rows, violations = run_sweep(bench_base, RESIDENT_ROUTES)
    highs = [r for r in rows if r["severity"] in ("high", "critical")]
    assert highs, (
        "the resident sweep produced no high findings -- the gate would "
        "pass on an empty population; fix the route list")
    assert not violations, (
        "evidence-shape invariant violated:\n" + "\n".join(
            f"  {v}" for v in violations))


def test_the_gate_bites_without_the_cap(bench_base, monkeypatch):
    """Mutation control: the cap is what keeps arm 1 green."""
    import xssentinel.core.async_scanner as A
    import xssentinel.core.scanner as S

    monkeypatch.setattr(S, "cap_unverified_severity", lambda d: False)
    monkeypatch.setattr(A, "cap_unverified_severity", lambda d: False)
    rows, violations = run_sweep(bench_base, RESIDENT_ROUTES)
    assert violations, (
        "with the cap disabled the sweep still shows no violations -- "
        "the mutation did not bite and arm 1 proves nothing")
    bitten = {r["type"] for r in rows
              if r["severity"] in ("high", "critical")
              and not (r["has_proof"] or r["has_evidence"]
                       or r["headless_confirmed"]
                       or r["evidence_class"] in ("browser-executed", "oob"))}
    assert bitten, "violations reported but the offending rows are gone"


def test_invariant_function_rejects_a_bare_high():
    """Unit shape: the checker itself, no server needed."""
    violations = invariant_violations([{
        "type": "tt_taint_flow", "severity": "high", "url": "/x",
        "evidence_class": "browser-unavailable", "has_proof": False,
        "has_evidence": False, "headless_confirmed": False,
    }])
    assert len(violations) == 1
    assert invariant_violations([{
        "type": "reflected", "severity": "high", "url": "/x",
        "evidence_class": "model-only", "has_proof": True,
        "has_evidence": False, "headless_confirmed": False,
    }]) == []
    assert invariant_violations([{
        "type": "reflected", "severity": "high", "url": "/x",
        "evidence_class": "browser-executed", "has_proof": False,
        "has_evidence": False, "headless_confirmed": False,
    }]) == []
