"""OPTIMIZATION 2.1: the dual-engine BEHAVIORAL parity gate.

The existing parity tests are pointwise -- one per past incident -- so a
divergence of a kind that never happened yet has no gate.  This file is
the general gate: the SAME deterministic slice of manifest endpoints goes
through BOTH engines with the SAME budgets, and the normalized finding
sets must match field-for-field (type / context / severity / confidence).

What is deliberately NOT compared:
  * transform tags and evidence_class -- engines legitimately reach the
    same verdict by different ladders;
  * request counts -- async scheduling differs;
  * detail strings -- free text;
  * ``context`` -- WHICH payload confirms first is ladder-order-dependent
    when a parameter has several viable vectors (measured: /s/flt05's
    keyword filter confirms a concat-stamped svg payload on sync and a
    javascript:-URI payload on async; both findings are true).  The
    verdict-SHAPE fields -- type, severity, confidence, and the finding
    COUNT -- are the contract: they are what dedup, reports, PoC replay
    and every severity-driven consumer act on.

Acceptance (per 2.1: a gate that cannot reproduce the known incidents is
not a gate): each historical incident is replayed here as a MUTATION --
the async fix is monkeypatched away and the gate must go red:

  * 178c -- async lacked the non-HTML content-type downgrade: patching
    ``_non_html_grade`` to a no-op flips /r/jsonct01 (raw echo served as
    application/json) to high/high on async while sync stays low/low;
  * 177 -- async lacked the Phase-166 concat-stamp retry: shimming
    ``mark(style="concat")`` to a no-op leaves /s/flt05 (keyword filter
    rewriting ``alert(`` -> ``blocked(``) unconfirmed on async while sync
    confirms through the stamp.

Runs against the manifest-driven benchmark server (benchmark/server.py),
loopback only, no browser, no OOB.  DOM-source endpoints are out of scope
for v1: their static layers deserve their own comparison once the
reflection-side gate has proven its worth.
"""
from __future__ import annotations

import asyncio
import os
import sys
import threading
import time
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "benchmark"))

from server import run_server as bench_run_server  # noqa: E402

# One endpoint per reflection family that has a deterministic manifest
# case, plus BOTH incident shapes and two safe twins.  (path, param)
_PARITY_SLICE = [
    ("/echo", "q"),            # raw html_element
    ("/attr", "q"),            # quoted attribute
    ("/script", "q"),          # script string
    ("/cdata", "q"),           # CDATA breakout
    ("/tpl", "q"),             # angular template
    ("/css", "q"),             # css context
    ("/comment", "q"),         # html comment
    ("/meta", "q"),            # meta refresh
    ("/safe", "q"),            # escaped -> BOTH silent
    ("/s/jsonct01", "q"),      # escaped JSON content-type -> BOTH silent
    ("/s/flt05", "q"),         # keyword filter -> concat stamp (incident 1)
    ("/r/jsonct01", "q"),      # raw JSON content-type -> downgrade (incident 2)
]

_BUDGETS = dict(max_payloads=14, max_transforms=12)


def _norm(findings) -> list:
    """The comparable form of one endpoint's finding collection.

    (type, severity, confidence) per finding, as a sorted list -- the
    COUNT is part of the contract (an extra finding on one engine is a
    divergence), while context is excluded (see the module docstring).
    """
    rows = []
    for f in findings:
        d = f.data if hasattr(f, "data") else dict(f)
        rows.append((d.get("type"), d.get("severity"), d.get("confidence")))
    return sorted(r for r in rows if r[0] != "fuzzer_triage")


def _run_sync(base: str, slice_=_PARITY_SLICE) -> dict:
    from xssentinel.core.requester import Requester
    from xssentinel.core.scanner import Scanner

    out: dict = {}
    for path, param in slice_:
        sc = Scanner(requester=Requester(timeout=8), dom_engine="off",
                     verbose=False, **_BUDGETS)
        sc.scan_endpoint(base + path, "GET", {param: "probe"}, {})
        out[path] = _norm(sc.findings)
    return out


def _run_async(base: str, slice_=_PARITY_SLICE) -> dict:
    from xssentinel.core.async_scanner import AsyncScanner

    async def _one(path, param):
        asc = AsyncScanner(max_concurrent=4, per_host_delay=0, jitter=0,
                           timeout=8, dom_engine="off",
                           advanced_layers=True, **_BUDGETS)
        got = []
        async for f in asc.scan(base + path, method="GET",
                                params={param: "probe"}):
            got.append(f.data if hasattr(f, "data") else dict(f))
        return _norm(got)

    async def _all():
        out = {}
        for path, param in slice_:
            out[path] = await _one(path, param)
        return out

    return asyncio.run(_all())


def _diff(sync_out: dict, async_out: dict) -> dict:
    """Per-endpoint verdict-shape differences (empty == parity)."""
    diffs = {}
    for path in sorted(set(sync_out) | set(async_out)):
        s, a = sync_out.get(path), async_out.get(path)
        if s != a:
            diffs[path] = {"sync": s, "async": a}
    return diffs


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


class TestEngineParity:
    def test_reflection_slice_finding_sets_match(self, bench_base):
        """The gate: same input, same verdict shape, both engines."""
        sync_out = _run_sync(bench_base)
        async_out = _run_async(bench_base)
        diffs = _diff(sync_out, async_out)
        assert not diffs, (
            "dual-engine behavioral divergence on the parity slice:\n"
            + "\n".join(f"  {p}: sync={v['sync']} async={v['async']}"
                        for p, v in diffs.items()))


class TestGateCatchesKnownIncidents:
    """2.1 acceptance: the gate must go red when an async fix is patched
    away.  A gate that cannot reproduce the historical incidents is a
    green light with no detection power."""

    def test_missing_content_type_downgrade_is_red(self, bench_base,
                                                   monkeypatch):
        from xssentinel.core import async_scanner as asm
        monkeypatch.setattr(asm, "_non_html_grade",
                            lambda hdrs: ("high", "high"))
        case = [("/r/jsonct01", "q")]
        diffs = _diff(_run_sync(bench_base, case),
                      _run_async(bench_base, case))
        assert diffs, "gate MISSED the 178c content-type-downgrade incident"

    def test_missing_concat_retry_is_red(self, bench_base, monkeypatch):
        from xssentinel.core import async_scanner as asm
        from xssentinel.core import verifier as real_v

        shim = types.SimpleNamespace(
            mark=lambda p, t, style="plain": (
                p if style == "concat" else real_v.mark(p, t, style=style)),
            verify_semantic=real_v.verify_semantic,
            payload_survived=real_v.payload_survived)
        monkeypatch.setattr(asm, "verifier", shim)
        case = [("/s/flt05", "q")]
        diffs = _diff(_run_sync(bench_base, case),
                      _run_async(bench_base, case))
        assert diffs, "gate MISSED the 177/Phase-166 concat-retry incident"
