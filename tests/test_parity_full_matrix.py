# -*- coding: utf-8 -*-
"""OPTIMIZATION 2.1 open item #1: the parity gate over the WHOLE manifest.

The existing gate (test_engine_parity_gate.py) covers 24 hand-picked
endpoints -- 12 reflection + 12 DOM.  Every point in it corresponds to an
incident that already happened, which is exactly the weakness 2.1 names:
"a divergence of a kind that never happened yet has no gate".

Phase 222 measured the rest of the matrix (dev/_parity_matrix.py, both
engines, calibrated 14/12 budgets, all 182 comparable cases -- the other 10
are engine-scoped in the manifest and are neither credited nor blamed):
**2 divergences**, both since fixed:

  1. pos-csp-02  -- sync's csp_bypass carried confidence=None while async's
     carried "medium".  Measured to be the ONLY confidence-less finding type
     in the entire matrix.  Fixed in scanner_layers._scan_csp.
  2. pos-pmmine-01 -- async found reflected/high/high, sync nothing.  NOT a
     product divergence: hidden-parameter mining lives in sync's
     scan_target() but in async's scan() generator, so a harness that enters
     sync at scan_endpoint() and async at scan() mines one side only.

After both fixes: **0 divergences across all 182 cases.**

That second one is why this file builds its own runner instead of reusing
_run_sync/_run_async from the 24-endpoint gate: BOTH engines must be entered
at the same public entry point, and the two engines' public entry points do
not mine in the same place.  A gate that compares scan_endpoint() to scan()
measures the harness, not the engines.

Cost note: the full slice takes ~15-20 min (measured 586s sync / 419s async),
so it is NOT run on every pytest invocation.  It is the gate that backs the
claim "the two engines agree everywhere the matrix looks", and it is the
one to run after touching detection logic on either side.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "benchmark"))

from server import run_server as bench_run_server  # noqa: E402

# The calibrated gate budget -- identical to the benchmark's and to
# test_engine_parity_gate's, so a divergence here means a divergence there.
BUDGETS = dict(max_payloads=14, max_transforms=12)


def _load_cases() -> list[dict]:
    with open(os.path.join(ROOT, "benchmark", "manifest.json"),
              encoding="utf-8") as f:
        return json.load(f)["cases"]


def _norm(findings) -> list:
    """Byte-identical to the 24-endpoint gate's normaliser.

    The two gates must never disagree about what "parity" means, so this
    intentionally duplicates rather than imports: importing would couple a
    24-endpoint gate's tuning to a 182-case one.
    """
    rows = []
    for f in findings:
        d = f.data if hasattr(f, "data") else dict(f)
        rows.append([d.get("type"), d.get("severity"), d.get("confidence")])
    return sorted(r for r in rows if r[0] != "fuzzer_triage")


def _target(base: str, case: dict):
    """The benchmark runner's own URL builder: it owns the host alias
    (sub.localhost), the body-carrier rule and the Phase-122 param_value
    container override."""
    from runner import _build_target_url
    url = _build_target_url(base, case)
    param = case.get("param", "q") or "q"
    method = case.get("method", "GET").upper()
    if method == "GET":
        return url, param, method, {}
    return url, param, method, {param: case.get("param_value")
                                or "xssentinel_bench_probe"}


def _run_sync(base: str, cases: list[dict]) -> dict:
    """scan_target(), not scan_endpoint(): mining lives in scan_target, and
    entering sync at the other entry point is what produced the fake
    pos-pmmine-01 divergence."""
    from xssentinel.core.requester import Requester
    from xssentinel.core.scanner import Scanner

    out = {}
    for c in cases:
        url, param, method, data = _target(base, c)
        sc = Scanner(requester=Requester(timeout=8), dom_engine="off",
                     verbose=False, **BUDGETS)
        try:
            sc.scan_target(url, method, {param: "probe"}, data,
                           oob_collect=False)
            out[c["id"]] = _norm(sc.findings)
        except Exception as e:
            out[c["id"]] = [f"ERROR:{type(e).__name__}"]
    return out


def _run_async(base: str, cases: list[dict]) -> dict:
    from xssentinel.core.async_scanner import AsyncScanner

    async def _one(c):
        url, param, method, data = _target(base, c)
        asc = AsyncScanner(max_concurrent=4, per_host_delay=0, jitter=0,
                           timeout=8, dom_engine="off", advanced_layers=True,
                           **BUDGETS)
        got = []
        try:
            async for f in asc.scan(url, method=method,
                                    params={param: "probe"},
                                    data=data or None):
                got.append(f.data if hasattr(f, "data") else dict(f))
            return _norm(got)
        except Exception as e:
            return [f"ERROR:{type(e).__name__}"]

    async def _all():
        return {c["id"]: await _one(c) for c in cases}

    holder: dict = {}
    t = threading.Thread(target=lambda: holder.update(res=asyncio.run(_all())))
    t.start()
    t.join()
    return holder["res"]


@pytest.fixture(scope="module")
def bench_base():
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session (security software/TCP state)")
    holder = {"ready": threading.Event()}

    def on_ready(srv):
        holder["port"] = srv.server_address[1]
        holder["ready"].set()

    threading.Thread(target=bench_run_server, args=(0,),
                     kwargs={"ready_callback": on_ready},
                     daemon=True).start()
    assert holder["ready"].wait(20), "benchmark server did not start"
    time.sleep(0.2)
    yield f"http://127.0.0.1:{holder['port']}"


def _divergences(sync_out, async_out, cases):
    """Engine-scoped cases are excluded: a case whose manifest entry
    restricts `engines` to one side cannot be credited or blamed on the
    other."""
    out = []
    for c in cases:
        supported = c.get("engines")
        if supported and len(supported) == 1:
            continue
        s, a = sync_out.get(c["id"]), async_out.get(c["id"])
        if s != a:
            out.append((c["id"], s, a))
    return out


def test_full_matrix_engines_agree(bench_base):
    """The gate: every manifest case both engines implement must produce the
    same normalized finding set.

    Opt in with XSSENTINEL_PARITY_FULL=1 -- the sweep takes ~15-20 minutes,
    which is a deliberate cost for the claim it buys ("no divergence
    anywhere the matrix looks", not "no divergence on the 24 endpoints
    somebody thought to write down").
    """
    if os.environ.get("XSSENTINEL_PARITY_FULL") != "1":
        pytest.skip("set XSSENTINEL_PARITY_FULL=1 (about 15-20 minutes)")
    cases = _load_cases()
    diffs = _divergences(_run_sync(bench_base, cases),
                         _run_async(bench_base, cases), cases)
    assert not diffs, (
        f"dual-engine divergence on {len(diffs)} of "
        f"{len(cases)} manifest cases:\n"
        + "\n".join(f"  {cid}: sync={s} async={a}" for cid, s, a in diffs))


@pytest.mark.no_loopback
class TestGateShape:
    """Cheap, always-on checks that the gate above is wired the way its
    findings depend on -- these run in seconds and would otherwise be
    invisible until someone spent 20 minutes on a false red."""

    def test_engine_scoped_cases_are_excluded_not_compared(self):
        cases = _load_cases()
        scoped = [c for c in cases
                  if c.get("engines") and len(c["engines"]) == 1]
        assert scoped, ("the manifest no longer contains engine-scoped "
                        "cases -- re-check whether the exclusion is still "
                        "wanted, or whether both engines now implement them")
        # Give every case a DISTINCT pair so an accidental comparison would
        # show up as a divergence rather than as equality.
        sync_out = {c["id"]: [["reflected", "high", "high"]] for c in cases}
        async_out = {c["id"]: [["reflected", "high", "medium"]] for c in cases}
        for c in scoped:
            # an engine-scoped case: only one side ever produced a verdict
            engine = c["engines"][0]
            sync_out[c["id"]] = [] if engine == "async" else sync_out[c["id"]]
            async_out[c["id"]] = [] if engine == "sync" else async_out[c["id"]]
        diffs = _divergences(sync_out, async_out, cases)
        assert len(diffs) == len(cases) - len(scoped), (
            f"exclusion covered {len(scoped)} cases but the diff set has "
            f"{len(diffs)} of {len(cases) - len(scoped)} comparable ones")

    def test_norm_excludes_the_fuzzer_triage_note(self):
        class F:
            def __init__(self, d):
                self.data = d
        assert _norm([F({"type": "fuzzer_triage", "severity": "low",
                         "confidence": "low"})]) == []
        assert _norm([F({"type": "reflected", "severity": "high",
                         "confidence": "high"})]) == [
            ["reflected", "high", "high"]]

    def test_every_csp_bypass_finding_carries_a_confidence(self):
        """Regression guard for divergence #1.

        sync's _scan_csp appended its Finding directly instead of going
        through _record, so confidence reached the report as null -- the
        same defect class Phase 198 fixed for polyglot and Phase 209 for
        template_ssti_*.  csp_bypass was the last one standing; measured as
        the only confidence-less type across all 182 comparable cases.

        The first version of this test compared ``keyword.value`` to the
        string 'csp_bypass' -- but that attribute is an ast.Constant NODE,
        never a str, so it matched ZERO calls and the assertion passed on
        an empty list.  It was mutation-proven useless (removing the
        confidence left it green).  Hence the explicit Constant unwrap AND
        the assert below: a guard that finds nothing must say so.
        """
        import ast
        src = open(os.path.join(ROOT, "xssentinel", "core",
                                "scanner_layers.py"),
                   encoding="utf-8").read()
        tree = ast.parse(src)

        def _is_literal(kw, value):
            return isinstance(getattr(kw, "value", None), ast.Constant) \
                and kw.value.value == value

        offenders, matched = [], 0
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            kw = {k.arg for k in node.keywords}
            if not kw <= {"url", "method", "param", "payload", "context",
                          "severity", "type", "evidence_class", "evidence",
                          "confidence", "csp_header", "bypass_type",
                          "bypass_reason"}:
                continue
            if not kw.issuperset({"type", "severity"}):
                continue
            if not any(_is_literal(k, "csp_bypass") for k in node.keywords):
                continue
            matched += 1
            if "confidence" not in kw:
                offenders.append(node.lineno)
        assert matched, (
            "the AST scan found no csp_bypass Finding() call at all -- the "
            "guard is matching nothing and would pass forever")
        assert not offenders, (
            f"csp_bypass Finding built without a confidence at "
            f"scanner_layers.py:{offenders} -- async carries "
            f"confidence='medium' (async_scanner_layers.py), so omitting it "
            f"here is a live dual-engine divergence")