"""Phase 331: sync's primary candidate slice takes the corpus HEAD.

Measured mechanism (docs/OPTIMIZATION.md 2.1.4, re-measured on the fix
round -- the ledger's original "variant budget eaten by one fat candidate"
description was incomplete):

  * range3 ``r3-pos-utf7`` (/legacy, declared charset=UTF-7, raw echo):
    sync's stride sample of the 206-entry ``html_element`` family picked
    javascript:-URI shapes and tag-soup (all correctly refused by the
    verifier) -- the bare ``<script>alert(1)</script>`` sits at corpus
    index 1 and was never inside the effective_max=10 window.  Result:
    11x polyglot_reflection/medium/model-only while async (whose shared
    sampler takes the corpus HEAD) confirmed 11x reflected/high with
    browser evidence.
  * The shared sampler's own docstring already recorded the identical
    lesson on the async side ("stride sampling with small budgets was
    observed to skip the basic confirmation payloads"); sync never got
    that fix -- the reverse of the usual "async missed sync's repair".
  * Micro-measurement on the live endpoint: the bare script reflected
    raw CONFIRMS semantically (ctx=script_block) -- the gap was purely
    queue ordering.

Contracts pinned here:
  * sync's primary slice == the corpus head (same selection semantics as
    the shared ``cross_context_candidates_tagged``);
  * the canonical bare script is inside the first two primary slots;
  * the escaped-reflection path keeps its 2-candidate head budget;
  * MUTATION CONTROL: the pre-fix stride, reimplemented below against the
    CURRENT corpus, must NOT contain the bare script in its window --
    proving these assertions fail on the old algorithm;
  * live regression: scanning /legacy end-to-end (no browser needed -- the
    semantic leg is what the ordering fix repairs) produces a confirmed
    ``reflected``/script_block finding where pre-fix produced none.
"""
from __future__ import annotations

import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from tests.conftest import SOCKETPAIR_OK  # noqa: E402
from xssentinel.core import payloads  # noqa: E402
from xssentinel.core.scanner import Scanner  # noqa: E402

#: Per-test loopback gate (never module-level: it lives on the Module node
#: and cannot be waived -- tests/conftest.py documents the measured cost).
requires_loopback = pytest.mark.skipif(
    not SOCKETPAIR_OK, reason="loopback socketpair degraded")

_BARE = "<script>alert(1)</script>"


def _scanner(max_payloads: int = 10) -> Scanner:
    # Phase 183 fixture pattern: __new__-built scanner; the candidate
    # builder reads max_payloads/max_transforms/_custom_payloads only.
    sc = Scanner.__new__(Scanner)
    sc.max_payloads = max_payloads
    sc.max_transforms = 6
    sc._custom_payloads = None
    return sc


def _primary_payloads(context: str, max_payloads: int = 10) -> list[str]:
    sc = _scanner(max_payloads)
    cands, _polies = sc._build_candidates(context, False)
    primary_budget = max(6, max_payloads // 2)
    return [c["payload"] for c in cands[:primary_budget]]


class TestPrimaryQueueHead:
    def test_primary_slice_equals_corpus_head(self):
        for ctx in ("html_element", "script_block", "url_href"):
            sc = _scanner()
            cands, _ = sc._build_candidates(ctx, False)
            budget = max(6, sc.max_payloads // 2)
            head = [p["payload"] for p in payloads.by_context(ctx)[:budget]
                    if p.get("payload")]
            # The primary slice is the first len(head) entries -- for a
            # context whose family is smaller than the budget (url_href),
            # sibling-corpus payloads follow INSIDE the budget window.
            got = [c["payload"] for c in cands[:len(head)]]
            assert got == head, ctx

    def test_bare_script_leads_the_html_element_queue(self):
        pls = _primary_payloads("html_element")
        assert _BARE in pls[:2], (
            "the canonical no-interaction probe must sit in the first two "
            f"slots; got {pls[:4]}")

    def test_parity_with_shared_sampler(self):
        # The whole point of 2.1: both engines must draw the SAME primary
        # slice.  The shared builder computes head[:max(6, budget//2)].
        for ctx in ("html_element", "script_block"):
            from xssentinel.core.payloads import (
                cross_context_candidates_tagged)
            shared = [s for s, fam in
                      cross_context_candidates_tagged(ctx, 10)
                      if fam == ctx]
            assert _primary_payloads(ctx) == shared[:6], ctx

    def test_escaped_path_keeps_two_from_head(self):
        sc = _scanner()
        cands, _ = sc._build_candidates("html_element", True)
        assert len(cands) == 2
        head = [p["payload"] for p in payloads.by_context("html_element")]
        assert [c["payload"] for c in cands] == head[:2]

    def test_mutation_control_stride_skips_the_bare_script(self):
        """The pre-fix algorithm, run against the CURRENT corpus, must not
        contain the bare script -- if this ever fails, the corpus has been
        reordered onto a stride point and the ordering fix below is no
        longer discriminative: stop and re-derive the contract."""
        ps = payloads.by_context("html_element")
        n = 6
        step = len(ps) / n
        old_stride = [ps[int(i * step)]["payload"] for i in range(n)]
        assert _BARE not in old_stride, (
            "corpus reorder put the bare script on a stride point; the "
            "mutation control no longer reproduces the Phase 331 gap")


@pytest.fixture(scope="module")
def range3_base():
    # Import range3's server BY FILE PATH with a unique module name: a bare
    # `from server import ...` collides with benchmark/server.py whenever
    # another test module in the same pytest process imported benchmark.runner
    # first (sys.modules['server'] is then benchmark's -- measured: the
    # fixture started the BENCHMARK server on 18777 and probed 8901).
    import importlib.util
    r3_server = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "range3", "server.py")
    spec = importlib.util.spec_from_file_location("range3_server_p331",
                                                  r3_server)
    r3srv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(r3srv)
    started = threading.Event()
    th = threading.Thread(target=r3srv.run_server,
                          kwargs={"ready_callback": lambda s: started.set()},
                          daemon=True)
    th.start()
    if not started.wait(10):
        pytest.skip("range3 server failed to start (port busy?)")
    time.sleep(0.3)
    base = "http://127.0.0.1:8901"
    import requests
    r = requests.get(f"{base}/legacy", params={"q": "probe"}, timeout=5)
    assert r.status_code == 200 and "legacy archive" in r.text, \
        "range3 /legacy did not answer -- refusing to score a dead server"
    yield base


class TestLegacyEndpointRegression:
    """End-to-end FN net: the ordering fix must make sync CONFIRM on
    /legacy where pre-fix it only reached L7 polyglot (model-only)."""

    @requires_loopback
    def test_sync_confirms_bare_script_on_legacy(self, range3_base):
        sc = Scanner(max_payloads=10, max_transforms=6, verbose=False,
                     use_headless=False)
        findings = sc.scan_target(f"{range3_base}/legacy?q=xssentinel",
                                  oob_collect=False)

        def _d(f):
            return f.data if hasattr(f, "data") else f

        rows = [_d(f) for f in findings]
        shapes = [(d.get("type"), d.get("context")) for d in rows]
        # _record stamps the finding with the CLASSIFIED reflection
        # context of the payload's position (the bare script lands in an
        # element body), not the verifier's token context (script_block).
        reflected = [d for d in rows if d.get("type") == "reflected"]
        assert reflected, (
            "sync must confirm the bare script on /legacy; pre-fix this "
            f"scan produced only polyglot_reflection rows; got {shapes}")
        assert all(d.get("severity") == "high" for d in reflected), (
            f"semantic-confirmed reflection grades high; got "
            f"{[d.get('severity') for d in reflected]}")
