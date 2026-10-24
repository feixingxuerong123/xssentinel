# -*- coding: utf-8 -*-
"""Phase 311: the async coverage row names the payload's real corpus family.

Phase 310 wired the per-param payload_classes column, but the async engine
could only stamp every dispatch with the classified context -- the
candidate sampler returned plain strings and the family information was
lost at the sampler boundary.  ``cross_context_candidates_tagged`` returns
``(payload, family)`` pairs (the plain list is now a thin projection of
it), and the fire loop records ``families.get(payload, context)``: real
families for sampled candidates, the classified context for strings the
profiler/ladder derived.

Pre-fix, test 3 observes exactly one family (the classified context) no
matter how many corpora were sampled.
"""
import asyncio
import html
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from xssentinel.core import payloads as payloads_mod  # noqa: E402
from xssentinel.core.async_scanner import AsyncScanner  # noqa: E402

_BUDGETS = dict(max_payloads=10, max_transforms=6)


# ---------------------------------------------------------------------------
# Sampler contract (no network)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("context", ["html_element", "script_string", "cdata"])
def test_tagged_strings_mirror_the_plain_list(context):
    plain = payloads_mod.cross_context_candidates(context, 10)
    tagged = payloads_mod.cross_context_candidates_tagged(context, 10)
    assert [s for s, _ in tagged] == plain
    assert len(tagged) <= 10


def test_tagged_families_carry_primary_and_siblings():
    tagged = payloads_mod.cross_context_candidates_tagged("html_element", 10)
    families = {f for _, f in tagged}
    assert "html_element" in families, "primary family missing"
    siblings = {ctx for ctx, _ in payloads_mod._CROSS_CONTEXT["html_element"]}
    assert families & siblings, (
        f"no sibling family tagged (got {families}) -- the tagged sampler "
        "stopped labelling the cross-context slice")


# ---------------------------------------------------------------------------
# Integration: the coverage row shows the real families (loopback)
# ---------------------------------------------------------------------------
class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        parts = urlsplit(self.path)
        value = (parse_qs(parts.query).get("q") or [""])[0]
        body = f"<html><body>{html.escape(value, quote=True)}</body></html>"
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


@pytest.fixture(scope="module")
def base():
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        srv.shutdown()


def test_escaped_echo_payload_classes_show_the_real_families(base, monkeypatch):
    """End-to-end wiring: the dispatch stamp uses the SAMPLER's family.

    The escaped page probes with cand_budget=3, whose sampled candidates
    all come from the primary corpus -- so the real families alone cannot
    distinguish pre/post-311 there.  The sampler is tagged with a sentinel
    family instead: pre-311 the row read the classified context
    ('html_element'); post-311 it must read exactly the sampler's label.
    """
    monkeypatch.setattr(
        payloads_mod, "cross_context_candidates_tagged",
        lambda ctx, budget: [("p-%d" % i, "unit_test_family")
                             for i in range(min(budget, 5))])

    async def _run():
        asc = AsyncScanner(max_concurrent=2, per_host_delay=0, jitter=0,
                           timeout=8, dom_engine="off",
                           advanced_layers=False, **_BUDGETS)
        async for _f in asc.scan(base + "/esc", method="GET",
                                 params={"q": "a"}):
            pass
        return asc

    try:
        asc = asyncio.run(asyncio.wait_for(_run(), timeout=90))
    except asyncio.TimeoutError:
        pytest.fail("async scan did not finish within 90s")

    rows = [pc.to_dict()
            for ep in asc.coverage._endpoints.values()
            for pc in ep.params.values()]
    assert rows, "no param rows recorded"
    row = rows[0]
    assert row["payloads_sent"] >= 1
    # The sampled candidates must carry the sampler's tag, and derived
    # payloads (generative/ladder) legitimately record the classified
    # context -- so the row shows both sources.  Pre-311 the sampled
    # candidates were stamped 'html_element' too and the sentinel family
    # could never appear.
    assert "unit_test_family" in row["payload_classes"], (
        f"the dispatch stamp ignored the sampler's family tag "
        f"({row['payload_classes']})")
    assert "html_element" in row["payload_classes"], (
        "derived payloads must still show the classified context")
