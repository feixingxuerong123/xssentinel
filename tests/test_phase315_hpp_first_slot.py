# -*- coding: utf-8 -*-
"""Phase 315: the HPP probe covers BOTH duplicate orderings.

Phase 193's probe sent first-occurrence-benign / second-occurrence-payload
-- it catches filters that read the FIRST value.  XSSMaze hpp-level1 is
the mirror shape, measured with curl before any code moved: the filter
inspects the LAST value (a dangerous last value gets the whole param
dropped) while the renderer shows the FIRST -- so the exploit REQUIRES
the payload in the first slot, and the single-value form is filtered too
(no L1 path).  The engine also lost the duplicate-key evidence at CLI
parse (``setdefault`` keeps one value); the dup names now reach the
engines as ``dup_params`` and widen the HPP gate beyond WAF fingerprints.

The pre-fix engine sends only the benign-first ordering, so test 1 and 2
are red by construction against it.
"""
import asyncio
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from xssentinel.core.async_scanner import AsyncScanner  # noqa: E402
from xssentinel.core.requester import Requester  # noqa: E402
from xssentinel.core.scanner import Scanner  # noqa: E402

_BUDGETS = dict(max_payloads=10, max_transforms=6)


class _Handler(BaseHTTPRequestHandler):
    """The measured lab shape: render FIRST q value raw, but only when the
    LAST q value is benign (the filter inspects the last occurrence)."""

    def log_message(self, *args):
        pass

    def do_GET(self):
        parts = urlsplit(self.path)
        qs = parse_qs(parts.query, keep_blank_values=True)
        vals = qs.get("q") or []
        last_dangerous = bool(vals) and ("<" in vals[-1] or "%" in vals[-1])
        first = vals[0] if vals else ""
        if last_dangerous:
            body = "<html><body>[filtered]</body></html>"
        else:
            body = f"<html><body>results for {first}</body></html>"
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


def _scan_sync(base, dup_params):
    sc = Scanner(requester=Requester(timeout=8), dom_engine="off",
                 advanced_layers=False, dup_params=dup_params, **_BUDGETS)
    sc.scan_endpoint(base + "/hpp", "GET", {"q": "safe"}, {})
    return [f.data for f in sc.findings]


def _scan_async(base, dup_params):
    async def _run():
        asc = AsyncScanner(max_concurrent=2, per_host_delay=0, jitter=0,
                           timeout=8, dom_engine="off",
                           advanced_layers=False, dup_params=dup_params,
                           **_BUDGETS)
        return [f.data async for f in asc.scan(
            base + "/hpp", method="GET", params={"q": "safe"})]

    try:
        return asyncio.run(asyncio.wait_for(_run(), timeout=120))
    except asyncio.TimeoutError:
        pytest.fail("async scan did not finish within 120s")


def test_sync_first_slot_ordering_confirms(base):
    """Dup evidence, no WAF: the payload-first HPP shape must confirm."""
    rows = _scan_sync(base, {"q"})
    hpp = [r for r in rows if r.get("transform") == ["hpp"]]
    assert hpp, (
        f"no HPP finding (all rows: {[r.get('type') for r in rows]}) -- "
        "the payload-first ordering was never sent")
    assert hpp[0]["severity"] == "high"


def test_async_first_slot_ordering_confirms(base):
    rows = _scan_async(base, {"q"})
    hpp = [r for r in rows if r.get("transform") == ["hpp"]]
    assert hpp, (
        f"async: no HPP finding ({[r.get('type') for r in rows]})")


def test_no_dup_evidence_and_no_waf_stays_silent(base):
    """Gate unchanged: without dup evidence and without a WAF fingerprint
    the HPP layer does not fire (the single-value form IS filtered, so
    nothing else confirms either)."""
    rows = _scan_sync(base, set())
    assert not [r for r in rows if r.get("transform") == ["hpp"]], (
        "HPP fired without dup evidence or a WAF -- gate widened too far")


def test_async_no_dup_evidence_stays_silent(base):
    rows = _scan_async(base, set())
    assert not [r for r in rows if r.get("transform") == ["hpp"]]
