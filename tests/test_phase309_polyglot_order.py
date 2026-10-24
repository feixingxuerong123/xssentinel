# -*- coding: utf-8 -*-
"""Phase 309: the polyglot probe must never preempt the context queue.

Defect (measured on the five benchmark cases that scored FN after the
Phase 308 gate): ``_fire_probe_variants`` appended ``build_polyglot(marker)``
to EVERY candidate's variant list.  On a raw-echoing page the candidate
queue leads with the corpus polyglot (``cross_context_candidates``), whose
base and transform variants the static verifier correctly refuses -- and
then the appended flavour CONFIRMED, set ``param_confirmed`` and stopped
the loop before any context-specific payload was ever sent.  The finding
came out ``polyglot_reflection``/medium where sync -- which never had the
append; its polyglot lives in the L7 layer behind the nothing-confirmed
guard -- confirms ``reflected``/high on the same page.  Five manifest
cases scored FN on the scorer's ``finding_types: ["reflected"]`` narrowing
alone.

Fix: the flavour fires ONCE, after the whole candidate queue -- never
ahead of a context payload, still reached when nothing context-specific
confirmed, same grading as before.

The pre-fix engine yields ``polyglot_reflection`` on the raw page below,
so test 1 is red against the old code by construction.
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

from xssentinel.core.async_scanner import AsyncScanner  # noqa: E402
from xssentinel.core.requester import Requester  # noqa: E402
from xssentinel.core.scanner import Scanner  # noqa: E402

_BUDGETS = dict(max_payloads=10, max_transforms=6)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        parts = urlsplit(self.path)
        value = (parse_qs(parts.query).get("q") or [""])[0]
        safe = parts.path.endswith("-safe")
        if parts.path.rstrip("-safe") not in ("/raw", "/raw-safe"):
            self.send_response(404)
            self.end_headers()
            return
        if safe:
            body = f"<html><body>{html.escape(value, quote=True)}</body></html>"
        else:
            body = f"<html><body>results for {value}</body></html>"
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


def _scan_async(base, path):
    async def _run():
        asc = AsyncScanner(max_concurrent=2, per_host_delay=0, jitter=0,
                           timeout=8, dom_engine="off",
                           advanced_layers=False, **_BUDGETS)
        return [f.data async for f in asc.scan(
            base + path, method="GET", params={"q": "a"})]

    try:
        return asyncio.run(asyncio.wait_for(_run(), timeout=90))
    except asyncio.TimeoutError:
        pytest.fail(f"async scan of {path} did not finish within 90s")


def _scan_sync(base, path):
    sc = Scanner(requester=Requester(timeout=8), dom_engine="off",
                 advanced_layers=False, **_BUDGETS)
    sc.scan_endpoint(base + path, "GET", {"q": "a"}, {})
    return [f.data for f in sc.findings]


def _hits(rows):
    return [r for r in rows
            if r.get("type") in ("reflected", "polyglot_reflection")
            and r.get("severity") in ("high", "medium", "critical")]


def test_raw_echo_confirms_reflected_before_any_polyglot(base):
    """THE regression: the first confirm on a raw-echo page is reflected.

    Pre-fix this exact scan yielded polyglot_reflection/medium: the
    appended flavour confirmed on the corpus-polyglot candidate and
    stopped the loop before ``<script>alert()`` (candidate #2) was sent.
    """
    rows = _scan_async(base, "/raw")
    hits = _hits(rows)
    assert hits, "async reported nothing on a raw-echo page"
    types = {r["type"] for r in hits}
    assert types == {"reflected"}, (
        f"polyglot probe preempted the context queue: got {types} "
        f"(payload {[r.get('payload', '')[:40] for r in hits]})")
    assert hits[0]["severity"] == "high"
    assert hits[0]["confidence"] == "high"


def test_sync_agrees_on_the_same_page(base):
    """Dual-engine shape agreement (the parity contract, one page form)."""
    s_rows = _scan_sync(base, "/raw")
    a_rows = _scan_async(base, "/raw")
    s_types = {r["type"] for r in _hits(s_rows)}
    a_types = {r["type"] for r in _hits(a_rows)}
    assert s_types == a_types, f"sync={s_types} async={a_types}"
    assert s_types == {"reflected"}


def test_escaped_twin_stays_silent_tail_included(base):
    """The tail flavour must not turn an escaped echo into a finding."""
    rows = _scan_async(base, "/raw-safe")
    assert _hits(rows) == [], (
        f"safe twin produced findings: {[r.get('type') for r in _hits(rows)]}")
