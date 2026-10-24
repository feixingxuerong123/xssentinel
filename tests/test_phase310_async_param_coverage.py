# -*- coding: utf-8 -*-
"""Phase 310: the async engine writes the per-param coverage columns.

Phase 290 wired requests and layers into the async tracker, but the
per-parameter row stayed unwired: every --async report read
``reflected=False / context=None / payloads_sent=0 / confirmed=False``
for scans that had just confirmed a finding on that very param
(measured on the benchmark's /r/jsecho01 during the Phase 309 probe,
which is what misread "0 payloads dispatched" as engine behavior).
Sync writes these columns from scanner.py's Phase 20-3 record_param
sites; this pins the async mirror.

Pre-fix, test 1 fails on every asserted field.
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

_BUDGETS = dict(max_payloads=10, max_transforms=6)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        parts = urlsplit(self.path)
        value = (parse_qs(parts.query).get("q") or [""])[0]
        safe = parts.path.endswith("-safe")
        body = (f"<html><body>{html.escape(value, quote=True)}</body></html>"
                if safe else
                f"<html><body>results for {value}</body></html>")
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


def _scan(base, path):
    async def _run():
        asc = AsyncScanner(max_concurrent=2, per_host_delay=0, jitter=0,
                           timeout=8, dom_engine="off",
                           advanced_layers=False, **_BUDGETS)
        async for _f in asc.scan(base + path, method="GET",
                                 params={"q": "a"}):
            pass
        return asc

    try:
        return asyncio.run(asyncio.wait_for(_run(), timeout=90))
    except asyncio.TimeoutError:
        pytest.fail(f"async scan of {path} did not finish within 90s")


def _param_row(asc, path):
    """The one (endpoint, param) row the L1 scan must have written."""
    rows = []
    for ep in asc.coverage._endpoints.values():
        for pc in ep.params.values():
            rows.append(pc.to_dict())
    assert rows, f"no param rows recorded for {path}"
    return rows


def test_raw_echo_param_row_is_fully_wired(base):
    """reflected / context / payloads_sent / confirmed all read true."""
    asc = _scan(base, "/raw")
    rows = _param_row(asc, "/raw")
    confirmed = [r for r in rows if r["confirmed"]]
    assert confirmed, f"no confirmed param row: {rows}"
    row = confirmed[0]
    assert row["reflected"] is True
    assert row["context"], "context column empty on a confirmed param"
    assert row["payloads_sent"] >= 1, (
        "payload dispatch counter stayed at zero (the Phase 309 probe "
        "misread this as engine behavior)")
    assert row["payload_classes"], "payload_classes empty on a confirmed param"


def test_safe_twin_row_reflected_but_never_confirmed(base):
    """The escaped twin still shows the probe work, minus the confirm."""
    asc = _scan(base, "/raw-safe")
    rows = _param_row(asc, "/raw-safe")
    assert rows, "no param rows recorded for the safe twin"
    row = rows[0]
    assert row["reflected"] is True, (
        "escaped echo IS a reflection -- the row must say so")
    assert row["payloads_sent"] >= 1
    assert row["confirmed"] is False, (
        "an escaped echo must not read as a confirmed param")
