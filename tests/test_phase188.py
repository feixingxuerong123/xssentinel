"""Phase 188: competitor absorption round two, per-item behavioural tests.

  * kxss-style meta-char triage on findings (reflection_profile.triage_line
    wired through _record);
  * blind-XSS collection beacons: the ezXSS/XSSHunter-style collector
    payload + SelfHostedListener query recording + collect_oob reporting;
  * async JSONP gadget parity: the Phase-183 wrapper is the browser, but
    the candidate is only emitted when a browser actually exists (same
    semantics as sync).
"""
from __future__ import annotations

import os
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import csp as csp_mod  # noqa: E402
from xssentinel.core import reflection_profile as rp_mod  # noqa: E402
from xssentinel.core.oob import SelfHostedListener  # noqa: E402

_LAB_JSONP = '<script src="__SRC__/jsonp?cb=alert(1)//"></script>'


# ---------------------------------------------------------------------------
# 1. reflected_meta triage
# ---------------------------------------------------------------------------

class TestTriageLine:
    def test_raw_kept_chars_lead(self):
        p = rp_mod.profile_reflection("x xssp_1234\"'><>()=/;`", "xssp_1234")
        line = rp_mod.triage_line(p)
        assert line and line.startswith('raw="')
        assert "stripped=" not in line and "encoded=" not in line

    def test_partial_reflection_shows_all_buckets(self):
        p = rp_mod.profile_reflection("x xssp_1234&quot;'><", "xssp_1234")
        line = rp_mod.triage_line(p)
        assert line and "encoded=" in line

    def test_no_profile_is_none(self):
        assert rp_mod.triage_line(None) is None
        assert rp_mod.triage_line({"reflected": False}) is None


def test_finding_carries_reflected_meta():
    """A confirmed reflected finding must carry the kxss-style line when
    the sandwich profile ran for that param."""
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session (security software/TCP state)")

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            from urllib.parse import urlparse, parse_qs
            u = urlparse(self.path)
            q = (parse_qs(u.query).get("q") or [""])[0]
            body = (f"<!DOCTYPE html><html><body><div id=\"out\">"
                    f"{q}</div></body></html>").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.2)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        from xssentinel.core.requester import Requester
        from xssentinel.core.scanner import Scanner

        sc = Scanner(requester=Requester(timeout=8), use_headless=False,
                     max_payloads=2, max_transforms=1, verbose=False)
        sc.scan_target(base + "/", method="GET", params={"q": "probe"})
        metas = [f.data.get("reflected_meta") for f in sc.findings
                 if hasattr(f, "data") and f.data.get("type") == "reflected"]
        assert any(m and m.startswith('raw="') for m in metas), \
            f"no reflected_meta on confirmed findings: {metas}"
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# 2. blind collection beacons
# ---------------------------------------------------------------------------

def test_listener_records_beacon_query():
    lst = SelfHostedListener(host="127.0.0.1")   # OS-assigned port
    lst.start()
    try:
        tok = lst.token()
        q = "c=secret%3D1&l=%5B%5D&p=http%3A%2F%2Ft%2F&r=ref&u=UA&d=%3Cp%3E"
        urllib.request.urlopen(lst.callback_url(tok) + "?" + q,
                               timeout=5).read()
        assert lst.poll({tok}, timeout=3) == {tok}
        assert lst.hit_query(tok) == q
        assert lst.hit_query("never-sent") == ""
    finally:
        lst.stop()


def test_collect_oob_reports_collected_params():
    """End to end on loopback: injection -> beacon with collection params ->
    confirmed blind finding whose detail names the params and whose proof
    carries the raw query."""
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session (security software/TCP state)")

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            from urllib.parse import urlparse, parse_qs
            u = urlparse(self.path)
            q = (parse_qs(u.query).get("q") or [""])[0]
            body = (f"<!DOCTYPE html><html><body><div id=\"out\">"
                    f"{q}</div></body></html>").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.2)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        from xssentinel.core.requester import Requester
        from xssentinel.core.scanner import Scanner

        oob = SelfHostedListener(host="127.0.0.1")
        sc = Scanner(requester=Requester(timeout=8), oob=oob, verbose=False)
        sc.scan_endpoint(base + "/blind", "GET", {"q": "test"}, {})
        assert sc._oob_pending, "blind injection never armed"
        # The armed payload must be the COLLECTOR (it rides first).
        assert "localStorage" in sc._oob_pending[0]["payload"]
        tok = sc._oob_pending[0]["token"]
        oob.start()
        sc._oob_started = True
        beacon_q = ("c=admin%3D1&l=%7B%22k%22%3A%22v%22%7D&s=%7B%7D"
                    "&r=http%3A%2F%2Fadmin.example%2F&p=" + base
                    + "%2Fblind&u=Firefox&d=%3Cdiv%3E")
        urllib.request.urlopen(oob.callback_url(tok) + "?" + beacon_q,
                               timeout=5).read()
        sc.collect_oob(timeout=3)
        blind = [f.data for f in sc.findings
                 if f.data.get("type") == "blind"]
        assert blind, "confirmed blind finding missing"
        d = blind[0]
        assert "collection params" in d["detail"]
        for name in ("c", "d", "l", "p", "r", "s", "u"):
            assert name in d["detail"].split("collection params:")[1] \
                .split("(legend")[0], f"param {name} missing from detail"
        assert d["proof"]["callback_query"].startswith("c=")
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# 3. async JSONP gadget parity
# ---------------------------------------------------------------------------

def _async_jsonp_lab(available: bool):
    """Run the async scan against a CSP-gadget lab page.

    Returns (findings, evidence_classes).  ``available`` monkeypatches the
    browser-availability gate: True -> the JSONP candidate is emitted and
    the Phase-183 wrapper confirms it; False -> nothing is emitted (the
    sync-without-headless semantics).
    """
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session (security software/TCP state)")
    from xssentinel.core import dom_engine
    if available and not dom_engine.DynamicDomAnalyzer.available():
        pytest.skip("playwright/chromium not available")

    class H(BaseHTTPRequestHandler):
        port = 0

        def do_GET(self):
            from urllib.parse import urlparse, parse_qs, unquote
            u = urlparse(self.path)
            q = (parse_qs(u.query).get("q") or [""])[0]
            if u.path == "/jsonp":
                # the lab's attacker-controlled JSONP endpoint: echo the
                # callback param as the response body
                cb = unquote((parse_qs(u.query).get("cb") or [""])[0])
                body = cb.encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            body = (f"<!DOCTYPE html><html><body><div id=\"out\">"
                    f"{q}</div></body></html>").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            if u.path == "/gadget":
                self.send_header(
                    "Content-Security-Policy",
                    f"script-src 'self' http://127.0.0.1:{self.port}")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), H)
    H.port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.2)
    csp_mod._EXTRA_GADGETS.clear()
    csp_mod.register_gadget(r"127\.0\.0\.1", _LAB_JSONP, "lab JSONP gadget")

    import asyncio
    from unittest.mock import patch
    from xssentinel.core.async_scanner import AsyncScanner

    async def _run():
        asc = AsyncScanner(max_concurrent=4, max_payloads=3,
                           max_transforms=2, timeout=8,
                           use_headless=available)
        got = []
        async for f in asc.scan(
                f"http://127.0.0.1:{H.port}/gadget", params={"q": "probe"}):
            got.append(f.data if hasattr(f, "data") else dict(f))
        return got

    try:
        if available:
            got = asyncio.run(_run())
        else:
            with patch.object(dom_engine.DynamicDomAnalyzer, "available",
                              staticmethod(lambda: False)):
                got = asyncio.run(_run())
        return got
    finally:
        csp_mod._EXTRA_GADGETS.clear()
        server.shutdown()
        server.server_close()


def test_async_jsonp_gadget_confirmed_by_wrapper():
    got = _async_jsonp_lab(available=True)
    gadgets = [d for d in got
               if "csp_gadget" in tuple(d.get("transform") or [])]
    assert gadgets, f"async JSONP gadget produced no finding: {got}"
    d = gadgets[0]
    # The Phase-183 wrapper upgraded the candidate to a browser verdict.
    assert d["evidence_class"] == "browser-executed", d
    assert d["confidence"] == "high"
    assert (d.get("headless") or {}).get("confirmed") is True


def test_async_jsonp_gadget_silent_without_browser():
    got = _async_jsonp_lab(available=False)
    gadgets = [d for d in got
               if "csp_gadget" in tuple(d.get("transform") or [])]
    assert not gadgets, (
        "a browserless async engine must not emit JSONP gadget candidates "
        "(sync-without-headless emits nothing either)")
