# -*- coding: utf-8 -*-
"""End-to-end browser test for the desktop console.

The shell tests prove the page's strings/headers; this one proves the JS
actually creates a scan, polls it to completion, renders a finding and lets
the operator act on its PoC.  It starts its own loopback target and the
console's real in-process API -- no fixed ports.
"""
from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from urllib.request import urlopen

import pytest

from tests.conftest import loopback_healthy
from xssentinel.desktop import app as desktop_app

pytest.importorskip("playwright.sync_api")
from playwright.sync_api import sync_playwright  # noqa: E402


class _Target(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        value = (q.get("q") or q.get("v") or [""])[0]
        body = ("<html><body><div id='out'>" + value + "</div></body></html>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_console_creates_and_renders_a_scan():
    if not loopback_healthy():
        pytest.skip("loopback unavailable")
    target = _serve(_Target)
    console = desktop_app.build_server(port=0)
    console.start_in_thread()
    browser = None
    try:
        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(headless=True)
            except Exception as e:  # browser binary missing on a slim host
                pytest.skip(f"chromium unavailable: {e}")
            page = browser.new_context(
                viewport={"width": 1280, "height": 900}).new_page()
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.on("console", lambda m: errors.append(m.text)
                    if m.type == "error" else None)
            page.goto(console.base_url + "/", wait_until="networkidle")
            page.wait_for_selector("#url", timeout=15000)
            assert "XSSentinel" in page.title()
            assert "API" in page.locator("#apiState").inner_text()
            assert not page.locator("#covRing").is_visible(), \
                "an empty coverage ring must stay hidden"

            theme_before = page.evaluate("document.documentElement.dataset.theme")
            page.click("#themeBtn")
            assert page.evaluate("document.documentElement.dataset.theme") != theme_before

            target_url = f"http://127.0.0.1:{target.server_address[1]}/echo?q=test"
            page.fill("#url", target_url)
            page.click('[data-preset="quick"]')
            assert page.input_value("#maxPayloads") == "8"
            page.click("#startBtn")
            page.wait_for_selector("tr[data-id]", timeout=20000)

            deadline = time.time() + 90
            state = ""
            while time.time() < deadline:
                state = page.evaluate(
                    "() => { const r=document.querySelector('tr[data-id]'); "
                    "return r ? r.querySelector('.td-state').innerText.trim() : ''; }")
                if "completed" in state or "failed" in state:
                    break
                time.sleep(0.5)
            assert "completed" in state, state
            scan_id = page.get_attribute("tr[data-id]", "data-id")
            with urlopen(console.base_url + "/api/v1/scans/" + scan_id,
                         timeout=15) as r:
                job = json.load(r)
            # The preset is not decoration: the same budgets must be what the
            # server-side worker received.
            assert job["options"]["max_payloads"] == 8
            assert job["options"]["max_transforms"] == 4
            assert job["options"]["timeout"] == 12

            page.click("tr[data-id]")
            page.wait_for_timeout(1200)
            rows = page.locator("#findingRows tbody tr[data-x]")
            assert rows.count() >= 1, page.locator("#findingRows").inner_text()
            total = rows.count()
            rows.first.click()
            page.wait_for_timeout(200)
            assert page.locator('[data-copy-kind="curl"]').count() >= 1
            assert page.locator('[data-copy-kind="url"]').count() >= 1

            page.select_option("#evidenceF", "browser-refuted")
            page.wait_for_timeout(200)
            assert rows.count() <= total
            page.select_option("#evidenceF", "")
            page.wait_for_timeout(200)
            assert rows.count() == total
            assert not page.locator("#reportBtn").is_disabled()
            assert not errors, errors
    finally:
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass
        for srv in (console._httpd, target):
            try:
                srv.shutdown()
                srv.server_close()
            except Exception:
                pass
