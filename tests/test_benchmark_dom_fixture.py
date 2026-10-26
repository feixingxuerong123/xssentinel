# -*- coding: utf-8 -*-
"""The three hash->DOM benchmark fixtures must be executable as written.

Phase 265 measured the old pages: Chromium percent-encodes '<' in
``location.hash``, so ``innerHTML = location.hash.slice(1)`` received
``%3Cimg...%3E`` as inert text.  The DOM engine's old self-alert made those
cases look browser-confirmed; the class split exposed the stale ground
truth.  The fixtures now decode the fragment, and the jQuery one uses the
repository's vendored build instead of a CDN that cannot load offline.

These tests are cheap (static + one HTTP asset + three real dialogs) and
pin exactly the property that went stale for many phases.
"""
from __future__ import annotations

import json
import os
import sys
import threading
from http.server import ThreadingHTTPServer
from urllib.request import urlopen

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from benchmark.server import (  # noqa: E402
    BenchmarkHandler,
    load_routes,
    m_dom_hash_docwrite,
    m_dom_hash_innerhtml,
    m_dom_jquery_html,
)
from tests.conftest import loopback_healthy  # noqa: E402

pytest.importorskip("playwright.sync_api")


def _body(fn) -> str:
    return fn("")[2]


class TestFixtureSource:
    def test_hash_innerhtml_decodes_before_parsing(self):
        body = _body(m_dom_hash_innerhtml)
        assert "decodeURIComponent(location.hash.slice(1))" in body

    def test_hash_docwrite_decodes_before_writing(self):
        body = _body(m_dom_hash_docwrite)
        assert "decodeURIComponent(location.hash.slice(1))" in body

    def test_jquery_html_uses_local_vendor_and_decodes(self):
        body = _body(m_dom_jquery_html)
        assert "/vendor/jquery.min.js" in body
        assert "code.jquery.com" not in body
        assert "decodeURIComponent(location.hash.slice(1))" in body


@pytest.fixture()
def bench_base():
    if not loopback_healthy():
        pytest.skip("loopback unavailable")
    BenchmarkHandler.routes = load_routes()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), BenchmarkHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


class TestEngineDeclarations:
    def test_second_order_and_scenario_are_sync_only(self):
        """async has no stored/second-order/scenario flow.

        The manifest lost these ``engines`` declarations during the wipe;
        the async full matrix then ran four vectors it cannot implement and
        scored the two positive twins as FN.  SKIP is the honest result only
        when the manifest says so; this pins the four declarations that
        restore the 10-SKIP baseline.
        """
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "benchmark", "manifest.json")
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        by_id = {c["id"]: c for c in doc["cases"]}
        for cid in ("pos-so2-01", "neg-so2-01",
                    "pos-scn-01", "neg-scn-01"):
            assert by_id[cid].get("engines") == ["sync"], cid


class TestVendoredAsset:
    def test_jquery_is_served_from_the_repo(self, bench_base):
        with urlopen(bench_base + "/vendor/jquery.min.js", timeout=15) as r:
            body = r.read()
            ctype = r.headers.get("Content-Type", "")
        assert r.status == 200
        assert "javascript" in ctype.lower()
        assert b"jQuery" in body or b"jquery" in body
        assert len(body) > 10_000


class TestRealBrowser:
    """One dialog per case is the ground-truth check.  If a fixture stops
    executing, this fails here instead of surfacing as a mysterious FN in a
    15-minute matrix."""

    @pytest.mark.parametrize("path", [
        "/dom/hash-innerhtml",
        "/dom/hash-docwrite",
        "/dom/jquery-html",
    ])
    def test_fixture_fires_in_chromium(self, bench_base, path):
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                page = browser.new_context().new_page()
                dialogs = []
                page.on("dialog", lambda d: (dialogs.append(d.message),
                                             d.dismiss()))
                page.goto(
                    bench_base + path
                    + "#%3Cimg%20src=x%20onerror=alert(777)%3E",
                    wait_until="load", timeout=30000)
                page.wait_for_timeout(1000)
                assert "777" in dialogs, (
                    f"{path} did not execute the decoded fragment; "
                    f"dialogs={dialogs}")
            finally:
                browser.close()
