"""Phase 196: browser-rendered input discovery + HPP body position.

  * harvest(): one render of the target yields the LIVE input face --
    SPA form-field names for the mining wordlist and the same-origin API
    endpoints the page itself fetched as additional scan targets.  The
    normalizer is a pure function (untrusted page output in, capped
    same-origin lists out) and is unit-tested without a browser.
  * HPP gains the form-body position (Phase 193 did query only): the
    parameter rides twice in a raw urlencoded body -- a dict cannot carry
    duplicate keys, so the body is a string with an explicit
    application/x-www-form-urlencoded Content-Type.
"""
from __future__ import annotations

import html
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.dom_engine import _normalize_harvest  # noqa: E402


# ---------------------------------------------------------------------------
# _normalize_harvest (pure)
# ---------------------------------------------------------------------------

class TestNormalizeHarvest:
    def test_names_dedup_cap(self):
        raw = {"names": ["q", "q", "comment", "", None, "author"],
               "urls": []}
        out = _normalize_harvest(raw, "http://t/")
        assert out["names"] == ["q", "comment", "author"]

    def test_names_cap(self):
        raw = {"names": [f"n{i}" for i in range(300)], "urls": []}
        assert len(_normalize_harvest(raw, "http://t/")["names"]) == 200

    def test_resource_urls_same_origin_only(self):
        raw = {"names": [],
               "urls": ["http://t/api/comments?limit=5",
                        "https://analytics.thirdparty/collect",
                        "ftp://t/x",
                        "http://t/api/comments?limit=5",
                        "not a url",
                        "/relative/only"]}
        out = _normalize_harvest(raw, "http://t/")
        assert out["resource_urls"] == ["http://t/api/comments?limit=5"]

    def test_host_match_is_case_insensitive_and_fragments_dropped(self):
        raw = {"names": [],
               "urls": ["http://T:80/api#a#b", "http://t/api#frag"]}
        out = _normalize_harvest(raw, "http://t/")
        assert out["resource_urls"] == ["http://t/api"]

    def test_garbage_input_degrades(self):
        assert _normalize_harvest(None, "http://t/") == \
            {"names": [], "resource_urls": []}
        assert _normalize_harvest([1, 2], "http://t/") == \
            {"names": [], "resource_urls": []}

    def test_cross_host_targets_are_never_kept(self):
        raw = {"names": [], "urls": ["http://evil.t/api"]}
        assert _normalize_harvest(raw, "http://t/")["resource_urls"] == []


# ---------------------------------------------------------------------------
# harvest: real render (loopback, browser-gated)
# ---------------------------------------------------------------------------

def test_harvest_names_and_resources():
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session")
    from xssentinel.core import dom_engine
    if not dom_engine.DynamicDomAnalyzer.available():
        pytest.skip("playwright/chromium not available")

    class _H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/api/comments"):
                body = b'{"comments": []}'
            else:
                body = (b"<!DOCTYPE html><html><body>"
                        b"<form><input name=comment><textarea name=body>"
                        b"</textarea><select name=rating></select>"
                        b"<button name=submit>go</button></form>"
                        b"<script>fetch('/api/comments?limit=5');</script>"
                        b"</body></html>")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.2)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        engine = dom_engine.DynamicDomAnalyzer(timeout=15)
        res = engine.harvest(base + "/")
        for name in ("comment", "body", "rating", "submit"):
            assert name in res["names"], (name, res)
        assert any(u.startswith(base + "/api/comments")
                   for u in res["resource_urls"]), res
        assert all(u.split("/")[2] == res["resource_urls"] and True
                   for u in res["resource_urls"][:1])
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# HPP body position
# ---------------------------------------------------------------------------

class _HppBodyHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        from urllib.parse import parse_qs
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        values = parse_qs(raw, keep_blank_values=True).get("q", [])
        first = values[0] if values else ""
        if "<" in first:
            body = (f"<html><body><div>"
                    f"{html.escape(values[-1], quote=True) if values else ''}"
                    f"</div></body></html>").encode()
        else:
            body = (f"<html><body><div>{values[-1] if values else ''}"
                    f"</div></body></html>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture()
def hpp_body_site():
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _HppBodyHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.2)
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def test_hpp_body_confirms_through_first_occurrence_filter(hpp_body_site):
    """POST form field: the single-occurrence ladder is neutered by the
    first-occurrence filter; the duplicated raw body renders the payload."""
    from xssentinel.core.requester import Requester
    from xssentinel.core.scanner import Scanner

    sc = Scanner(requester=Requester(timeout=8), use_headless=False,
                 verbose=False)
    ok = sc._try_hpp(sc.req, f"{hpp_body_site}/write", "POST",
                     {}, {"q": "probe"}, "q", True,
                     [{"payload": "<svg onload=alert(1)>"}], "html_element")
    assert ok, "body-position HPP did not confirm"
    hits = [f.data for f in sc.findings
            if "hpp" in tuple(f.data.get("transform") or [])]
    assert hits and hits[0]["param_in"] == "body"


def test_hpp_body_skips_json_carrier(hpp_body_site):
    """A JSON carrier's duplicate-key semantics belong to the pre-encode
    machinery -- the HPP probe must not touch it."""
    from xssentinel.core.requester import Requester
    from xssentinel.core.scanner import Scanner

    sc = Scanner(requester=Requester(timeout=8), use_headless=False,
                 verbose=False, json_body={"q": "probe"})
    ok = sc._try_hpp(sc.req, f"{hpp_body_site}/write", "POST",
                     {}, {}, "q", True,
                     [{"payload": "<svg onload=alert(1)>"}], "html_element")
    assert ok is False
    assert not [f for f in sc.findings
                if "hpp" in tuple(f.data.get("transform") or [])]
