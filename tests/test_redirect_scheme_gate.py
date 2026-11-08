# -*- coding: utf-8 -*-
"""A redirect Location is attacker-controlled bytes, not a URL we chose.

Measured on official XSSMaze (2026-11-08): a 302 whose Location is a
``javascript:`` payload was followed by requests, which then raised
``InvalidSchema: No connection adapters were found for "javascript:..."``.
The failure was counted, so 14-16 of 86 targets came back
``scan_status=partial`` -- the scanner looked broken on a target that was
merely reflecting our own probe into a Location header.

What this locks:

1. A hop whose resolved scheme is not http/https is NOT followed.  The 3xx
   itself is handed back, no synthetic response, and -- importantly -- no
   request is attempted, so the tally records no failure and the scan is not
   marked partial.
2. Legitimate relative / absolute / protocol-relative redirects still work.
   A scheme allowlist applied to the RAW Location would silently kill these.
"""
import ast
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from tests.conftest import loopback_healthy  # noqa: E402
from xssentinel.core.requester import Requester  # noqa: E402
from xssentinel.core.url_safety import is_safe_redirect  # noqa: E402


class _State:
    visits = []
    base = ""


class _Handler(BaseHTTPRequestHandler):
    """One endpoint per Location shape; /land is the follow-through target."""

    def do_GET(self):
        path = urlparse(self.path).path
        _State.visits.append(path)
        locations = {
            "/js": "javascript:window.onerror=alert;throw 1",
            "/data": "data:text/html,<script>alert(1)</script>",
            "/vbs": "vbscript:msgbox(1)",
            "/file": "file:///etc/passwd",
            "/rel": "/land",
            "/abs": _State.base + "/land",
            "/schemeless": "//" + _State.base.split("//", 1)[1].split("/")[0] + "/land",
        }
        if path in locations:
            self.send_response(302)
            self.send_header("Location", locations[path])
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"landed"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def server(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    if not loopback_healthy():
        pytest.skip("loopback degraded on this host")
    _State.visits = []
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    _State.base = f"http://127.0.0.1:{httpd.server_port}"
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        yield _State.base
    finally:
        httpd.shutdown()
        httpd.server_close()
        t.join(timeout=2)


@pytest.mark.parametrize("path", ["/js", "/data", "/vbs", "/file"])
def test_unsafe_scheme_redirect_is_not_followed(server, path):
    """The 3xx comes back untouched and NO request failure is recorded."""
    _State.visits = []
    tally_owner = Requester(timeout=5)
    resp = tally_owner.get(server + path)
    assert resp.status_code == 302, "the redirect must be visible, not swallowed"
    assert _State.visits == [path], "a non-http hop must not be requested"
    assert tally_owner.tally.failed == 0, (
        "a refused hop is not a transport failure; it must not mark the scan "
        "partial")
    assert tally_owner.failure_reasons == [], (
        "no InvalidSchema should ever reach the failure tally")


@pytest.mark.parametrize("path", ["/rel", "/abs", "/schemeless"])
def test_legitimate_redirects_still_follow(server, path):
    """An allowlist on the RAW Location would break these -- do not."""
    _State.visits = []
    resp = Requester(timeout=5).get(server + path)
    assert resp.status_code == 200
    assert resp.text == "landed"
    assert _State.visits == [path, "/land"]


# -- shared allowlist boundaries -------------------------------------------

@pytest.mark.parametrize("loc", [
    "JAVASCRIPT:alert(1)", "java\tscript:alert(1)", "java\nscript:alert(1)",
    "data:text/html,x", "vbscript:msgbox(1)", "file:///etc/passwd",
    "mailto:a@b", "blob:http://x/u", "about:blank",
])
def test_allowlist_rejects_non_http_schemes_and_variants(loc):
    assert not is_safe_redirect("http://h/p?q=1", loc)


@pytest.mark.parametrize("loc", [
    "/land", "//cdn.example/x", "http://h/land", "https://h/land",
    "?next=1", "#frag", "../up",
])
def test_allowlist_keeps_legal_relative_and_absolute_hops(loc):
    assert is_safe_redirect("http://h/p?q=1", loc)


def test_empty_location_means_no_redirect():
    assert is_safe_redirect("http://h/p", None)
    assert is_safe_redirect("http://h/p", "")


# -- source contract: the gate must not rot back into a hand-written copy ---

def _source(rel):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, rel), encoding="utf-8") as fh:
        return fh.read()


def _method_node(rel, cls_name, fn_name):
    tree = ast.parse(_source(rel))
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == cls_name:
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                        and item.name == fn_name:
                    return item
    raise AssertionError(f"{rel}:{cls_name}.{fn_name} not found")


def _literals(node):
    return [n.value for n in ast.walk(node)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def test_guard_is_wired_to_the_shared_allowlist():
    node = _method_node("xssentinel/core/requester.py",
                        "GuardedSession", "get_redirect_target")
    called = {n.func.id for n in ast.walk(node)
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert "is_safe_redirect" in called, (
        "the hop gate must use the one shared allowlist, not a local copy")
    assert "from .url_safety import is_safe_redirect" in _source(
        "xssentinel/core/requester.py")


def test_guard_does_not_handwrite_a_scheme_blacklist():
    node = _method_node("xssentinel/core/requester.py",
                        "GuardedSession", "get_redirect_target")
    lits = {s.strip().lower() for s in _literals(node)}
    for bad in ("javascript:", "data:", "vbscript:", "http", "https"):
        assert bad not in lits, (
            f"hand-written scheme token {bad!r} -- use url_safety instead")


def test_shared_module_is_the_only_definition():
    src = _source("xssentinel/core/url_safety.py")
    tree = ast.parse(src)
    fns = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
    assert "is_safe_redirect" in fns
    assert "_ALLOWED_SCHEMES" in src
