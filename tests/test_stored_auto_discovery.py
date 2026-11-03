# -*- coding: utf-8 -*-
"""Phase 352: stored-XSS viewer auto-discovery.

The explicit --stored-inject path needs an operator to name the viewer.  This
gate locks the default path instead: a URL-only target whose page carries a
POST form must be exercised, the viewer located (redirect landing / viewer
link / sink-backed API), and a `stored` finding emitted -- with an escaped
twin staying silent.

Runs in-process against a local fixture (no external target), so it is part
of the normal file-per-file gate rather than an opt-in acceptance test.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import pytest

from xssentinel.core import stored_discovery
from xssentinel.core.requester import Requester
from xssentinel.core.scanner import Scanner

RAW_STORE: list[str] = []
SAFE_STORE: list[str] = []
SPA_STORE: list[str] = []


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence the fixture
        pass

    def _send(self, body: str, status: int = 200, ctype="text/html",
              extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body.encode())))
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/gb":
            items = "".join(f"<div>{v}</div>" for v in RAW_STORE)
            self._send("<html><body><form method='post'>"
                       "<input name='msg'></form>" + items + "</body></html>",
                       extra={"ETag": f'"{len(items)}"'})
        elif path == "/gb-redirect":
            self._send("<html><body><form method='post' "
                       "action='/gb-redirect'><input name='msg'></form>"
                       "</body></html>")
        elif path == "/list2":
            items = "".join(f"<div>{v}</div>" for v in RAW_STORE)
            self._send("<html><body>" + items + "</body></html>",
                       extra={"ETag": f'"{len(items)}"'})
        elif path == "/safe":
            items = "".join(f"<div>{v}</div>" for v in SAFE_STORE)
            self._send("<html><body><form method='post'>"
                       "<input name='msg'></form>" + items + "</body></html>",
                       extra={"ETag": f'"{len(items)}"'})
        elif path == "/spa":
            self._send("<html><body><form method='post'>"
                       "<input name='msg'></form><div id='out'></div>"
                       "<script>fetch('/spa/api').then(r=>r.json())"
                       ".then(d=>{document.getElementById('out')"
                       ".innerHTML=d.msg})</script></body></html>")
        elif path == "/spa/api":
            self._send('{"msg": %s}' % _json_str(SPA_STORE[-1] if SPA_STORE else ""),
                       ctype="application/json")
        elif path == "/login":
            self._send("<html><body><form method='post'>"
                       "<input name='user'><input type='password' name='pass'>"
                       "</form></body></html>")
        else:
            self._send("<html><body>plain</body></html>")

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length") or 0)
        data = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        value = (data.get("msg") or [""])[0]
        if path == "/gb":
            RAW_STORE.append(value)
            self._send("<html><body>ok</body></html>")
        elif path == "/gb-redirect":
            RAW_STORE.append(value)
            self._send("", status=302, extra={"Location": "/list2"})
        elif path == "/safe":
            SAFE_STORE.append(value.replace("<", "").replace(">", ""))
            self._send("<html><body>ok</body></html>")
        elif path == "/spa":
            SPA_STORE.append(value)
            self._send("<html><body>ok</body></html>")
        else:
            self._send("<html><body>ok</body></html>")


def _json_str(s: str) -> str:
    import json
    return json.dumps(s)


@pytest.fixture()
def server():
    RAW_STORE.clear()
    SAFE_STORE.clear()
    SPA_STORE.clear()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def _scan(base, path, **kw):
    sc = Scanner(requester=Requester(timeout=6), stored_auto=kw.pop(
        "stored_auto", True), dom_engine="static", threads=1,
        max_payloads=6, max_transforms=2, **kw)
    sc.scan_target(base + path)
    return [f.data for f in sc.findings]


def test_discover_write_faces_skips_login_and_keeps_companions():
    html = ("<form method='post' action='/gb'>"
            "<input name='msg'><input type='text' name='title'>"
            "<input type='hidden' name='csrf' value='S'>"
            "<input type='password' name='pass'></form>")
    assert stored_discovery.discover_write_faces(html, "http://h/") == []

    html2 = ("<form method='post' action='/gb'>"
             "<input name='msg'><input type='text' name='title'>"
             "<input type='hidden' name='csrf' value='S'></form>")
    faces = stored_discovery.discover_write_faces(html2, "http://h/")
    assert len(faces) == 1
    assert faces[0]["action"] == "http://h/gb"
    assert faces[0]["fields"] == ["msg", "title"]
    assert faces[0]["data"] == {"csrf": "S"}


def test_discover_view_urls_requires_sink_for_api():
    html = ('<a href="/comments/list">list</a>'
            "<script>fetch('/app/api').then(d=>{el.innerHTML=d.x})</script>")
    views, api = stored_discovery.discover_view_urls(
        html, "http://h/write", "http://h/write")
    assert "http://h/comments/list" in views
    assert "http://h/app/api" in views and "http://h/app/api" in api

    # No sink -> the API path is not a viewer (JSON is not execution).
    views2, api2 = stored_discovery.discover_view_urls(
        "<script>fetch('/app/api')</script>", "http://h/write", "http://h/write")
    assert "http://h/app/api" not in views2
    assert api2 == set()


def test_auto_stored_self_view_confirms(server):
    found = _scan(server, "/gb")
    stored = [f for f in found if f.get("type") == "stored"]
    assert stored, f"expected a stored finding, got {found}"
    f = stored[0]
    assert f["param"] == "msg" and f["method"] == "POST"
    assert f["proof"]["view_url"].endswith("/gb")
    assert f["confidence"] == "medium"  # same-session self-view is honest


def test_auto_stored_redirect_landing_confirms(server):
    # The form posts to /gb-redirect, which 302s to /list2.  The landing is
    # the viewer; the write page itself never renders the entry.
    found = _scan(server, "/gb-redirect")
    stored = [f for f in found if f.get("type") == "stored"]
    assert stored, f"expected a stored finding, got {found}"
    assert stored[0]["proof"]["view_url"].endswith("/list2"), stored[0]


def test_auto_stored_escaped_twin_is_silent(server):
    found = _scan(server, "/safe")
    assert not [f for f in found if f.get("type") == "stored"], found


def test_auto_stored_api_viewer_confirms(server):
    found = _scan(server, "/spa")
    stored = [f for f in found if f.get("type") == "stored"]
    assert stored, f"expected a stored finding, got {found}"
    assert stored[0]["proof"]["view_url"].endswith("/spa/api"), stored[0]


def test_no_stored_auto_flag_disables(server):
    found = _scan(server, "/gb", stored_auto=False)
    assert not [f for f in found if f.get("type") == "stored"], found
