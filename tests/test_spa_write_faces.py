# -*- coding: utf-8 -*-
"""Phase 241/242: SPA write-face discovery -- the offline gates.

Phase 240 measured the gap on OWASP Juice Shop (60 endpoints, L4_stored ran
ZERO times: every Angular form carries no action attribute, so the write
face lives only in component code) and Phase 241 closed it: drive the
rendered page's own UI with a marker, keep the requests whose BODY carries
it, and hand the observed (method, url, field, encoding) triples to the
stored layer.

These are the offline gates for that path:

  * discovery -- a fixture whose Send button emits fetch POST with the
    filled value in a JSON body yields exactly that face;
  * deny-list -- a page whose only button is "Delete" must not be clicked
    (the server log is the evidence: a destructive click would show up as a
    DELETE);
  * attribution -- _marker_field parses JSON, nested JSON and form bodies,
    and returns "" for a body that does not carry the marker.  The control's
    own id is NOT the API field (measured: id "complaintMessage", API field
    "message"), which is why the body is parsed;
  * opt-out -- harvest() without write_faces must not touch the page at all
    (clicking real UI has side effects, so the default is off).
  * Phase 242 -- a nameless icon button is never clicked (with the real
    submit disabled the picker used to fall through to one), while a
    Material ligature button still is (its textContent IS "send").

Run: C:/Python39/python.exe -m pytest tests/test_spa_write_faces.py -q
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.conftest import SOCKETPAIR_OK, loopback_healthy  # noqa: E402

_SEND_PAGE = b"""<html><body>
<textarea name="msg"></textarea>
<button id="send">Send</button>
<script>
document.getElementById('send').addEventListener('click', function(){
  fetch('/api/feedback', {method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({msg: document.querySelector('textarea').value})});
});
</script></body></html>"""

_DANGER_PAGE = b"""<html><body>
<textarea name="msg"></textarea>
<button id="del">Delete account</button>
<script>
document.getElementById('del').addEventListener('click', function(){
  fetch('/api/account', {method: 'DELETE'});
});
</script></body></html>"""

# A control with NO accessible name -- the shape Phase 242 measured on
# Juice Shop's /#/forgot-password, where the real submit ("Change") was
# disabled and the picker fell through to a nameless icon button.
_ICON_ONLY_PAGE = b"""<html><body>
<textarea name="msg"></textarea>
<button id="ico" aria-hidden="true"><svg width="16" height="16"></svg></button>
<script>
document.getElementById('ico').addEventListener('click', function(){
  fetch('/api/unexpected', {method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({msg: document.querySelector('textarea').value})});
});
</script></body></html>"""

# The same icon control WITH a Material ligature: its textContent is
# "send", so it IS the submit action and clicking it is correct.
_LIGATURE_PAGE = b"""<html><body>
<textarea name="msg"></textarea>
<button id="ico"><span class="material-icons">send</span></button>
<script>
document.getElementById('ico').addEventListener('click', function(){
  fetch('/api/feedback', {method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({msg: document.querySelector('textarea').value})});
});
</script></body></html>"""


def _server(pages: dict):
    """pages: path -> html bytes.  Records every request the fixture got."""
    seen: list = []

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _respond(self, code, body=b"", ctype="text/html; charset=utf-8"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            body = pages.get(self.path.split("?")[0])
            if body is None:
                seen.append(("GET", self.path, ""))
                self._respond(404, b"nope")
                return
            self._respond(200, body)

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n).decode("utf-8", "replace")
            seen.append(("POST", self.path, body))
            self._respond(200, json.dumps({"ok": True}).encode(),
                          "application/json")

        def do_DELETE(self):
            seen.append(("DELETE", self.path, ""))
            self._respond(200, b"{}")

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    holder, ready = {}, threading.Event()

    def _run():
        holder["p"] = srv.server_address[1]
        ready.set()
        srv.serve_forever()

    threading.Thread(target=_run, daemon=True).start()
    assert ready.wait(10)
    return srv, holder, seen


@pytest.mark.skipif(not SOCKETPAIR_OK, reason="no socketpair")
class TestWriteFaceDiscovery:
    def test_send_click_yields_the_observed_face(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        from xssentinel.core import dom_engine as dem

        srv, holder, seen = _server({"/send": _SEND_PAGE})
        try:
            url = f"http://127.0.0.1:{holder['p']}/send"
            res = dem.DynamicDomAnalyzer(timeout=20).harvest(
                url, write_faces=True)
            faces = res.get("write_faces") or []
            assert len(faces) == 1, faces
            face = faces[0]
            assert face["method"] == "POST", face
            assert face["url"].endswith("/api/feedback"), face
            assert face["field"] == "msg", (
                "field must be the API field parsed out of the BODY, not the "
                f"control's own name -- got {face['field']!r}")
            assert face["encoding"] == "json", face
            assert any(m == "POST" and "/api/feedback" in p
                       for m, p, _ in seen), (
                f"the fixture never received the POST: {seen}")
        finally:
            srv.shutdown()
            dem.shutdown_thread_browser()

    def test_deny_listed_button_is_never_clicked(self):
        """A destructive control must stay untouched -- clicking real UI is
        why this whole feature is opt-in."""
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        from xssentinel.core import dom_engine as dem

        srv, holder, seen = _server({"/danger": _DANGER_PAGE})
        try:
            url = f"http://127.0.0.1:{holder['p']}/danger"
            res = dem.DynamicDomAnalyzer(timeout=20).harvest(
                url, write_faces=True)
            assert res.get("write_faces") == [], res.get("write_faces")
            assert not any(m == "DELETE" for m, _, _ in seen), (
                f"the deny-listed Delete button was clicked: {seen}")
        finally:
            srv.shutdown()
            dem.shutdown_thread_browser()

    def test_icon_only_button_is_never_clicked(self):
        """Phase 242: with the real submit disabled, the picker used to
        fall through to an icon-only control.  That click is useless at
        best and destructive at worst, so an unnamed button now scores
        zero -- unless it is a submit inside a form."""
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        from xssentinel.core import dom_engine as dem

        srv, holder, seen = _server({"/icon": _ICON_ONLY_PAGE})
        try:
            url = f"http://127.0.0.1:{holder['p']}/icon"
            res = dem.DynamicDomAnalyzer(timeout=20).harvest(
                url, write_faces=True)
            assert res.get("write_faces") == [], res.get("write_faces")
            assert not any("/api/unexpected" in p for _, p, _ in seen), (
                f"an icon-only button was clicked: {seen}")
        finally:
            srv.shutdown()
            dem.shutdown_thread_browser()

    def test_material_ligature_button_is_still_clicked(self):
        """The counterpart: a Material icon button carries its ligature as
        text ("send"), so it is a legitimate submit and must be clicked --
        the zero-score rule is for UNNAMED controls, not icon-shaped ones."""
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        from xssentinel.core import dom_engine as dem

        srv, holder, seen = _server({"/lig": _LIGATURE_PAGE})
        try:
            url = f"http://127.0.0.1:{holder['p']}/lig"
            res = dem.DynamicDomAnalyzer(timeout=20).harvest(
                url, write_faces=True)
            faces = res.get("write_faces") or []
            assert len(faces) == 1, faces
            assert faces[0]["field"] == "msg", faces
        finally:
            srv.shutdown()
            dem.shutdown_thread_browser()

    def test_harvest_without_the_flag_touches_nothing(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        from xssentinel.core import dom_engine as dem

        srv, holder, seen = _server({"/send": _SEND_PAGE})
        try:
            url = f"http://127.0.0.1:{holder['p']}/send"
            res = dem.DynamicDomAnalyzer(timeout=20).harvest(url)
            assert res.get("write_faces") == []
            assert not any(m == "POST" for m, _, _ in seen), (
                "harvest() without write_faces must not drive the page: "
                f"{seen}")
        finally:
            srv.shutdown()
            dem.shutdown_thread_browser()


class TestMarkerField:
    """Attribution parses the request body; the control id is often a
    different string entirely (measured on Juice Shop)."""

    @staticmethod
    def _field(body: str) -> str:
        from xssentinel.core.dom_engine import DynamicDomAnalyzer
        return DynamicDomAnalyzer._marker_field(body, "MK7")

    def test_json_body(self):
        assert self._field('{"message":"MK7payload"}') == "message"

    def test_nested_json_body(self):
        assert self._field('{"user":{"bio":"MK7x"}}') == "bio"

    def test_form_body(self):
        assert self._field("msg=MK7payload&other=1") == "msg"

    def test_body_without_the_marker(self):
        assert self._field('{"message":"clean"}') == ""

    def test_malformed_json_falls_through(self):
        # Not a crash and not a wrong answer -- just no attribution.
        assert self._field('{"message":MK7') in ("message", "")


class TestNamesHarvest:
    """Phase 241 also fixed a Phase 196 defect: the name harvest matched
    only [name], which on a modern Material app (measured: 4 controls, 0
    with name) returned nothing -- on the very SPA input faces it exists
    to collect.  ids count, framework-generated ones do not."""

    @pytest.mark.skipif(not SOCKETPAIR_OK, reason="no socketpair")
    def test_material_style_controls_are_named(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        from xssentinel.core import dom_engine as dem

        page = (b"<html><body>"
                b"<input id='mat-input-1'><textarea id='complaintMessage'>"
                b"</textarea><input name='email'>"
                b"<input id='cdk-overlay-1'></body></html>")
        srv, holder, _ = _server({"/mat": page})
        try:
            url = f"http://127.0.0.1:{holder['p']}/mat"
            res = dem.DynamicDomAnalyzer(timeout=20).harvest(url)
            names = res.get("names") or []
            assert "email" in names, names
            assert "complaintMessage" in names, (
                "an id-only control must still contribute its id -- measured "
                f"on Juice Shop: {names}")
            assert "mat-input-1" not in names, (
                "framework-generated ids are wordlist noise: " + str(names))
        finally:
            srv.shutdown()
            dem.shutdown_thread_browser()
