# -*- coding: utf-8 -*-
"""Phase 247: the stored pipeline's CLI-level acceptance gate.

Phases 241-246 built the modern-app stored path piece by piece and proved
each piece at unit level.  This gate locks the WHOLE chain through the
product's own CLI, against a target that models the real shape:

  * a SPA whose write face is a textarea + button posting JSON (no
    <form action> -- observed by driving the page, Phase 241);
  * a SPA viewer route that renders the stored value CLIENT-side
    (so the HTML channel is blind, Phase 244's browser arm decides);
  * the viewer renders the sink ONLY when the session is seeded (so the
    Phase 237 auth bridge is load-bearing end to end);
  * the base page links both routes (so --discover supplies the viewer
    candidates, Phase 243).

Assertions through the CLI's own JSON report:
  * full pipeline  -> a `stored` finding whose proof names the viewer
    route and carries fired browser evidence;
  * without --discover -> no stored finding (route knowledge is what makes
    the confirmation reachable);
  * without the auth seed -> no stored finding (the sink is post-login and
    the bridge is what opens it).

A measured correction to an earlier premise of this gate: dropping ONLY
--spa-write-faces still confirms here, because the write API is visible to
discovery and the classic endpoint scan reaches it.  The flag's marginal
value is for write faces that are NOT otherwise discoverable.

Opt-in: three CLI scans.  XSSENTINEL_STORED_E2E=1

Run: XSSENTINEL_STORED_E2E=1 C:/Python39/python.exe -m pytest tests/test_stored_e2e_acceptance.py -q
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# One SPA shell served for every path, with a real hash router: pointing
# the scanner at the app root yields the nav links (so --discover learns
# the routes), and rendering "#/write" yields the write UI.  Serving
# different HTML per path would be a server-rendered app -- the wrong shape
# for this pipeline, and the first fixture did exactly that.
_SHELL = b"""<html><body>
<nav><a href='#/write'>write</a> <a href='#/viewer'>viewer</a></nav>
<div id='view'></div>
<script>
function route() {
  var h = location.hash || '#/';
  var v = document.getElementById('view');
  if (h.indexOf('#/write') === 0) {
    v.innerHTML =
      "<textarea name='msg'></textarea><button id='send'>Send</button>";
    document.getElementById('send').addEventListener('click', function(){
      fetch('/api/notes', {method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({msg: document.querySelector('textarea').value})});
    });
  } else if (h.indexOf('#/viewer') === 0) {
    var SESSION = window.localStorage.getItem('token') === 'SESS-TOKEN';
    fetch('/api/notes').then(r => r.json()).then(d => {
      if (SESSION) {              // post-login sink by construction
        v.innerHTML = d.msg;
      }
    });
  }
}
window.addEventListener('hashchange', route);
route();
</script></body></html>"""


def _start_target():
    store: list = []

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, body: bytes, ctype="text/html; charset=utf-8"):
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?")[0]
            if path == "/api/notes":
                self._send(json.dumps({"msg": "".join(store)}).encode(),
                           "application/json")
            else:
                # One shell for every path: the route is the fragment and
                # the client renders it.  That is what makes the write face
                # observable only after the route renders.
                self._send(_SHELL)

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n).decode("utf-8", "replace")
            if self.path.startswith("/api/notes"):
                try:
                    store.append(json.loads(raw).get("msg") or "")
                except Exception:
                    store.append("")
            self._send(b'{"ok":true}', "application/json")

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
    return srv, holder


def _run_cli(base: str, extra: list, tag: str) -> dict:
    # A fresh output name per run (never os.remove: the sandbox's
    # safe-delete layer refuses it, which is how this helper first failed).
    out = os.path.join(ROOT, "dev", "_js_out", f"stored_e2e_{tag}.json")
    # The app ROOT, the way an operator points at a real SPA: the nav links
    # there teach --discover the routes, and the write face is reaped from
    # the "#/write" route (Phase 247 -- base-only reaping found nothing).
    cmd = [sys.executable, "-m", "xssentinel",
           "-u", base + "/", "--discover", "--headless",
           "--login-token", "SESS-TOKEN",
           "--browser-local-storage", "token=SESS-TOKEN",
           "--progress", "none", "--log-level", "error",
           "-f", "json", "-o", out] + extra
    subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                   encoding="utf-8", errors="replace", timeout=600,
                   env=dict(os.environ, NO_PROXY="127.0.0.1,localhost"))
    with open(out, encoding="utf-8") as f:
        return json.load(f)


def _stored(data: dict) -> list:
    return [f for f in (data.get("findings") or [])
            if f.get("type") == "stored"]


@pytest.mark.skipif(
    os.environ.get("XSSENTINEL_STORED_E2E") != "1",
    reason="three CLI scans (~1-2 min); opt in with XSSENTINEL_STORED_E2E=1")
class TestStoredPipelineEndToEnd:
    def test_full_pipeline_confirms_a_stored_finding(self):
        srv, holder = _start_target()
        try:
            base = f"http://127.0.0.1:{holder['p']}"
            data = _run_cli(base, ["--spa-write-faces"], "full")
            stored = _stored(data)
            assert stored, (
                "the full pipeline confirmed nothing -- write-face "
                "observation, auth bridge, multi-view and the browser arm "
                "are supposed to add up to one stored finding here")
            f = stored[0]
            proof = f.get("proof") or {}
            assert "/viewer" in str(proof.get("view_url", "")), proof
            assert (f.get("headless") or {}).get("outcome") == "fired", (
                f"the finding is not browser-confirmed: {f.get('headless')}")
        finally:
            srv.shutdown()

    def test_without_discovery_nothing_is_confirmed(self):
        """Route knowledge is what makes the stored confirmation reachable:
        without --discover the scanner sees one paramless shell page and
        finds nothing stored."""
        srv, holder = _start_target()
        try:
            base = f"http://127.0.0.1:{holder['p']}"
            out = os.path.join(ROOT, "dev", "_js_out", "stored_e2e_nodisc.json")
            cmd = [sys.executable, "-m", "xssentinel",
                   "-u", base + "/", "--headless",
                   "--login-token", "SESS-TOKEN",
                   "--browser-local-storage", "token=SESS-TOKEN",
                   "--progress", "none", "--log-level", "error",
                   "-f", "json", "-o", out]
            subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=600,
                           env=dict(os.environ, NO_PROXY="127.0.0.1,localhost"))
            with open(out, encoding="utf-8") as f:
                data = json.load(f)
            assert _stored(data) == [], (
                "a stored finding appeared without --discover -- the routes "
                "are not what makes it reachable after all")
        finally:
            srv.shutdown()

    def test_without_the_auth_seed_nothing_is_confirmed(self):
        """The sink is post-login: drop the localStorage seed and the
        viewer renders nothing, so the Phase 237 bridge is load-bearing."""
        srv, holder = _start_target()
        try:
            base = f"http://127.0.0.1:{holder['p']}"
            out = os.path.join(ROOT, "dev", "_js_out", "stored_e2e_noauth.json")
            cmd = [sys.executable, "-m", "xssentinel",
                   "-u", base + "/", "--discover", "--headless",
                   "--spa-write-faces",
                   "--progress", "none", "--log-level", "error",
                   "-f", "json", "-o", out]
            subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=600,
                           env=dict(os.environ, NO_PROXY="127.0.0.1,localhost"))
            with open(out, encoding="utf-8") as f:
                data = json.load(f)
            assert _stored(data) == [], (
                "a stored finding appeared without the session seed -- the "
                "viewer is supposed to render nothing for an anonymous "
                "browser")
        finally:
            srv.shutdown()
