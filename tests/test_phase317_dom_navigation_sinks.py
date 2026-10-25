# -*- coding: utf-8 -*-
"""Phase 317: the DOM engine records delivery at the three hookable
navigation/content sinks and the carrier wave proves execution.

The 314 attribution measured five DOM-channel FNs whose sinks the init
script never instrumented (no hit -> the carrier wave is never paid ->
FN).  Three are hookable and verified end-to-end here on LOCAL fixture
pages (no lab dependency):

  document.execCommand('insertHTML', false, value)   -> execCommand hook
  scriptTag.innerText / textContent = value          -> script-text hook
     (the accessor lives on HTMLScriptElement.prototype, SHADOWING
      HTMLElement.prototype's -- hooking the latter silently misses every
      script element; measured, and the reason the first probe run read
      "installed but never called")
  Object.assign(location, {href: value})             -> Object.assign hook
     (the assignment navigates the moment it fires, killing the document
      with its hit array -- hit() mirrors to sessionStorage and the reader
      slices by a consumed cursor, so the hit survives its own navigation)

The two unhookable sinks (location.assign -- [LegacyUnforgeable] instance
member; dynamic import() -- a syntax construct) and the wave-gating
decision they need are recorded in the 317 notes, not pretended here.

Execution is claimed only by the page's own dialog (Phase 226): the rows
below assert ``executed is True`` only where the carrier dialog fired.
"""
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from xssentinel.core import dom_engine  # noqa: E402

PAGES = {
    "/execcommand": (
        "<html><body><div id='editor' contenteditable='true'></div><script>"
        "const q = new URL(location.href).searchParams.get('q') || '';"
        "document.getElementById('editor').focus();"
        "document.execCommand('insertHTML', false, q);"
        "</script></body></html>"),
    "/script-text": (
        "<html><body><script id='t'></script><script>"
        "const q = new URL(location.href).searchParams.get('q') || '';"
        "document.getElementById('t').innerText = q;"
        "</script></body></html>"),
    "/assign-href": (
        "<html><body><script>"
        "const q = new URL(location.href).searchParams.get('q') || '';"
        "if (q) { Object.assign(location, { href: q }); }"
        "</script></body></html>"),
    # The safe twin: the same sinks, but the value never reaches them.
    "/safe": (
        "<html><body><div id='editor' contenteditable='true'></div>"
        "<script id='t'></script><script>"
        "document.getElementById('editor').textContent = 'static';"
        "document.getElementById('t').textContent = 'static';"
        "</script></body></html>"),
}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        path = self.path.split("?")[0]
        body = PAGES.get(path, "not found").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


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


def _rows(base, path):
    an = dom_engine.DynamicDomAnalyzer()
    return an.analyze(f"{base}{path}?q=xssent", "xssent")


@pytest.mark.parametrize("path", ["/execcommand", "/script-text", "/assign-href"])
def test_hookable_sink_executes_and_is_claimed_by_the_page(base, path):
    """Delivery hook fires, the carrier wave gets paid, and the page's own
    dialog proves execution (browser-executed, not the engine's word)."""
    rows = _rows(base, path)
    exec_rows = [r for r in rows
                 if (r if isinstance(r, dict) else getattr(r, "__dict__", {}))
                 .get("executed") is True]
    assert exec_rows, (
        f"no executed row for {path} (rows: {len(rows)}) -- the sink hook "
        "did not record delivery or the carrier wave was never paid")


def test_safe_twin_never_claims_execution(base):
    """The sinks that never receive the value must not fire at all."""
    rows = _rows(base, "/safe")
    exec_rows = [r for r in rows
                 if (r if isinstance(r, dict) else getattr(r, "__dict__", {}))
                 .get("executed") is True]
    assert not exec_rows, (
        f"the safe twin produced {len(exec_rows)} executed rows "
        "-- the sink hooks fire on values the page never routed to them")
