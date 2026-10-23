# -*- coding: utf-8 -*-
"""A page whose CSP blocks every script route cannot support JS findings.

XSSMaze `csp-bypass-level3` / `cspbypass-level3` / `csp-bypass-level4` are
controls: their only script is an inline block and the policy carries no
`'unsafe-inline'`, no nonce/hash, no external script and no bypass.  Yet the
mutation / postMessage / WebSocket / Trusted-Types / static-DOM hints still
fired, including two `high` claims.  `csp.script_execution_blocked` is the
conservative premise: anything that could still execute (external script,
nonce/hash, wildcard/gadget, no policy at all) answers False.
"""
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from xssentinel.core import csp  # noqa: E402
from xssentinel.core.requester import Requester  # noqa: E402
from xssentinel.core.scanner import Scanner  # noqa: E402

PAGE = """<html><head></head><body><div id='out'></div>
<iframe src="data:text/html,<script>parent.postMessage('{q}','*')</script>"></iframe>
<script>
var q = "{q}";
window.addEventListener('message', function(e) {{
  document.getElementById('out').innerHTML += '<div>' + e.data + '</div>';
}});
var ws = new WebSocket('ws://example.test/socket');
ws.onmessage = function(e) {{
  document.getElementById('out').innerHTML = e.data;
}};
eval('var userInput = "' + q + '"; document.getElementById('out').innerHTML = userInput;');
</script></body></html>"""

JS_HINTS = {
    "dom", "dom_clobber", "mutation_xss", "postmessage_xss",
    "websocket_xss", "websocket_insecure",
    "trusted_types_no_policy", "trusted_types_taint_flow",
    "trusted_types_policy_bypass", "framework_react_xss",
    "framework_vue_xss", "framework_angular_xss",
}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        parts = urlsplit(self.path)
        q = (parse_qs(parts.query).get("q") or [""])[0]
        raw = PAGE.format(q=q).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if parts.path == "/csp":
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; script-src 'self'")
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


# ---------------------------------------------------------------------------
# the predicate
# ---------------------------------------------------------------------------
def test_no_policy_means_execution_is_possible():
    assert not csp.script_execution_blocked({}, "<script>x</script>")


@pytest.mark.parametrize("policy", [
    "default-src 'self'; script-src 'self'",
    "script-src 'unsafe-eval'",
    "script-src 'self' 'unsafe-eval'",
    "default-src 'none'",
    # A host allowlist only matters if the page actually loads a script from
    # it; this fixture has no <script src>, so nothing can run.
    "script-src 'self' https://cdn.example",
])
def test_inline_only_page_is_blocked(policy):
    assert csp.script_execution_blocked(
        {"Content-Security-Policy": policy}, "<script>var x=1;</script>")


@pytest.mark.parametrize("policy", [
    "script-src 'unsafe-inline'",
    "script-src 'nonce-abc123'",
    "script-src 'sha256-abc'",
    "script-src 'self' *.cdn.example",
])
def test_routes_that_may_still_execute_are_not_blocked(policy):
    assert not csp.script_execution_blocked(
        {"Content-Security-Policy": policy}, "<script>var x=1;</script>")


def test_an_external_script_element_keeps_execution_possible():
    assert not csp.script_execution_blocked(
        {"Content-Security-Policy": "script-src 'self'"},
        "<script>var x=1;</script><script src='/app.js'></script>")


def test_report_only_is_not_enforcement():
    assert not csp.script_execution_blocked(
        {"Content-Security-Policy-Report-Only": "default-src 'none'"},
        "<script>x</script>")


def test_a_meta_policy_is_consulted():
    html = ('<meta http-equiv="Content-Security-Policy" '
            'content="default-src \'self\'"><script>x</script>')
    assert csp.script_execution_blocked({}, html)


# ---------------------------------------------------------------------------
# real scan path
# ---------------------------------------------------------------------------
def _scan(base, path):
    sc = Scanner(requester=Requester(timeout=8), max_payloads=4,
                 max_transforms=2, dom_engine="static")
    sc.scan_target(base + path, method="GET", params={"q": "x"}, data={},
                   oob_collect=False)
    sc.dedup()
    return [f.data for f in sc.findings]


def test_blocked_scripts_silence_every_js_dependent_hint(base):
    types = {f.get("type") for f in _scan(base, "/csp")}
    assert not (types & JS_HINTS), (
        "JS-dependent findings survived a page whose CSP blocks every "
        f"script route: {sorted(types)}")


def test_without_the_policy_the_same_page_still_fires(base):
    """Sensitivity anchor: the negative test above must not pass because the
    fixture stopped triggering anything."""
    types = {f.get("type") for f in _scan(base, "/nocsp")}
    assert len(types & JS_HINTS) >= 2, sorted(types)


# ---------------------------------------------------------------------------
# wiring guards
# ---------------------------------------------------------------------------
def test_sync_layers_call_the_predicate():
    from xssentinel.core import scanner_layers
    src = open(scanner_layers.__file__, encoding="utf-8").read()
    assert src.count("script_execution_blocked(") >= 3, (
        "expected the static-DOM, mutation and clobber sites to gate")


def test_page_dispatcher_calls_the_predicate():
    from xssentinel.core import advanced_layers
    src = open(advanced_layers.__file__, encoding="utf-8").read()
    assert "script_execution_blocked(" in src


def test_async_dom_layer_takes_the_flag():
    import inspect

    from xssentinel.core.async_scanner_layers import AsyncDetectionLayersMixin
    sig = inspect.signature(AsyncDetectionLayersMixin._scan_dom_async)
    assert "no_script_exec" in sig.parameters


def test_async_call_site_passes_the_flag():
    from xssentinel.core import async_scanner
    src = open(async_scanner.__file__, encoding="utf-8").read()
    assert "no_script_exec=csp_mod.script_execution_blocked(" in src
