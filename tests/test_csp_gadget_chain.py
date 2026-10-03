"""Phase 187: CSP allowlist -> script gadget EXECUTION chain.

Absorbed from the nuclei csp-bypass template family (renniepak/CSPBypass
corpus): a strict script-src that still allowlists a known gadget host
(JSONP endpoint, Angular CDN, ...) re-opens script execution.  The scanner
already KNEW the gadget table (csp.SCRIPT_GADGETS, static suggestions only);
the chain now runs those payloads against real reflection points and lets
the same verification machinery every other finding uses decide.

Layers tested here:
  * unit: gadget extraction, __SRC__ substitution, relevance gate, and the
    quote-nesting contract with verifier.mark (angular entries must stamp to
    VALID JS);
  * sync e2e, no browser: a lab Angular gadget registered against the
    loopback host confirms via the same template_angular machinery the
    corpus uses (evidence: EVIDENCE_MODEL);
  * sync e2e + real Chromium: a lab JSONP gadget (token rides a src
    attribute -- no honest static verdict) confirms only through actual
    script execution in the browser (evidence: EVIDENCE_BROWSER_EXECUTED).

register_gadget mutates module-level state: every test that registers MUST
clean up, or the whole in-process suite inherits the lab gadget.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import csp as csp_mod
from xssentinel.core import verifier

_LAB_ANGULAR = ('<script src="__SRC__/angular.min.js"></script>'
                '<div ng-app ng-csp>{{constructor.constructor("alert(1)")()}}'
                '</div>')
_LAB_JSONP = '<script src="__SRC__/jsonp?cb=alert(1)//"></script>'


# ---------------------------------------------------------------------------
# unit: extraction / substitution / gates
# ---------------------------------------------------------------------------

class TestGadgetExtraction:
    def setup_method(self):
        csp_mod._EXTRA_GADGETS.clear()

    def teardown_method(self):
        csp_mod._EXTRA_GADGETS.clear()

    def test_static_table_jsonp_selected(self):
        gps = csp_mod.gadget_bypass_payloads(
            "script-src 'self' https://www.google.com")
        assert any("alert(1)" in g["payload"] for g in gps)

    def test_wildcard_source_still_yields_gadgets(self):
        # *.googleapis.com must match the static patterns (re.search, not
        # equality) -- wildcard policies whitelist real gadget hosts.
        gps = csp_mod.gadget_bypass_payloads(
            "script-src 'self' *.googleapis.com")
        assert any("googleapis" in g["payload"] for g in gps)

    def test_no_gadget_host_yields_nothing(self):
        assert csp_mod.gadget_bypass_payloads("script-src 'self'") == []
        assert csp_mod.gadget_bypass_payloads("") == []

    def test_register_gadget_src_placeholder(self):
        csp_mod.register_gadget(r"127\.0\.0\.1", _LAB_JSONP, "lab JSONP")
        gps = csp_mod.gadget_bypass_payloads(
            "script-src 'self' http://127.0.0.1:18081")
        assert gps and gps[0]["host"] == "http://127.0.0.1:18081"
        assert "http://127.0.0.1:18081/jsonp?cb=alert(1)//" in gps[0]["payload"]

    def test_registered_gadget_ignored_for_other_hosts(self):
        csp_mod.register_gadget(r"internal\.cdn\.example", _LAB_JSONP)
        assert csp_mod.gadget_bypass_payloads(
            "script-src 'self' https://other.example") == []

    def test_token_stamp_produces_valid_angular(self):
        # Phase 187 contract: mark() replaces alert(1) -> alert('tok'), so a
        # single-quoted Function body would nest broken.  The static table
        # uses double quotes outside; assert the stamped payload stays
        # syntactically valid JS inside the template expression.
        gps = csp_mod.gadget_bypass_payloads(
            "script-src 'self' https://cdn.jsdelivr.net")
        ang = [g for g in gps if "constructor" in g["payload"]]
        assert ang, "no angular gadget matched jsdelivr"
        stamped = verifier.mark(ang[0]["payload"], "xssv_t")
        assert 'xssv_t' in stamped
        assert "constructor.constructor(\"alert('xssv_t')\")" in stamped

    def test_relevance_gate(self):
        h = "script-src 'self' https://www.google.com"
        assert csp_mod.gadget_chain_relevant(h)           # gadget, no inline
        assert not csp_mod.gadget_chain_relevant(
            h + " 'unsafe-inline'")                       # inline already wins
        assert not csp_mod.gadget_chain_relevant("script-src 'self'")
        assert not csp_mod.gadget_chain_relevant("")
        # inline keyword absent but a nonce makes 'unsafe-inline' inert per
        # CSP2+ -- the gadget remains the only route.
        assert csp_mod.gadget_chain_relevant(
            "script-src 'nonce-k8Fj3x9Qm2Rw7Yp4' https://www.google.com")


# ---------------------------------------------------------------------------
# loopback lab: both engines' chains measured end to end
# ---------------------------------------------------------------------------

class _LabHandler(BaseHTTPRequestHandler):
    port = 0  # set by the fixture

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs, unquote
        u = urlparse(self.path)
        q = (parse_qs(u.query).get("q") or [""])[0]
        if u.path == "/gadget":
            # reflects q RAW + a CSP that allowlists this very origin as a
            # script source -- the lab gadget host.
            body = (f"<!DOCTYPE html><html><body>"
                    f"<div id=\"out\">{q}</div></body></html>").encode()
            extra = {"Content-Security-Policy":
                     f"script-src 'self' http://127.0.0.1:{self.port}"}
        elif u.path == "/plain":
            body = (f"<!DOCTYPE html><html><body><div id=\"out\">"
                    f"{q}</div></body></html>").encode()
            extra = {"Content-Security-Policy": "script-src 'self'"}
        elif u.path == "/jsonp":
            # the attacker's JSONP endpoint: echo the callback param as JS
            cb = (parse_qs(u.query).get("cb") or [""])[0]
            body = unquote(cb).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        else:
            body = b"<html><body>nf</body></html>"
            extra = {}
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in extra.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def lab():
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session (security software/TCP state)")
    _LabHandler.port = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), _LabHandler)
    port = server.server_address[1]
    _LabHandler.port = port
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.2)
    yield f"http://127.0.0.1:{port}"
    try:
        server.shutdown()
        server.server_close()
    except Exception:
        pass


@pytest.fixture()
def lab_gadgets():
    csp_mod._EXTRA_GADGETS.clear()
    csp_mod.register_gadget(r"127\.0\.0\.1", _LAB_ANGULAR, "lab angular gadget")
    csp_mod.register_gadget(r"127\.0\.0\.1", _LAB_JSONP, "lab JSONP gadget")
    yield
    csp_mod._EXTRA_GADGETS.clear()


class TestSyncGadgetChain:
    @staticmethod
    def _gadget_hits(sc):
        hits = []
        for f in sc.findings:
            d = f.data if hasattr(f, "data") else dict(f)
            if "csp_gadget" in tuple(d.get("transform") or []):
                hits.append(d)
        return hits

    def test_lab_angular_gadget_confirms_statically(self, lab, lab_gadgets):
        """No browser: the framework-gadget payload confirms via the same
        template_angular machinery the corpus uses.  The inline queue cannot
        confirm anything here (strict CSP), so without the chain this
        endpoint was invisible."""
        from xssentinel.core.requester import Requester
        from xssentinel.core.scanner import Scanner

        sc = Scanner(requester=Requester(timeout=8), use_headless=False,
                     max_payloads=3, max_transforms=2, verbose=False)
        sc.scan_target(f"{lab}/gadget", method="GET", params={"q": "probe"})
        hits = self._gadget_hits(sc)
        assert hits, "CSP gadget chain did not fire on the lab endpoint"
        h = hits[0]
        assert h["type"] == "reflected"
        assert h["context"] == "template_angular"
        assert h["confidence"] == "high"
        assert "lab angular gadget" in h["detail"]
        # the token-stamped payload must have been the reflected one
        assert "alert('" in h["payload"]
        assert h["evidence_class"] == "model-only"

    def test_strict_csp_without_gadget_stays_silent(self, lab, lab_gadgets):
        """The FP guard: no allowlisted gadget host -> no chain attempt, and
        the strict CSP keeps the inline queue from confirming anything."""
        from xssentinel.core.requester import Requester
        from xssentinel.core.scanner import Scanner

        sc = Scanner(requester=Requester(timeout=8), use_headless=False,
                     max_payloads=3, max_transforms=2, verbose=False)
        sc.scan_target(f"{lab}/plain", method="GET", params={"q": "probe"})
        assert not self._gadget_hits(sc)
        # and nothing at all was confirmed on a strict-CSP raw reflector
        confirmed = [f for f in sc.findings
                     if (f.data if hasattr(f, "data") else dict(f))
                     .get("confidence") == "high"]
        assert not confirmed, \
            f"strict-CSP page produced confirmed findings: {confirmed}"


class TestSyncJsonpGadgetBrowser:
    def test_lab_jsonp_gadget_executes_in_browser(self, lab):
        """The nuclei csp-bypass flow, measured: JSONP gadget payload rides a
        src attribute (static verdict is honestly silent), so only a real
        Chromium executing the allowlisted script can confirm.  ONLY the
        JSONP gadget is registered -- the angular one would confirm
        statically first and the browser leg would never run."""
        from xssentinel.core.requester import Requester
        from xssentinel.core.scanner import Scanner
        from xssentinel.core import dom_engine

        if not dom_engine.DynamicDomAnalyzer.available():
            pytest.skip("playwright/chromium not available")

        csp_mod._EXTRA_GADGETS.clear()
        csp_mod.register_gadget(r"127\.0\.0\.1", _LAB_JSONP, "lab JSONP gadget")
        try:
            sc = Scanner(requester=Requester(timeout=8), use_headless=True,
                         max_payloads=3, max_transforms=2, verbose=False)
            sc.scan_target(f"{lab}/gadget", method="GET",
                           params={"q": "probe"})
        finally:
            csp_mod._EXTRA_GADGETS.clear()
        hits = TestSyncGadgetChain._gadget_hits(sc)
        assert hits, "JSONP gadget chain produced no finding"
        h = hits[0]
        head = h.get("headless") or {}
        assert head.get("confirmed") is True, head
        assert h["evidence_class"] == "browser-executed"
