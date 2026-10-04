"""Phase 194: stored-XSS dialog closure + session-loss policy.

Two competitor-parity items (dalfox --sxss waitdialog semantics and
--session-check / --on-session-loss):

  * the stored-DOM flow now arms a DIALOG channel on the view page: a pure
    ``<script>alert('token')</script>`` stored payload executes without
    ever flowing through an instrumented sink and used to be invisible.
    The channel is a fallback (sink hits stay the stronger evidence) and
    is opt-in per call -- for URL-source probes a page merely DISPLAYING
    the marker (``alert(location.hash)``) is not XSS, so the default must
    stay off;
  * ``--session-check REGEX`` extends loss detection to response BODIES
    (a 200 page saying "please log in" defeats status-based checks) and
    ``--on-session-loss abort`` stops the scan through the existing
    BudgetExhausted graceful-stop machinery instead of relogging-in.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.budget import BudgetExhausted  # noqa: E402
from xssentinel.core.session import SessionManager  # noqa: E402


# ---------------------------------------------------------------------------
# session: body-regex detection + abort policy
# ---------------------------------------------------------------------------

class _FakeResp:
    def __init__(self, status=200, body="", headers=None):
        self.status_code = status
        self.text = body
        self.headers = headers or {}


class _FakeSession:
    def __init__(self, resp):
        self._resp = resp
        self.cookies = {}
        self.headers = {}

    def get(self, url, timeout=None, allow_redirects=False):
        return self._resp


class _FakeRequester:
    def __init__(self, resp):
        self.session = _FakeSession(resp)
        self.timeout = 5
        self.on_response = None


def _mgr(resp, **kw) -> SessionManager:
    req = _FakeRequester(resp)
    m = SessionManager(req)
    m.logged_in = True
    m._login_url = "http://t/login"
    for k, v in kw.items():
        setattr(m, k, v)
    return m


class TestSessionCheckRegex:
    def test_body_regex_detects_loss_on_200(self):
        m = _mgr(_FakeResp(body="please log in first"),
                 session_check_re=__import__("re").compile("please log in"))
        assert m.looks_logged_out(_FakeResp(body="welcome please log in now"))

    def test_body_regex_no_match_is_not_loss(self):
        import re
        m = _mgr(_FakeResp(body="all good"), session_check_re=re.compile("please log in"))
        assert not m.looks_logged_out(_FakeResp(body="all good"))

    def test_without_regex_200_body_is_never_loss(self):
        m = _mgr(_FakeResp(body="please log in first"))
        assert not m.looks_logged_out(_FakeResp(body="please log in first"))

    def test_status_checks_still_work_alongside(self):
        import re
        m = _mgr(_FakeResp(body="x"), session_check_re=re.compile("nope"))
        assert m.looks_logged_out(_FakeResp(status=401, body="x"))


class TestOnSessionLoss:
    def test_abort_policy_raises_through_the_hook(self):
        import re
        m = _mgr(_FakeResp(body="please log in"),
                 session_check_re=re.compile("please log in"),
                 on_session_loss="abort")
        req = m.requester
        m.attach(req)
        with pytest.raises(BudgetExhausted, match="session lost"):
            req.on_response(_FakeResp(body="please log in"),
                            req, "GET", "http://t/x", None, None)

    def test_relogin_policy_does_not_raise(self):
        import re

        class _NeverReauth(SessionManager):
            def reauth(self):
                return False

        req = _FakeRequester(_FakeResp(body="please log in"))
        m = _NeverReauth(req)
        m.logged_in = True
        m._login_url = "http://t/login"
        m.session_check_re = re.compile("please log in")
        m.on_session_loss = "relogin"
        m.attach(req)
        # reauth fails -> hook returns None (no exception, no retry)
        assert req.on_response(_FakeResp(body="please log in"),
                               req, "GET", "http://t/x", None, None) is None

    def test_keep_alive_abort_reraises_not_swallowed(self):
        import re
        m = _mgr(_FakeResp(body="please log in"),
                 session_check_re=re.compile("please log in"),
                 on_session_loss="abort")
        with pytest.raises(BudgetExhausted):
            m.keep_alive(probe_url="http://t/x", relogin_on_loss=True)


def test_cli_flags_exist():
    import subprocess
    r = subprocess.run(
        [sys.executable, "-m", "xssentinel", "--help"],
        capture_output=True, text=True, timeout=60)
    assert "--session-check" in (r.stdout + r.stderr)
    assert "--on-session-loss" in (r.stdout + r.stderr)


# ---------------------------------------------------------------------------
# stored-XSS dialog closure (real browser, loopback stored fixture)
# ---------------------------------------------------------------------------

class _StoredHandler(BaseHTTPRequestHandler):
    stored = {"q": ""}

    def do_POST(self):
        import json as _json
        from urllib.parse import parse_qs
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        ct = self.headers.get("Content-Type") or ""
        # a real write endpoint accepts BOTH encodings; scan_stored_dom
        # sends form AND json per payload, and the second must not wipe
        # the first
        if "json" in ct:
            try:
                q = (_json.loads(raw) or {}).get("q") or ""
            except Exception:
                q = ""
        else:
            form = parse_qs(raw, keep_blank_values=True)
            q = (form.get("q") or [""])[0]
        if q:
            _StoredHandler.stored["q"] = q
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        body = (f"<!DOCTYPE html><html><body><div id=\"comments\">"
                f"{_StoredHandler.stored['q']}</div></body></html>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def test_stored_dom_pure_alert_payload_confirmed_via_dialog():
    """The blind-spot proof: html-001 is a pure <script>alert(...)</script>
    payload -- it EXECUTES on the view page but never flows through an
    instrumented sink.  Before the dialog channel this returned False."""
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session")
    from xssentinel.core import dom_engine
    if not dom_engine.DynamicDomAnalyzer.available():
        pytest.skip("playwright/chromium not available")
    from xssentinel.core.requester import Requester
    from xssentinel.core.scanner import Scanner

    _StoredHandler.stored["q"] = ""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _StoredHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.2)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        sc = Scanner(requester=Requester(timeout=8), dom_engine="auto",
                     verbose=False)
        ok = sc.scan_stored_dom(base + "/inject", base + "/view",
                                param="q")
        assert ok, "pure-alert stored payload went unconfirmed"
        hits = [f.data for f in sc.findings
                if f.data.get("type") == "stored_dom"]
        assert hits
        d = hits[0]
        assert d["evidence_class"] == "browser-executed"
        assert "dialog carried the probe token" in d["detail"]
        assert "dialog" in (d.get("proof", {}).get("sinks") or "")
    finally:
        server.shutdown()
        server.server_close()
        _StoredHandler.stored["q"] = ""
