"""Phase 400: headless replay must carry the scan session's cookies.

Regression for the DVWA finding: HTTP replay reached the authenticated
reflection, but ``verify_headless`` opened a fresh browser page with no
cookies, got bounced to login.php, and graded a real finding
``browser-refuted`` (``no dialog``).

Two layers of guard, because the function body alone does not stay fixed:

* behaviour: a real Chromium against a tiny auth-gated server that only
  renders the payload when ``Cookie: session=ok`` is present;
* source assertions: every call site that owns a session must pass
  ``cookies=`` -- a call site reverting to headers-only must turn the suite
  red even if the function body is still correct.
"""
from __future__ import annotations

import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from xssentinel.core import verifier

TOKEN = "phase400probe"
PAYLOAD = "<img src=x onerror=\"alert('%s')\">" % TOKEN
REPO = Path(__file__).resolve().parents[1]


class _AuthHandler(BaseHTTPRequestHandler):
    seen_headers: list[dict] = []

    def log_message(self, *a):
        pass

    def _serve(self, payload):
        self.seen_headers.append(dict(self.headers))
        authed = self.headers.get("Cookie", "") == "session=ok"
        if not authed:
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
            return
        body = ("<html><body><pre>Hello " + payload +
                "</pre></body></html>").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parts = urlsplit(self.path)
        if parts.path == "/login":
            body = b"<html><body>login wall</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        q = parse_qs(parts.query).get("q", [""])[0]
        self._serve(q)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        form = parse_qs(self.rfile.read(n).decode("utf-8", "replace"))
        self._serve(form.get("q", [""])[0])


@pytest.fixture
def auth_site():
    _AuthHandler.seen_headers = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _AuthHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield "http://127.0.0.1:%d/vuln" % srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(timeout=5)


def _verify(url, **kw):
    return verifier.verify_headless(
        url, "GET", {"q": PAYLOAD}, None, kw.pop("headers", None),
        TOKEN, timeout=8, **kw)


def test_explicit_cookie_confirms(auth_site):
    """The bug: no cookies meant login wall meant browser-refuted."""
    r = _verify(auth_site, cookies={"session": "ok"})
    assert r["available"] is True, r
    assert r["confirmed"] is True, r
    assert r["outcome"] == "fired", r


def test_no_cookie_is_not_confirmed(auth_site):
    r = _verify(auth_site)
    assert r["confirmed"] is False, r
    assert "no dialog" in r["detail"], r


def test_cookie_header_in_headers_is_honoured(auth_site):
    """MCP / llm_propose only own headers; their Cookie must still work."""
    r = _verify(auth_site, headers={"Cookie": "session=ok"})
    assert r["confirmed"] is True, r


def test_other_headers_survive_cookie_split(auth_site):
    """Playwright refuses Cookie in extra headers; stripping it must not
    throw away Authorization along with it."""
    r = _verify(auth_site, headers={"Cookie": "session=ok",
                                   "Authorization": "Bearer keep-me"})
    assert r["confirmed"] is True, r
    assert any(h.get("Authorization") == "Bearer keep-me"
               for h in _AuthHandler.seen_headers), _AuthHandler.seen_headers


def test_post_replay_carries_cookie(auth_site):
    r = verifier.verify_headless(
        auth_site, "POST", None, {"q": PAYLOAD},
        {"Authorization": "Bearer keep-me"}, TOKEN,
        cookies={"session": "ok"}, timeout=8)
    assert r["confirmed"] is True, r
    assert any(h.get("Authorization") == "Bearer keep-me"
               for h in _AuthHandler.seen_headers), _AuthHandler.seen_headers


class TestScreenshotOnlyOnConfirmation:
    """Phase 402: an evidence screenshot is only useful when the payload
    actually executed.  A not-fired replay never renders one in report.py,
    so capturing a base64 PNG there just bloats every finding (up to 2MB)
    with a page that can carry session data.
    """

    def test_confirmed_replay_has_screenshot(self, auth_site):
        r = _verify(auth_site, cookies={"session": "ok"})
        assert r["confirmed"] is True, r
        assert r.get("screenshot_b64"), "confirmed replay must embed evidence"

    def test_not_fired_replay_has_no_screenshot(self, auth_site):
        r = _verify(auth_site)  # no cookie -> login wall -> no dialog
        assert r["confirmed"] is False, r
        assert r["outcome"] == "not-fired", r
        assert "screenshot_b64" not in r, (
            "not-fired replay must not carry an unshown screenshot")


def _call_blocks(path: str) -> list[str]:
    src = (REPO / path).read_text(encoding="utf-8")
    out = []
    for m in re.finditer(r"verify_headless\s*\(", src):
        i = m.end()
        depth = 1
        while depth and i < len(src):
            if src[i] == "(":
                depth += 1
            elif src[i] == ")":
                depth -= 1
            i += 1
        out.append(src[m.start():i])
    return out


@pytest.mark.parametrize("path,expected", [
    ("xssentinel/core/scanner.py", 3),
    ("xssentinel/core/async_scanner_verify.py", 1),
    ("xssentinel/api/mcp_server.py", 1),
])
def test_session_owning_call_sites_pass_cookies(path, expected):
    blocks = _call_blocks(path)
    assert len(blocks) == expected, (path, len(blocks))
    for b in blocks:
        assert "cookies=" in b, (path, b[:240])


def test_cookie_aware_function_shape():
    """The body guard: cookies are actually installed on the context, not
    merely accepted and dropped on the floor."""
    src = (REPO / "xssentinel/core/verifier.py").read_text(encoding="utf-8")
    funcs = [s for s in re.split(r"\ndef ", src)
             if s.startswith("verify_headless(")]
    assert len(funcs) == 1
    signature = funcs[0].split('"""')[0]
    assert "cookies=" in signature, signature[:400]
    assert "add_cookies(" in funcs[0], "browser context never gets cookies"
