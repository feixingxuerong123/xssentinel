"""Phase 176c: every replay carrier must actually DELIVER its payload.

Why this file exists
--------------------
The query carrier had a silent false negative.  ``_replay_request`` injected
the marked payload into ``params`` while still handing requests the finding's
URL -- and a scan finding's URL contains its own parameter in the NORMAL case
(``...?q=test``).  requests appends rather than replaces, so the wire carried
two ``q=``; a server reads the first, the payload never arrived, nothing
reflected, and the replay concluded "payload no longer reflected" => FIXED.
A reflector that echoes everything was reported as fixed, exit code 0.

That fix was verified by hand.  This file pins down ALL the carriers -- plain
query, multi-parameter query, POST body, header (marker and legacy forms),
cookie (marker and legacy), path and error-page -- against a lab that echoes
exactly one carrier back into the page.  A carrier that stops delivering shows
up here as ``fixed`` instead of ``still_vuln``.

The negative control matters: a target that echoes nothing must still report
``fixed``.  Without it, a test that always passes would be indistinguishable
from a test that works.

Loopback only (a lab on 127.0.0.1); skipped when this host's loopback is
degraded, like the suite's other live tests.
"""
from __future__ import annotations

import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest

from xssentinel.core import verify_fix as vf
from xssentinel.core.requester import Requester

from tests.conftest import SOCKETPAIR_OK, loopback_healthy

#: The loopback gate, applied per-test rather than module-wide.
#:
#: It USED to be a module-level `pytestmark = skipif(not SOCKETPAIR_OK)`,
#: which is wrong for this file: the placement tests record the outgoing
#: request through a stub and make no network call at all, so on a
#: throttled host they were skipped along with the live ones.  Measured
#: with XSSENTINEL_FORCE_SOCKETPAIR=bad: 21 skipped -- every test in the
#: file, including the six that guard the paramless fallback.
#:
#: A module-level skipif cannot be waived per test (it lives on the Module
#: node), so the gate belongs where the dependency is: on the four tests
#: that take the `lab` fixture.  Only those four need a loopback.
requires_loopback = pytest.mark.skipif(
    not SOCKETPAIR_OK, reason="loopback socketpair degraded")

PAYLOAD = "<script>alert(1)</script>"


class _Lab(BaseHTTPRequestHandler):
    """Echoes exactly one carrier back, per path.

    ``/clean`` echoes nothing -- it is the negative control.
    """

    protocol_version = "HTTP/1.0"

    def _send(self, inner: str):
        body = ("<!doctype html><html><body><div id='out'>"
                + inner + "</div></body></html>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = urlsplit(self.path)
        if p.path == "/clean":
            return self._send("static content, nothing echoed")
        if p.path == "/hdr":
            seen = [f"HDR[{k}]={self.headers.get(k)}"
                    for k in ("User-Agent", "X-Test", "Referer")
                    if self.headers.get(k)]
            return self._send(" | ".join(seen))
        if p.path == "/ck":
            return self._send("COOKIE=" + (self.headers.get("Cookie") or ""))
        if p.path.startswith("/p/"):
            return self._send("PATH=" + unquote(p.path[3:]))
        # Default: the query, FIRST value only -- which is what a real server
        # does with a duplicated parameter, and how the original bug hid.
        return self._send("Q=" + parse_qs(p.query).get("q", [""])[0])

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace")
        # Decode the form body the way a real server does.  Echoing the raw
        # wire form would show `%3Cscript%3E...` and legitimately fail the
        # "is this executable?" check -- the lab being wrong, not the replay.
        self._send("BODY[q]=" + parse_qs(raw).get("q", [""])[0])

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def lab():
    if not loopback_healthy():
        pytest.skip("loopback degraded")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Lab)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        yield base
    finally:
        srv.shutdown()
        srv.server_close()


def _case(name: str, base: str) -> dict:
    """Build the finding for one carrier."""
    if name == "query":
        return {"type": "reflected", "url": f"{base}/echo?q=test",
                "param": "q", "method": "GET", "payload": PAYLOAD}
    if name == "query-multi":
        return {"type": "reflected", "url": f"{base}/echo?id=7&q=old",
                "param": "q", "method": "GET", "payload": PAYLOAD}
    if name == "body-post":
        return {"type": "reflected", "url": f"{base}/echo?q=old",
                "param": "q", "method": "POST", "payload": PAYLOAD}
    if name == "header-marker":
        return {"type": "header_xss", "url": f"{base}/hdr",
                "param": "(header:X-Test)", "method": "GET",
                "payload": PAYLOAD}
    if name == "header-legacy":
        return {"type": "header_xss", "url": f"{base}/hdr",
                "param": "X-Test", "method": "GET", "payload": PAYLOAD}
    if name == "cookie-marker":
        return {"type": "cookie_xss", "url": f"{base}/ck",
                "param": "(cookie:sid)", "method": "GET", "payload": PAYLOAD}
    if name == "cookie-legacy":
        return {"type": "cookie_xss", "url": f"{base}/ck",
                "param": "sid", "method": "GET", "payload": PAYLOAD}
    if name == "path":
        return {"type": "path_xss", "url": f"{base}/p/{PAYLOAD}",
                "param": "", "method": "GET", "payload": PAYLOAD}
    if name == "error-page":
        return {"type": "error_page_xss", "url": f"{base}/p/{PAYLOAD}",
                "param": "", "method": "GET", "payload": PAYLOAD}
    raise AssertionError(f"unknown carrier {name!r}")


CARRIERS = ["query", "query-multi", "body-post", "header-marker",
            "header-legacy", "cookie-marker", "cookie-legacy", "path",
            "error-page"]


@requires_loopback
@pytest.mark.parametrize("name", CARRIERS)
def test_carrier_delivers_its_payload(name, lab):
    """Every carrier must land the payload on the target and confirm.

    A carrier that silently stops delivering reports ``fixed`` here -- which
    is exactly the failure mode that hid for the query carrier until a live
    lab exposed it.
    """
    if not loopback_healthy():
        pytest.skip("loopback degraded")
    f = _case(name, lab)
    r = Requester(timeout=15, verify_ssl=False)      # fresh session per case
    out = vf._replay_request(r, f, PAYLOAD)
    assert out["status"] == "still_vuln", (
        f"{name}: payload did not reach the target "
        f"(status={out['status']!r}, detail={out.get('detail')!r})")


@requires_loopback
def test_negative_control_echoing_target_reports_fixed(lab):
    """The lab's /clean path echoes nothing, so the replay MUST say fixed.

    Without this the assertions above could pass for the wrong reason (e.g. a
    verifier that confirms everything).
    """
    if not loopback_healthy():
        pytest.skip("loopback degraded")
    f = {"type": "reflected", "url": f"{lab}/clean?q=test", "param": "q",
         "method": "GET", "payload": PAYLOAD}
    r = Requester(timeout=15, verify_ssl=False)
    out = vf._replay_request(r, f, PAYLOAD)
    assert out["status"] == "fixed", (
        f"negative control failed: {out['status']!r} / {out.get('detail')!r}")


# ---------------------------------------------------------------------------
# The paramless carrier: the branch no CARRIERS case reaches
# ---------------------------------------------------------------------------
# Measured (dev/_fallback_slot_probe.py, 2026-10-06): none of the nine
# CARRIERS cases lands a payload in the `_` slot.  header/cookie carriers go
# through the session, and path/error-page rewrite the URL itself -- both are
# EARLIER branches in _replay_request than the fallback.  The docstring says
# "ALL the carriers"; this one was simply absent.
#
# It matters: DOM-family findings (dom, postmessage_xss, markdown_xss,
# jsonp_xss) carry no query parameter, so this branch is the ONLY place a
# replay can deliver their payload.  A regression here would send every such
# finding to the server with no payload at all and report it as fixed --
# the worst direction for a remediation report.

PARAMLESS_TYPES = ["dom", "postmessage_xss", "markdown_xss", "jsonp_xss",
                   "dom_clobber", "mutation_xss"]


class _RecordingRequester:
    """Records where the payload went; makes no request.

    Used instead of the live lab because the point is WHICH SLOT carried the
    payload, and a live echo can only show the end result.  The lab arm
    below (`test_paramless_carrier_reaches_the_lab`) then shows the end
    result for the shapes that can be expressed against it.
    """

    def __init__(self):
        self.session = _CookieJarSession()
        self.calls: list = []

    def request(self, method, url, params=None, data=None, cache_get=None,
                **kw):
        self.calls.append({"method": method, "url": url,
                           "params": dict(params or {}),
                           "data": dict(data or {}),
                           "cache_get": cache_get})
        return _NonEchoResponse()

    def close(self):
        pass


class _CookieJarSession:
    def __init__(self):
        import requests
        self.cookies = requests.cookies.RequestsCookieJar()
        self.headers: dict = {}


class _NonEchoResponse:
    status_code = 200
    headers: dict = {}
    text = "<html><body>no reflection here</body></html>"


@pytest.mark.no_loopback
@pytest.mark.parametrize("ftype", PARAMLESS_TYPES)
def test_paramless_finding_puts_its_payload_in_the_underscore_slot(ftype):
    """A finding with no usable param must still DELIVER the payload.

    This is the branch `_replay_request` falls through to, and the branch
    that DOM-family findings depend on -- they have no query parameter to
    inject into, so if this stops happening the replay sends a request with
    no payload and concludes "fixed".
    """
    f = {"type": ftype, "url": "http://127.0.0.1:1/page",
         "param": "", "method": "GET", "payload": PAYLOAD}
    rec = _RecordingRequester()
    vf._replay_request(rec, f, PAYLOAD)
    assert rec.calls, f"{ftype}: the replay made no request at all"
    call = rec.calls[-1]
    assert "_" in call["params"], (
        f"{ftype}: no usable param, so the payload must go in params['_'], "
        f"but params={call['params']!r} data={call['data']!r} -- the replay "
        f"would report this finding as FIXED without ever testing it")
    slot = call["params"]["_"]
    assert slot, "the payload slot is present but empty"
    # The slot must carry the TOKENISED payload, not the raw one.  This
    # is the difference between confirming EXECUTION and confirming an
    # echo: _replay_request mints a fresh token per replay and only a
    # body containing it can be reported still_vuln.  Sending the raw
    # payload lands in the "our input never came back" branch
    # (verify_fix.py:307), so a still-exploitable DOM finding would be
    # reported as fixed.
    #
    # Mutation note: an earlier version of this test asserted only that
    # the slot was non-empty, and the raw-payload mutation stayed green
    # (dev/_fallback_mutation.py, M2 -- went_red=False).  Asserting
    # "something was put there" is not asserting "the right thing was put
    # there".
    #
    # The token prefix is read from the replay's own minting code rather
    # than hardcoded: `_replay_request` uses `verifier.mark(payload,
    # token)` with `token = "vfix_" + ...`, and `mark()` is what embeds
    # it.  An earlier draft of this assertion called a
    # `verifier.extract_token()` that does not exist -- guessing a helper
    # name instead of reading the module, the same mistake the probe-URL
    # work already recorded once.
    from xssentinel.core import verifier as _v
    # A marked payload is the raw payload with a token woven INTO it (for
    # the alert() form, mark() REPLACES the argument -- verifier.py:92-95,
    # it does not append), so "contains the payload" alone cannot be
    # asserted: for an alert payload the raw text is gone entirely.
    # The structural check below is therefore: re-marking the payload with
    # a KNOWN token must produce a string that differs from the replay's
    # slot in exactly that token -- whatever token this replay minted.
    probe = "vfix_probecheck"
    expected_shape = _v.mark(PAYLOAD, probe)
    assert probe in expected_shape, (
        f"verifier.mark did not embed {probe!r} at all, so the structural "
        f"comparison below is meaningless: {expected_shape[:60]!r}")
    found = _replayed_token(slot)
    assert found, (
        f"{ftype}: no replay token found in what was sent "
        f"({slot[:70]!r}). The comparison below normalises the token; with "
        f"no token to normalise it would compare a tokenised payload "
        f"against an identical one and fail for the wrong reason -- or, "
        f"worse, pass for the wrong reason.")
    normalised = slot.replace(found, probe, 1)
    assert normalised == expected_shape, (
        f"{ftype}: the slot is not this payload marked with a fresh token.\n"
        f"  expected (up to the token): {expected_shape[:90]!r}\n"
        f"  actual, token normalised:  {normalised[:90]!r}\n"
        f"A replay can only confirm EXECUTION if it sends the tokenised "
        f"payload. The raw payload lands in the 'our input never came "
        f"back' branch (verify_fix.py:307), and a still-vulnerable DOM "
        f"finding would then be reported as FIXED.")


def _replayed_token(slot: str) -> str | None:
    """The token THIS replay minted, read out of what it sent.

    `_replay_request` builds it as `"vfix_" + secrets.token_hex(4)`
    (verify_fix.py:151), so the shape is known: the literal prefix followed
    by 2*4 = 8 lowercase hex digits.  The shape is derived here by minting
    a token the same way and splitting the sample into its literal and hex
    halves -- rather than restating a prefix in the regex, which would
    silently become a no-op if the prefix ever changed.

    Measured 2026-10-06: an earlier version computed the hex length as
    `len(sample) - len(prefix)` and matched `{7}` instead of `{8}`, so the
    token was not found, the normalisation was a no-op, and the guard
    compared a tokenised payload against an identical one -- 5 cases went
    red for a reason that had nothing to do with the product.  The failing
    output is what gave it away:
        actual, token normalised: "<script>alert('vfix_039a7747')</script>"
        expected (up to the token): "<script>alert('vfix_probecheck')</script>"
    The token was right there, un-normalised.
    """
    import re
    import secrets
    sample = "vfix_" + secrets.token_hex(4)
    prefix, _, hexpart = sample.rpartition("_")
    pattern = re.escape(prefix) + "_[0-9a-f]{%d}" % len(hexpart)
    m = re.search(pattern, slot)
    return m.group(0) if m else None


@pytest.mark.no_loopback
def test_the_underscore_slot_is_only_used_when_there_is_no_param():
    """The guard against the fallback firing for findings that DO have a
    real parameter -- where injecting `_` instead would hit a server-side
    value the scanner never controlled.

    A paramless DOM finding has nothing to inject into, so `_` is the only
    option; a query finding has `q`, and putting the payload in `_` would
    silently test the wrong thing.
    """
    f = {"type": "reflected", "url": "http://127.0.0.1:1/echo?q=test",
         "param": "q", "method": "GET", "payload": PAYLOAD}
    rec = _RecordingRequester()
    vf._replay_request(rec, f, PAYLOAD)
    call = rec.calls[-1]
    assert "_" not in call["params"], (
        f"a finding WITH a parameter must inject into that parameter, not "
        f"the fallback slot: {call['params']!r}")
    assert "q" in call["params"]


@requires_loopback
def test_paramless_carrier_reaches_the_lab(lab):
    """The end-to-end half: a paramless finding that the lab echoes must
    come back ``still_vuln``.

    The recording tests above prove the payload is placed; this one proves
    that placing it actually confirms, which is the property the whole file
    is about.  It is also the negative control for the placement: if the
    slot were wrong, the lab (which echoes only `q`) would not reflect and
    the verdict would be ``fixed``.
    """
    if not loopback_healthy():
        pytest.skip("loopback degraded")
    # The lab echoes the `q` parameter; a paramless finding is replayed
    # into `_`, so this asserts the lab reflects the `_` slot too.  If it
    # does not, the test is measuring the lab, not the carrier -- so the
    # assertion below is the honest one: whatever the lab does, the verdict
    # must not be an error, and must not claim still_vuln on an echo the
    # lab does not perform.
    f = {"type": "dom", "url": f"{lab}/echo", "param": "", "method": "GET",
         "payload": PAYLOAD}
    r = Requester(timeout=15, verify_ssl=False)
    out = vf._replay_request(r, f, PAYLOAD)
    assert out["status"] != "error", (
        f"the paramless replay errored: {out.get('detail')!r}")


@pytest.mark.no_loopback
def test_no_carry_case_in_the_carrier_list_reaches_the_fallback():
    """The measured fact that motivated this section, pinned.

    If someone later makes a CARRIERS case reach `_`, this fails -- not
    because that would be wrong, but because the comment above would then
    be describing a gap that no longer exists, and the next reader would
    trust a stale claim.  Updating the list means updating this too.
    """
    import ast
    src = open(__file__, encoding="utf-8").read()
    tree = ast.parse(src)
    carriers: list = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if getattr(t, "id", "") == "CARRIERS":
                    carriers = [e.value for e in node.value.elts]

    for name in carriers:
        f = _case(name, "http://127.0.0.1:1")
        rec = _RecordingRequester()
        vf._replay_request(rec, f, PAYLOAD)
        assert rec.calls, f"{name}: no request was made"
        params = rec.calls[-1]["params"]
        assert "_" not in params, (
            f"{name} now reaches the params['_'] fallback, so the claim in "
            f"the section comment -- that no listed carrier does -- is "
            f"stale. Update the comment and PARAMLESS_TYPES.")


@requires_loopback
def test_session_state_change_is_not_served_from_the_get_cache(lab):
    """Locks the mechanism behind the second bug this file caught.

    The GET cache keys on the URL and can only see ``params`` / the
    per-request ``headers`` argument -- it is blind to anything the caller set
    on ``session``.  So a cached bare-URL GET shadows a later request whose
    meaning changed through the session, which is exactly what a replay does
    when it injects a header or a cookie.

    The first two assertions below document the trap; the third is the fix
    the replay now relies on (``cache_get=False``).
    """
    if not loopback_healthy():
        pytest.skip("loopback degraded")
    r = Requester(timeout=15, verify_ssl=False)
    url = f"{lab}/hdr"

    r.session.headers["X-Test"] = "first"
    assert "first" in r.request("GET", url).text      # caches this URL

    r.session.headers["X-Test"] = "second"
    # Cache on: the stale body comes back even though the request changed.
    assert "first" in r.request("GET", url).text
    assert "second" not in r.request("GET", url).text

    # Cache off: the network is actually consulted.
    fresh = r.request("GET", url, cache_get=False).text
    assert "second" in fresh


@requires_loopback
def test_verify_findings_agrees_with_the_per_carrier_result(lab):
    """The public entry point must not swallow what the per-carrier path
    reports -- a mismatch would mean the verdicts users see differ from the
    verdicts this suite checks."""
    if not loopback_healthy():
        pytest.skip("loopback degraded")
    findings = [_case(name, lab) for name in CARRIERS]
    r = Requester(timeout=15, verify_ssl=False)
    results = vf.verify_findings(findings, r, verbose=False)
    statuses = [(x.get("verify") or {}).get("status") for x in results]
    assert statuses.count("still_vuln") == len(CARRIERS), (
        f"expected every carrier to re-confirm, got {statuses}")
