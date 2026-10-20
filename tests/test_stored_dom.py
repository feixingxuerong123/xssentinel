"""Phase 152: scan_stored_dom -- stored XSS verified by the real browser.

Pure-logic tests: a fake host (the StoredBlindMixin needs req / _add /
_bump / coverage / max_payloads / verbose), a recording requester, and a
fake DOM engine replaying analyze() results.  No network, no subprocess,
no Playwright.

Locks the contract that the Juice-Shop-shaped flow (§17/§18 of the
delivery report) depends on:
  * submits BOTH a form-encoded and a JSON body variant (SPA write
    endpoints are JSON; classic guestbooks are form),
  * passes the submission token to engine.analyze(marker=...),
  * emits a stored_dom finding only when the browser reports a hit,
  * self-view (no explicit view URL) is confidence=medium,
  * payloads without an alert() call are skipped (mark() would leave
    them token-free -- the hooks could never see them),
  * extra_fields (companion fields real write APIs demand -- password,
    csrf, captcha) ride along in BOTH encodings, payload in `param`.
"""
from __future__ import annotations

import pytest

from xssentinel.core.scanner_stored import StoredBlindMixin
from xssentinel.core import payloads as payloads_mod


HIT = [{"sink": "Element.innerHTML", "snippet": "<li>...xssv_tok...</li>"}]
# Phase 282: a dialog hit means the stored payload EXECUTED (the dialog
# carried the probe token); a bare sink hit means it only reached a sink.
DIALOG_HIT = [{"sink": "dialog", "snippet": "alert('xssv_tok')"}]


class _FakeEngine:
    def __init__(self, hits):
        self._hits = hits
        self.calls = []
        self.clicks = []
        self.url_probes = []

    def available(self):
        return True

    def analyze(self, url, marker=None, dialog_token=None,
                click_selector=None,
                url_probes=True):
        self.calls.append((url, marker, dialog_token))
        self.clicks.append(click_selector)
        self.url_probes.append(url_probes)
        return list(self._hits)


class _FakeCoverage:
    def touch_layer(self, *a, **k):
        pass


class _RecordingReq:
    def __init__(self):
        self.calls = []

    def request(self, method, url, params=None, data=None, json=None,
                files=None, headers=None):
        self.calls.append({"method": method, "url": url, "data": data,
                           "json": json, "headers": headers})
        return object()  # truthy response stand-in


class _Host(StoredBlindMixin):
    """Minimal Scanner stand-in for the mixin."""

    def __init__(self, engine):
        self.req = _RecordingReq()
        self.engine = engine
        self.findings = []
        self.verbose = False
        self.max_payloads = 5
        self.max_transforms = 3
        self.coverage = _FakeCoverage()
        # Phase 278: --stored-relogin updates these before the render.
        self.auth_headers: dict = {}
        self.auth_cookies: list = []
        self.auth_local_storage: dict = {}

    def _add(self, finding):
        self.findings.append(finding)

    def _bump(self):
        pass

    def _resolve_dom_engine(self):
        return self.engine


def test_hit_emits_stored_dom_and_submits_form_plus_json():
    eng = _FakeEngine(HIT)
    host = _Host(eng)
    ok = host.scan_stored_dom("http://t/write", view_url="http://t/view",
                              param="comment")
    assert ok is True
    assert len(host.findings) == 1
    f = host.findings[0].data
    assert f["type"] == "stored_dom"
    assert f["severity"] == "high"
    assert f["confidence"] == "high"
    # The engine DID run a browser here, so this finding must stop filing as
    # "never checked" (`headless` used to be None on this exact path).
    assert f["evidence_class"] == "browser-executed"
    assert f["headless"]["outcome"] == "fired"
    assert f["method"] == "POST" and f["param"] == "comment"
    proof = f["proof"]
    assert proof["view_url"] == "http://t/view"
    assert proof["token"].startswith("xssv_")
    # The token submitted is the token the engine was told to expect.
    assert eng.calls and eng.calls[0][0] == "http://t/view"
    assert proof["token"] in eng.calls[0][1]
    # Both encodings were submitted with the same token-carrying variant.
    submissions = [c for c in host.req.calls if c["method"] == "POST"]
    # Phase 280: a delivery-only answer no longer ends the probe, so every
    # base is submitted (_STORED_DOM_PROBE_BASES x 2 encodings).
    from xssentinel.core.scanner_stored import _STORED_DOM_PROBE_BASES
    assert len(submissions) == _STORED_DOM_PROBE_BASES * 2
    assert submissions[0]["data"] == {"comment": submissions[0]["data"]["comment"]}
    assert submissions[1]["json"] is not None
    assert proof["token"] in submissions[0]["data"]["comment"]
    assert proof["token"] in submissions[1]["json"]["comment"]


class _ExecutesOnSecondProbe:
    """Phase 280: the first probe only reaches the sink, the second fires.

    The corpus puts three inert-through-innerHTML shapes before
    `<img src=x onerror=...>`, so stopping at the first hit reports the
    inert payload and never asks the one that executes.
    """

    def __init__(self):
        self.n = 0

    def available(self):
        return True

    def analyze(self, url, marker=None, dialog_token=None,
                click_selector=None,
                url_probes=True):
        self.n += 1
        if self.n == 1:
            return list(HIT)          # delivery only
        return [{"sink": "dialog", "snippet": f"alert('{marker}')"}]


def test_probe_continues_until_a_payload_executes():
    eng = _ExecutesOnSecondProbe()
    host = _Host(eng)
    ok = host.scan_stored_dom("http://t/write", view_url="http://t/view",
                              param="comment")
    assert ok is True
    assert eng.n >= 2, "the probe stopped on the delivery-only answer"
    f = host.findings[0].data
    # the reported row is the one that EXECUTED, not the first delivery
    assert f["type"] == "stored_dom"
    assert f["severity"] == "high"
    assert f["headless"]["outcome"] == "fired"
    assert f["proof"] is not None


def test_view_click_is_forwarded_to_the_engine():
    """Phase 282: a view that renders the stored value only after a click
    (Juice Shop's product-details dialog) is unreachable from a URL view,
    so the click has to reach the engine as the selector the operator
    asked for."""
    eng = _FakeEngine(DIALOG_HIT)
    host = _Host(eng)
    ok = host.scan_stored_dom("http://t/api/Products/1",
                              view_url="http://t/search", param="description",
                              method="PUT", view_click="mat-card")
    assert ok is True
    assert eng.clicks == ["mat-card"], eng.clicks


def test_stored_verification_does_not_push_the_marker_into_url_sources():
    """Phase 283: the stored path used to share ONE token with the engine's
    URL probes, so a view page reflecting location.hash or a query parameter
    delivered that token to a sink and the hit was attributed to the stored
    payload.  Measured on Juice Shop's API-only XSS: replaying the finding's
    own payload showed the token never reaching the page."""
    eng = _FakeEngine(DIALOG_HIT)
    host = _Host(eng)
    ok = host.scan_stored_dom("http://t/api/Products/1",
                              view_url="http://t/search", param="description",
                              method="PUT", view_click="mat-card")
    assert ok is True
    assert eng.url_probes == [False], (
        "stored verification must not run the engine's URL-source probes")
    # the marker the engine is told to watch is still the stored token, so a
    # hit can only have come from the page's own data
    assert eng.calls[0][1].startswith("xssv_")


def test_view_click_defaults_to_none():
    eng = _FakeEngine(DIALOG_HIT)
    host = _Host(eng)
    host.scan_stored_dom("http://t/write", view_url="http://t/view",
                         param="comment")
    assert eng.clicks == [None]


def test_no_browser_hit_means_no_finding():
    host = _Host(_FakeEngine([]))
    ok = host.scan_stored_dom("http://t/write", view_url="http://t/view")
    assert ok is False
    assert host.findings == []


def test_json_body_flag_narrows_the_encodings():
    host = _Host(_FakeEngine([]))
    host.scan_stored_dom("http://t/write", view_url="http://t/view",
                         json_body=True)
    posts = [c for c in host.req.calls if c["method"] == "POST"]
    assert posts and all(c["json"] is not None and c["data"] is None
                         for c in posts)


def test_unavailable_engine_is_a_clean_noop():
    class _Dead:
        def available(self):
            return False

        def analyze(self, url, marker=None):  # pragma: no cover
            raise AssertionError("analyze must not be called")

    host = _Host(_Dead())
    assert host.scan_stored_dom("http://t/write",
                                view_url="http://t/view") is False
    assert host.req.calls == []
    assert host.findings == []


def test_self_view_is_downgraded_to_medium_confidence():
    eng = _FakeEngine(HIT)
    host = _Host(eng)
    # view_url omitted -> self-view -> medium + explicit note.
    ok = host.scan_stored_dom("http://t/write")
    assert ok is True
    assert host.findings[0].data["confidence"] == "medium"
    # Execution and persistence are separate claims: the browser DID fire the
    # marker here, so the tier says so -- and the grading must not spend that
    # fact to upgrade a confidence number that is about "renders for OTHER
    # viewers", which self-view has not shown.
    _d = host.findings[0].data
    assert _d["evidence_class"] == "browser-executed"
    assert _d["confidence"] == "medium", "grading must not raise this"
    assert _d["severity"] == "high", "severity is impact, not belief"


def test_alertless_payloads_are_skipped(monkeypatch):
    """A payload whose text never carries the token can never be seen by
    the sink hooks -- mark() leaves alert-less payloads unchanged, so the
    flow must skip them instead of burning browser passes on nothing."""

    def _fake_by_context(name):
        return [{"payload": "<script>fetch('/x')</script>"}]  # no alert()

    monkeypatch.setattr(payloads_mod, "by_context", _fake_by_context)
    host = _Host(_FakeEngine(HIT))
    ok = host.scan_stored_dom("http://t/write", view_url="http://t/view")
    assert ok is False
    assert host.findings == []
    assert all(c["method"] != "POST" for c in host.req.calls)


def test_extra_fields_ride_along_in_both_encodings():
    """Phase 152b (Juice Shop): register/profile write APIs reject a POST
    that carries only the payload field -- companion fields (password,
    securityAnswer, ...) must be merged into every submission while the
    payload still rides in ``param``."""
    eng = _FakeEngine(HIT)
    host = _Host(eng)
    extras = {"password": "Xss-T3st!", "securityAnswer": "x"}
    ok = host.scan_stored_dom("http://t/users", view_url="http://t/admin",
                              param="email", extra_fields=extras)
    assert ok is True
    posts = [c for c in host.req.calls if c["method"] == "POST"]
    from xssentinel.core.scanner_stored import _STORED_DOM_PROBE_BASES
    assert len(posts) == _STORED_DOM_PROBE_BASES * 2
    for sub in posts:
        body = sub["json"] if sub["json"] is not None else sub["data"]
        assert body["password"] == "Xss-T3st!"
        assert body["securityAnswer"] == "x"
        assert body["email"].startswith("<")  # payload field intact
    # the payload field must be the only marker-carrying field
    assert eng.calls and eng.calls[0][1] in posts[1]["json"]["email"]


def test_header_param_sends_the_payload_in_a_header():
    """Phase 277: header-borne writes (Juice Shop persists True-Client-IP
    into the user's last-login IP via GET /rest/saveLoginIp).  The payload
    cannot ride in a body or a query there, and this path used to ignore
    --stored-header entirely."""
    host = _Host(_FakeEngine([]))
    ok = host.scan_stored_dom("http://t/rest/saveLoginIp",
                              view_url="http://t/view",
                              method="GET", header_param="True-Client-IP")
    assert ok is False           # no browser hit -> no finding
    subs = [c for c in host.req.calls if c["method"] == "GET"]
    assert subs, "nothing was submitted"
    for c in subs:
        assert c["headers"] and c["headers"]["True-Client-IP"]
        assert c["data"] is None and c["json"] is None, (
            "a header write must not also leak the payload into the body")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))


def test_relogin_refreshes_auth_before_the_render():
    """Phase 278: a view that serves a value snapshotted at login time
    (Juice Shop's last-login IP lives in the JWT) can only render the
    payload after a fresh login.  The callback must update both the HTTP
    session headers and the browser's localStorage before engine.analyze."""
    host = _Host(_FakeEngine([]))
    seen: dict = {}

    def relogin():
        seen["called"] = True
        return {"Authorization": "Bearer NEW"}, {"token": "NEW"}, "NEW"

    host.scan_stored_dom("http://t/rest/saveLoginIp", view_url="http://t/view",
                         method="GET", header_param="True-Client-IP",
                         relogin=relogin)
    assert seen.get("called"), "re-login was never performed"
    assert host.auth_headers["Authorization"] == "Bearer NEW"
    assert host.auth_local_storage["token"] == "NEW"


def test_relogin_failure_does_not_kill_the_render():
    host = _Host(_FakeEngine([]))

    def relogin():
        raise RuntimeError("login endpoint down")

    ok = host.scan_stored_dom("http://t/write", view_url="http://t/view",
                              relogin=relogin)
    assert ok is False          # no hit, but the run completed
