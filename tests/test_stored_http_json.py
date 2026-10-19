# -*- coding: utf-8 -*-
"""Phase 274: the HTTP stored path can carry a JSON body and companion fields.

Why this file exists.  ``scan_stored_dom`` grew ``extra_fields`` in Phase
152b (password / csrf / captcha), and ``scan_stored`` grew ``data_json`` in
Phase 241 -- but the CLI never exposed ``data_json``, and ``--stored-extra``
was parsed only inside the ``--stored-dom`` branch.  A JSON write API that
also demands a captcha could therefore not be driven from the command line
at all: OWASP Juice Shop's ``POST /api/Feedbacks`` needs
``{comment, rating, captchaId, captcha}`` as JSON, and the only path that
sent JSON was the browser-rendered one.

These are pure-logic tests with a recording requester: no network, no
browser.  They lock the wire shape, not the verdict.
"""
from __future__ import annotations

from xssentinel.core.scanner_stored import StoredBlindMixin


class _Resp:
    def __init__(self, text: str = ""):
        self.text = text
        self.status_code = 200


class _RecordingReq:
    def __init__(self):
        self.calls: list[dict] = []
        self.gets: list[str] = []

    def request(self, method, url, params=None, data=None, json=None,
                headers=None, **kw):
        self.calls.append({"method": method, "url": url, "params": params,
                           "data": data, "json": json, "headers": headers})
        return _Resp()

    def get(self, url, cache_get: bool = True, **kw):
        self.gets.append(url)
        return _Resp("")          # view never shows the token -> no finding

    def invalidate(self, url):
        pass


class _Coverage:
    def touch_layer(self, *a, **k):
        pass


class _Host(StoredBlindMixin):
    def __init__(self):
        self.req = _RecordingReq()
        self.findings: list = []
        self.verbose = False
        self.max_payloads = 1
        self.max_transforms = 1
        self.coverage = _Coverage()

    def _add(self, finding):
        self.findings.append(finding)

    def _bump(self):
        pass


def _posts(host):
    return [c for c in host.req.calls if c["method"] == "POST"]


def test_json_body_carries_companion_fields():
    """The Juice-Shop feedback shape: a JSON API that refuses the write
    unless rating/captcha arrive in the same document."""
    host = _Host()
    host.scan_stored("http://t/api/Feedbacks",
                     view_url="http://t/api/Feedbacks", param="comment",
                     data_json=True,
                     extra_fields={"rating": "5", "captchaId": "7",
                                   "captcha": "12"})
    posts = _posts(host)
    assert posts, "nothing was submitted"
    for p in posts:
        assert p["data"] is None, "JSON mode must not also send a form body"
        body = p["json"]
        assert body["rating"] == "5"
        assert body["captchaId"] == "7"
        assert body["captcha"] == "12"
        assert "comment" in body


def test_form_body_carries_companion_fields_too():
    host = _Host()
    host.scan_stored("http://t/write", view_url="http://t/view",
                     param="comment", data_json=False,
                     extra_fields={"csrf": "abc"})
    posts = _posts(host)
    assert posts
    for p in posts:
        assert p["json"] is None
        assert p["data"]["csrf"] == "abc"
        assert "comment" in p["data"]


def test_companion_field_cannot_overwrite_the_payload():
    """`--stored-param comment` means the payload rides in `comment`; an
    operator who also passes `--stored-extra comment=...` must not be able
    to replace every probe with a constant."""
    host = _Host()
    host.scan_stored("http://t/write", view_url="http://t/view",
                     param="comment", data_json=True,
                     extra_fields={"comment": "OVERWRITE"})
    body = _posts(host)[0]["json"]
    assert body["comment"] != "OVERWRITE"


def test_header_param_puts_the_payload_in_the_header():
    """Phase 277: header-borne writes (Juice Shop persists True-Client-IP
    into the user's last-login IP on a GET).  The payload cannot ride in a
    body or a query there."""
    host = _Host()
    host.scan_stored("http://t/rest/saveLoginIp", view_url="http://t/view",
                     method="GET", param="ignored",
                     header_param="True-Client-IP")
    calls = host.req.calls
    assert calls, "nothing was submitted"
    for c in calls:
        assert c["method"] == "GET"
        assert c["params"] is None, "the payload must not leak into the query"
        assert c["headers"] and "True-Client-IP" in c["headers"]
        assert c["headers"]["True-Client-IP"], "header value is empty"


def test_header_param_keeps_extras_in_a_post_body():
    host = _Host()
    host.scan_stored("http://t/write", view_url="http://t/view",
                     param="comment", header_param="X-Attack",
                     extra_fields={"csrf": "abc"})
    posts = _posts(host)
    assert posts
    for p in posts:
        assert p["headers"]["X-Attack"]
        assert p["data"]["csrf"] == "abc"
