# -*- coding: utf-8 -*-
"""Phase 278: JSON login -- token out of the body, into both worlds.

Juice Shop's login is `POST /rest/user/login` with a JSON document, and the
session token comes back at `authentication.token`.  Form login cannot
express that, so --stored-relogin (the fix for views that serve a value
snapshotted at login time) had nothing to call.
"""
from __future__ import annotations

from xssentinel.core.session import login_json


class _Resp:
    def __init__(self, data):
        self._data = data

    def json(self):
        if isinstance(self._data, Exception):
            raise self._data
        return self._data


class _Req:
    def __init__(self, resp):
        self._resp = resp
        self.sent = None

    def post(self, url, json=None, **kw):
        self.sent = json
        return self._resp


def test_login_json_reads_the_dotted_path():
    rq = _Req(_Resp({"authentication": {"token": "T0K"}}))
    headers, storage, token = login_json(
        rq, "http://t/rest/user/login", "admin@juice-sh.op", "admin123",
        user_field="email", pass_field="password")
    assert token == "T0K"
    assert headers == {"Authorization": "Bearer T0K"}
    assert storage == {"token": "T0K"}
    assert rq.sent == {"email": "admin@juice-sh.op", "password": "admin123"}


def test_login_json_without_a_token_returns_nothing():
    rq = _Req(_Resp({"authentication": {}}))
    headers, storage, token = login_json(rq, "http://t/login", "u", "p")
    assert (headers, storage, token) == ({}, {}, None)


def test_login_json_survives_a_non_json_response():
    rq = _Req(_Resp(ValueError("not json")))
    assert login_json(rq, "http://t/login", "u", "p") == ({}, {}, None)
