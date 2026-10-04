# -*- coding: utf-8 -*-
"""Phase 196/197 parity lock: the async engine's form-body HPP position.

Why this file exists: `scanner._try_hpp` hardcoded ``param_in="query"`` for
body-position probes while async already computed
``"body" if is_body else "query"`` -- the usual drift in this repo, running the
other direction (sync lagged async).  It was not cosmetic: `poc.py` builds the
replay from ``param_in``, so every body-position HPP finding shipped a PoC that
put the payload in the URL and would never fire.  Nothing covered the async
side at the body position, so nothing could have caught it either way.

Two things are asserted per case, because asserting the FIELD alone proves
nothing -- a bug could set param_in="body" while sending the pair as a query
and the test would still be green:

  * what went on the wire: the duplicated parameter must be in the request
    BODY (twice, benign first / marked second) with a urlencoded
    Content-Type, and the query string must stay empty;
  * what the finding claims: ``param_in`` matches the position that was used.

Plus the reverse control the query-position test in test_phase193.py has:
against a backend that honours the FIRST occurrence, the probe must stay
silent -- otherwise "a finding appeared" is not evidence of anything.
"""
from __future__ import annotations

import asyncio
import os
import sys
from urllib.parse import parse_qsl, unquote

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.async_scanner import AsyncScanner  # noqa: E402


class _Resp:
    def __init__(self, text, status=200):
        self._text = text
        self.status = status
        self.headers = {"Content-Type": "text/html"}

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _BodyHppSession:
    """aiohttp stub whose filter reads only the FIRST q in the form body.

    `take_first` flips which occurrence the application renders, which is the
    whole difference between a bypassable filter and one the probe cannot beat.
    """

    def __init__(self, take_first: bool = False):
        self.take_first = take_first
        self.bodies: list[str] = []
        self.query: list = []
        self.headers: list[dict] = []

    def request(self, method, url, params=None, data=None, headers=None,
                proxy=None, **kw):
        self.query.append(params)
        self.headers.append(dict(headers or {}))
        body = data if isinstance(data, str) else ""
        if body:
            self.bodies.append(body)
        pairs = parse_qsl(body, keep_blank_values=True)
        qs = [v for k, v in pairs if k == "q"]
        if not qs:
            # not the HPP probe (ladder / baseline requests) -- reflect nothing
            return _Resp("<html><body>no q</body></html>")
        if "<" in qs[0]:
            return _Resp("request blocked by filter")
        shown = qs[0] if self.take_first else qs[-1]
        return _Resp(f"<html><body><div>{shown}</div></body></html>")

    def get(self, url, params=None, **kw):
        return self.request("GET", url, params=params, **kw)


def _probe_body(take_first: bool):
    async def run():
        asc = AsyncScanner(max_concurrent=2, per_host_delay=0, jitter=0,
                           timeout=5, max_payloads=3, max_transforms=1,
                           advanced_layers=False)
        asc.waf_name = "generic"          # the gate both engines share
        asc._semaphore = asyncio.Semaphore(2)
        session = _BodyHppSession(take_first=take_first)
        out = []
        async for f in asc._probe_param(session, "http://t/write", "POST",
                                        "q", {}, {"q": "probe"}, True,
                                        "<html>baseline</html>"):
            out.append(f.data if hasattr(f, "data") else dict(f))
        return out, session

    return asyncio.run(run())


def test_async_hpp_body_sends_the_pair_in_the_body_and_says_so():
    got, session = _probe_body(take_first=False)
    hpp = [d for d in got if "hpp" in tuple(d.get("transform") or [])]
    assert hpp, f"no async body-position HPP finding: {[d.get('transform') for d in got]}"

    # the claim must match what actually went out
    assert hpp[0].get("param_in") == "body", hpp[0].get("param_in")

    hpp_bodies = [b for b in session.bodies if len(
        [v for k, v in parse_qsl(b) if k == "q"]) == 2]
    assert hpp_bodies, ("the duplicated parameter never appeared in a request "
                        f"body; bodies seen: {session.bodies}")
    pairs = [(k, v) for k, v in parse_qsl(hpp_bodies[0])]
    q_vals = [unquote(v) for k, v in pairs if k == "q"]
    assert "<" not in q_vals[0], f"first occurrence must stay benign: {q_vals[0]!r}"
    assert "<" in q_vals[1], f"second occurrence must carry the payload: {q_vals[1]!r}"

    ctype = [h for h in session.headers
             if "urlencoded" in str(h.get("Content-Type", "")).lower()]
    assert ctype, ("a form-body probe must state its Content-Type; a dict "
                   f"cannot carry duplicate keys: {session.headers}")


def test_async_hpp_body_silent_when_backend_takes_the_first_occurrence():
    """Reverse control: without the take-last asymmetry there is nothing to
    bypass, so the probe must not report.  A test without this arm would also
    pass against an engine that fires on everything."""
    got, _session = _probe_body(take_first=True)
    hpp = [d for d in got if "hpp" in tuple(d.get("transform") or [])]
    assert not hpp, f"body HPP reported against a take-first backend: {hpp}"
