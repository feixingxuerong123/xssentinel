# -*- coding: utf-8 -*-
"""Phase 308: case-normalised reflections still count as reflections.

XSSMaze's casemanip family changes only the case of the input:

  level2  upper-first   ``xssm_...`` -> ``Xssm_...``
  level3  swap-case     ``xssm_...`` -> ``XSSM_...``
  level6  titlecase     ``xssm_...`` -> ``Xssm_...``

The scanner tested ``marker in text`` exactly, so every one of those pages
took the "not reflected" branch and never sent a payload -- while a live
``<img onerror>`` reflection sat in the body.  ``find_reflected_marker``
returns the reflected spelling (exact first, then an ASCII case-insensitive
match) and both engines use it for context analysis.

Swap-case also turns ``alert`` into ``ALERT``, so level3 additionally needs
a case-swap-aware payload; that is a separate gap and is not asserted here.
"""
import asyncio
import html
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from xssentinel.core import context  # noqa: E402
from xssentinel.core.async_scanner import AsyncScanner  # noqa: E402
from xssentinel.core.requester import Requester  # noqa: E402
from xssentinel.core.scanner import Scanner  # noqa: E402

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        parts = urlsplit(self.path)
        value = (parse_qs(parts.query).get("q") or [""])[0]
        path = parts.path
        safe = path.endswith("-safe")
        base = path[:-5] if safe else path

        if base == "/upper-first":
            out = value[:1].upper() + value[1:]
        elif base == "/titlecase":
            out = re.sub(r"(^|\s)(\w)",
                         lambda m: m.group(1) + m.group(2).upper(), value)
        elif base == "/swap-case":
            out = value.swapcase()
        elif base == "/no-reflect":
            out = None
        else:
            self.send_response(404)
            self.end_headers()
            return

        if out is None:
            body = "<html><body>nothing to see</body></html>"
        elif safe:
            body = f"<html><body>{html.escape(out)}</body></html>"
        else:
            body = f"<html><body>{out}</body></html>"
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
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


def _scan(base, path):
    sc = Scanner(requester=Requester(timeout=8), max_payloads=14,
                 max_transforms=12, dom_engine="static",
                 advanced_layers=False)
    sc.scan_target(base + path, method="GET", params={"q": "a"}, data={},
                   oob_collect=False)
    sc.dedup()
    return [f.data for f in sc.findings]


def _scan_async(base, path):
    async def _run():
        asc = AsyncScanner(max_concurrent=2, per_host_delay=0, jitter=0,
                           timeout=8, dom_engine="static",
                           advanced_layers=False, max_payloads=14,
                           max_transforms=12)
        return [f.data async for f in asc.scan(
            base + path, method="GET", params={"q": "a"})]

    try:
        return asyncio.run(asyncio.wait_for(_run(), timeout=90))
    except asyncio.TimeoutError:
        pytest.fail(f"async scan of {path} did not finish within 90s")


def _detected(rows):
    return [r for r in rows
            if r.get("type") in ("reflected", "polyglot_reflection")
            and r.get("severity") in ("high", "medium", "critical")]


# ---------------------------------------------------------------------------
# Helper contract
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("text,expected", [
    ("<div>xssm_ab12</div>", "xssm_ab12"),
    ("<div>Xssm_ab12</div>", "Xssm_ab12"),
    ("<div>XSSM_AB12</div>", "XSSM_AB12"),
    ("<div>xSsM_Ab12</div>", "xSsM_Ab12"),
])
def test_find_reflected_marker_returns_the_reflected_spelling(text, expected):
    assert context.find_reflected_marker(text, "xssm_ab12") == expected


def test_find_reflected_marker_prefers_the_exact_spelling():
    text = "XSSM_AB12 and xssm_ab12"
    assert context.find_reflected_marker(text, "xssm_ab12") == "xssm_ab12"


@pytest.mark.parametrize("text,marker", [
    ("", "xssm_ab12"),
    ("<div>nothing</div>", "xssm_ab12"),
    ("<div>xssm_ab1</div>", "xssm_ab12"),
    ("<div>xssm_ab12</div>", ""),
])
def test_find_reflected_marker_returns_none_when_absent(text, marker):
    assert context.find_reflected_marker(text, marker) is None


def test_find_reflected_marker_ascii_lower_is_length_preserving():
    # A non-ASCII capital before the marker must not shift the offset.
    assert context.find_reflected_marker("İİ-XSSM_AB12", "xssm_ab12") \
        == "XSSM_AB12"


# ---------------------------------------------------------------------------
# End-to-end: the marker fallback unblocks the payload loop
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("path", ["/upper-first", "/titlecase"])
def test_sync_case_normalised_reflection_is_detected(base, path):
    rows = _scan(base, path)
    assert _detected(rows), rows


@pytest.mark.parametrize("path", ["/upper-first", "/titlecase"])
def test_async_case_normalised_reflection_is_detected(base, path):
    rows = _scan_async(base, path)
    assert _detected(rows), rows


@pytest.mark.parametrize("path", ["/upper-first-safe", "/titlecase-safe"])
def test_safe_twins_stay_silent(base, path):
    rows = _scan(base, path)
    assert not _detected(rows), rows


def test_no_reflection_stays_silent(base):
    rows = _scan(base, "/no-reflect")
    assert not _detected(rows), rows


# ---------------------------------------------------------------------------
# Swap-case retry: gated on an exact swap-case marker reflection
# ---------------------------------------------------------------------------
def test_sync_swap_case_retry_detects(base):
    rows = _scan(base, "/swap-case")
    hits = [r for r in rows if r.get("type") == "reflected"]
    assert hits, rows
    assert hits[0].get("transform") == ["swap_case"], hits[0]


def test_async_swap_case_retry_detects(base):
    rows = _scan_async(base, "/swap-case")
    hits = [r for r in rows if r.get("type") == "reflected"]
    assert hits, rows
    assert hits[0].get("transform") == ["swap_case"], hits[0]


def test_swap_case_safe_twin_stays_silent(base):
    rows = _scan(base, "/swap-case-safe")
    assert not _detected(rows), rows


class _CountingReq:
    def __init__(self, inner, counter):
        self.inner = inner
        self.counter = counter

    def request(self, *args, **kwargs):
        self.counter["n"] += 1
        return self.inner.request(*args, **kwargs)


class _CountingSession:
    def __init__(self, inner, counter):
        self.inner = inner
        self.counter = counter

    def request(self, *args, **kwargs):
        self.counter["n"] += 1
        return self.inner.request(*args, **kwargs)


def test_swap_case_retry_costs_one_request(base, monkeypatch):
    counter = {"n": 0}
    original = Scanner._try_case_swap

    def counted(self, req, *args, **kwargs):
        return original(self, _CountingReq(req, counter), *args, **kwargs)

    monkeypatch.setattr(Scanner, "_try_case_swap", counted)
    rows = _scan(base, "/swap-case")
    assert [r for r in rows if r.get("type") == "reflected"], rows
    assert counter["n"] == 1


def test_async_swap_case_retry_costs_one_request(base, monkeypatch):
    from xssentinel.core.async_scanner_layers import (
        AsyncDetectionLayersMixin,
    )

    counter = {"n": 0}
    original = AsyncDetectionLayersMixin._try_case_swap_async

    async def counted(self, session, *args, **kwargs):
        async for finding in original(self, _CountingSession(session, counter),
                                      *args, **kwargs):
            yield finding

    monkeypatch.setattr(AsyncDetectionLayersMixin,
                        "_try_case_swap_async", counted)
    rows = _scan_async(base, "/swap-case")
    assert [r for r in rows if r.get("type") == "reflected"], rows
    assert counter["n"] == 1


def test_swap_case_gate_ignores_non_swap_transforms(base, monkeypatch):
    calls = []
    monkeypatch.setattr(Scanner, "_try_case_swap",
                        lambda *args, **kwargs: calls.append(args) or False)
    _scan(base, "/upper-first")
    assert calls == []


def test_swap_case_retry_is_load_bearing_sync(base, monkeypatch):
    monkeypatch.setattr(Scanner, "_try_case_swap",
                        lambda *args, **kwargs: False)
    rows = _scan(base, "/swap-case")
    assert not [r for r in rows if r.get("type") == "reflected"], rows


def test_swap_case_retry_is_load_bearing_async(base, monkeypatch):
    from xssentinel.core.async_scanner_layers import (
        AsyncDetectionLayersMixin,
    )

    async def _empty(self, *args, **kwargs):
        if False:  # pragma: no cover - makes this an async generator
            yield None

    monkeypatch.setattr(AsyncDetectionLayersMixin,
                        "_try_case_swap_async", _empty)
    rows = _scan_async(base, "/swap-case")
    assert not [r for r in rows if r.get("type") == "reflected"], rows


# ---------------------------------------------------------------------------
# Mutation control: exact-only matching must lose the detection
# ---------------------------------------------------------------------------
def _exact_only(text, marker):
    return marker if marker in text else None


def test_case_fallback_is_load_bearing_sync(base, monkeypatch):
    # The sync engine returns at the "not reflected" branch, so losing the
    # case-insensitive match loses the finding outright.
    monkeypatch.setattr(context, "find_reflected_marker", _exact_only)
    rows = _scan(base, "/upper-first")
    assert not _detected(rows), rows


def test_both_engines_call_the_shared_helper():
    """The async engine already falls through to payloads when the marker is
    missing (its polyglot/payload path can still flag these pages), so an
    outcome mutation control would not be load-bearing there.  What must not
    drift is the wiring: both engines use the same canonical helper for the
    reflected spelling and the escaped-marker check."""
    import inspect

    from xssentinel.core import async_scanner, scanner

    sync_src = inspect.getsource(scanner.Scanner._scan_param)
    async_src = inspect.getsource(async_scanner.AsyncScanner._probe_param)
    for src in (sync_src, async_src):
        assert "ctx.find_reflected_marker" in src
        assert "marker = reflected_marker" in src
