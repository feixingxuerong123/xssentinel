# -*- coding: utf-8 -*-
"""Phase 306: encoding-first probes for decode-then-reflect endpoints.

A plain alphanumeric marker is not reflected when the app decodes the
parameter before echoing it (base64 / multi-URL decode), so `_probe_param`
returns at the "not reflected" branch and the transform ladder never sees
the parameter.  XSSMaze's realworld-encoding/decode families are that shape.

The bounded pass (GET query + HTML only, one payload x 3 decode shapes) must
detect the decode-then-reflect page and stay silent on the escaped twin.
"""
import base64
import html
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from xssentinel.core import transform  # noqa: E402
from xssentinel.core.requester import Requester  # noqa: E402
from xssentinel.core.scanner import Scanner  # noqa: E402


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        parts = urlsplit(self.path)
        q = (parse_qs(parts.query).get("q") or [""])[0]
        if parts.path == "/b64":
            try:
                q = base64.b64decode(q).decode("utf-8", "replace")
            except Exception:
                q = ""  # strict decoder: invalid input yields no reflection
            body = f"<html><body><div>{q}</div></body></html>"
        elif parts.path == "/bin":
            # XSSMaze decode-level1 shape: anything that is not valid base64
            # is answered with raw binary bytes (the marker becomes 20 bytes
            # of undecodable noise), while a real base64 payload decodes to
            # an HTML script block.
            try:
                decoded = base64.urlsafe_b64decode(q + "=" * (-len(q) % 4))
            except Exception:
                decoded = b""
            if b"<script>" in decoded:
                body = f"<html><body>{decoded.decode('utf-8', 'replace')}</body></html>"
            else:
                body = b"\xc6\xcb\x1e\x9e\xd8\xa7z_\xda\xb3)\xdc\xfe\xab\x9e\xaf/\xddy\xa7"
                raw = body
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return
        else:  # /safe: escaped twin, never executes
            body = f"<html><body><div>{html.escape(q)}</div></body></html>"
        raw = body.encode()
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
                 max_transforms=12, dom_engine="static")
    sc.scan_target(base + path, method="GET", params={"q": "a"}, data={},
                   oob_collect=False)
    sc.dedup()
    return [f.data for f in sc.findings]


def test_base64_and_triple_transforms_round_trip():
    from urllib.parse import unquote
    assert base64.b64decode(transform.apply("base64", "a b")).decode() == "a b"
    triple = transform.apply("triple_url_encode", "<x>")
    assert "%25" in triple
    s = triple
    for _ in range(3):
        s = unquote(s)
    assert s == "<x>"


def test_decode_then_reflect_is_a_finding(base):
    rows = _scan(base, "/b64")
    assert [r for r in rows if r.get("type") == "reflected"], rows


def test_escaped_twin_stays_silent(base):
    rows = _scan(base, "/safe")
    assert not [r for r in rows if r.get("type") == "reflected"], rows


def test_async_engine_has_the_same_pass(base):
    import asyncio

    from xssentinel.core.async_scanner import AsyncScanner

    async def _run():
        asc = AsyncScanner(max_concurrent=2, per_host_delay=0, jitter=0,
                           timeout=8, dom_engine="static",
                           max_payloads=14, max_transforms=12)
        return [f.data async for f in asc.scan(
            base + "/b64", method="GET", params={"q": "a"})]

    rows = asyncio.run(_run())
    assert [r for r in rows if r.get("type") == "reflected"], rows


class _BinaryBody:
    async def text(self):
        raise UnicodeDecodeError("utf-8", b"\xc6", 0, 1, "invalid start byte")

    async def read(self):
        return b"\xc6\xcbA"


class _PlainBody:
    def __init__(self):
        self.read_calls = 0

    async def text(self):
        return "<p>ok</p>"

    async def read(self):
        self.read_calls += 1
        return b""


def test_read_text_tolerates_an_undecodable_body():
    """The sync transport (requests) replaces bad bytes; aiohttp raises.

    Without the shared tolerant reader, the marker probe on a binary-echo
    endpoint raised inside `_probe_param` and the whole parameter was
    silently skipped -- measured on XSSMaze /decode/level1, where the
    encoding-first pass then never ran (0 requests, 0 findings, async).
    """
    import asyncio

    from xssentinel.core.async_scanner_common import _read_text

    out = asyncio.run(_read_text(_BinaryBody()))
    assert "A" in out
    assert "\ufffd" in out


def test_read_text_leaves_a_decodable_body_untouched():
    import asyncio

    from xssentinel.core.async_scanner_common import _read_text

    resp = _PlainBody()
    assert asyncio.run(_read_text(resp)) == "<p>ok</p>"
    assert resp.read_calls == 0


def test_async_survives_a_binary_marker_echo(base):
    """End-to-end for the shape above: the marker probe returns bytes that
    are not valid UTF-8; the encoded probe that follows must still run."""
    import asyncio

    from xssentinel.core.async_scanner import AsyncScanner

    async def _run():
        asc = AsyncScanner(max_concurrent=2, per_host_delay=0, jitter=0,
                           timeout=8, dom_engine="static",
                           max_payloads=14, max_transforms=12)
        return [f.data async for f in asc.scan(
            base + "/bin", method="GET", params={"q": "a"})]

    rows = asyncio.run(_run())
    assert [r for r in rows if r.get("type") == "reflected"], rows
