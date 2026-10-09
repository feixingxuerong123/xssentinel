# -*- coding: utf-8 -*-
"""Phase 209: the async engine must not advertise an encoding it cannot decode.

Found by scanning a real application.  ``--async`` against OWASP Juice Shop
made 1 request and 1 failure: aiohttp raised

    400, message: Can not decode content-encoding: br

because ``aiohttp.compression_utils.HAS_BROTLI`` is True here (the ``Brotli``
package imports), so aiohttp puts ``br`` in its default Accept-Encoding -- and
then its own decompressor calls ``brotli.Decompressor.process(data,
max_length)``, which this package's binding implements as ``process(data)``.
TypeError, rewritten as a 400, and every response dies: a healthy site with
compression enabled reads as "0 findings" to the async engine.  No fixture in
this repo could have shown it, because stdlib ``http.server`` never
compresses.

Two assertions, both behavioural:

  * the scan asks only for encodings it can decode, so a negotiation-honouring
    server answers in plaintext/gzip and the body arrives;
  * the control half -- a client that DOES advertise ``br`` (the pre-fix
    behaviour, forced here) fails on the same server.  Without that pair the
    test would pass on a server that simply never compresses, which is the
    shape every previous test in this repo had.
"""
from __future__ import annotations

import asyncio
import gzip
import io
import os
import socket
import sys
import threading
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

aiohttp = pytest.importorskip("aiohttp")

from xssentinel.core.async_scanner import AsyncScanner  # noqa: E402
from xssentinel.core.async_scanner_common import (  # noqa: E402
    safe_accept_encoding, _aiohttp_can_decode)

MARKER = "xssentinel-accept-encoding-probe"


def _encoders():
    """br encoder only when a real brotli encoder is importable."""
    try:
        import brotli
        return {"br": lambda b: brotli.compress(b)}
    except Exception:
        return {}


class _Handler(BaseHTTPRequestHandler):
    """Compresses the body in whatever the client asked for, like a real
    Express/`compression()` server -- which is the entire point."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        body = f"<html><body>{MARKER}</body></html>".encode()
        asked = (self.headers.get("Accept-Encoding") or "").lower()
        used = None
        if "br" in asked and "br" in _encoders():
            body, used = _encoders()["br"](body), "br"
        elif "gzip" in asked:
            buf = io.BytesIO()
            with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
                gz.write(body)
            body, used = buf.getvalue(), "gzip"
        elif "deflate" in asked:
            body, used = zlib.compress(body), "deflate"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        if used:
            self.send_header("Content-Encoding", used)
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def origin():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    srv = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


def _fetch(url: str, headers: dict) -> str:
    async def go():
        async with aiohttp.ClientSession() as s:
            async with s.get(url, headers=headers) as r:
                return await r.text()
    return asyncio.run(go())


def _brotli_serving_environment() -> bool:
    """The control half only means something if a client that asks for br
    would actually break here -- i.e. a brotli encoder exists AND aiohttp's
    own decompressor cannot round-trip it."""
    if not _encoders():
        return False
    return not _aiohttp_can_decode("br")


def test_safe_accept_encoding_lists_only_gzip_and_deflate_by_default():
    value = safe_accept_encoding()
    assert "gzip" in value and "deflate" in value
    for ext in ("br", "zstd"):
        if ext in value:
            assert _aiohttp_can_decode(ext), (
                f"{ext} advertised but aiohttp cannot decode it -- this is "
                "the Phase 209 failure: the flag says available, the decoder "
                "raises TypeError")


def test_async_headers_carry_the_safe_encoding():
    asc = AsyncScanner()
    hdrs = asc._req_headers({})
    assert hdrs.get("Accept-Encoding") == safe_accept_encoding()


def test_operator_accept_encoding_is_not_overwritten():
    """The pin exists to fix a capability mismatch, not to override a person
    who set the header on purpose (their proxy may decode br fine)."""
    asc = AsyncScanner()
    hdrs = asc._req_headers({"accept-encoding": "br"})
    assert hdrs["accept-encoding"] == "br"
    assert "Accept-Encoding" not in hdrs


def test_async_request_gets_the_body_back(origin):
    """Behaviour: a compressing server must answer us in something we can
    read, so the scan sees the page instead of erroring."""
    asc = AsyncScanner()
    body = _fetch(origin + "/", asc._req_headers({}))
    assert MARKER in body, (
        "async could not read a negotiation-honouring server; this is the "
        f"Phase 209 outage (advertised: {safe_accept_encoding()})")


@pytest.mark.skipif(
    not _brotli_serving_environment(),
    reason="no brotli encoder here, or aiohttp decodes br correctly; the "
           "control would not be a control")
def test_control_advertising_br_really_does_break(origin):
    """Proves the previous test measured something: a client that asks for br
    (aiohttp's own default when HAS_BROTLI is set) gets a br body it cannot
    decode.  Without this pair, "we don't advertise br" is unfalsifiable."""
    with pytest.raises(Exception) as exc:
        _fetch(origin + "/", {"Accept-Encoding": "gzip, deflate, br"})
    assert "br" in str(exc.value) or "content-encoding" in str(
        exc.value).lower(), f"expected the br decode failure, got {exc.value}"
