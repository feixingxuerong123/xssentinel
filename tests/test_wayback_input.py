"""Phase 188: --wayback CDX import (gau/waymore/ParamSpider absorption).

The expansion logic is driven through an injected ``fetch`` (no network);
one loopback test exercises the REAL requests path by pointing the module's
CDX endpoint constant at a local server.  Scope partitioning itself lives
in cli_runner (mirrored from --sitemap) and is covered there by contract.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import wayback_import as wb  # noqa: E402
from xssentinel.core.wayback_import import (  # noqa: E402
    build_cdx_url,
    wayback_to_urls,
)

CDX_BODY = """http://example.com/old?q=1
http://example.com/app/page
https://example.com/app/page
http://example.com/old?q=1#frag
javascript:alert(1)
not a url
ftp://example.com/file
http://web.archive.org/web/20240101000000/http://example.com/rewritten
"""


def test_cdx_url_bare_domain():
    u = build_cdx_url("example.com")
    assert "url=example.com%2F%2A" in u
    assert "fl=original" in u and "collapse=urlkey" in u
    assert "filter=statuscode%3A200" in u
    assert "limit=500" in u


def test_cdx_url_path_prefix_narrows():
    u = build_cdx_url("https://example.com/app/")
    assert "url=example.com%2Fapp%2F%2A" in u


def test_cdx_url_requires_a_host():
    try:
        build_cdx_url("not a host")
        raised = False
    except ValueError:
        raised = True
    assert raised


def test_parse_dedupe_validate_cap():
    urls = wayback_to_urls("example.com", fetch=lambda u: CDX_BODY,
                           max_urls=4)
    # junk schemes dropped; the rewritten wayback URL unwrapped; dedupe is
    # fragment-insensitive; cap respected.
    assert urls == [
        "http://example.com/old?q=1",
        "http://example.com/app/page",
        "https://example.com/app/page",
        "http://example.com/rewritten",
    ]


def test_empty_archive_is_empty_list_not_error():
    assert wayback_to_urls("example.com", fetch=lambda u: "") == []
    assert wayback_to_urls("example.com", fetch=lambda u: "\n\n") == []


def test_cdx_error_propagates():
    def boom(u):
        raise ConnectionError("cdx down")
    try:
        wayback_to_urls("example.com", fetch=boom)
        raised = False
    except ConnectionError:
        raised = True
    assert raised


def test_fragment_only_difference_is_one_target():
    body = ("http://example.com/a\nhttp://example.com/a#x\n")
    urls = wayback_to_urls("example.com", fetch=lambda u: body)
    assert urls == ["http://example.com/a"]


class _CdxHandler(BaseHTTPRequestHandler):
    body = CDX_BODY.encode()

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *a):
        pass


def test_real_http_path_against_loopback():
    """One true requests.get() path: the CDX endpoint is pointed at a local
    server, so the module's fetch/raise/decode pipeline runs for real."""
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        import pytest
        pytest.skip("loopback degraded mid-session")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CdxHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.2)
    original = wb._CDX_ENDPOINT
    wb._CDX_ENDPOINT = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        urls = wayback_to_urls("127.0.0.1", max_urls=10)
    finally:
        wb._CDX_ENDPOINT = original
        server.shutdown()
        server.server_close()
    assert "http://example.com/old?q=1" in urls
    assert "http://example.com/rewritten" in urls


def test_cli_flag_exists():
    """--wayback must be a first-class input flag on the shared CLI."""
    import subprocess
    r = subprocess.run(
        [sys.executable, "-m", "xssentinel", "--help"],
        capture_output=True, text=True, timeout=60)
    assert "--wayback" in (r.stdout + r.stderr)
    assert "DOMAIN_OR_URL" in (r.stdout + r.stderr)
