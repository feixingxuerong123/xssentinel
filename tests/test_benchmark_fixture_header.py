# -*- coding: utf-8 -*-
"""The benchmark fixture must answer a probe, not die on it.

What actually happened on 2026-10-04: the async strict gate went red with
`neg-header-01 ERROR timeout after 90s`.  Nothing was wrong with the scanner.
That case's mode is `header_only` -- it copies the query value into a RESPONSE
header -- and our own fullwidth transform family (`transform.t_fullwidth`)
maps ASCII to U+FF01..U+FF5E, which is not representable in an HTTP field
value (RFC 7230).  stdlib's `send_header` raised `UnicodeEncodeError` inside
the request handler, the socket closed without a response, and the engine
spent its whole 90 s budget on a case it had been denied the answer to.

So the target was manufacturing "not measured" rows, and a gate that does
that is worse than no gate.  Two things are pinned here:

  1. `_safe_header_value` escapes codepoints above U+00FF and leaves
     everything representable byte-identical -- so no existing
     header-reflection expectation moves;
  2. the end-to-end path really answers now, and REALLY does not without the
     guard (the mutation control below patches the helper back to identity and
     asserts the connection still dies).  A test that only ever sees the fixed
     behavior proves nothing -- that lesson cost this repo three separate
     vacuous guards.

Scope of the end-to-end part, stated because it is bounded by the target and
not by the test: `m_header_only` is the ONLY mode in `benchmark/server.py`
that puts a request-supplied value into a response header (measured by
scanning every mode for header dicts).  It is a GET-only mode: the fixture's
POST dispatch consults a separate `POST_MODES` registry and answers
"405 method is not a POST endpoint" for this path (measured), so there is no
POST route today that can reach a header echo.  A POST variant here would mean
inventing a reflection mode to test a shape the target cannot produce -- while
the guard itself lives in `_respond`, which EVERY response goes through: GET,
POST, custom headers and the CSP header alike.
"""
from __future__ import annotations

import os
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from benchmark.server import (  # noqa: E402
    BenchmarkHandler, _safe_header_value, load_routes)
from xssentinel.core.transform import t_fullwidth  # noqa: E402


PORT_HOLDER = {}


@pytest.fixture()
def fixture_server():
    BenchmarkHandler.routes = load_routes()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), BenchmarkHandler)
    PORT_HOLDER["port"] = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


# ---------------------------------------------------------------------------
# 1. the encoding rule itself
# ---------------------------------------------------------------------------
def test_latin1_representable_values_pass_through_byte_identical():
    for value in ("", "<script>alert(1)</script>", "café", "a b\tc"):
        assert _safe_header_value(value) == value, repr(value)


def test_unrepresentable_codepoints_become_percent_escapes():
    out = _safe_header_value("＜script＞")
    assert out == "%EF%BC%9Cscript%EF%BC%9E", out
    assert all(ord(ch) <= 0xFF for ch in out)


def test_fullwidth_family_output_is_now_sendsafe():
    probe = t_fullwidth("<script>alert(1)</script>")
    # t_fullwidth maps ALL printable ASCII (0x21-0x7E), so the probe is
    # entirely above U+00FF -- that is why this payload class broke the header.
    assert sum(1 for ch in probe if ord(ch) > 0xFF) == len(probe), repr(probe)
    safe = _safe_header_value(probe)
    assert all(ord(ch) <= 0xFF for ch in safe)
    assert safe != probe


# ---------------------------------------------------------------------------
# 2. end to end, plus the mutation control that keeps this honest
# ---------------------------------------------------------------------------
def _get(url):
    with urllib.request.urlopen(url, timeout=10) as resp:
        return resp.status, dict(resp.headers)


def test_header_reflection_case_answers_instead_of_dropping_the_connection(
        fixture_server):
    from urllib.parse import quote
    probe = t_fullwidth("<script>alert(1)</script>")
    status, headers = _get(f"{fixture_server}/s/hdr01?q={quote(probe)}")
    assert status == 200, status
    # the mode echoes into X-Reflected-Input; the escaped form is what a
    # spec-conformant server could actually put on the wire
    assert headers.get("X-Reflected-Input") == _safe_header_value(probe), \
        headers
    assert all(all(ord(c) <= 0xFF for c in v) for v in headers.values())


def test_without_the_guard_the_same_probe_still_kills_the_response(
        fixture_server, monkeypatch):
    """Mutation control: prove the guard is what saves this path.

    Patched back to identity, the identical request must fail the way it did
    in the red gate run.  If this ever passes, the fixture no longer exercises
    the header path at all and the test above has gone vacuous.
    """
    import benchmark.server as bs
    from urllib.parse import quote
    monkeypatch.setattr(bs, "_safe_header_value", lambda v: v)
    probe = t_fullwidth("<script>alert(1)</script>")
    with pytest.raises((urllib.error.URLError, ConnectionResetError,
                        OSError)):
        _get(f"{fixture_server}/s/hdr01?q={quote(probe)}")
