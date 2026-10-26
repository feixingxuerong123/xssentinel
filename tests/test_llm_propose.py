"""Phase 322: LLM payload PROPOSAL with deterministic verification.

No network, no real LLM: the pool is a fake object whose complete()
returns canned text; the replay side runs against loopback fixtures.
The contracts locked here:

  * parse_candidates tolerates the shapes models actually emit;
  * the deterministic filter rejects inert/oversize/placeholder entries;
  * a proposal is "confirmed" ONLY when the token oracle says so -- a
    reflected-but-encoded proposal stays unverified, and a payload that
    never reflects stays unverified, regardless of what the model said;
  * an unconfigured pool errors honestly instead of half-working.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from xssentinel.api import mcp_server
from xssentinel.core.llm_propose import (LLMProposeError, build_messages,
                                         filter_candidates, parse_candidates,
                                         propose_and_verify)


class _Candidate:
    model = "fake-model"


class _FakeResult:
    def __init__(self, text):
        self.text = text
        self.candidate = _Candidate()
        self.attempts = []

    @property
    def failovers(self):
        return 0


class _FakePool:
    def __init__(self, text):
        self._text = text
        self.calls = []

    def complete(self, messages, **kw):
        self.calls.append((messages, kw))
        return _FakeResult(self._text)


class TestParseCandidates:
    def test_bare_array(self):
        out = parse_candidates('["<script>alert(1)</script>", '
                               '"<img src=x onerror=alert(1)>"]')
        assert out == ["<script>alert(1)</script>",
                       "<img src=x onerror=alert(1)>"]

    def test_fenced_block(self):
        out = parse_candidates('```json\n["<b onmouseover=alert(1)>x</b>"]'
                               '\n```')
        assert out == ["<b onmouseover=alert(1)>x</b>"]

    def test_array_in_prose(self):
        out = parse_candidates('Sure! Here are candidates:\n'
                               '["<svg onload=alert(1)>"]\nhope they help')
        assert out == ["<svg onload=alert(1)>"]

    def test_non_string_entries_dropped(self):
        out = parse_candidates('["ok", 1, null, {"a": 2}]')
        assert out == ["ok"]

    def test_junk_yields_empty(self):
        assert parse_candidates("no arrays here") == []
        assert parse_candidates("") == []

    def test_duplicates_removed(self):
        out = parse_candidates('["a", "a"]')
        assert out == ["a"]


class TestFilterCandidates:
    def test_inert_entry_rejected_with_reason(self):
        passed, rejected = filter_candidates(["just words"])
        assert passed == []
        assert rejected[0]["reason"].startswith("no execution point")

    def test_placeholder_syntax_rejected(self):
        passed, rejected = filter_candidates(["{{url_encode(x)}}"])
        assert passed == []
        assert "placeholder" in rejected[0]["reason"]

    def test_oversize_rejected(self):
        passed, rejected = filter_candidates(["<script>alert('"
                                              + "A" * 500 + "')</script>"])
        assert passed == []
        assert rejected[0]["reason"] == "too long"

    def test_valid_shapes_pass(self):
        passed, rejected = filter_candidates([
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
        ])
        assert passed == ["<script>alert(1)</script>",
                          "<img src=x onerror=alert(1)>",
                          "javascript:alert(1)"]
        assert rejected == []


class _RawEchoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        value = (parse_qs(urlsplit(self.path).query).get("q") or [""])[0]
        body = f"<html><body><div>{value}</div></body></html>".encode()
        self._reply(body)

    def _reply(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _EscapedEchoHandler(_RawEchoHandler):
    import html as _html

    def do_GET(self):
        value = (parse_qs(urlsplit(self.path).query).get("q") or [""])[0]
        safe = self._html.escape(value, quote=True)
        body = f"<html><body><div>{safe}</div></body></html>".encode()
        self._reply(body)


def _loopback(handler):
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.fixture(scope="module")
def raw_base():
    yield from _loopback(_RawEchoHandler)


@pytest.fixture(scope="module")
def escaped_base():
    yield from _loopback(_EscapedEchoHandler)


def _requester(base):
    from xssentinel.api.server import _build_requester
    return _build_requester({"headers": {}, "cookies": {}, "timeout": 5})


_GOOD = '["<script>alert(\'x\')</script>", "inert words", "{{nope}}"]'


class TestProposeAndVerify:
    def test_confirmed_only_via_token_oracle(self, raw_base):
        out = propose_and_verify(_requester(raw_base), raw_base + "/",
                                 "q", pool=_FakePool(_GOOD))
        assert out["proposals_parsed"] == 3
        assert out["proposals_verified"] == 1     # the two rejects never send
        assert len(out["rejected"]) == 2
        r = out["results"][0]
        assert r["confirmed"] is True
        assert r["evidence_class"] == "model-only"
        assert out["confirmed"] == ["<script>alert('x')</script>"]
        # the honest note travels with every result
        assert "never the model's word" in out["note"]

    def test_encoded_reflection_stays_unverified(self, escaped_base):
        # the payload reflects (as entities) but the token cannot execute:
        # unverified is the only honest verdict, whatever the model said
        out = propose_and_verify(_requester(escaped_base), escaped_base + "/",
                                 "q", pool=_FakePool(_GOOD))
        r = out["results"][0]
        assert r["confirmed"] is False
        assert r["evidence_class"] == "browser-unavailable"
        assert out["confirmed"] == []

    def test_unparseable_completion_raises(self, raw_base):
        with pytest.raises(LLMProposeError):
            propose_and_verify(_requester(raw_base), raw_base + "/", "q",
                               pool=_FakePool("I refuse to answer in JSON"))

    def test_prompt_carries_the_facts(self):
        msgs = build_messages("attr_double_quote", meta_chars='" < >',
                              waf="Cloudflare", count=3)
        blob = json.dumps(msgs)
        assert "attr_double_quote" in blob
        assert "Cloudflare" in blob
        assert "execution point" in blob


class TestMCPWiring:
    def test_catalogue_includes_propose(self):
        import io
        srv = mcp_server.MCPServer()
        srv._stdin = io.StringIO(json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n")
        out = io.StringIO()
        srv._stdout = out
        srv.serve()
        tools = json.loads(out.getvalue().splitlines()[0])["result"]["tools"]
        names = [t["name"] for t in tools]
        assert names == ["xssentinel_scan", "xssentinel_discover",
                         "xssentinel_profile", "xssentinel_verify",
                         "xssentinel_param_mine", "xssentinel_csp_analyze",
                         "xssentinel_propose"]

    def test_unconfigured_pool_is_an_honest_error(self, monkeypatch):
        # point the discovery at a nonexistent config: the tool must say
        # "not configured", never half-run
        import xssentinel.core.llm_pool as lp
        monkeypatch.setattr(lp, "_default_config_path", lambda: None)
        monkeypatch.delenv("XSSENTINEL_LLM_CONFIG", raising=False)
        res = mcp_server.run_propose_tool({"url": "http://127.0.0.1:1/",
                                           "param": "q"})
        assert res.get("isError") is True
        assert "not configured" in res["content"][0]["text"] \
            or "not found" in res["content"][0]["text"]

    def test_tool_with_injected_pool(self, raw_base, monkeypatch):
        # route the tool's default-pool construction at the fake
        import xssentinel.core.llm_pool as lp
        fake = _FakePool(_GOOD)
        monkeypatch.setattr(lp, "default_pool", lambda *_a, **_k: fake)
        res = mcp_server.run_propose_tool({"url": raw_base + "/",
                                           "param": "q"})
        assert not res.get("isError")
        out = json.loads(res["content"][0]["text"])
        assert out["confirmed"]
