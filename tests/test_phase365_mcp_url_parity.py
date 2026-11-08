"""Phase 365: GET injection points must REPLACE an existing query parameter.

Found by an external CLI-agent e2e (see
``benchmark/results/agent_cli_e2e_20261107.md``): ``run_profile_tool`` passed a
query-bearing ``url`` straight to
``requester.request("GET", url, params={param: probe})``, so requests appended
``?q=hello&q=<probe>``. Servers that read the FIRST same-named parameter never
see the probe, and the tool answered ``reflected: false`` for a parameter that
``xssentinel_scan`` reports as a high reflected XSS. ``skills/xssentinel-mcp/
SKILL.md`` tells agents to use profile as a cheap pre-scan gate -- a false
negative there silently skips the whole scan.

The same hand-rolled shape existed in ``run_verify_tool`` and
``core/llm_propose.propose_and_verify``; ``run_scan_tool`` had a correct but
separately hand-written version. This is the "same contract written twice"
family again, so the fix unifies all four call sites on ONE helper and these
behaviour tests lock the real HTTP shape (loopback, first-param server).
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from xssentinel.api import mcp_server
from xssentinel.core.llm_propose import propose_and_verify


class _FirstParamHandler(BaseHTTPRequestHandler):
    """Echo the FIRST ``q``, like PHP ``$_GET`` / ``parse_qs(...)[0]``."""

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        u = urlparse(self.path)
        q = (parse_qs(u.query, keep_blank_values=True).get("q") or [""])[0]
        body = ("<!DOCTYPE html><html><body><div id='out'>" + q +
                "</div></body></html>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def base():
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _FirstParamHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


def _requester():
    from xssentinel.api.server import _build_requester
    return _build_requester({"headers": {}, "cookies": {}, "timeout": 5})


class _FakeResult:
    text = '["<script>alert(\'x\')</script>"]'
    candidate = type("_Candidate", (), {"model": "fake-model"})()
    attempts = []
    failovers = 0


class _FakePool:
    def complete(self, messages, **kw):
        return _FakeResult()


class TestQueryBearingUrl:
    def test_profile_replaces_existing_q(self, base):
        res = mcp_server.run_profile_tool(
            {"url": base + "/echo?q=hello", "param": "q"})
        assert not res.get("isError")
        out = json.loads(res["content"][0]["text"])
        assert out["reflected"] is True, out.get("note")

    def test_verify_replaces_existing_q(self, base):
        res = mcp_server.run_verify_tool({
            "url": base + "/echo?q=hello", "param": "q",
            "payload": "<script>alert(1)</script>"})
        assert not res.get("isError")
        out = json.loads(res["content"][0]["text"])
        assert out["reflected"] is True

    def test_propose_replaces_existing_q(self, base):
        out = propose_and_verify(_requester(), base + "/echo?q=hello", "q",
                                 pool=_FakePool())
        assert out["proposals_verified"] == 1
        assert out["results"][0]["confirmed"] is True

    def test_scan_still_detects_with_existing_q(self, base):
        # The one call site that was already correct: guard against a
        # "unification" that breaks it.
        res = mcp_server.run_scan_tool(
            {"url": base + "/echo?q=hello", "max_payloads": 2})
        assert not res.get("isError")
        assert json.loads(res["content"][0]["text"])["finding_count"] >= 1


class TestSingleDefinitionLock:
    """The helper does not rot; the CALL SITES do (Phase 259/176u family).

    A behaviour test only covers the tools that exist today. This source-level
    gate keeps a future tool -- or a "simplification" of an existing one --
    from hand-rolling the old append shape again.
    """

    @staticmethod
    def _function(tree, name):
        import ast
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                    and node.name == name:
                return node
        raise AssertionError(f"function {name} not found in source")

    def test_helper_pure_cases(self):
        from xssentinel.core.target_url import split_target_url
        assert split_target_url("http://h/p") == ("http://h/p", {})
        assert split_target_url("http://h/p?q=hello") == (
            "http://h/p", {"q": "hello"})
        assert split_target_url("http://h/p?a=1&q=hello&b=2") == (
            "http://h/p", {"a": "1", "q": "hello", "b": "2"})
        # first value wins, like parse_qs(...)[0] on the server side
        assert split_target_url("http://h/p?q=a&q=b") == (
            "http://h/p", {"q": "a"})
        # a bare flag is not an injectable pair; the fragment never reaches
        # the server (hash routes belong to the crawler)
        assert split_target_url("http://h/p?flag&q=x#/route") == (
            "http://h/p", {"q": "x"})
        # keep values RAW -- requests re-encodes, and decoding here would
        # change the bytes the engine has always injected
        assert split_target_url("http://h/p?q=a%20b") == (
            "http://h/p", {"q": "a%20b"})

    def test_all_get_injection_sites_share_the_helper(self):
        import ast
        import pathlib
        root = pathlib.Path(__file__).resolve().parents[1]
        trees = {
            "xssentinel/api/mcp_server.py": (
                "run_scan_tool", "run_profile_tool", "run_verify_tool"),
            "xssentinel/core/llm_propose.py": ("propose_and_verify",),
        }
        for rel, fn_names in trees.items():
            tree = ast.parse((root / rel).read_text(encoding="utf-8"))
            for name in fn_names:
                fn = self._function(tree, name)
                called = {n.func.id for n in ast.walk(fn)
                          if isinstance(n, ast.Call)
                          and isinstance(n.func, ast.Name)}
                assert "split_target_url" in called, (
                    f"{rel}:{name} no longer uses the shared URL splitter")

    def test_no_call_site_feeds_a_live_query_url_to_request(self):
        """The actual append bug: request(url, params={param: ...})."""
        import ast
        import pathlib
        root = pathlib.Path(__file__).resolve().parents[1]
        trees = {
            "xssentinel/api/mcp_server.py": (
                "run_scan_tool", "run_profile_tool", "run_verify_tool"),
            "xssentinel/core/llm_propose.py": ("propose_and_verify",),
        }
        for rel, fn_names in trees.items():
            tree = ast.parse((root / rel).read_text(encoding="utf-8"))
            for name in fn_names:
                fn = self._function(tree, name)
                for n in ast.walk(fn):
                    if not (isinstance(n, ast.Call)
                            and isinstance(n.func, ast.Attribute)):
                        continue
                    if n.func.attr in ("request", "verify_headless"):
                        first = n.args[1] if n.func.attr == "request" \
                            else n.args[0]
                        assert not (isinstance(first, ast.Name)
                                    and first.id == "url"), (
                            f"{rel}:{name} passes the query-bearing url to "
                            f"{n.func.attr}() -- that appends a second "
                            f"same-named parameter")
