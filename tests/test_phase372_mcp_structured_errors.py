# -*- coding: utf-8 -*-
"""Phase 372 / OPTIMIZATION.md §8.1-2: tool ERRORS become machine-readable.

Measured gap (dev/agent_surface_probe.py, 2026-11-06): all five error frames
were ``isError:true`` + ``content[0].text`` only.  An agent had to parse
sentences like ``"unknown argument(s): cokies. accepted: ..."`` to correct
itself.  Successful results already carried ``structuredContent``; errors
did not, so the two outcomes had different contracts.

Boundary that matters more than the feature: Phase 358 promises LEGACY frames
byte-for-byte the responses they have always had, and
test_phase324_mcp_http.py::test_error_result_has_no_structured_content pins
that an error result has NO structuredContent.  So the structured error
channel is MODERN-ONLY, and ``content[0].text`` is never rewritten.  Both
sides are tested through the real dispatch entry point, not by calling the
classifier in isolation.
"""
from __future__ import annotations

import ast
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.api import mcp_server as m  # noqa: E402
from xssentinel.api.mcp_server import dispatch_message  # noqa: E402

REQ = {"jsonrpc": "2.0", "id": 1}
MODERN = "2026-07-28"
_ERROR_KEYS = {"code", "message", "field", "accepted_keys", "hint",
               "retryable"}


def _meta():
    return {"_meta": {
        "io.modelcontextprotocol/protocolVersion": MODERN,
        "io.modelcontextprotocol/clientInfo": {"name": "agent-cli",
                                               "version": "1.0"},
        "io.modelcontextprotocol/clientCapabilities": {},
    }}


def _frame(params, modern=True):
    if modern:
        p = _meta()
        p.update(params)
    else:
        p = params
    return {**REQ, "method": "tools/call", "params": p}


def _call(params, modern=True):
    return dispatch_message(_frame(params, modern=modern))["result"]


def _error(result):
    assert result.get("isError") is True, result
    assert "content" in result and result["content"][0]["type"] == "text"
    assert "structuredContent" in result, "modern error lacks the channel"
    payload = result["structuredContent"]
    assert set(payload) == {"error"}, payload
    err = payload["error"]
    assert set(err) == _ERROR_KEYS, err
    assert isinstance(err["code"], str) and err["code"]
    assert isinstance(err["message"], str)
    assert isinstance(err["accepted_keys"], list)
    assert isinstance(err["retryable"], bool)
    assert err["message"] == result["content"][0]["text"], (
        "structured message must equal the text, not a paraphrase")
    return err


# Error shapes that never open a socket: every one of these is a fast path.
FAST_CASES = [
    ("unknown_tool", {"name": "no_such_tool", "arguments": {}},
     "unknown_tool", False),
    ("unknown_argument", {"name": "xssentinel_scan",
                          "arguments": {"cokies": {}}},
     "unknown_argument", False),
    ("missing_required", {"name": "xssentinel_scan", "arguments": {}},
     "missing_required_argument", False),
    ("invalid_url", {"name": "xssentinel_scan",
                     "arguments": {"url": "not-a-url"}},
     "invalid_url", False),
    ("invalid_value", {"name": "xssentinel_scan",
                       "arguments": {"url": "http://127.0.0.1/",
                                     "max_payloads": "many"}},
     "invalid_argument_value", False),
    ("bad_shape", {"name": "xssentinel_scan", "arguments": "not-an-object"},
     "invalid_request_shape", False),
]


@pytest.mark.parametrize("label,params,code,retryable", FAST_CASES)
def test_modern_error_frames_carry_a_stable_code(label, params, code,
                                                 retryable):
    err = _error(_call(params))
    assert err["code"] == code, (label, err)
    assert err["retryable"] is retryable, (label, err)
    assert err["hint"]


@pytest.mark.parametrize("label,params,code,retryable", FAST_CASES)
def test_legacy_error_frames_are_byte_identical(label, params, code,
                                                retryable):
    legacy = _call(params, modern=False)
    modern = _call(params, modern=True)
    assert legacy.get("isError") is True
    assert "structuredContent" not in legacy, (
        "Phase 358 legacy contract broken for " + label)
    assert legacy["content"] == modern["content"], (
        "the text channel must be identical across eras for " + label)
    # Modernization adds only protocol-level fields plus the error channel.
    assert set(modern) - set(legacy) == {"resultType", "_meta",
                                        "structuredContent"}


def test_unknown_argument_lists_accepted_keys_and_the_offending_field():
    err = _error(_call({"name": "xssentinel_scan",
                        "arguments": {"cokies": {}}}))
    assert err["field"] == "cokies"
    assert "url" in err["accepted_keys"]
    assert "cokies" not in err["accepted_keys"]


def test_timeout_and_scan_failure_are_marked_retryable(monkeypatch):
    """Two errors that only appear from inside a runner, driven through the
    REAL dispatch path with a substituted runner (not a fake result)."""
    entry = m._TOOL_TABLE["xssentinel_scan"]
    schema = entry[0]

    def _timeout(args, cancel_event=None, emit=None):
        raise m._ToolTimeout("wall-clock budget exhausted")

    def _failed(args, cancel_event=None, emit=None):
        return {"content": [{"type": "text",
                             "text": "scan failed: ValueError: boom"}],
                "isError": True}

    monkeypatch.setitem(m._TOOL_TABLE, "xssentinel_scan",
                        (schema, _timeout))
    err = _error(_call({"name": "xssentinel_scan",
                        "arguments": {"url": "http://127.0.0.1/"}}))
    assert err["code"] == "timeout" and err["retryable"] is True

    monkeypatch.setitem(m._TOOL_TABLE, "xssentinel_scan",
                        (schema, _failed))
    err = _error(_call({"name": "xssentinel_scan",
                        "arguments": {"url": "http://127.0.0.1/"}}))
    assert err["code"] == "tool_execution_failed"
    assert err["retryable"] is True


def test_structured_errors_are_wired_only_into_the_modern_branch():
    """A source-level guard: the attachment must sit under `if modern` in
    dispatch_message.  A pure behavioural test could pass while a future
    edit moved the call into the legacy path (Phase 358 contract)."""
    src = open(m.__file__, encoding="utf-8").read()
    tree = ast.parse(src)
    fn = next(n for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name == "dispatch_message")
    calls = [n for n in ast.walk(fn)
             if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Name)
             and n.func.id == "_attach_structured_error"]
    assert len(calls) == 1, "exactly one structured-error attachment point"
    guarded = any(
        isinstance(n, ast.If)
        and any(isinstance(v, ast.Name) and v.id == "modern"
                for v in ast.walk(n.test))
        and calls[0] in list(ast.walk(n))
        for n in ast.walk(fn))
    assert guarded, "the attachment is not guarded by the modern-era flag"


def test_tools_list_shape_is_unchanged():
    """The new error channel must not leak into non-tool results."""
    res = dispatch_message({**REQ, "method": "tools/list",
                            "params": _meta()})["result"]
    assert "structuredContent" not in res
    assert [t["name"] for t in res["tools"]] == [
        t["name"] for t in m.TOOL_DEFINITIONS]
