# -*- coding: utf-8 -*-
"""Phase 374 / OPTIMIZATION.md §8.1-5: declare what these tools actually DO.

Measured gap (dev/agent_surface_probe.py, 2026-11-06): all seven tools had
``has_title=False`` / ``has_annotations=False``.  MCP platforms use
``destructiveHint`` / ``openWorldHint`` / ``idempotentHint`` / ``readOnlyHint``
to decide whether to ask for confirmation, cache, or parallelise.  A tool
that actively sends attack payloads to an operator-supplied host must not
look like a safe read-only lookup.

Hard boundary: Phase 358 promises legacy frames byte-for-byte their old
responses.  Annotations are therefore attached ONLY to a modern tools/list
response, never written into TOOL_DEFINITIONS itself.  Both eras are checked
through the real dispatch entry point, and a source-level guard pins the
modern-only wiring.
"""
from __future__ import annotations

import ast
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.api import mcp_server as m  # noqa: E402
from xssentinel.api.mcp_server import dispatch_message  # noqa: E402

REQ = {"jsonrpc": "2.0", "id": 1}
MODERN_META = {"_meta": {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientInfo": {"name": "agent-cli",
                                           "version": "1.0"},
    "io.modelcontextprotocol/clientCapabilities": {},
}}
EXPECTED_HINTS = {
    "readOnlyHint": False,
    "destructiveHint": True,
    "openWorldHint": True,
    "idempotentHint": False,
}


def _tools(frame):
    return dispatch_message(frame)["result"]


def test_catalogue_and_title_table_cannot_drift():
    names = {t["name"] for t in m.TOOL_DEFINITIONS}
    assert names == set(m._TOOL_TITLES)
    assert len(names) == 7
    assert all(isinstance(v, str) and v for v in m._TOOL_TITLES.values())


def test_modern_tools_list_declares_every_hint():
    res = _tools({**REQ, "method": "tools/list", "params": MODERN_META})
    assert res["resultType"] == "complete"      # Phase 358 still intact
    assert res["ttlMs"] > 0
    tools = res["tools"]
    # Phase 377: modern frames carry two extra async tools.  The contract is
    # UNCHANGED in strength -- every advertised tool, legacy or async, must
    # have a declared title, the full hint set and both schemas.
    expected_titles = {**m._TOOL_TITLES, **m._ASYNC_TOOL_TITLES}
    assert len(tools) == (len(m.TOOL_DEFINITIONS)
                          + len(m._ASYNC_TOOL_DEFINITIONS)) == 9
    for tool in tools:
        assert tool["title"] == expected_titles[tool["name"]]
        assert tool["annotations"] == EXPECTED_HINTS, tool["name"]
        assert tool["inputSchema"] and tool["outputSchema"]


def test_legacy_tools_list_is_byte_identical_to_the_catalogue():
    res = _tools({**REQ, "method": "tools/list"})
    assert set(res) == {"tools"}
    assert res["tools"] == m.TOOL_DEFINITIONS
    for tool in res["tools"]:
        assert "title" not in tool
        assert "annotations" not in tool
    # Sanity: the modern copy must not have mutated the shared dicts.
    assert all("title" not in t for t in m.TOOL_DEFINITIONS)


def test_annotations_are_wired_only_into_the_modern_branch():
    src = open(m.__file__, encoding="utf-8").read()
    fn = next(n for n in ast.parse(src).body
              if isinstance(n, ast.FunctionDef) and n.name == "dispatch_message")
    calls = [n for n in ast.walk(fn)
             if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Name)
             and n.func.id == "_modernize_tools"]
    assert len(calls) == 1
    guarded = any(
        isinstance(n, ast.If)
        and any(isinstance(v, ast.Name) and v.id == "modern"
                for v in ast.walk(n.test))
        and calls[0] in list(ast.walk(n))
        for n in ast.walk(fn))
    assert guarded, "catalogue modernization escaped the modern-era guard"
