# -*- coding: utf-8 -*-
"""Phase 323: MCP ``tools/call`` argument validation -- unknown keys are
rejected, never silently dropped.

The defect this pins (dalfox v3.2.4 shipped the same fix after a real
incident, #1464/#1513): an agent that sent ``cookie`` instead of
``cookies`` got a scan that ran WITHOUT authentication and answered
"no findings" -- a false negative wearing a success costume.  The honest
contract is: normalize the spellings an agent realistically sends (REST
spellings, camelCase), then reject everything else with the accepted-key
list so the agent can self-correct in one round trip.

Three layers here:
  * ``_normalize_arguments`` unit cases (aliases, camelCase, duplicates,
    types, enum case-insensitivity, digit-string coercion, bounds);
  * end-to-end through ``_tool_call`` (rejection AND an alias round-trip
    against a real loopback reflection page);
  * catalogue/dispatch parity (``TOOL_DEFINITIONS`` == ``_TOOL_TABLE``).
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.api import mcp_server                            # noqa: E402
from xssentinel.api.mcp_server import MCPServer                  # noqa: E402

REQ = {"jsonrpc": "2.0", "id": 1}


def _session(server: MCPServer, *msgs: dict) -> list[dict]:
    import io
    inn = io.StringIO("".join(json.dumps(m) + "\n" for m in msgs))
    out = io.StringIO()
    server._stdin, server._stdout = inn, out
    server.serve()
    return [json.loads(ln) for ln in out.getvalue().splitlines()]


def _call(name: str, arguments: dict) -> dict:
    (resp,) = _session(MCPServer(), {**REQ, "method": "tools/call",
                                     "params": {"name": name,
                                                "arguments": arguments}})
    return resp["result"]


# ---------------------------------------------------------------------------
# 1. the normalizer: aliases fold, unknowns error, types are checked
# ---------------------------------------------------------------------------
def _norm(schema, args):
    return mcp_server._normalize_arguments(schema, args)


def test_rest_spellings_normalize_onto_canonical_names():
    norm, err = _norm(mcp_server._TOOL_SCAN_SCHEMA,
                      {"target": "http://t/", "cookie": {"a": "b"},
                       "header": {"X": "y"}, "body": "k=v"})
    assert err is None, err
    assert norm == {"url": "http://t/", "cookies": {"a": "b"},
                    "headers": {"X": "y"}, "data": "k=v"}


def test_camelcase_spellings_normalize_for_js_clients():
    # scan tool knows max_payloads -> maxPayloads folds in
    norm, err = _norm(mcp_server._TOOL_SCAN_SCHEMA,
                      {"url": "http://t/", "maxPayloads": 3})
    assert err is None, err
    assert norm["max_payloads"] == 3
    # but max_params is NOT in the scan schema: same camel alias must be
    # UNKNOWN there (per-tool contracts, not one global bag of names)
    _, err_scan = _norm(mcp_server._TOOL_SCAN_SCHEMA,
                        {"url": "http://t/", "maxParams": 9})
    assert err_scan and "unknown argument" in err_scan
    # while the param_mine tool does own it
    norm2, err2 = _norm(mcp_server._TOOL_PARAM_MINE_SCHEMA,
                        {"url": "http://t/", "maxParams": 9})
    assert err2 is None, err2
    assert norm2["max_params"] == 9


def test_canonical_spelling_wins_over_its_alias():
    norm, err = _norm(mcp_server._TOOL_VERIFY_SCHEMA,
                      {"url": "http://t/", "param": "q", "payload": "p",
                       "cookies": {"good": "1"},
                       "cookie": {"bad": "2"}})
    assert err is None, err
    assert norm["cookies"] == {"good": "1"}


def test_alias_only_still_fills_the_canonical_key():
    norm, err = _norm(mcp_server._TOOL_VERIFY_SCHEMA,
                      {"url": "http://t/", "param": "q", "payload": "p",
                       "cookie": {"only": "1"}})
    assert err is None, err
    assert norm["cookies"] == {"only": "1"}


def test_unknown_keys_are_rejected_with_the_accepted_list():
    _, err = _norm(mcp_server._TOOL_SCAN_SCHEMA,
                   {"url": "http://t/", "cookiees": {}, "paylods": []})
    assert err, "unknown keys must be an error, not a silent drop"
    assert "cookiees" in err and "paylods" in err
    # the agent can self-correct from the error text alone
    assert "url" in err and "cookies" in err and "max_payloads" in err


def test_object_type_is_enforced():
    _, err = _norm(mcp_server._TOOL_SCAN_SCHEMA,
                   {"url": "http://t/", "cookies": "a=1"})
    assert err and "'cookies' must be an object" in err


def test_integer_type_bounds_and_digit_string_coercion():
    norm, err = _norm(mcp_server._TOOL_SCAN_SCHEMA,
                      {"url": "http://t/", "max_payloads": "5"})
    assert err is None, err
    assert norm["max_payloads"] == 5
    _, err = _norm(mcp_server._TOOL_SCAN_SCHEMA,
                   {"url": "http://t/", "max_payloads": "abc"})
    assert err and "'max_payloads' must be an integer" in err
    _, err = _norm(mcp_server._TOOL_SCAN_SCHEMA,
                   {"url": "http://t/", "max_payloads": 9999})
    assert err and "<= 100" in err
    # bool is an int subclass in Python -- it must not pass an integer field
    _, err = _norm(mcp_server._TOOL_SCAN_SCHEMA,
                   {"url": "http://t/", "max_payloads": True})
    assert err and "boolean" in err


def test_enum_matches_case_insensitively_and_normalizes():
    norm, err = _norm(mcp_server._TOOL_VERIFY_SCHEMA,
                      {"url": "http://t/", "param": "q", "payload": "p",
                       "method": "post"})
    assert err is None, err
    assert norm["method"] == "POST"
    _, err = _norm(mcp_server._TOOL_VERIFY_SCHEMA,
                   {"url": "http://t/", "param": "q", "payload": "p",
                    "method": "PATCH"})
    assert err and "'method' must be one of" in err


def test_boolean_type_is_enforced():
    _, err = _norm(mcp_server._TOOL_VERIFY_SCHEMA,
                   {"url": "http://t/", "param": "q", "payload": "p",
                    "headless": "true"})
    assert err and "'headless' must be a boolean" in err


# ---------------------------------------------------------------------------
# 2. end-to-end through the JSON-RPC dispatch
# ---------------------------------------------------------------------------
def test_dispatch_rejects_unknown_keys():
    result = _call("xssentinel_scan",
                   {"url": "http://127.0.0.1:1/", "cookie": {},
                    "max_payload": 5})
    assert result["isError"] is True
    text = result["content"][0]["text"]
    assert "unknown argument" in text and "max_payload" in text
    assert "max_payloads" in text, "error must teach the canonical name"


def test_dispatch_type_error_beats_a_broken_scan():
    result = _call("xssentinel_scan",
                   {"url": "http://127.0.0.1:1/", "headers": "X: y"})
    assert result["isError"] is True
    assert "'headers' must be an object" in result["content"][0]["text"]


class _XssHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        u = urlparse(self.path)
        q = (parse_qs(u.query).get("q") or [""])[0]
        body = (f"<!DOCTYPE html><html><body><div id=\"out\">"
                f"{q}</div></body></html>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def test_dispatch_alias_round_trip_against_a_live_page():
    """REST spellings reach the SAME tool outcome as the canonical names:
    profile ``{"target": url, "parameter": "q"}`` must behave exactly like
    ``{"url": url, "param": "q"}`` -- pre-Phase 323 the alias call errored
    (``param is required``), which is the self-correctable failure this
    round trip proves is gone."""
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        import pytest
        pytest.skip("loopback degraded mid-session")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _XssHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.2)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        canonical = _call("xssentinel_profile", {"url": base + "/",
                                                  "param": "q"})
        aliased = _call("xssentinel_profile", {"target": base + "/",
                                               "parameter": "q"})
        assert not canonical.get("isError"), canonical
        assert not aliased.get("isError"), aliased
        canon_payload = json.loads(canonical["content"][0]["text"])
        alias_payload = json.loads(aliased["content"][0]["text"])
        assert canon_payload["reflected"] is True
        assert alias_payload == canon_payload
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# 3. catalogue/dispatch parity (the table cannot drift from the catalogue)
# ---------------------------------------------------------------------------
def test_tool_table_keys_equal_the_catalogue():
    catalogue = {t["name"] for t in mcp_server.TOOL_DEFINITIONS}
    table = set(mcp_server._TOOL_TABLE)
    assert catalogue == table, (catalogue, table)


def test_every_table_entry_uses_its_catalogue_schema():
    by_name = {t["name"]: t for t in mcp_server.TOOL_DEFINITIONS}
    for name, (schema, _runner) in mcp_server._TOOL_TABLE.items():
        assert by_name[name]["inputSchema"] is schema, \
            f"{name}: dispatch schema drifted from the catalogue schema"


def test_error_messages_mention_no_ansi_stripped_path():
    """The guard text an agent sees must stay plain: validation errors are
    agent-facing and carry no target data here, but the contract test
    keeps it that way even when arguments DO carry target bytes."""
    result = _call("xssentinel_scan",
                   {"url": "http://127.0.0.1:1/\x1b[2J", "cookiez": {}})
    text = result["content"][0]["text"]
    assert "\x1b" not in text
