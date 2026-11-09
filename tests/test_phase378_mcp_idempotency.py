# -*- coding: utf-8 -*-
"""Phase 378 / OPTIMIZATION.md §8.2 #7: an agent retry must be idempotent.

Measured gap (dev/agent_surface_probe.py, probe ids 10/11): the SAME
``tools/call`` sent twice ran TWO real scans.  A host that times out at 30s
and retries is the normal case, so a retry silently doubles attack traffic.

Pinned here through the REAL ``dispatch_message`` -> ``_tool_call`` chain
(only the runner / socket is substituted):

  * a second identical MODERN call is a ``cache_hit`` and re-sends NOTHING;
  * the key is the LOGICAL call (defaults filled, aliases folded, cookies
    included), so different targets / auth contexts never collide;
  * ``requestKey`` / ``cacheScope`` / ``cacheTtlMs`` give the client control;
  * only SUCCESS is reusable -- failures, timeouts and cancellations retry
    for real; a status poll is always fresh;
  * a LEGACY frame is byte-for-byte unchanged and never caches;
  * text and structuredContent never disagree about the hit;
  * the store is bounded and the call sites are source-pinned.
"""
from __future__ import annotations

import ast
import inspect
import json
import os
import sys
import textwrap
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.api import mcp_server as m  # noqa: E402

URL = "http://127.0.0.1/?a=1"


def _call(args, meta=None, modern=True, name="xssentinel_scan", **kwargs):
    params = {"name": name, "arguments": args}
    if modern:
        params["_meta"] = {m._META_VERSION_KEY: "2026-07-28"}
        if meta:
            params["_meta"].update(meta)
    return m.dispatch_message(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": params}, **kwargs)


def _result(args, **kw):
    response = _call(args, **kw)
    assert response is not None, "cancelled call must not answer"
    return response["result"]


def _payload(result):
    assert not result.get("isError"), result
    return json.loads(result["content"][0]["text"])


@pytest.fixture
def runner(monkeypatch):
    """Real dispatch, counting fake runner, isolated cache."""
    state = {"calls": 0, "fail_once": False, "timeout_once": False,
             "cancel_once": False}
    schema = m._TOOL_TABLE["xssentinel_scan"][0]

    def fake(args, cancel_event=None, emit=None):
        state["calls"] += 1
        if state["cancel_once"]:
            state["cancel_once"] = False
            raise m._ToolCancelled()
        if state["timeout_once"]:
            state["timeout_once"] = False
            raise m._ToolTimeout("wall-clock budget exceeded after 1 request(s)")
        if state["fail_once"]:
            state["fail_once"] = False
            return {"content": [{"type": "text",
                                 "text": "scan failed: RuntimeError: boom"}],
                    "isError": True}
        return {"content": [{"type": "text", "text": json.dumps({
            "target": args.get("url"), "finding_count": 0,
            "requests_made": state["calls"], "findings": []})}]}

    monkeypatch.setitem(m._TOOL_TABLE, "xssentinel_scan", (schema, fake))
    m._clear_result_cache()
    yield state
    m._clear_result_cache()


# -- 1. the core acceptance: same call, one scan ---------------------------
def test_second_identical_call_is_a_hit_and_sends_zero_new_requests(runner):
    first = _result({"url": URL})
    second = _result({"url": URL})
    p1, p2 = _payload(first), _payload(second)
    assert p1["cache_hit"] is False
    assert p2["cache_hit"] is True
    assert p1["cache_scope"] == p2["cache_scope"] == "private"
    assert p2["cache_ttl_ms"] == m._CACHE_DEFAULT_TTL_MS
    assert runner["calls"] == 1, "a retry must not re-send attack payloads"
    assert p1["requests_made"] == p2["requests_made"] == 1
    for r, expected in ((first, False), (second, True)):
        sc = r["structuredContent"]
        assert sc["cache_hit"] is expected
        assert sc["cache_scope"] == "private"
        assert sc["cache_ttl_ms"] == m._CACHE_DEFAULT_TTL_MS
    # Everything except the cache fields is the SAME object the first call
    # produced -- a replay, not a re-scan.
    def strip(p):
        return {k: v for k, v in p.items()
                if k not in ("cache_hit", "cache_scope", "cache_ttl_ms")}
    assert strip(p1) == strip(p2)


def test_a_hit_emits_no_progress_beacon(runner):
    notifications = []
    _result({"url": URL}, emit=lambda *a: notifications.append(a))
    assert notifications, "the first call still reports its start beacon"
    notifications.clear()
    _result({"url": URL}, emit=lambda *a: notifications.append(a))
    assert notifications == [], "a replay sends no request and no beacon"


# -- 2. key correctness -----------------------------------------------------
@pytest.mark.parametrize("other", [
    {"url": "http://127.0.0.1/?a=2"},
    {"url": URL, "max_payloads": 20},
    {"url": URL, "cookies": {"sid": "B"}},
])
def test_different_logical_calls_never_collide(runner, other):
    first = {"url": URL, "cookies": {"sid": "A"}} \
        if "cookies" in other else {"url": URL}
    assert _payload(_result(first))["cache_hit"] is False
    assert _payload(_result(other))["cache_hit"] is False
    assert runner["calls"] == 2


def test_explicit_default_and_omitted_argument_are_the_same_call(runner):
    assert _payload(_result({"url": URL}))["cache_hit"] is False
    hit = _payload(_result({"url": URL, "max_payloads": 14}))
    assert hit["cache_hit"] is True
    assert runner["calls"] == 1


def test_camelcase_alias_folds_into_the_canonical_key(runner):
    assert _payload(_result({"url": URL}))["cache_hit"] is False
    hit = _payload(_result({"url": URL, "maxPayloads": 14}))
    assert hit["cache_hit"] is True
    assert runner["calls"] == 1


def test_authenticated_contexts_do_not_share_a_result(runner):
    assert _payload(_result({"url": URL, "cookies": {"sid": "A"}}))[
        "cache_hit"] is False
    assert _payload(_result({"url": URL, "cookies": {"sid": "B"}}))[
        "cache_hit"] is False
    assert runner["calls"] == 2


# -- 3. client controls -----------------------------------------------------
def test_request_key_overrides_the_argument_key(runner):
    meta = {"requestKey": "retry-42"}
    assert _payload(_result({"url": URL}, meta=meta))["cache_hit"] is False
    hit = _payload(_result({"url": "http://other/", "max_payloads": 90},
                           meta=meta))
    assert hit["cache_hit"] is True
    assert runner["calls"] == 1, "requestKey means 'this IS the same request'"
    other = _payload(_result({"url": URL}, meta={"requestKey": "retry-43"}))
    assert other["cache_hit"] is False
    assert runner["calls"] == 2


def test_cache_scope_none_disables_reuse_without_touching_the_payload(runner):
    meta = {"cacheScope": "none"}
    for _ in range(2):
        payload = _payload(_result({"url": URL}, meta=meta))
        assert "cache_hit" not in payload
    assert runner["calls"] == 2


def test_invalid_cache_scope_is_an_explicit_structured_error(runner):
    result = _result({"url": URL}, meta={"cacheScope": "public"})
    assert result["isError"] is True
    assert "invalid cacheScope" in result["content"][0]["text"]
    err = result["structuredContent"]["error"]
    assert err["code"] == "invalid_cache_scope"
    assert err["field"] == "cacheScope"
    assert runner["calls"] == 0


def test_ttl_expiry_forces_a_real_retry(runner):
    meta = {"cacheTtlMs": 20}
    assert _payload(_result({"url": URL}, meta=meta))["cache_hit"] is False
    time.sleep(0.04)
    assert _payload(_result({"url": URL}, meta=meta))["cache_hit"] is False
    assert runner["calls"] == 2


def test_ttl_is_clamped_to_the_cap(runner):
    payload = _payload(_result({"url": URL},
                               meta={"cacheTtlMs": 999999999}))
    assert payload["cache_ttl_ms"] == m._CACHE_MAX_TTL_MS


# -- 4. what must NEVER be cached -------------------------------------------
@pytest.mark.parametrize("flag", ["fail_once", "timeout_once"])
def test_failed_and_timed_out_calls_are_never_replayed(runner, flag):
    runner[flag] = True
    first = _result({"url": URL})
    assert first["isError"] is True
    second = _result({"url": URL})
    assert _payload(second)["cache_hit"] is False
    assert runner["calls"] == 2


def test_cancelled_call_is_never_cached(runner):
    runner["cancel_once"] = True
    assert _call({"url": URL}) is None       # MCP: no answer on cancellation
    assert _payload(_result({"url": URL}))["cache_hit"] is False
    assert runner["calls"] == 2


def test_status_poll_is_always_fresh(monkeypatch, runner):
    states = iter(["pending", "completed"])
    schema = m._ASYNC_TOOL_TABLE["xssentinel_scan_status"][0]

    def fake(args, cancel_event=None, emit=None):
        return {"content": [{"type": "text", "text": json.dumps({
            "scan_id": args["scan_id"], "state": next(states),
            "terminal": False, "finding_count": 0})}]}

    monkeypatch.setitem(m._ASYNC_TOOL_TABLE, "xssentinel_scan_status",
                        (schema, fake))
    a = _payload(_result({"scan_id": "scan_x"},
                         name="xssentinel_scan_status"))
    b = _payload(_result({"scan_id": "scan_x"},
                         name="xssentinel_scan_status"))
    assert (a["state"], b["state"]) == ("pending", "completed")
    assert "cache_hit" not in a and "cache_hit" not in b


def test_legacy_frames_never_cache_and_keep_their_shape(runner):
    first = _result({"url": URL}, modern=False)
    second = _result({"url": URL}, modern=False)
    assert set(first) == set(second)       # no modern-only result field
    for res in (first, second):
        payload = json.loads(res["content"][0]["text"])
        assert "cache_hit" not in payload
        assert "cache_hit" not in res.get("structuredContent", {})
    assert runner["calls"] == 2, "legacy frames must still run every time"


# -- 5. bounded store + contracts ------------------------------------------
def test_lru_bound_evicts_the_oldest_entry(monkeypatch, runner):
    monkeypatch.setattr(m, "_CACHE_MAX_ENTRIES", 2)
    for n in (1, 2, 3):
        assert _payload(_result({"url": f"http://t/{n}"}))["cache_hit"] is False
    again = _payload(_result({"url": "http://t/1"}))
    assert again["cache_hit"] is False, "oldest entry must have been evicted"
    assert runner["calls"] == 4


def test_cache_fields_are_declared_exactly_where_they_occur():
    schemas = {**m._TOOL_OUTPUT_SCHEMAS,
               **m._ASYNC_TOOL_OUTPUT_SCHEMAS}
    assert m._CACHE_EXCLUDED <= (set(m._TOOL_TABLE)
                                 | set(m._ASYNC_TOOL_TABLE))
    for name, schema in schemas.items():
        props = schema["properties"]
        if name in m._CACHE_EXCLUDED:
            assert "cache_hit" not in props, name
        else:
            assert props["cache_hit"]["type"] == "boolean", name
            assert props["cache_scope"]["type"] == "string", name
            assert props["cache_ttl_ms"]["type"] == "integer", name


def _calls(src, func_name):
    tree = ast.parse(textwrap.dedent(src))
    return [n for n in ast.walk(tree) if isinstance(n, ast.Call)
            and (getattr(n.func, "id", None) == func_name
                 or getattr(n.func, "attr", None) == func_name)]


def test_discover_declares_the_reuse_policy():
    result = m.dispatch_message(
        {"jsonrpc": "2.0", "id": 1, "method": "server/discover"})["result"]
    policy = result["resultReuse"]
    assert policy["ttlMs"] == m._CACHE_DEFAULT_TTL_MS
    assert policy["scope"] == "private"
    assert "requestKey" in policy["key"]
    assert "none" in policy["disable"]
    assert "only successful" in policy["note"]


def test_wiring_is_source_pinned():
    src = inspect.getsource(m._tool_call)
    assert "if modern and name not in _CACHE_EXCLUDED" in src
    assert _calls(src, "_cache_lookup") and _calls(src, "_cache_store")
    assert _calls(src, "_stamp_cache")
    assert 'not result.get("isError")' in src
    # A hit checked AFTER the beacon would still emit a progress frame for
    # a call that sends no requests.
    assert src.index("_cache_lookup") < src.index("scoped_emit")
