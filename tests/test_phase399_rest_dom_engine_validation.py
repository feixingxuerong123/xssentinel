"""Phase 399: REST dom_engine validation mirrors the MCP contract exactly.

REST used to accept ANY dom_engine value with 202 and pass it to the Scanner,
where an unknown value fell through to DynamicDomAnalyzer -- the same bug
family as Phase 397's "off ignored" (a public contract not enforced at the
boundary).  The fix reads the ONE authoritative value set from the MCP input
schema (not a hand-written fifth copy) and applies MCP's own
case-insensitive enum semantics.

Every assertion calls the REAL ``_handle_create_scan`` with a stub ctx whose
job_manager only answers ``create`` / ``start`` -- the two calls the handler
makes.  A ``mark_completed`` call ABORTs (Phase 201 stub-fidelity rule).
"""
from __future__ import annotations

import ast
import inspect

from xssentinel.api import server as rest
from xssentinel.api.mcp_server import _TOOL_SCAN_SCHEMA


class _StubJob:
    scan_id = "probe"
    state = "queued"
    target_url = "http://127.0.0.1:9/?q=1"
    created_at = "probe"
    options = {}

    def to_summary(self):
        return {}


class _StubMgr:
    def __init__(self):
        self.captured = None
        self.started = False

    def create(self, url, **kw):
        job = _StubJob()
        job.options = dict(kw["options"])
        self.captured = job.options
        return job

    def start(self, scan_id, worker):
        self.started = True
        return None

    def mark_completed(self, *a, **kw):
        raise AssertionError("stub must not answer calls the handler cannot make")


class _StubServer:
    def __init__(self):
        self.job_manager = _StubMgr()
        self.ai_config = None
        self.webhook = None


def _ctx():
    class C:
        api_key_valid = True
        server = _StubServer()
    return C()


def _create(value, *, omit=False):
    ctx = _ctx()
    body = {"url": "http://127.0.0.1:9/?q=1"}
    if not omit:
        body["dom_engine"] = value
    resp = rest._handle_create_scan(ctx, None, body, {})
    return (getattr(resp, "status", None),
            (ctx.server.job_manager.captured or {}).get("dom_engine"),
            ctx.server.job_manager.started)


def _mcp_enum():
    return list(_TOOL_SCAN_SCHEMA["properties"]["dom_engine"]["enum"])


def test_value_set_is_read_from_mcp_schema_not_hand_written():
    """REST has NO second declaration: the enum comes from the MCP schema."""
    assert rest._dom_engine_values() == _mcp_enum()
    src = inspect.getsource(rest._dom_engine_values)
    # Inspect the function BODY via AST, ignoring the docstring (which may
    # legitimately quote the old hand-written code as history).  No string
    # literal equal to a canonical value may appear as an executable constant.
    tree = ast.parse(src)
    fn = tree.body[0]
    body = fn.body[1:] if (fn.body and isinstance(fn.body[0], ast.Expr)
                           and isinstance(fn.body[0].value, ast.Constant)
                           and isinstance(fn.body[0].value.value, str)) else fn.body
    literals = {n.value for n in ast.walk(ast.Module(body=body, type_ignores=[]))
                if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    for v in _mcp_enum():
        assert v not in literals, (
            f"REST re-declared '{v}' as a literal instead of reading the MCP schema")
    assert any(
        (isinstance(n, ast.Name) and n.id == "_TOOL_SCAN_SCHEMA")
        or (isinstance(n, ast.alias) and n.name == "_TOOL_SCAN_SCHEMA")
        for n in ast.walk(tree)), "must read the MCP schema"


def test_every_declared_value_is_accepted_verbatim():
    for v in _mcp_enum():
        status, reached, started = _create(v)
        assert (status, reached, started) == (202, v, True), v


def test_case_variants_normalize_like_mcp():
    for raw, canonical in (("AUTO", "auto"), ("Playwright", "playwright"),
                           ("OFF", "off"), ("StAtIc", "static")):
        status, reached, started = _create(raw)
        assert (status, reached, started) == (202, canonical, True), raw


def test_unknown_values_are_rejected_before_the_scanner():
    for bad in ("bogus", "on", "", "AUTO ", 123, None):
        status, reached, started = _create(bad)
        assert status == 400, bad
        assert reached is None and started is False, bad


def test_missing_value_defaults_to_auto():
    assert _create(None, omit=True) == (202, "auto", True)


def test_rest_and_mcp_normalizer_agree_on_every_case():
    """Byte-identical verdicts for the same value on both surfaces."""
    from xssentinel.api.mcp_server import _check_type

    prop = _TOOL_SCAN_SCHEMA["properties"]["dom_engine"]
    for raw in ("auto", "AUTO", "off", "OFF", "bogus", "", 123):
        mcp_val, mcp_err = _check_type("dom_engine", prop, raw)
        rest_val = rest._normalize_dom_engine(raw)
        # Both accept-or-reject identically; accepted values are canonical.
        assert (mcp_val is None) == (rest_val is None), (raw, mcp_err)
        if mcp_val is not None:
            assert mcp_val == rest_val, (raw, mcp_val, rest_val)
