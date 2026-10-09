"""MCP (Model Context Protocol) stdio server -- Phase 189 (dalfox v3 parity).

dalfox v3 ships an MCP server so LLM agents can drive scans as a tool;
2025-26 security tools increasingly expose exactly this integration
surface.  XSSentinel already had a REST API (``--serve``); this module
adds the MCP stdio transport over the SAME scan machinery, so an agent
and a CI pipeline get identical verdicts.

Protocol subset implemented (the stable core of the MCP spec -- one
JSON-RPC 2.0 message per stdin line, one response per stdout line):

  * ``initialize``               -> protocolVersion (echo when supported),
                                    capabilities {tools}, serverInfo
  * ``notifications/initialized`` (any notification) -> silent
  * ``tools/list``               -> the tool catalogue
  * ``tools/call``               -> run the tool, return text content
  * ``ping``                     -> {}

Unknown methods answer -32601; malformed JSON answers -32700; anything
that is not an object answers -32600.  NOTHING is ever logged to stdout --
stdout is the protocol channel; diagnostics go to stderr only.

The single tool, ``xssentinel_scan``, runs one bounded synchronous scan
(the same Scanner the CLI drives, minus crawl/OOB) and returns compact
findings.  It inherits the operator's trust model: the agent scanning a
URL is the operator scanning a URL -- scoping/authorization is the
caller's responsibility, exactly as with the CLI and the REST API.
"""
from __future__ import annotations

import json
import os
import sys
from urllib.parse import urlparse

__all__ = ["MCPServer", "serve", "run_scan_tool", "TOOL_DEFINITIONS"]

#: Protocol versions this server speaks; the client's is echoed when known.
SUPPORTED_PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18")
LATEST_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[-1]

#: Findings/response bounds -- an agent's context window is the resource
#: being protected here, not memory.
_MAX_FINDINGS = 200
_MAX_FIELD = 500

_TOOL_SCAN_SCHEMA = {
    "type": "object",
    "properties": {
        "url": {
            "type": "string",
            "description": ("Target URL. Query parameters are picked up as "
                            "injection points, same as the CLI's -u."),
        },
        "method": {
            "type": "string", "enum": ["GET", "POST"], "default": "GET",
            "description": "HTTP method for the probes.",
        },
        "data": {
            "type": "string",
            "description": "Form-encoded request body (POST).",
        },
        "headers": {
            "type": "object", "additionalProperties": {"type": "string"},
            "description": "Extra HTTP headers (auth, etc.).",
        },
        "cookies": {
            "type": "object", "additionalProperties": {"type": "string"},
            "description": "Session cookies for authenticated scanning.",
        },
        "max_payloads": {
            "type": "integer", "default": 14, "minimum": 1, "maximum": 100,
            "description": "Payload budget per parameter (request cost).",
        },
        "headless": {
            "type": "boolean", "default": False,
            "description": ("Confirm findings in a real headless browser "
                            "(Playwright; slower, strongest evidence)."),
        },
        "timeout": {
            "type": "integer", "default": 15, "minimum": 1, "maximum": 120,
            "description": "Per-request timeout in seconds.",
        },
    },
    "required": ["url"],
}

_TOOL_DISCOVER_SCHEMA = {
    "type": "object",
    "properties": {
        "url": {
            "type": "string",
            "description": "Page to render and harvest (must be http(s)).",
        },
        "headers": {
            "type": "object", "additionalProperties": {"type": "string"},
            "description": "Extra HTTP headers (auth, etc.).",
        },
        "cookies": {
            "type": "object", "additionalProperties": {"type": "string"},
            "description": "Session cookies for authenticated pages.",
        },
        "timeout": {
            "type": "integer", "default": 20, "minimum": 5, "maximum": 120,
            "description": "Render timeout in seconds.",
        },
    },
    "required": ["url"],
}

_TOOL_PROFILE_SCHEMA = {
    "type": "object",
    "properties": {
        "url": {
            "type": "string",
            "description": ("Target URL; ``param`` is submitted with a "
                            "sandwich probe value and the reflection is "
                            "classified."),
        },
        "param": {
            "type": "string",
            "description": "The parameter to profile.",
        },
        "headers": {
            "type": "object", "additionalProperties": {"type": "string"},
            "description": "Extra HTTP headers (auth, etc.).",
        },
        "cookies": {
            "type": "object", "additionalProperties": {"type": "string"},
            "description": "Session cookies for authenticated pages.",
        },
        "timeout": {
            "type": "integer", "default": 15, "minimum": 1, "maximum": 120,
            "description": "Per-request timeout in seconds.",
        },
    },
    "required": ["url", "param"],
}

TOOL_DEFINITIONS = [
    {
        "name": "xssentinel_scan",
        "description": (
            "Scan a URL for XSS with XSSentinel (dual-engine XSS scanner: "
            "context-aware reflection payloads, DOM/static analysis, CSP "
            "nonce/gadget chains, WAF evasion). Returns findings with "
            "type/severity/confidence/evidence_class. Only scan targets "
            "you are authorized to test."),
        "inputSchema": _TOOL_SCAN_SCHEMA,
    },
    {
        "name": "xssentinel_discover",
        "description": (
            "Render a page in a headless browser and harvest the LIVE "
            "input face: SPA form-field names, the same-origin API "
            "endpoints the page itself fetched, and the hash routes it links "
            "to (fragment-only URLs a server-side crawl cannot see). Use "
            "BEFORE xssentinel_scan to find what is actually worth scanning "
            "(Phase 196 machinery, routes added in Phase 210; requires "
            "playwright)."),
        "inputSchema": _TOOL_DISCOVER_SCHEMA,
    },
    {
        "name": "xssentinel_profile",
        "description": (
            "Cheap one-request reflection triage (kxss-style): submit a "
            "sandwich probe through the parameter and return the reflection "
            "context, which meta characters survive RAW/stripped/encoded, "
            "and whether the context is RCDATA. Use it to decide whether a "
            "full scan is worthwhile."),
        "inputSchema": _TOOL_PROFILE_SCHEMA,
    },
]


def _compact_finding(f: dict) -> dict:
    """Trim a finding dict to what an agent can act on.

    Proof snippets and PoC HTML are delivery machinery; type/param/severity/
    evidence are the verdict.  Long free-text fields are clipped to keep one
    finding from outweighing the whole report.
    """
    keep = ("type", "url", "method", "param", "context", "payload",
            "severity", "confidence", "evidence_class", "detail",
            "evidence", "transform", "param_in")
    out: dict = {}
    for k in keep:
        v = f.get(k)
        if v is None:
            continue
        if isinstance(v, str) and len(v) > _MAX_FIELD:
            v = v[:_MAX_FIELD] + "..."
        out[k] = v
    return out


def run_scan_tool(args: dict) -> dict:
    """Execute one ``xssentinel_scan`` tool call -> MCP content payload.

    Mirrors the REST API's ``_scan_worker`` shape (query params become
    injection points, dedup + PoC attach run) but synchronous and without
    the job machinery.  A scan that finds nothing is a SUCCESS with zero
    findings -- only a failed scan is ``isError``.
    """
    from .server import _build_requester
    from ..core.scanner import Scanner

    url = (args.get("url") or "").strip()
    if not url:
        return {"content": [{"type": "text", "text": "url is required"}],
                "isError": True}
    method = (args.get("method") or "GET").upper()
    if method not in ("GET", "POST"):
        return {"content": [{"type": "text",
                             "text": f"unsupported method: {method}"}],
                "isError": True}

    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return {"content": [{"type": "text",
                             "text": f"not an absolute http(s) URL: {url}"}],
                "isError": True}
    base_url = parsed.scheme + "://" + parsed.netloc + parsed.path
    params: dict = {}
    if parsed.query:
        for pair in parsed.query.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params.setdefault(k, v)

    try:
        requester = _build_requester({
            "headers": args.get("headers") or {},
            "cookies": args.get("cookies") or {},
            "timeout": args.get("timeout", 15),
        })
        scanner = Scanner(
            requester=requester,
            use_headless=bool(args.get("headless", False)),
            max_payloads=int(args.get("max_payloads", 14)),
            max_transforms=8,
            dom_engine="auto" if args.get("headless", False) else "off",
            verbose=False,
        )
        scanner.scan_target(base_url, method=method, params=params,
                            data=args.get("data") or None,
                            oob_collect=False)
        scanner.dedup()
        findings = [_compact_finding(f.to_dict() if hasattr(f, "to_dict")
                                     else dict(f))
                    for f in scanner.findings][:_MAX_FINDINGS]
    except Exception as e:                      # scan failure is a tool error
        return {"content": [{"type": "text",
                             "text": f"scan failed: {type(e).__name__}: {e}"}],
                "isError": True}

    result = {
        "target": url,
        "requests_made": getattr(scanner, "requests_made", 0),
        "waf": getattr(scanner, "waf_name", None),
        "finding_count": len(findings),
        "findings": findings,
    }
    return {"content": [{"type": "text",
                         "text": json.dumps(result, ensure_ascii=False,
                                            indent=2)}]}


def run_discover_tool(args: dict) -> dict:
    """``xssentinel_discover``: render + harvest the live input face."""
    from .server import _build_requester
    from ..core.dom_engine import DynamicDomAnalyzer

    url = (args.get("url") or "").strip()
    if not url:
        return {"content": [{"type": "text", "text": "url is required"}],
                "isError": True}
    from urllib.parse import urlparse
    p = urlparse(url)
    if not p.scheme or not p.netloc:
        return {"content": [{"type": "text",
                             "text": f"not an absolute http(s) URL: {url}"}],
                "isError": True}

    engine = DynamicDomAnalyzer(timeout=int(args.get("timeout", 20)))
    if not engine.available():
        return {"content": [{"type": "text",
                             "text": ("playwright/chromium is not "
                                      "installed -- xssentinel_discover "
                                      "requires a headless browser")}],
                "isError": True}
    # auth state flows through the analyzer the same way the CLI's
    # --discover pass wires it (headers ride the page, cookies the context)
    _built = _build_requester({
        "headers": args.get("headers") or {},
        "cookies": args.get("cookies") or {},
        "timeout": args.get("timeout", 20),
    })
    engine.auth_headers = dict(getattr(_built, "headers", None) or {})
    try:
        res = engine.harvest(url)
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"discover failed: "
                                     f"{type(e).__name__}: {e}"}],
                "isError": True}
    return {"content": [{"type": "text",
                         "text": json.dumps({
                             "url": url,
                             "input_field_names": res.get("names") or [],
                             "same_origin_endpoints":
                                 res.get("resource_urls") or [],
                             # Phase 210: the fragment routes.  An agent that
                             # plans "scan these API endpoints" from the two
                             # lists above would still miss every client-side
                             # sink on a hash-routing SPA, because those URLs
                             # are only meaningful to a browser.
                             "spa_routes": res.get("routes") or [],
                         }, ensure_ascii=False, indent=2)}]}


def run_profile_tool(args: dict) -> dict:
    """``xssentinel_profile``: one-request reflection triage.

    The sandwich probe (kxss lineage, Phase 31 machinery) reveals which
    meta characters the server leaves RAW -- the cheapest honest answer to
    "is a full scan worth it, and what class of payload could work".
    Metadata only: nothing here confirms or denies a vulnerability.
    """
    from .server import _build_requester
    from ..core import context as ctx_mod
    from ..core import reflection_profile as rp_mod
    from ..core import verifier as _unused  # noqa: F401  (import parity)

    url = (args.get("url") or "").strip()
    param = (args.get("param") or "").strip()
    if not url or not param:
        return {"content": [{"type": "text",
                             "text": "url and param are required"}],
                "isError": True}
    from urllib.parse import urlparse
    p = urlparse(url)
    if not p.scheme or not p.netloc:
        return {"content": [{"type": "text",
                             "text": f"not an absolute http(s) URL: {url}"}],
                "isError": True}

    token = "xssp_" + os.urandom(4).hex()
    probe_value = rp_mod.build_probe(token)
    try:
        requester = _build_requester({
            "headers": args.get("headers") or {},
            "cookies": args.get("cookies") or {},
            "timeout": args.get("timeout", 15),
        })
        resp = requester.request("GET", url, params={param: probe_value})
        text = resp.text or ""
        status = getattr(resp, "status_code", 0)
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"profile probe failed: "
                                     f"{type(e).__name__}: {e}"}],
                "isError": True}

    profile = rp_mod.profile_reflection(text, token)
    if profile is None or not profile.get("reflected"):
        result = {"url": url, "param": param, "status": status,
                  "reflected": False,
                  "note": "the sandwich probe value did not reflect -- "
                          "the parameter is probably not rendered"}
    else:
        sel = ctx_mod.analyze_all(text, token)
        result = {
            "url": url, "param": param, "status": status,
            "reflected": True,
            "context": sel.get("context"),
            "extra_contexts": [c for c in sel.get("contexts", [])
                               if c != sel.get("context")][:2],
            "meta_chars": rp_mod.triage_line(profile),
            "full_reflection": profile.get("full_reflection"),
            "rcdata_tag": profile.get("rcdata_tag"),
            "note": ("raw= lists the meta characters the server leaves "
                     "unencoded at the reflection point; a raw '<' plus a "
                     "raw quote usually means a plain breakout works"),
        }
    return {"content": [{"type": "text",
                         "text": json.dumps(result, ensure_ascii=False,
                                            indent=2)}]}


class MCPServer:
    """JSON-RPC/MCP dispatch over two text streams (injectable for tests)."""

    def __init__(self, stdin=None, stdout=None):
        self._stdin = stdin if stdin is not None else sys.stdin
        self._stdout = stdout if stdout is not None else sys.stdout

    # -- dispatch -----------------------------------------------------------

    def _handle(self, msg: dict):
        """One decoded request/notification -> response dict or None."""
        method = msg.get("method")
        mid = msg.get("id")
        if method is None:
            return self._error(mid, -32600, "invalid request: no method")
        try:
            if method == "initialize":
                return self._result(mid, {
                    "protocolVersion": self._negotiate_version(msg),
                    "capabilities": {"tools": {}},
                    "serverInfo": self._server_info(),
                })
            if method == "tools/list":
                return self._result(mid, {"tools": TOOL_DEFINITIONS})
            if method == "tools/call":
                return self._result(mid, self._tool_call(msg.get("params")))
            if method == "ping":
                return self._result(mid, {})
            if method.startswith("notifications/"):
                return None                     # notifications never answer
            return self._error(mid, -32601, f"method not found: {method}")
        except Exception as e:                  # one bad call != dead server
            return self._error(mid, -32603,
                               f"internal error: {type(e).__name__}: {e}")

    @staticmethod
    def _negotiate_version(msg: dict) -> str:
        client = msg.get("params", {}).get("protocolVersion") \
            if isinstance(msg.get("params"), dict) else None
        return client if client in SUPPORTED_PROTOCOL_VERSIONS \
            else LATEST_PROTOCOL_VERSION

    @staticmethod
    def _server_info() -> dict:
        from .. import __version__
        return {"name": "xssentinel", "version": __version__}

    def _tool_call(self, params) -> dict:
        if not isinstance(params, dict):
            return {"content": [{"type": "text",
                                 "text": "params must be an object"}],
                    "isError": True}
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if name == "xssentinel_scan":
            if not isinstance(arguments, dict):
                return {"content": [{"type": "text",
                                     "text": "arguments must be an object"}],
                        "isError": True}
            return run_scan_tool(arguments)
        if name == "xssentinel_discover":
            if not isinstance(arguments, dict):
                return {"content": [{"type": "text",
                                     "text": "arguments must be an object"}],
                        "isError": True}
            return run_discover_tool(arguments)
        if name == "xssentinel_profile":
            if not isinstance(arguments, dict):
                return {"content": [{"type": "text",
                                     "text": "arguments must be an object"}],
                        "isError": True}
            return run_profile_tool(arguments)
        return {"content": [{"type": "text",
                             "text": f"unknown tool: {name}"}],
                "isError": True}

    @staticmethod
    def _result(mid, result: dict):
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    @staticmethod
    def _error(mid, code: int, message: str):
        return {"jsonrpc": "2.0", "id": mid,
                "error": {"code": code, "message": message}}

    # -- transport ----------------------------------------------------------

    def serve(self) -> int:
        """Read lines until EOF; write one response line per request."""
        for line in self._stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError as e:
                self._write(self._error(None, -32700,
                                        f"parse error: {e}"))
                continue
            if not isinstance(msg, dict):
                self._write(self._error(None, -32600,
                                        "invalid request: expected object"))
                continue
            resp = self._handle(msg)
            if resp is not None:
                self._write(resp)
        return 0

    def _write(self, resp: dict) -> None:
        self._stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
        self._stdout.flush()


def serve() -> int:
    """CLI entry (``xssentinel --mcp``): serve the MCP stdio protocol."""
    return MCPServer().serve()
