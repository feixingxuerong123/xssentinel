#!/usr/bin/env python3
"""Phase 384 / OPTIMIZATION §8.3 #11: credential-echo audit over real MCP frames.

Question (from the backlog row): do caller-supplied ``cookies`` / ``headers``
values ever come back through a channel the TARGET did not put them in --
error sentences, ``waf``, ``boundary_stops``, result metadata?

Method: canary credentials sent to real loopback servers, every arm's FULL
response bytes grepped for the canaries.  Two sides, both required:

* server-side arrival proof -- the target records the canary Cookie/header
  arriving, so a clean result is not vacuous (the credentials DID travel);
* client-side absence proof -- canaries appear nowhere in the tool's own
  channels.  For the reflecting arm the canary legitimately lives in the
  page body the target itself echoes; the audit checks it never surfaces
  OUTSIDE target-derived finding fields.

Measured here and pinned by tests/test_phase384_credential_echo.py:
requests' exception texts embed host/port/path but never URL userinfo
(``user:pass@`` is stripped before the pool string is built), so the
``scan failed: {type}: {e}`` echo path has no realistic credential source.

Usage: .venv/Scripts/python.exe dev/credential_echo_probe.py
Writes: dev/_credential_echo_audit.json (gitignored, like all dev/_ facts).
"""
from __future__ import annotations

import json
import os
import secrets
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.api import mcp_server as m  # noqa: E402

SCAN_ARGS = {"max_payloads": 1, "timeout": 5, "max_seconds": 30}
TOOLS_WITH_URL = ("xssentinel_scan", "xssentinel_discover",
                  "xssentinel_profile", "xssentinel_verify",
                  "xssentinel_param_mine", "xssentinel_csp_analyze")


class _Target:
    """Loopback server with arms: static / reflecting / abrupt-close."""

    def __init__(self, mode: str = "static"):
        self._hits: list = []
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _record(self):
                with outer._lock:
                    outer._hits.append({
                        "path": self.path,
                        "cookie": self.headers.get("Cookie") or "",
                        "canary": self.headers.get("X-Audit-Canary") or "",
                    })

            def do_GET(self):
                self._record()
                if outer.mode == "abrupt":
                    self.send_response(200)
                    self.send_header("Content-Length", "1000")
                    self.end_headers()
                    self.wfile.write(b"<html>")
                    self.connection.close()
                    return
                if outer.mode == "reflecting":
                    body = (
                        "<html><body>"
                        f"<p id=cookie>{self.headers.get('Cookie') or ''}</p>"
                        f"<p id=hdr>{self.headers.get('X-Audit-Canary') or ''}"
                        "</p></body></html>").encode()
                else:
                    body = b"<html><body><p>static</p></body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.mode = mode
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever,
                         daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/"

    def arrived(self, cookie_canary: str, header_canary: str) -> bool:
        with self._lock:
            return any(cookie_canary in h["cookie"]
                       and header_canary in h["canary"] for h in self._hits)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _call(tool: str, url: str, canaries: tuple) -> dict:
    """One modern frame with canary credentials; full-response text out."""
    m.configure_scope(None, allow_any_host=True)   # audit is open-mode
    args = dict(SCAN_ARGS)
    args.update({
        "url": url,
        "cookies": {"xsaudit": canaries[0]},
        "headers": {"X-Audit-Canary": canaries[1]},
    })
    if tool != "xssentinel_scan":
        # discover/profile/... accept a narrower argument surface than the
        # scan tool; the extra scan knobs would be refused as unknown keys.
        args = {k: v for k, v in args.items()
                if k in ("url", "cookies", "headers", "timeout")}
    resp = m.dispatch_message({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": tool,
                   "arguments": args,
                   "_meta": {m._META_VERSION_KEY: "2026-07-28"}}})
    result = resp["result"]
    text = json.dumps(result, ensure_ascii=False)
    return {
        "tool": tool,
        "url_kind": url.split(":")[0] + ":" + str(len(url)),
        "isError": bool(result.get("isError")),
        "canary_in_response": (canaries[0] in text) or (canaries[1] in text),
        "response_head": text[:160],
    }


def main() -> int:
    ck = f"canary_ck_{secrets.token_hex(8)}"
    hd = f"canary_hd_{secrets.token_hex(8)}"
    canaries = (ck, hd)
    rows: list = []

    # 1. static target: a clean scan must not carry the canaries anywhere.
    t = _Target("static")
    rows.append(_call("xssentinel_scan", t.url, canaries))
    arrived_static = t.arrived(ck, hd)
    t.stop()

    # 2. reflecting target: the TARGET echoes the credentials into its own
    #    body (server-side arrival proves they travelled); the tool must
    #    still keep them out of every non-finding channel.
    t = _Target("reflecting")
    rows.append(_call("xssentinel_scan", t.url, canaries))
    arrived_reflecting = t.arrived(ck, hd)
    t.stop()

    # 3. abrupt close: whatever the scan answers (error or swallow-and-continue),
    #    no canary may ride along.
    t = _Target("abrupt")
    rows.append(_call("xssentinel_scan", t.url, canaries))
    t.stop()

    # 4. unreachable: the pre-flight error sentence, for every url tool.
    closed = _closed_port()
    for tool in TOOLS_WITH_URL:
        rows.append(_call(tool, f"http://127.0.0.1:{closed}/", canaries))

    # 5. static discover frame (the one non-error success outside scan).
    t = _Target("static")
    rows.append(_call("xssentinel_discover", t.url, canaries))
    t.stop()

    leaks = [r for r in rows if r["canary_in_response"]]
    report = {
        "canary_cookie": ck,
        "canary_header": hd,
        "server_side_arrival": {"static": arrived_static,
                                "reflecting": arrived_reflecting},
        "rows": rows,
        "leaks": leaks,
        "verdict": ("LEAK" if leaks else
                    "NO ECHO: caller credentials never return through a "
                    "channel the target did not put them in"),
    }
    os.makedirs(os.path.join(os.path.dirname(__file__)), exist_ok=True)
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "_credential_echo_audit.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    for r in rows:
        print(f"[{'LEAK' if r['canary_in_response'] else 'clean'}] "
              f"{r['tool']:<24} isError={r['isError']}")
    print("server-side arrival:", report["server_side_arrival"])
    print("verdict:", report["verdict"])
    print("written:", out)
    return 1 if leaks else 0


if __name__ == "__main__":
    sys.exit(main())
