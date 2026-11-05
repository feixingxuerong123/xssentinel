# -*- coding: utf-8 -*-
"""What does an AGENT actually see when it calls XSSentinel over MCP?

Real stdio subprocess, real frames.  Measurement for the "agent-callable
tool" backlog (2026-11-06); output: dev/_agent_surface_probe.json.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
ENV = {**os.environ, "NO_PROXY": "127.0.0.1,localhost",
       "no_proxy": "127.0.0.1,localhost", "PYTHONIOENCODING": "utf-8",
       "PYTHONPATH": ROOT}
META = {"_meta": {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28"}}


class T(BaseHTTPRequestHandler):
    def do_GET(self):
        from urllib.parse import parse_qs, urlparse
        q = (parse_qs(urlparse(self.path).query).get("q") or [""])[-1]
        b = ("<html><body><div id=out>" + q +
             "</div></body></html>").encode("utf-8", "replace")
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


class Quiet(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass


def req(mid, method, params=None):
    return {"jsonrpc": "2.0", "id": mid, "method": method,
            "params": params or {}}


def main():
    srv = Quiet(("127.0.0.1", 0), T)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    target = "http://127.0.0.1:%d/?q=probe" % srv.server_address[1]

    frames = [
        req(1, "server/discover", META),
        req(2, "tools/list", META),
        req(3, "initialize", {"protocolVersion": "2025-06-18",
                              "capabilities": {},
                              "clientInfo": {"name": "probe", "version": "1"}}),
        req(4, "tools/list"),
        req(5, "tools/call", {"name": "no_such_tool", "arguments": {}}),
        req(6, "tools/call", {"name": "xssentinel_scan",
                              "arguments": {"url": target, "cokies": "x"}}),
        req(7, "tools/call", {"name": "xssentinel_scan",
                              "arguments": {}}),
        req(8, "tools/call", {"name": "xssentinel_scan",
                              "arguments": {"url": "not-a-url"}}),
        req(9, "tools/call", {"name": "xssentinel_profile",
                              "arguments": {"url": target, "param": "q"}}),
        req(10, "tools/call", {"name": "xssentinel_scan",
                               "arguments": {"url": target,
                                             "maxPayloads": 1,
                                             "domEngine": "static"}}),
        req(11, "tools/call", {"name": "xssentinel_scan",
                               "arguments": {"url": target,
                                             "maxPayloads": 1,
                                             "domEngine": "static"},
                               "_meta": {"progressToken": "tok-1"}}),
    ]
    payload = "\n".join(json.dumps(f) for f in frames) + "\n"
    p = subprocess.Popen([PY, "-m", "xssentinel", "mcp"], cwd=ROOT,
                         env=ENV, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate(payload.encode("utf-8"), timeout=180)
    srv.shutdown()
    srv.server_close()

    responses = []
    for line in out.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            responses.append(json.loads(line))
        except ValueError:
            responses.append({"_non_json": line[:200]})
    by_id = {r.get("id"): r for r in responses if isinstance(r, dict)
             and "id" in r and "_non_json" not in r}

    tools = by_id.get(2, {}).get("result", {}).get("tools", [])
    catalogue = [{
        "name": t.get("name"),
        "has_title": "title" in t,
        "has_annotations": "annotations" in t,
        "annotations": t.get("annotations"),
        "desc_len": len(t.get("description", "")),
        "has_outputSchema": "outputSchema" in t,
        "input_props": len(t.get("inputSchema", {}).get("properties", {})),
        "required": t.get("inputSchema", {}).get("required"),
    } for t in tools]

    def call_shape(mid):
        r = by_id.get(mid, {})
        res = r.get("result")
        if not isinstance(res, dict):
            return {"raw": r}
        text = ""
        for c in res.get("content", []):
            if c.get("type") == "text":
                text += c.get("text", "")
        return {"isError": res.get("isError"),
                "has_structured": "structuredContent" in res,
                "structured_keys": sorted(
                    (res.get("structuredContent") or {}).keys())
                if isinstance(res.get("structuredContent"), dict) else None,
                "text_len": len(text), "text_head": text[:260],
                "top_keys": sorted(res.keys()),
                "error": r.get("error")}

    report = {
        "rc": p.returncode,
        "frames_sent": len(frames), "responses": len(responses),
        "notifications": [r for r in responses
                          if isinstance(r, dict) and "method" in r
                          and "id" not in r],
        "discover_keys": sorted(by_id.get(1, {}).get("result", {}).keys()),
        "catalogue": catalogue,
        "tools_list_top_keys": sorted(by_id.get(2, {}).get("result", {}).keys()),
        "legacy_initialize_keys": sorted(
            by_id.get(3, {}).get("result", {}).keys()),
        "calls": {str(i): call_shape(i) for i in range(5, 12)},
        "stderr_head": err[:300].decode("utf-8", "replace"),
    }
    with open(os.path.join(ROOT, "dev", "_agent_surface_probe.json"), "w",
              encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=1)

    print("rc=%s frames=%d responses=%d" %
          (report["rc"], len(frames), len(responses)))
    print("discover keys:", report["discover_keys"])
    print("tools/list keys:", report["tools_list_top_keys"])
    print("catalogue:")
    for c in catalogue:
        print("  %-26s title=%-5s annotations=%-5s desc=%3d out=%s props=%s" %
              (c["name"], c["has_title"], c["has_annotations"],
               c["desc_len"], c["has_outputSchema"], c["input_props"]))
    print("notifications:", len(report["notifications"]))
    for k, v in report["calls"].items():
        print("call %-2s isError=%-5s structured=%-5s text=%-6s %s" %
              (k, v.get("isError"), v.get("has_structured"),
               v.get("text_len"), repr((v.get("text_head") or "")[:110])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
