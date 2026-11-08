# -*- coding: utf-8 -*-
"""The official XSSMaze runner hands the wrapper a URL and nothing else.

A POST-only endpoint therefore gets a GET request with no body, so the
scanner cannot reach the parameter at all.  ``postmethod`` scored 0/6 and
``post`` 0/2 in the 2026-11-08 full scorecard for that reason -- a hole in
the *measurement*, not proof that the scanner cannot find POST XSS.

This file locks the fix in the dev wrapper (NOT in the product):

1. With POST-aware enabled and a map index, a POST-only endpoint is actually
   requested with POST + a body, and the finding is reported.
2. With the flag OFF the command is byte-identical to the historical wrapper
   -- the previous scorecard must stay reproducible.
3. A GET endpoint never gets a POST body even with the flag on.
"""
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WRAPPER = os.path.join(ROOT, "dev", "_xssmaze", "wrapper.py")
PY = sys.executable


class _State:
    methods = []


class _Handler(BaseHTTPRequestHandler):
    """POST-only endpoint reflects its body; GET-only reflects its query."""

    def _reply(self, body):
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        _State.methods.append("GET")
        path = urlparse(self.path).path
        if path == "/getonly/":
            q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            self._reply(f"<html><body><div>{q}</div></body></html>")
        else:
            self._reply("<html><body>no reflection here</body></html>")

    def do_POST(self):
        _State.methods.append("POST")
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", "replace")
        q = parse_qs(raw).get("q", [""])[0]
        self._reply(f"<html><body><div>{q}</div></body></html>")

    def log_message(self, *args):
        pass


@pytest.fixture
def target(tmp_path, monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    _State.methods = []
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_port}"
    index = tmp_path / "map_index.json"
    index.write_text(json.dumps({
        "/postonly/": {"method": "POST", "params": ["q"]},
        "/getonly/": {"method": "GET", "params": ["q"]},
    }), encoding="utf-8")
    try:
        yield base, str(index)
    finally:
        httpd.shutdown()
        httpd.server_close()


def _scan(base, path, index, aware, invlog=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")
    env["NO_PROXY"] = "127.0.0.1,localhost"
    env["no_proxy"] = "127.0.0.1,localhost"
    env["XSSMAZE_MAP_INDEX"] = index
    env["XSSMAZE_TIMEOUT"] = "30"
    if invlog is not None:
        env["XSSMAZE_INVLOG"] = str(invlog)
    else:
        env.pop("XSSMAZE_INVLOG", None)
    if aware:
        env["XSSMAZE_POST_AWARE"] = "1"
    else:
        env.pop("XSSMAZE_POST_AWARE", None)
    proc = subprocess.run([PY, WRAPPER, base + path], cwd=ROOT, env=env,
                          capture_output=True, text=True, timeout=90)
    assert proc.returncode == 0, proc.stderr[-400:]
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_post_aware_detects_post_only_endpoint(target):
    base, index = target
    _State.methods = []
    payload = _scan(base, "/postonly/", index, aware=True)
    assert "POST" in _State.methods, "the wrapper never sent a POST body"
    assert payload["findings"], "POST-only XSS was not detected"


def test_default_wrapper_is_byte_identical(target):
    """Flag OFF must reproduce the historical (GET-only) behaviour."""
    base, index = target
    _State.methods = []
    payload = _scan(base, "/postonly/", index, aware=False)
    assert "POST" not in _State.methods
    assert payload["findings"] == []


def test_get_endpoint_never_gets_a_post_body(target):
    base, index = target
    _State.methods = []
    _scan(base, "/getonly/?q=x", index, aware=True)
    assert "POST" not in _State.methods, "GET endpoint must stay GET"


# -- source contract: opt-in must not rot into always-on -------------------

def _wrapper_source():
    with open(WRAPPER, encoding="utf-8") as fh:
        return fh.read()


def test_main_uses_the_single_command_builder():
    import ast
    tree = ast.parse(_wrapper_source())
    main = next(n for n in tree.body
                if isinstance(n, ast.FunctionDef) and n.name == "main")
    called = {n.func.id for n in ast.walk(main)
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert {"_build_cmd", "_post_params"} <= called, (
        "main must not hand-roll a second command shape")


def test_post_aware_is_opt_in_and_fail_safe():
    src = _wrapper_source()
    assert 'XSSMAZE_POST_AWARE' in src
    assert 'XSSMAZE_MAP_INDEX' in src
    assert '_flag("XSSMAZE_POST_AWARE")' in src, (
        "the gate must be an explicit flag check, not an unconditional branch")


def test_missing_index_is_fail_safe(target):
    base, _ = target
    _State.methods = []
    # Empty index path: wrapper must fall back to the historical command.
    payload = _scan(base, "/postonly/", "", aware=True)
    assert "POST" not in _State.methods
    assert payload["findings"] == []


def test_invlog_records_the_post_shape(target, tmp_path):
    """Exercise the TSV branch too -- it once hid an undefined helper."""
    base, index = target
    log = tmp_path / "invlog.tsv"
    _State.methods = []
    payload = _scan(base, "/postonly/", index, aware=True, invlog=log)
    assert payload["findings"]
    assert "POST:q" in log.read_text(encoding="utf-8")
