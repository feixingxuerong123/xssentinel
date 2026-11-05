# -*- coding: utf-8 -*-
"""Can the CLI actually reach every feature?  (Phase 360 follow-up)

Measured with ``dev/cli_surface_probe.py`` (real ``python -m xssentinel``
subprocesses, 29 surface cases + 133 parser flags).  The pre-change run
found five real breaks; this guard pins the fixes so they cannot rot:

  * ``--raw-request`` with a malformed file -> uncaught RawRequestError
    (rc=1 + traceback).
  * ``--resume`` with a JSON document that is not an object -> uncaught
    AttributeError; a merely corrupt file was reported as "No checkpoint,
    starting fresh", silently discarding resume progress.
  * ``--self-test`` hard-coded port 8899 in THREE files; a host already
    serving on 8899 (measured: an unrelated ``python -m http.server``)
    made the mode unreachable ("Vuln server did not start", rc=1).
  * ``--poc-dir`` write failure shared the report writer's except and
    turned a completed scan into "Report write failed" -> exit 3.
  * ``--ai-timeout`` was declared but never forwarded to ``--ai-check``'s
    provider probe.

The post-change probe: 29 surface cases / 0 crashes, 133 flags / 0 crashes
and 0 timeouts, all 8 report formats produced non-empty artefacts.
"""
from __future__ import annotations

import ast
import json
import os
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
COMMON = ["--max-payloads", "1", "--max-transforms", "1",
          "--dom-engine", "static", "--timeout", "2"]


class _Target(BaseHTTPRequestHandler):
    def do_GET(self):
        from urllib.parse import parse_qs, urlparse
        q = (parse_qs(urlparse(self.path).query).get("q") or [""])[-1]
        body = ("<html><body><div id=out>" + q +
                "</div></body></html>").encode("utf-8", "replace")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass


@pytest.fixture(scope="module")
def target():
    srv = _QuietServer(("127.0.0.1", 0), _Target)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield "http://127.0.0.1:%d/?q=probe" % srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


def _cli(args, stdin=None, timeout=90, env=None):
    base = {**os.environ, "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
            "PYTHONIOENCODING": "utf-8", "PYTHONPATH": ROOT}
    base.update(env or {})
    return subprocess.run([PY, "-m", "xssentinel", *args], cwd=ROOT,
                          env=base, input=stdin, capture_output=True,
                          timeout=timeout)


# ---------------------------------------------------------------------------
# 1. raw request input
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw", [
    b"NOT A REQUEST\r\n\r\n",
    b"GET / HTTP/1.1\r\n\r\n",              # missing Host
    b"\x81\x30\xff\xfe\x00",               # undecodable bytes
], ids=["bad-request-line", "missing-host", "bad-encoding"])
def test_bad_raw_request_is_rc2_without_traceback(tmp_path, raw):
    p = tmp_path / "bad.raw"
    p.write_bytes(raw)
    r = _cli(["--raw-request", str(p)])
    assert r.returncode == 2, r.stderr[-300:]
    assert b"Traceback" not in r.stderr
    assert r.stdout == b""


def test_valid_raw_request_reaches_the_scan(target, tmp_path):
    authority = target.split("//", 1)[1].split("/", 1)[0]
    p = tmp_path / "ok.raw"
    p.write_bytes(("GET /?q=probe HTTP/1.1\r\nHost: " + authority +
                   "\r\n\r\n").encode("ascii"))
    out = tmp_path / "raw.json"
    r = _cli(["--raw-request", str(p), "-o", str(out), "-f", "json",
              *COMMON], timeout=120)
    assert r.returncode == 0, r.stderr[-300:]
    assert out.exists() and "findings" in json.loads(out.read_text())
    assert b"Invalid raw HTTP request" not in r.stderr


# ---------------------------------------------------------------------------
# 2. checkpoint / resume input
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("data", [
    b"1", b"[]", b'"a string"', b"{broken", b"\xef\xbb\xbf" + b"1",
], ids=["int", "list", "string", "bad-json", "bom-int"])
def test_corrupt_checkpoint_is_rc2_not_a_crash_or_silent_reset(tmp_path, data):
    p = tmp_path / "bad.ckpt.json"
    p.write_bytes(data)
    r = _cli(["-u", "http://127.0.0.1:1/", "--resume", str(p),
              *COMMON, "--timeout", "1"])
    assert r.returncode == 2, r.stderr[-300:]
    assert b"Traceback" not in r.stderr
    assert b"not a valid XSSentinel checkpoint" in r.stderr
    assert b"starting fresh" not in r.stderr


def test_missing_checkpoint_is_still_a_legitimate_fresh_start(tmp_path):
    p = tmp_path / "never.ckpt.json"
    r = _cli(["-u", "http://127.0.0.1:1/", "--resume", str(p),
              *COMMON, "--timeout", "1"])
    assert b"Traceback" not in r.stderr
    # Human text goes to stdout unless -o - makes it a machine channel.
    assert b"No checkpoint at" in r.stdout
    assert b"not a valid XSSentinel checkpoint" not in r.stdout + r.stderr


def test_checkpoint_load_shares_the_cli_decoder(tmp_path):
    from xssentinel.core.checkpoint import Checkpoint
    good = {"version": 1, "target": "http://t/", "scanned_urls": ["a"]}
    for enc, bom in (("utf-8", b"\xef\xbb\xbf"), ("gbk", b""),
                     ("utf-16", b"")):
        p = tmp_path / ("c_%s.json" % enc)
        p.write_bytes(bom + json.dumps(good).encode(enc))
        ckpt = Checkpoint.load(str(p))
        assert ckpt is not None and "a" in ckpt._scanned, enc


# ---------------------------------------------------------------------------
# 3. self-test port contract (three files, one value)
# ---------------------------------------------------------------------------

def test_selftest_port_is_one_shared_contract():
    cc = open(os.path.join(ROOT, "xssentinel", "cli_commands.py"),
              encoding="utf-8").read()
    srv = open(os.path.join(ROOT, "tests", "vuln_server.py"),
               encoding="utf-8").read()
    suite = open(os.path.join(ROOT, "tests", "run_self_test.py"),
                 encoding="utf-8").read()
    assert "SELFTEST_PORT_ENV" in cc
    assert "SELFTEST_DEFAULT_PORT = 8899" in cc
    for src in (srv, suite):
        assert 'XSSENTINEL_SELFTEST_PORT' in src
        assert '"8899"' in src, "standalone default drifted from cli_commands"
    # The readiness probe must use the chosen port, not a literal.
    fn = next(n for n in ast.walk(ast.parse(cc))
              if isinstance(n, ast.FunctionDef) and n.name == "_run_self_test")
    assert "8899" not in ast.unparse(fn)


def test_selftest_port_falls_back_when_default_is_occupied(monkeypatch):
    from xssentinel import cli_commands as cc
    monkeypatch.delenv("XSSENTINEL_SELFTEST_PORT", raising=False)
    taken = socket.socket()
    taken.bind(("127.0.0.1", 0))
    occupied = taken.getsockname()[1]
    monkeypatch.setattr(cc, "SELFTEST_DEFAULT_PORT", occupied)
    try:
        chosen = cc._selftest_port()
        assert chosen != occupied and chosen > 0
    finally:
        taken.close()


def test_selftest_reaches_the_vuln_server():
    # Bound the suite deliberately: this guards REACHABILITY, not a full
    # minutes-long self-test run (which has its own gate).
    r = _cli(["--self-test"], timeout=90,
             env={"XSSentinel_SELFTEST_TIMEOUT": "8"})
    assert b"Vuln server ready" in r.stdout, r.stdout[:300]
    assert b"did not start" not in r.stderr
    assert b"Traceback" not in r.stderr


def test_selftest_port_env_is_honoured(monkeypatch):
    from xssentinel import cli_commands as cc
    monkeypatch.setenv("XSSENTINEL_SELFTEST_PORT", "18777")
    assert cc._selftest_port() == 18777
    monkeypatch.setenv("XSSENTINEL_SELFTEST_PORT", "not-a-number")
    with pytest.raises(ValueError):
        cc._selftest_port()


# ---------------------------------------------------------------------------
# 4. PoC artifacts cannot fake a scan failure
# ---------------------------------------------------------------------------

def test_bad_poc_dir_does_not_turn_a_completed_scan_into_exit_3(target,
                                                                tmp_path):
    blocker = tmp_path / "not_a_dir.txt"
    blocker.write_text("x", encoding="utf-8")
    out = tmp_path / "out.json"
    r = _cli(["-u", target, "-o", str(out), "-f", "json",
              "--poc-dir", str(blocker), *COMMON], timeout=120)
    assert r.returncode == 0, (r.returncode, r.stderr[-300:])
    assert b"artifacts skipped" in r.stderr
    assert b"Report write failed" not in r.stderr
    assert out.exists() and "findings" in json.loads(out.read_text())


# ---------------------------------------------------------------------------
# 5. --ai-timeout actually reaches the probe
# ---------------------------------------------------------------------------

def test_ai_timeout_is_forwarded_to_the_probe():
    from xssentinel.core import llm_pool
    src = open(os.path.join(ROOT, "xssentinel", "core", "llm_pool.py"),
               encoding="utf-8").read()
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "probe")
    assert "timeout=timeout" in ast.unparse(fn)
    main = open(os.path.join(ROOT, "xssentinel", "__main__.py"),
                encoding="utf-8").read()
    check = next(n for n in ast.walk(ast.parse(main))
                 if isinstance(n, ast.FunctionDef) and n.name == "_run_ai_check")
    # Not just "timeout=": `pool.probe(models=models, timeout=None)` would
    # satisfy that weaker assertion while ignoring the flag entirely.
    assert "ai_timeout" in ast.unparse(check)

    # Behavioural: a fake _try_one must see the caller's timeout.
    import types
    pool = llm_pool.LLMPool.__new__(llm_pool.LLMPool)
    pool._candidates = [types.SimpleNamespace(endpoint="https://fake")]
    seen = {}

    class _Attempt:
        ok = False
        detail = ""
        kind = "fail"

        def to_dict(self):
            return {"ok": False, "kind": "fail", "status": None,
                    "detail": "", "elapsed": 0.0, "model": "m",
                    "provider": "p", "key": "k"}

    def fake(c, messages, **kw):
        seen.update(kw)
        return _Attempt()

    pool._try_one = fake
    pool._matches = lambda c, models: True
    pool.probe(timeout=1.5)
    assert seen["timeout"] == 1.5


def test_ai_check_returns_under_a_short_timeout():
    r = _cli(["--ai-check", "--ai-timeout", "1"], timeout=90)
    assert b"Traceback" not in r.stderr
    # rc=0/2: the probes ran and the health table was printed.  rc=1: the
    # LLM pool could not be loaded at all -- a Low-integrity/TEMP-degraded
    # host produces exactly that honest degradation (AGENTS.md environment
    # notes), not a hang.  Both shapes must return inside the 90s leash.
    assert r.returncode in (0, 1, 2), (r.returncode, r.stdout[-300:])
    if r.returncode in (0, 2):
        assert b"candidate(s) answered" in r.stdout
    else:
        assert b"Cannot load LLM pool" in r.stdout


# ---------------------------------------------------------------------------
# 6. all eight report formats really produce artefacts
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fmt", ["html", "json", "csv", "sarif", "junit",
                                 "markdown", "burp", "nuclei"])
def test_report_format_writes_a_non_empty_artefact(target, tmp_path, fmt):
    import glob as _glob
    out = tmp_path / ("report_" + fmt)
    r = _cli(["-u", target, "-o", str(out), "-f", fmt, *COMMON],
             timeout=120)
    assert r.returncode == 0, (fmt, r.stderr[-300:])
    if fmt == "nuclei":
        assert out.is_dir() and any(
            os.path.getsize(p) > 0 for p in _glob.glob(str(out) + "/*"))
    else:
        assert any(os.path.isfile(p) and os.path.getsize(p) > 0
                   for p in _glob.glob(str(out) + "*")), fmt
