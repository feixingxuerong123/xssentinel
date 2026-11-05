# -*- coding: utf-8 -*-
"""Phase 359: the CLI must be usable as a pipeline citizen.

Measured gaps on this tree before the change (2026-11-05, real subprocess):

  * ``--batch`` / ``--batch-stdin`` with a UTF-8 BOM validated the first
    line (``\\ufeff# comment``) as a URL -> rc=2 "Invalid URL"; a GBK list
    raised an uncaught UnicodeDecodeError -> rc=1 with a traceback.
  * ``-o -`` was a FILENAME: the CLI wrote ``-.json`` and stdout carried
    only a human summary.  There was no machine-readable stdout channel.
    Even after adding it, batch progress lines and ``[+] Batch complete``
    polluted the stream until every human print was routed to stderr.
  * ``-o reports/scan.json`` failed when ``reports/`` did not exist
    (FileNotFoundError -> "Report write failed" -> exit 3, which lies
    about a scan that actually completed).
  * No target printed a 40 KB ``--help`` to STDOUT while the error went to
    stderr, so a pipeline got a wall of help instead of an empty stdout.

These tests drive the REAL ``python -m xssentinel`` entry point against a
loopback page; the pure loader cases use injectable streams.  Exit codes
(0 ok / 1 crash / 2 usage / 3 incomplete) are pinned so a future "cleanup"
cannot silently change what CI branching means.
"""
from __future__ import annotations

import ast
import io
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
COMMON = ["--max-payloads", "1", "--max-transforms", "1",
          "--dom-engine", "static"]


class _Target(BaseHTTPRequestHandler):
    """Reflects the LAST q value (tools append their own q to the URL)."""

    def do_GET(self):
        from urllib.parse import parse_qs, urlparse
        q = (parse_qs(urlparse(self.path).query).get("q") or [""])[-1]
        body = ("<html><body><div id=out>" + q +
                "</div></body></html>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def target():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Target)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield "http://127.0.0.1:%d/?q=probe" % srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


def _cli(args, stdin=None, cwd=None):
    env = {**os.environ, "NO_PROXY": "127.0.0.1,localhost",
           "no_proxy": "127.0.0.1,localhost"}
    return subprocess.run([PY, "-m", "xssentinel", *args], cwd=cwd or ROOT,
                           env=env, input=stdin, capture_output=True,
                           timeout=120)


def _json_lines(raw: bytes):
    return [json.loads(line) for line in raw.decode("utf-8").splitlines()
            if line.strip()]


# ---------------------------------------------------------------------------
# 1. input decoding (pure loader)
# ---------------------------------------------------------------------------

def test_batch_file_accepts_utf8_bom_gbk_and_utf16(tmp_path):
    from xssentinel.cli_runner import load_target_urls
    urls = ["http://127.0.0.1:1/?a=1", "http://127.0.0.1:2/?a=2"]
    text = "\ufeff# comment\r\n" + urls[0] + "\r\n" + urls[1] + "\r\n"
    for enc, data in (("utf8-bom", text.encode("utf-8")),
                      ("gbk", text.replace("\ufeff", "").encode("gbk")),
                      ("utf16", text.encode("utf-16"))):
        p = tmp_path / ("list_%s.txt" % enc)
        p.write_bytes(data)
        got, err = load_target_urls(batch_file=str(p))
        assert err is None, enc
        assert got == urls, (enc, got)


def test_batch_stdin_decodes_bytes_and_text_streams():
    from xssentinel.cli_runner import load_target_urls
    raw = "# 中文注释\nhttp://127.0.0.1:1/\nhttp://127.0.0.1:2/\n"
    # Real stdin is a TextIOWrapper over a binary buffer; the bytes are GBK
    # even though the wrapper's declared encoding says UTF-8 (this is what
    # a Windows console hands a pipe).
    binary = io.TextIOWrapper(io.BytesIO(raw.encode("gbk")),
                               encoding="utf-8")
    got, err = load_target_urls(batch_stdin=True, stdin=binary)
    assert err is None and len(got) == 2, (got, err)
    # Injected text stream (the historical test harness) still works.
    got, err = load_target_urls(batch_stdin=True,
                                stdin=io.StringIO("\ufeff# c\r\nhttp://t/\r\n"))
    assert err is None and got == ["http://t/"], (got, err)


def test_undecodable_batch_is_an_honest_error(tmp_path):
    from xssentinel.cli_runner import load_target_urls
    p = tmp_path / "broken.txt"
    p.write_bytes(b"\x81\x30\x81\x30\xff\xfe\x00\x81")
    got, err = load_target_urls(batch_file=str(p))
    assert got == [] and err and "UTF-8" in err


def test_empty_stdin_is_not_a_crash():
    from xssentinel.cli_runner import load_target_urls
    got, err = load_target_urls(batch_stdin=True, stdin=io.StringIO(""))
    assert got == [] and err == "No URLs read from stdin"


# ---------------------------------------------------------------------------
# 2. stdout as a machine channel
# ---------------------------------------------------------------------------

def test_no_target_leaves_stdout_empty_and_returns_2():
    r = _cli([])
    assert r.returncode == 2
    assert r.stdout == b""                       # no 40 KB help on stdout
    assert b"No target specified" in r.stderr


def test_single_target_dash_o_is_one_json_frame(target):
    r = _cli(["-u", target, "-o", "-", "-f", "json", *COMMON])
    assert r.returncode == 0, r.stderr[-300:]
    frames = _json_lines(r.stdout)
    assert len(frames) == 1 and isinstance(frames[0], dict)
    assert "findings" in frames[0]
    assert b"[+] Done" in r.stderr              # summary moved off stdout


def test_batch_dash_o_is_json_lines(target):
    feed = (target + "\n" + target + "&b=2\n").encode("utf-8")
    r = _cli(["--batch-stdin", "-o", "-", "-f", "json", *COMMON], stdin=feed)
    assert r.returncode == 0, r.stderr[-300:]
    frames = _json_lines(r.stdout)
    assert len(frames) == 2, frames
    assert all(isinstance(f, dict) and "findings" in f for f in frames)


def test_batch_dash_o_rejects_non_json_format(target):
    r = _cli(["--batch-stdin", "-o", "-", "-f", "html", *COMMON],
             stdin=(target + "\n").encode())
    assert r.returncode == 2
    assert r.stdout == b""
    assert b"requires -f json" in r.stderr


def test_single_target_dash_o_csv_is_plain_text(target):
    r = _cli(["-u", target, "-o", "-", "-f", "csv", *COMMON])
    assert r.returncode == 0
    head = r.stdout.decode("utf-8").splitlines()[0]
    assert head.startswith("type,url,method")


def test_no_dash_json_file_is_written(target, tmp_path):
    """The legacy path must be byte-for-byte unchanged by the stdout mode."""
    out = tmp_path / "out" / "report.json"
    r = _cli(["-u", target, "-o", str(out), "-f", "json", *COMMON])
    assert r.returncode == 0 and out.exists()
    assert isinstance(json.loads(out.read_text(encoding="utf-8")), dict)
    assert b"[+] Done" in r.stdout            # summary stays on stdout


def test_dash_o_leaves_no_dash_named_file(target, tmp_path):
    """Regression for the measured artifacts ``-.json`` / ``-.csv``.

    Root cause: the report writer appended the format extension to the
    literal path ``-`` before the stdout branch was reached, so a pipeline
    run dropped a report file into the CWD and stdout carried only the
    human summary.  Both formats are exercised in a scratch CWD.
    """
    for fmt in ("json", "csv"):
        r = _cli(["-u", target, "-o", "-", "-f", fmt, *COMMON],
                 cwd=tmp_path)
        assert r.returncode == 0, r.stderr[-300:]
        assert not ({"-", "-.json", "-.csv"} & {p.name for p in tmp_path.iterdir()}), \
            sorted(p.name for p in tmp_path.iterdir())
        assert r.stdout.strip(), fmt


def test_diff_dash_o_is_a_stdout_frame_not_a_dash_file(tmp_path):
    """``--diff`` shared the same bug: ``-`` + ``.json`` became ``-.json``."""
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    baseline.write_text(json.dumps({"target": "http://t/", "findings": []}),
                        encoding="utf-8")
    current.write_text(json.dumps({"target": "http://t/", "findings": []}),
                       encoding="utf-8")
    r = _cli(["--diff", str(baseline), str(current),
              "-o", "-", "-f", "json"], cwd=tmp_path)
    assert r.returncode == 0, r.stderr[-300:]
    frames = _json_lines(r.stdout)
    assert len(frames) == 1 and isinstance(frames[0], dict)
    assert not ({"-", "-.json"} & {p.name for p in tmp_path.iterdir()}), \
        sorted(p.name for p in tmp_path.iterdir())


# ---------------------------------------------------------------------------
# 3. output path + exit code stability
# ---------------------------------------------------------------------------

def test_output_creates_missing_parent_directories(target, tmp_path):
    out = tmp_path / "never" / "existed" / "r.json"
    r = _cli(["-u", target, "-o", str(out), "-f", "json", *COMMON])
    assert r.returncode == 0 and out.exists()


def test_exit_code_contract():
    assert _cli(["--help"]).returncode == 0
    assert _cli(["--no-such-flag"]).returncode == 2
    assert _cli(["-u", "http://127.0.0.1:1/", "--max-payloads=abc"]) \
        .returncode == 2


def test_every_main_print_names_its_stream():
    """Guard the seam that rots: one future bare print pollutes `-o -`.

    The AST assertion is on the SOURCE, not on one function's behaviour --
    a new print added to _main_impl without ``file=`` must fail here.
    """
    src = open(os.path.join(ROOT, "xssentinel", "__main__.py"),
               encoding="utf-8").read()
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "_main_impl")
    bare = [n.lineno for n in ast.walk(fn)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            and n.func.id == "print"
            and not any(k.arg == "file" for k in n.keywords)]
    assert bare == [], "prints without an explicit stream: %s" % bare
