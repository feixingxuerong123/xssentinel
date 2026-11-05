# -*- coding: utf-8 -*-
"""Phase 360: CLI compatibility guard (measured before/after, 2026-11-05).

Pre-change findings, all from REAL ``python -m xssentinel`` subprocesses
(see ``dev/cli_compat_probe.py`` and its before/after JSON):

  * ``--version`` / ``-V`` -> rc=2 with 5.6 KB of usage on stderr.
  * ``-o -`` with ``--login-token`` / ``--login-basic`` / ``--ai-report`` /
    ``--fuzz`` / ``--discover`` emitted human lines INTO the report stream;
    Phase 359's AST guard only covered ``_main_impl``, leaving 97 bare
    prints in __main__ / cli_runner / cli_commands.
  * ``--config`` with a UTF-8 BOM silently returned an EMPTY config (rc=2
    "No target specified"); a GBK config raised UnicodeDecodeError (rc=1 +
    traceback).  Every key with a non-empty argparse default (``format``,
    ``timeout``, ``output``...) was silently overridden by that default.
  * ``-o - -f nuclei`` (single target) exited 3 "scan incomplete", because
    the report writer raised ValueError AFTER a successful scan; the batch
    shape of the same mistake correctly returned 2.
  * ``-o - | head -1`` on a batch marked every remaining target failed,
    exited 3, and left ``Exception ignored on flushing sys.stdout`` at
    interpreter shutdown (rc=120).

The guard has two halves: real-subprocess BEHAVIOUR (a fake/injected stream
can answer calls the real entry point never makes) and SOURCE-level AST
assertions (so a future bare print cannot re-pollute the channel).
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
CLI_MODULES = ("xssentinel/__main__.py", "xssentinel/cli_runner.py",
               "xssentinel/cli_commands.py")


class _Target(BaseHTTPRequestHandler):
    """Reflects the LAST q value; the page also carries non-ASCII text."""

    def do_GET(self):
        from urllib.parse import parse_qs, urlparse
        q = (parse_qs(urlparse(self.path).query).get("q") or [""])[-1]
        body = ("<html><body><div id=out>\u4e2d\u6587" + q +
                "</div></body></html>").encode("utf-8")
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


def _cli(args, stdin=None, timeout=120, env=None):
    base = {**os.environ, "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
            "PYTHONIOENCODING": "utf-8"}
    base.update(env or {})
    return subprocess.run([PY, "-m", "xssentinel", *args], cwd=ROOT,
                          env=base, input=stdin, capture_output=True,
                          timeout=timeout)


def _frames(raw: bytes):
    """Every non-empty stdout line MUST be a JSON object with findings."""
    frames = []
    for line in raw.decode("utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)             # ValueError here = pollution
        assert isinstance(obj, dict) and "findings" in obj, line[:200]
        frames.append(obj)
    return frames


def _write_cfg(tmp_path, name, data: dict, enc: str, bom: bytes = b""):
    p = tmp_path / name
    p.write_bytes(bom + json.dumps(data, ensure_ascii=False).encode(enc))
    return p


# ---------------------------------------------------------------------------
# A. version + argument spellings
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("flag", ["--version", "-V"])
def test_version_flags_print_single_line_and_exit_zero(flag):
    from xssentinel import __version__
    r = _cli([flag])
    assert r.returncode == 0, r.stderr[:300]
    assert r.stdout.decode().strip() == f"xssentinel {__version__}"
    assert r.stderr == b""


def test_version_flag_is_registered_in_help():
    r = _cli(["--help"])
    assert r.returncode == 0
    assert b"--version" in r.stdout and b"-V" in r.stdout


def test_ver_prefix_still_means_verbose_not_ambiguous():
    """Adding --version must not break --verbose's historical abbreviation."""
    from xssentinel.__main__ import build_parser
    assert build_parser().parse_args(["--ver", "-u", "http://t/"]).verbose
    assert build_parser().parse_args(["--verbose", "-u", "http://t/"]).verbose
    r = _cli(["--ver", "--help"])
    assert r.returncode == 0 and b"ambiguous" not in r.stderr


def test_exit_code_contract_unchanged(target, tmp_path):
    assert _cli(["--help"]).returncode == 0
    assert _cli([]).returncode == 2
    assert _cli(["--no-such-flag"]).returncode == 2
    assert _cli(["-u", "http://127.0.0.1:1/",
                 "--max-payloads=abc"]).returncode == 2
    out = tmp_path / "out.json"
    assert _cli(["-u", target, "-o", str(out), "-f", "json",
                 *COMMON]).returncode == 0


# ---------------------------------------------------------------------------
# B. stdout as a machine channel -- real entry point, real scans
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("extra", [
    [], ["--login-token", "T"], ["--login-basic", "u:p"],
    ["--ai-report"], ["--fuzz"], ["--discover"], ["--async"],
], ids=["baseline", "login-token", "login-basic", "ai-report",
        "fuzz", "discover", "async"])
def test_stdout_is_pure_json_for_every_human_mode(target, extra):
    r = _cli(["-u", target, "-o", "-", "-f", "json", *COMMON, *extra])
    assert r.returncode == 0, r.stderr[-400:]
    assert len(_frames(r.stdout)) == 1
    assert b"[+] Done" in r.stderr             # summary off the channel


def test_har_spec_import_keeps_stdout_clean(target, tmp_path):
    """_build_spec_targets() used to print a bare line into the stream."""
    har = {"log": {"version": "1.2", "entries": [
        {"request": {"method": "GET", "url": target,
                     "headers": [], "cookies": [], "postData": None},
         "response": {"status": 200, "statusText": "ok"}}]}}
    p = tmp_path / "cap.har"
    p.write_text(json.dumps(har), encoding="utf-8")
    r = _cli(["--har", str(p), "-o", "-", "-f", "json", *COMMON])
    assert r.returncode == 0, r.stderr[-400:]
    assert len(_frames(r.stdout)) >= 1


def test_batch_stdout_is_json_lines(target):
    feed = (target + "\n" + target + "&b=2\n").encode("utf-8")
    r = _cli(["--batch-stdin", "-o", "-", "-f", "json", *COMMON],
             stdin=feed)
    assert r.returncode == 0, r.stderr[-400:]
    assert len(_frames(r.stdout)) == 2


def test_non_dash_output_keeps_human_summary_on_stdout(target, tmp_path):
    """Phase 359's legacy contract: no -o - means stdout is human."""
    out = tmp_path / "out" / "report.json"
    r = _cli(["-u", target, "-o", str(out), "-f", "json", *COMMON])
    assert r.returncode == 0 and out.exists()
    assert b"[+] Done" in r.stdout


# ---------------------------------------------------------------------------
# C. source-level contract: no future print can rot the seam
# ---------------------------------------------------------------------------

def test_every_cli_print_names_its_stream():
    """All THREE CLI modules, not just _main_impl (Phase 359's blind spot)."""
    for rel in CLI_MODULES:
        src = open(os.path.join(ROOT, rel), encoding="utf-8").read()
        tree = ast.parse(src)
        bare = [n.lineno for n in ast.walk(tree)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                and n.func.id == "print"
                and not any(k.arg == "file" for k in n.keywords)]
        assert bare == [], f"{rel}: prints without file=: {bare}"


def test_no_cli_print_hardcodes_stdout():
    """file=sys.stdout would silently break the -o - channel again."""
    for rel in CLI_MODULES:
        src = open(os.path.join(ROOT, rel), encoding="utf-8").read()
        tree = ast.parse(src)
        for n in ast.walk(tree):
            if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                    and n.func.id == "print"):
                continue
            for k in n.keywords:
                if k.arg != "file":
                    continue
                assert not (isinstance(k.value, ast.Attribute)
                            and isinstance(k.value.value, ast.Name)
                            and k.value.value.id == "sys"
                            and k.value.attr == "stdout"), \
                    f"{rel}:{n.lineno} hardcodes sys.stdout"


def test_human_stream_is_scoped_to_one_call():
    from xssentinel import cli_output
    sentinel = io.StringIO()
    cli_output.set_human_stream(sentinel)
    assert cli_output.human() is sentinel
    cli_output.reset_human_stream()
    assert cli_output.human() is sys.stdout
    # main() resets it even when argparse exits early (version action raises
    # SystemExit, which still runs main()'s finally).
    from xssentinel.__main__ import main
    cli_output.set_human_stream(sentinel)
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert cli_output.human() is sys.stdout


# ---------------------------------------------------------------------------
# D. config input contract
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("enc,bom", [
    ("utf-8", b"\xef\xbb\xbf"), ("utf-16", b""), ("gbk", b""),
], ids=["utf8-bom", "utf16", "gbk"])
def test_config_accepts_windows_encodings(target, tmp_path, enc, bom):
    p = _write_cfg(tmp_path, "cfg_%s.json" % enc,
                   {"url": target, "format": "json", "output": "-",
                    "max_payloads": 1, "max_transforms": 1,
                    "dom_engine": "static", "note": "\u4e2d\u6587"},
                   enc, bom)
    r = _cli(["--config", str(p)])
    assert r.returncode == 0, r.stderr[-400:]
    assert len(_frames(r.stdout)) == 1


@pytest.mark.parametrize("data,needle", [
    (b"\xff\xfe\x00\xd8", "UTF-16"),   # BOM + lone high surrogate
    (b"{oops", "invalid JSON"),        # decodes fine, is not JSON
    (b"{\xff\xfe not json", "not valid"),  # undecodable in every encoding
], ids=["undecodable-utf16", "bad-json", "undecodable-all"])
def test_bad_config_is_an_honest_usage_error(tmp_path, data, needle):
    p = tmp_path / "bad.json"
    p.write_bytes(data)
    r = _cli(["--config", str(p)])
    assert r.returncode == 2
    assert needle.encode() in r.stderr
    assert b"Traceback" not in r.stderr
    # The pre-change shape: an empty Config blamed the operator.
    assert b"No target specified" not in r.stderr


def test_missing_config_and_non_object_are_honest(tmp_path):
    r = _cli(["--config", str(tmp_path / "nope.json")])
    assert r.returncode == 2 and b"not found" in r.stderr
    p = _write_cfg(tmp_path, "list.json", [], "utf-8")
    r = _cli(["--config", str(p)])
    assert r.returncode == 2 and b"JSON object" in r.stderr


def test_config_options_are_not_shadowed_by_argparse_defaults(target,
                                                              tmp_path):
    """format/timeout/output used to be overwritten by CLI defaults."""
    p = _write_cfg(tmp_path, "full.json",
                   {"url": target, "format": "json", "output": "-",
                    "timeout": 42, "max_payloads": 1, "max_transforms": 1,
                    "dom_engine": "static"}, "utf-8")
    r = _cli(["--config", str(p)])
    assert r.returncode == 0, r.stderr[-400:]
    assert len(_frames(r.stdout)) == 1      # JSON, not the default HTML
    assert b"No target specified" not in r.stderr


def test_explicit_cli_still_beats_config(target, tmp_path):
    p = _write_cfg(tmp_path, "cfg.json",
                   {"url": target, "format": "html", "output": "-",
                    "max_payloads": 1, "dom_engine": "static"}, "utf-8")
    r = _cli(["--config", str(p), "-f", "json", *COMMON])
    assert r.returncode == 0, r.stderr[-400:]
    assert len(_frames(r.stdout)) == 1


def test_config_driven_stdout_channel_binds_human_stream(target, tmp_path):
    p = _write_cfg(tmp_path, "dash.json",
                   {"url": target, "format": "json", "output": "-",
                    "max_payloads": 1, "max_transforms": 1,
                    "dom_engine": "static", "login_token": "T"}, "utf-8")
    r = _cli(["--config", str(p)])
    assert r.returncode == 0, r.stderr[-400:]
    assert len(_frames(r.stdout)) == 1
    assert b"[+] Done" in r.stderr


def test_config_text_inputs_share_the_batch_decoder(tmp_path):
    """BOM / GB18030 lists referenced BY a config must not be dropped."""
    from xssentinel.core.config import Config
    urls = tmp_path / "urls.txt"
    urls.write_bytes(b"\xef\xbb\xbf# c\r\nhttp://127.0.0.1:1/\r\n")
    payloads = tmp_path / "payloads.txt"
    payloads.write_bytes("# p\n\u4e2d\u6587<p>\n".encode("gbk"))
    cfg = Config({"batch_file": str(urls),
                  "custom_payloads": str(payloads)})
    assert cfg.batch_urls == ["http://127.0.0.1:1/"]
    assert cfg.custom_payloads == ["\u4e2d\u6587<p>"]


def test_one_decoder_for_batch_and_config():
    from xssentinel import cli_output
    from xssentinel.cli_runner import _decode_batch_bytes
    for raw in (b"plain", b"\xef\xbb\xbfbom",
                "\u4e2d\u6587".encode("gbk"),
                "x".encode("utf-16")):
        assert _decode_batch_bytes(raw) == cli_output.decode_input_bytes(raw)


# ---------------------------------------------------------------------------
# E. stdout format gate (before any scan work)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("args", [
    ["-f", "nuclei"],
    ["--batch-stdin", "-f", "nuclei"],
], ids=["single", "batch"])
def test_nuclei_cannot_be_written_to_stdout(target, args):
    stdin = (target + "\n").encode() if "--batch-stdin" in args else None
    r = _cli([*(["-u", target] if "-u" not in args and
                 "--batch-stdin" not in args else []), *args, "-o", "-",
              *COMMON], stdin=stdin)
    assert r.returncode == 2, r.stderr[-300:]
    assert r.stdout == b""
    assert b"Traceback" not in r.stderr
    assert b"Report write failed" not in r.stderr
    assert b"Exit 3" not in r.stderr
    assert b"Scan complete" not in r.stderr   # no scan was started


# ---------------------------------------------------------------------------
# F. report channel itself
# ---------------------------------------------------------------------------

def test_text_only_stdout_fallback_is_codepage_safe():
    """Injected StringIO / cp936 text stream must not drop a Chinese frame.

    The sink here deliberately has NO ``.buffer`` (a TextIOWrapper does,
    which would take the byte path and hide the fallback).  Its write()
    encodes to cp936, so a non-ASCII frame would raise UnicodeEncodeError.
    """
    from xssentinel.cli_output import write_report_frame

    class Cp936Text:
        def __init__(self):
            self._buf = io.BytesIO()

        def write(self, s):
            self._buf.write(s.encode("cp936"))
            return len(s)

        def flush(self):
            pass

        def getvalue(self):
            return self._buf.getvalue().decode("cp936")

    frame = json.dumps({"target": "\u4e2d\u6587", "findings": []},
                       ensure_ascii=False)
    for stream in (io.StringIO(), Cp936Text()):
        write_report_frame(frame, "json", stream=stream)
        text = stream.getvalue()
        assert "\\u4e2d" in text or "\u4e2d" in text
        parsed = json.loads(text)
        assert parsed["target"] == "\u4e2d\u6587"


def test_broken_pipe_ends_cleanly_without_a_false_incomplete_verdict(target):
    """A consumer that leaves is not 20 failed scans (exit 3)."""
    feed = ("\n".join(target + "&i=%d" % i for i in range(20)) +
            "\n").encode("utf-8")
    env = {**os.environ, "NO_PROXY": "127.0.0.1,localhost",
           "no_proxy": "127.0.0.1,localhost"}
    p = subprocess.Popen(
        [PY, "-m", "xssentinel", "--batch-stdin", "-o", "-", "-f", "json",
         *COMMON], cwd=ROOT, env=env,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    p.stdin.write(feed)
    p.stdin.close()
    assert p.stdout.read(1)                 # first frame consumed
    p.stdout.close()                       # consumer leaves
    try:
        p.wait(timeout=180)
    except subprocess.TimeoutExpired:
        p.kill()
        raise
    err = p.stderr.read().decode("utf-8", "replace")
    p.stderr.close()
    assert p.returncode == 0, (p.returncode, err[-500:])
    assert "consumer closed" in err
    assert "Exit 3" not in err
    assert "Traceback" not in err
    assert "Exception ignored" not in err
