"""Phase 349: --batch-workers contract + e2e guards.

What is pinned here and why
---------------------------
``--batch-workers N`` lets the sync batch loop scan several targets
concurrently (default 1 = sequential, byte-identical to previous releases).
A change here can fail in four shapes, and this file closes each:

  * a malformed N must fail loudly *before any traffic* (parse contract) --
    a silently degraded value would make ``--batch-workers 4`` a no-op that
    still looks green.  Note ``0`` specifically: an ``or 1`` normalization
    would swallow it, so the falsy value is part of the contract;
  * parallel targets must produce the same per-target *verdicts* as the
    sequential driver (same finding keys per target file) -- parallelism
    may reorder prints, never conclusions;
  * the parallel driver must actually be the thing that ran.  The verdict
    comparison alone is the classic "tested the representation, not the
    subject": a broken ``_use_parallel`` condition would silently run
    sequential, pass every verdict check, and nobody would know.  So the
    parallel run must also print the driver banner;
  * failure isolation must survive concurrency: a target whose scan raises
    fails alone (exit 3, listed in the summary), while the other targets'
    findings still reach the run total.  Mirrors the Phase 25-2/176k
    in-process harness in test_p25.py -- a connection-refused target does
    NOT exercise this path by design (the Requester tolerates it), so a
    real subprocess cannot reach the crash isolation branch honestly.

Wall-clock speed is deliberately NOT asserted here: scan timing noise on
this project's loopback reaches ±25x (see benchmark/layer_profile notes),
so the A/B numbers live in the phase log, not in a flaky gate.
"""
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import MagicMock, patch
from urllib.parse import urlparse, parse_qs

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class _H(BaseHTTPRequestHandler):
    def do_GET(self):
        import html as _html
        u = urlparse(self.path)
        q = parse_qs(u.query).get("q", [""])[0]
        if u.path == "/echo":
            body = f"<html><body><div>search: {q}</div></body></html>"
        elif u.path == "/attr":
            body = f'<html><body><a title="{q}">x</a></body></html>'
        elif u.path == "/safe":
            body = (f"<html><body><div>search: {_html.escape(q)}</div>"
                    f"</body></html>")
        else:
            self.send_response(404)
            self.end_headers()
            return
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def live_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


def _run_cli(args, timeout=240):
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run(
        [sys.executable, "-m", "xssentinel"] + args,
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=timeout,
        encoding="utf-8", errors="replace")
    # A child killed by the host security product can surface None streams
    # (measured 2026-11-10: TypeError on the concat below, twice in a row).
    # "" keeps the contract checks string-based instead of raising.
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


# --------------------------------------------------------------------------
# Parse contract: malformed N fails loudly before any traffic
# --------------------------------------------------------------------------

class TestParseContract:
    @pytest.mark.parametrize("bad", ["0", "-2", "99"])
    def test_out_of_range_fails_loudly(self, bad):
        code, out = _run_cli(["--batch-workers", bad, "-u",
                              "http://127.0.0.1:1/x"])
        assert code != 0
        assert "integer in [1, 64]" in out

    def test_non_integer_is_argparse_error(self):
        code, out = _run_cli(["--batch-workers", "abc", "-u",
                              "http://127.0.0.1:1/x"])
        assert code != 0
        assert "invalid int value" in out

    def test_valid_value_accepted_before_traffic(self):
        # 1 is the default; an explicit 2 must pass validation (the scan
        # against a dead port then fails on egress, not on the flag).
        code, out = _run_cli(["--batch-workers", "2", "-u",
                              "http://127.0.0.1:1/x", "--timeout", "3"])
        assert "integer in [1, 64]" not in out


# --------------------------------------------------------------------------
# E2E (real subprocess): parallel verdicts == sequential verdicts
# --------------------------------------------------------------------------

def _finding_keys(report_path):
    with open(report_path, encoding="utf-8") as fh:
        data = json.load(fh)
    return sorted(
        (f.get("type"), f.get("url"), f.get("param"), f.get("context"),
         f.get("severity"))
        for f in data.get("findings", []))


class TestParallelBatchE2E:
    URLS = ("/echo?q=probe", "/attr?q=probe", "/safe?q=probe")

    def test_sequential_and_parallel_verdicts_identical(self, live_server,
                                                        tmp_path):
        code1, out1, dir1 = self._batch(tmp_path, live_server, "seq", [])
        assert code1 == 0, out1
        code3, out3, dir3 = self._batch(tmp_path, live_server, "par",
                                        ["--batch-workers", "3"])
        assert code3 == 0, out3
        # The parallel driver must be the thing that ran -- a silent
        # sequential fallback would make every other assertion vacuous.
        assert "--batch-workers 3: targets run concurrently" in out3
        files = sorted(f for f in os.listdir(dir1) if f.endswith(".json"))
        assert len(files) == 3, files
        assert sorted(f for f in os.listdir(dir3)
                      if f.endswith(".json")) == files
        for name in files:
            assert _finding_keys(os.path.join(dir1, name)) == \
                _finding_keys(os.path.join(dir3, name)), name
        for out in (out1, out3):
            assert "Batch complete: 3 target(s) (3 ok, 0 failed)" in out
            assert "2 total finding(s)" in out

    @staticmethod
    def _batch(tmp_path, live_server, name, extra):
        urls_f = tmp_path / f"urls_{name}.txt"
        urls_f.write_text(
            "".join(f"{live_server}{p}\n" for p in TestParallelBatchE2E.URLS),
            encoding="utf-8")
        out_dir = str(tmp_path / name)
        code, out = _run_cli(
            ["--batch", str(urls_f), "-o", out_dir, "-f", "json",
             "--timeout", "5", "--max-payloads", "3", "--max-transforms",
             "2", "--threads", "2", "--progress", "none"] + extra)
        return code, out, out_dir


# --------------------------------------------------------------------------
# Failure isolation under concurrency (in-process, mirrors test_p25.py)
# --------------------------------------------------------------------------

class TestFailureIsolationParallel:
    def test_crashing_target_fails_alone(self, tmp_path, capsys):
        """Phase 349: one target raising must fail alone under workers=3.

        The sequential branch of this contract is pinned by test_p25.py
        (Phase 25-2/176k).  The parallel branch has its own ways to lose
        the same contract: an escaping exception in one future must not
        unwind the pool, and the surviving targets' findings must still
        reach the run total through _merge_target.
        """
        from xssentinel import __main__ as cli

        batch = tmp_path / "urls.txt"
        urls = [f"http://127.0.0.1:1/{n}" for n in ("a", "b", "c")]
        batch.write_text("".join(u + "\n" for u in urls), encoding="utf-8")
        out_dir = str(tmp_path / "reports")
        os.makedirs(out_dir, exist_ok=True)

        calls = []

        def fake_run_scan(args, url, requester, oob, progress, checkpoint,
                          auth_state=None):
            calls.append(url)
            if url == urls[1]:
                raise RuntimeError("simulated scan failure")
            ms = MagicMock()
            f = MagicMock()
            f.get.return_value = "high"
            ms.findings = [f, f]  # two findings per surviving target
            ms.waf_name = None
            return ms

        argv = ["--batch", str(batch), "-o", out_dir, "-f", "json",
                "--batch-workers", "3", "--progress", "none"]
        with patch.object(cli, "_run_scan", side_effect=fake_run_scan), \
             patch.object(cli, "_write_report",
                          side_effect=lambda *a, **k: "r.json"):
            rc = cli.main(argv)
        captured = capsys.readouterr()
        # All three targets were attempted -- the pool did not unwind.
        assert sorted(calls) == sorted(urls), calls
        assert rc == 3, f"a lost target must not exit 0 (got {rc})"
        assert "Scan incomplete" in captured.err, captured.err
        assert "1 failed" in captured.out, captured.out
        assert "Failed targets" in captured.out
        assert urls[1] in captured.out
        # The surviving targets' findings still reached the total (2 x 2).
        assert "4 total finding(s)" in captured.out, captured.out

    def test_crashing_target_marked_in_checkpoint(self, tmp_path, capsys):
        """A future-exception target is recorded in the checkpoint so
        --resume does not re-scan what crashed the scanner (same contract
        as the sequential in-body handler)."""
        from xssentinel import __main__ as cli
        from xssentinel.core.checkpoint import Checkpoint

        batch = tmp_path / "urls.txt"
        urls = [f"http://127.0.0.1:1/{n}" for n in ("a", "b")]
        batch.write_text("".join(u + "\n" for u in urls), encoding="utf-8")
        ckpt_path = str(tmp_path / "cp.json")

        def fake_run_scan(args, url, requester, oob, progress, checkpoint,
                          auth_state=None):
            if url == urls[0]:
                raise RuntimeError("simulated scan failure")
            ms = MagicMock()
            ms.findings = []
            ms.waf_name = None
            return ms

        argv = ["--batch", str(batch), "-o", str(tmp_path / "reports"),
                "-f", "json", "--batch-workers", "2", "--progress", "none"]
        with patch.object(cli, "_run_scan", side_effect=fake_run_scan), \
             patch.object(cli, "_write_report",
                          side_effect=lambda *a, **k: "r.json"):
            rc = cli.main(argv + ["--checkpoint", ckpt_path])
        assert rc == 3
        loaded = Checkpoint.load(ckpt_path)
        assert loaded is not None
        assert urls[0] in loaded._scanned, (
            "a crashed target must be checkpoint-marked under parallel")
