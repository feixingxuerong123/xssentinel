"""Phase 350: the threads>1 branch of scan_target must do the checkpoint
bookkeeping the serial branch always did.

The bug this pins
-----------------
``Scanner.scan_target`` had two branches: the serial loop marked every
scanned endpoint in the checkpoint (mark_scanned + counters + save) and
called ``progress.on_endpoint_done``; the parallel branch (threads>1,
multiple endpoints) called ``f.result()`` and moved on.  A ``--checkpoint``
+ ``--threads 4`` run therefore wrote a resume file that believed nothing
had been scanned -- resume re-scanned everything, silently.  This file
drives the REAL scan_target entry (real HTTP against a local server, real
ThreadPoolExecutor) and pins both branches:

  * parallel (threads=4): every endpoint lands in the on-disk checkpoint,
    requests_made is persisted, and on_endpoint_done fires per endpoint;
  * serial (threads=1): unchanged serial behavior still holds (the fix
    must not have broken the branch it copied from).

The findings *copy* in the checkpoint (add_findings) is deliberately not
pinned for the parallel branch: interleaving makes per-endpoint finding
slices unattributable, so the parallel branch records scanned URLs and
counters only (resume reads scanned_urls; nothing consumes the findings
copy downstream).
"""
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

from xssentinel.core.checkpoint import Checkpoint  # noqa: E402


class _H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><body><div>search: probe</div></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _ProgressRecorder:
    """Stand-in for ConsoleProgress that records per-endpoint callbacks."""

    def __init__(self):
        self.started = None
        self.endpoint_starts = []
        self.endpoint_dones = []
        self.done = None

    def on_start(self, total):
        self.started = total

    def on_endpoint_start(self, url, i, total):
        self.endpoint_starts.append(url)

    def on_endpoint_done(self, url, findings):
        self.endpoint_dones.append((url, findings))

    def on_request(self):
        pass

    def on_done(self, findings, requests):
        self.done = (findings, requests)


@pytest.fixture(scope="module")
def base():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


def _scan_with_checkpoint(base, threads, tmp_path):
    from xssentinel.core.requester import Requester
    from xssentinel.core.scanner import Scanner

    ckpt_path = str(tmp_path / f"cp_t{threads}.json")
    ckpt = Checkpoint(ckpt_path, base)
    progress = _ProgressRecorder()
    sc = Scanner(requester=Requester(timeout=8), max_payloads=3,
                 max_transforms=2, dom_engine="static", threads=threads,
                 # crawl=True is what makes scan_target() reach the crawl
                 # seam at all: without it `endpoints` stays [target] and the
                 # stub below is dead code (measured: only /echo was ever
                 # marked).  crawl_engine="static" is the second half -- the
                 # default "auto" dispatches to _crawl_spa(), so patching
                 # _crawl alone would still fire nothing (same measurement).
                 crawl=True, crawl_engine="static",
                 progress=progress, checkpoint=ckpt, verbose=False)
    endpoints = [(f"{base}/{p}", "GET", {"q": "probe"}, {})
                 for p in ("echo", "attr", "safe")]
    # The crawl seam is the documented multi-endpoint entry into
    # scan_target; everything past it (endpoint parallelism, checkpoint
    # bookkeeping, progress callbacks) is the real pipeline.
    sc._crawl = lambda url: list(endpoints)
    sc.scan_target(f"{base}/echo", method="GET", params={"q": "probe"},
                   data={}, oob_collect=False)
    return sc, ckpt, progress, ckpt_path


class TestParallelCheckpointBookkeeping:
    def test_parallel_marks_every_endpoint(self, base, tmp_path):
        sc, ckpt, progress, ckpt_path = _scan_with_checkpoint(
            base, threads=4, tmp_path=tmp_path)
        for p in ("echo", "attr", "safe"):
            url = f"{base}/{p}"
            assert ckpt.is_scanned(url), \
                f"threads=4 left {url} out of the checkpoint"
        # The in-memory object must also have been persisted to disk --
        # that is the file --resume reads.
        loaded = Checkpoint.load(ckpt_path)
        assert loaded is not None
        for p in ("echo", "attr", "safe"):
            assert f"{base}/{p}" in loaded._scanned
        assert loaded.requests_made > 0
        assert loaded.requests_made == sc.requests_made

    def test_parallel_calls_on_endpoint_done_per_endpoint(self, base,
                                                          tmp_path):
        _, _, progress, _ = _scan_with_checkpoint(base, threads=4,
                                                  tmp_path=tmp_path)
        done_urls = [u for u, _ in progress.endpoint_dones]
        assert sorted(done_urls) == sorted(f"{base}/{p}"
                                           for p in ("echo", "attr", "safe"))

    def test_serial_behavior_unchanged(self, base, tmp_path):
        sc, ckpt, progress, ckpt_path = _scan_with_checkpoint(
            base, threads=1, tmp_path=tmp_path)
        for p in ("echo", "attr", "safe"):
            url = f"{base}/{p}"
            assert ckpt.is_scanned(url), \
                f"serial branch regressed: {url} missing from checkpoint"
        loaded = Checkpoint.load(ckpt_path)
        assert loaded is not None
        assert loaded.requests_made > 0
        done_urls = [u for u, _ in progress.endpoint_dones]
        assert sorted(done_urls) == sorted(f"{base}/{p}"
                                           for p in ("echo", "attr", "safe"))
