# -*- coding: utf-8 -*-
"""Phase 394: the batch `-o FILE` contract, pinned after a false alarm.

Phase 392 recorded ``--batch -o FILE`` as a "silent no-output" defect
candidate: rc=0, no FILE, no stdout.  That was a probe error, not a defect --
the Phase 88 design ("Report path (or directory for --batch)") sends a
path-with-extension to per-target reports in the FILE's PARENT directory:
``dev/_x/report.json`` yields ``dev/_x/http_127.0.0.1_PORT_a.json`` etc.
The two ``http_127.0.0.1_18946_*.json`` files the 392 round later deleted as
"residue" WERE those reports.  Candidate ① is retracted; this test pins the
design so the next reader does not re-derive the same wrong conclusion.
"""
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

PY = sys.executable


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><body>batchout</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def test_batch_o_file_writes_per_target_reports_into_parent_dir(tmp_path):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        urls = tmp_path / "urls.txt"
        urls.write_text(f"http://127.0.0.1:{port}/a\n"
                        f"http://127.0.0.1:{port}/b\n", encoding="utf-8")
        out_file = tmp_path / "sub" / "report.json"
        out_file.parent.mkdir()
        proc = subprocess.run(
            [PY, "-m", "xssentinel", "--batch", str(urls),
             "-f", "json", "-o", str(out_file),
             "--progress", "none", "--log-level", "error"],
            cwd=_ROOT, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=300)
        assert proc.returncode == 0
        # the operator-named FILE is never created...
        assert not out_file.exists()
        # ...but the per-target reports land in its parent directory
        reports = [f for f in os.listdir(out_file.parent)
                   if f.endswith(".json")]
        assert len(reports) == 2, reports
        for name in reports:
            with open(out_file.parent / name, encoding="utf-8") as fh:
                data = json.load(fh)
            assert data.get("target", "").startswith("http://127.0.0.1:")
    finally:
        srv.shutdown()
