# -*- coding: utf-8 -*-
"""Phase 326: private report artifacts + duplicate CSP headers.

Two P2 items from docs/TRENDING_20261026.md:

  * **report 0600** -- report/PoC artifacts carry target URLs, parameters
    and live payloads; on a shared host they must not be world-readable.
    ``core.fsutil.secure_write_text`` chmods 0600 on POSIX (Windows has no
    POSIX modes; ACLs are the operator's).
  * **duplicate CSP headers** -- measured here: ``requests`` hands a client
    ONE comma-joined value (``"script-src 'self' 'unsafe-inline', script-src
    'self'"``) for two header lines, and the old ``policies()`` read it as a
    single policy.  The strict second policy vanished and the page was
    judged bypassable -- the FALSE-POSITIVE direction.  ``policies()`` now
    splits the joined value back into its policies (conservatively: a comma
    only starts a policy when a KNOWN directive name follows).
"""
from __future__ import annotations

import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import csp                                  # noqa: E402
from xssentinel.core import fsutil                               # noqa: E402

BYPASS = "script-src 'self' 'unsafe-inline'"
STRICT = "script-src 'self'"
JOINED = BYPASS + ", " + STRICT


# ---------------------------------------------------------------------------
# 1. private artifact writes
# ---------------------------------------------------------------------------
def test_secure_write_text_chmods_0600_on_posix(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.setattr(os, "chmod",
                        lambda p, m: calls.append((str(p), m)))
    path = tmp_path / "report.html"
    out = fsutil.secure_write_text(str(path), "<html>a</html>")
    assert out == str(path)
    assert path.read_text(encoding="utf-8") == "<html>a</html>"
    assert calls and calls[0][1] == 0o600, calls


def test_secure_write_text_is_a_noop_chmod_on_windows(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(os, "chmod",
                        lambda p, m: calls.append((str(p), m)))
    path = tmp_path / "report.json"
    fsutil.secure_write_text(str(path), "{}")
    assert path.read_text(encoding="utf-8") == "{}"
    assert calls == [], "Windows has no POSIX mode bits; chmod must be skipped"


def test_chmod_private_survives_a_missing_file(monkeypatch):
    monkeypatch.setattr(os, "name", "posix")
    # a chmod that raises must not blow up a scan that already wrote its data
    monkeypatch.setattr(os, "chmod",
                        lambda p, m: (_ for _ in ()).throw(OSError("nope")))
    fsutil.chmod_private("does-not-exist.json")      # must not raise


def test_cli_report_writer_uses_the_private_write(tmp_path, monkeypatch):
    """``_write_report`` (the CLI's single-target writer) must go through
    ``secure_write_text`` -- a plain ``open()`` here would silently keep
    the umask's default permissions."""
    from xssentinel import cli_runner
    calls = []
    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.setattr(os, "chmod",
                        lambda p, m: calls.append((str(p), m)))

    class _Scanner:
        findings = []
        requests_made = 0
        waf_name = None
        req = None
        coverage = None
        verbose = False

    out = tmp_path / "r.html"
    cli_runner._write_report(_Scanner(), "http://t/", str(out), "html")
    assert out.exists()
    assert calls and calls[0][1] == 0o600, calls


def test_poc_and_nuclei_artifacts_are_private(tmp_path, monkeypatch):
    from xssentinel.core import report as rpt
    calls = []
    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.setattr(os, "chmod",
                        lambda p, m: calls.append((str(p), m)))

    finding = {"type": "reflected", "severity": "high",
               "poc": {"html": "<html>x</html>", "curl": "curl x"}}
    poc_paths = rpt.write_poc_dir([finding], "http://t/", {"generated": "now"},
                                  str(tmp_path / "poc"))
    nuc_paths = rpt.write_nuclei_dir([finding], "http://t/", {"generated": "now"},
                                     str(tmp_path / "nuclei"))
    assert poc_paths and nuc_paths
    modes = {m for _p, m in calls}
    assert modes == {0o600}, modes
    assert len(calls) == len(poc_paths) + len(nuc_paths), (calls, poc_paths,
                                                           nuc_paths)


# ---------------------------------------------------------------------------
# 2. duplicate CSP headers (the measured false positive)
# ---------------------------------------------------------------------------
def test_joined_duplicate_header_splits_back_into_policies():
    pol = csp.policies({"Content-Security-Policy": JOINED}, "")
    assert pol["enforcing"] == [BYPASS, STRICT], pol
    # the browser enforces BOTH: inline is blocked, the page is NOT bypassable
    assert csp.blocks_family(pol, "elem") is True


def test_a_comma_inside_a_source_expression_is_not_a_policy_boundary():
    policy = "script-src https://cdn.example.com/a,b.js"
    pol = csp.policies({"Content-Security-Policy": policy}, "")
    assert pol["enforcing"] == [policy], pol


def test_single_policy_is_untouched():
    pol = csp.policies({"Content-Security-Policy": BYPASS}, "")
    assert pol["enforcing"] == [BYPASS]


def test_list_values_are_accepted():
    pol = csp.policies({"Content-Security-Policy": [BYPASS, STRICT]}, "")
    assert pol["enforcing"] == [BYPASS, STRICT], pol


def test_report_only_joined_values_split_too():
    pol = csp.policies(
        {"Content-Security-Policy-Report-Only": JOINED}, "")
    assert pol["report_only"] == [BYPASS, STRICT], pol
    assert pol["enforcing"] == []


def test_verifier_gate_reads_the_joined_form_as_blocked():
    from xssentinel.core.verifier import _csp_blocks_inline
    assert _csp_blocks_inline({"Content-Security-Policy": JOINED}) is True


def test_scan_layer_does_not_claim_a_bypass_over_a_joined_strict_policy():
    """End to end of the finding layer: bypassable + strict in ONE joined
    value must NOT produce a ``csp_bypass`` finding (not all enforcing
    policies are bypassable)."""
    from xssentinel.core.scanner_layers import AdvancedLayerMixin

    class _Cov:
        def __init__(self):
            self.layers = []

        def touch_layer(self, url, layer, method, detail=None):
            self.layers.append(layer)

        def record_finding(self, url, method):
            pass

        def record_request(self, url, method):
            pass

    class _Resp:
        def __init__(self):
            self.headers = {"Content-Security-Policy": JOINED}
            self.text = "<html><body>x</body></html>"

    class _Req:
        def __init__(self, resp):
            self._resp = resp

        def get(self, url):
            return self._resp

    class _Scanner:
        def __init__(self):
            self.coverage = _Cov()
            self.findings = []
            self.verbose = False
            import threading as _t
            self._lock = _t.RLock()

        def _bump(self):
            pass

    sc = _Scanner()
    resp = _Resp()
    AdvancedLayerMixin._scan_csp(sc, _Req(resp), "http://t/x")
    got = [f.data if hasattr(f, "data") else f for f in sc.findings]
    assert got == [], got


# ---------------------------------------------------------------------------
# 3. the real wire form (requests + loopback server)
# ---------------------------------------------------------------------------
class _DupCspHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><body>hi</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Security-Policy", BYPASS)
        self.send_header("Content-Security-Policy", STRICT)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def test_requests_joined_header_is_judged_as_blocked_end_to_end():
    from xssentinel.core.requester import Requester

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _DupCspHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    url = "http://127.0.0.1:%d/" % srv.server_address[1]
    try:
        resp = Requester(timeout=5).get(url)
        joined = resp.headers.get("Content-Security-Policy")
        assert "," in joined, joined
        pol = csp.policies(dict(resp.headers), "")
        assert csp.blocks_family(pol, "elem") is True, (joined, pol)
        # raw getlist view agrees
        pol_raw = csp.policies(
            {"Content-Security-Policy":
             resp.raw.headers.getlist("Content-Security-Policy")}, "")
        assert csp.blocks_family(pol_raw, "elem") is True
    finally:
        srv.shutdown()
        srv.server_close()
