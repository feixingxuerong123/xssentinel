"""Phase 322: nuclei dast template bridge + the revived custom-payload
channel.

Three layers:
  * pure extraction/merge tests against fixture YAML (no network);
  * the sync dead-wire guard: a custom payload MUST actually reach the
    wire and be able to confirm (pre-Phase 322 the channel was stored on
    the Scanner and consumed by nothing -- CLI flag, zero effect);
  * async parity: the same channel tags the coverage row 'custom'.
"""
from __future__ import annotations

import asyncio
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from xssentinel.core.nuclei_import import (NucleiImportError,
                                           extract_payloads,
                                           merge_into_custom)

_XSS_TEMPLATE = """id: generic-xss-fuzz
info:
  name: Generic XSS Fuzz
  author: someone
  severity: high
  tags: xss,dast,fuzz
http:
  - payloads:
      xss:
        - "<script>alert(1)</script>"
        - "<svg onload=alert(1)>"
    fuzzing:
      - parts:
          - query
        type: replace
        fuzz:
          - "{{xss}}"
    matchers:
      - type: dsl
        dsl:
          - "status_code == 200"
"""

_CMDI_TEMPLATE = """id: cmdi-probe
info:
  name: OS Command Injection
  severity: critical
  tags: cmdi,rce,dast
http:
  - payloads:
      cmd:
        - "cat /etc/passwd"
    fuzzing:
      - parts: [query]
        fuzz: ["{{cmd}}"]
"""

_OOB_TEMPLATE = """id: xss-oob
info:
  name: XSS with OOB detection
  severity: high
  tags: xss,dast
http:
  - payloads:
      p:
        - "<script src='//{{interactsh-url}}/x.js'></script>"
    fuzzing:
      - parts: [query]
        fuzz: ["{{p}}"]
"""


def _write_tpl(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


class TestExtraction:
    def test_xss_tagged_literals_extracted_with_provenance(self, tmp_path):
        path = _write_tpl(tmp_path, "xss.yaml", _XSS_TEMPLATE)
        out = extract_payloads(path)
        pls = [r["payload"] for r in out["payloads"]]
        assert "<script>alert(1)</script>" in pls
        assert "<svg onload=alert(1)>" in pls
        rec = out["payloads"][0]
        assert rec["template"] == "generic-xss-fuzz"
        assert "xss" in rec["tags"]
        assert rec["severity"] == "high"
        # the fuzz {{xss}} cross-reference resolves to the named
        # payloads already yielded -- it must NOT double-count
        assert out["skipped"]["duplicates"] == 0

    def test_non_xss_template_skipped_and_counted(self, tmp_path):
        path = _write_tpl(tmp_path, "cmdi.yaml", _CMDI_TEMPLATE)
        out = extract_payloads(path)
        assert out["payloads"] == []
        assert out["skipped"]["not_xss"] >= 1

    def test_interactsh_payloads_skipped_honestly(self, tmp_path):
        path = _write_tpl(tmp_path, "oob.yaml", _OOB_TEMPLATE)
        out = extract_payloads(path)
        assert out["payloads"] == []
        assert out["skipped"]["oob"] >= 1, (
            "OOB payloads depend on interactsh matchers -- half-honoring "
            "them in the reflection loop would mistranslate the template")

    def test_xss_shape_without_tag_still_relevant(self, tmp_path):
        tpl = _XSS_TEMPLATE.replace("tags: xss,dast,fuzz", "tags: dast,fuzz")
        path = _write_tpl(tmp_path, "notag.yaml", tpl)
        out = extract_payloads(path)
        assert len(out["payloads"]) == 2

    def test_xss_tagged_path_strings_are_not_payloads(self, tmp_path):
        """Measured on the real local corpus: an XSS-tagged CVE template
        (CVE-2021-24522) carries PATHS in its payloads block -- the tag
        must not make "/wp-login" a payload."""
        tpl = _XSS_TEMPLATE.replace(
            '"<script>alert(1)</script>"',
            '"/wp-login.php"').replace(
            '"<svg onload=alert(1)>"', '"/"')
        path = _write_tpl(tmp_path, "cvepath.yaml", tpl)
        out = extract_payloads(path)
        assert out["payloads"] == []
        assert out["skipped"]["not_xss"] >= 2

    def test_dsl_placeholder_payloads_skipped(self, tmp_path):
        """{{url_encode(...)}} / {{first}} are nuclei DSL, not literals
        (measured: they were the only survivors of the first local-dast
        extraction attempt)."""
        tpl = _XSS_TEMPLATE.replace(
            '"<script>alert(1)</script>"',
            '"{{url_encode(reflection)}}"').replace(
            '"<svg onload=alert(1)>"', "'{{first}}-breakout'")
        path = _write_tpl(tmp_path, "dsl.yaml", tpl)
        out = extract_payloads(path)
        assert out["payloads"] == []
        assert out["skipped"]["placeholders"] >= 2

    def test_bad_yaml_file_counted_not_raised(self, tmp_path):
        path = _write_tpl(tmp_path, "broken.yaml", "{ not: [valid ::: yaml")
        out = extract_payloads(path)
        assert out["skipped"]["bad_files"] == 1

    def test_directory_walk_and_dedupe(self, tmp_path):
        d = tmp_path / "tpls"
        d.mkdir()
        _write_tpl(d, "a.yaml", _XSS_TEMPLATE)
        _write_tpl(d, "b.yaml", _XSS_TEMPLATE.replace(
            "id: generic-xss-fuzz", "id: second-template"))
        out = extract_payloads(str(d))
        assert len(out["payloads"]) == 2
        assert out["skipped"]["duplicates"] == 2
        assert out["templates"] == 2

    def test_limit_bounds_the_import(self, tmp_path):
        path = _write_tpl(tmp_path, "xss.yaml", _XSS_TEMPLATE)
        out = extract_payloads(path, limit=1)
        assert len(out["payloads"]) == 1

    def test_missing_path_is_explicit(self, tmp_path):
        with pytest.raises(NucleiImportError):
            extract_payloads(str(tmp_path / "nope.yaml"))


class TestMerge:
    def test_operator_wordlist_outranks_imports(self):
        extracted = {"payloads": [{"payload": "<b>x</b>"}]}
        out = merge_into_custom(["<i>op</i>"], extracted)
        assert out[0] == "<i>op</i>"
        assert "<b>x</b>" in out

    def test_dedupe_and_limit(self):
        extracted = {"payloads": [{"payload": "  <b>  x  </b> "}]}
        out = merge_into_custom(["<b>x</b>"], extracted, limit=1)
        assert out == ["<b>x</b>"]


# ---------------------------------------------------------------------------
# Dead-wire guards: the custom channel must reach the WIRE
# ---------------------------------------------------------------------------

_CUSTOM = "<xssentinel320 onpointerover=alert(1)>"


class _RawEchoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        value = (parse_qs(urlsplit(self.path).query).get("q") or [""])[0]
        body = f"<html><body><div>{value}</div></body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def base():
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _RawEchoHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()


def test_sync_custom_payload_confirms(base):
    """Pre-Phase 322 this was the dead wire: the CLI loaded the file,
    Scanner stored it, nothing consumed it.  The invented tag name cannot
    exist in the corpus, so a finding carrying it can ONLY come from the
    custom channel actually firing."""
    from xssentinel.core.requester import Requester
    from xssentinel.core.scanner import Scanner
    sc = Scanner(requester=Requester(timeout=8), verbose=False,
                 max_payloads=6, max_transforms=4,
                 custom_payloads=[_CUSTOM, "inert string, no execution"])
    sc.scan_target(base + "/", method="GET", params={"q": "probe"})
    hits = [f for f in sc.findings
            if "xssentinel320" in str(f.data.get("payload", ""))]
    assert hits, ("custom payload never reached the wire -- dead wire "
                  "regression")
    assert hits[0].data["confidence"]


def test_sync_custom_channel_requires_execution_point(base):
    """The inert entry must NOT be sent (mark() cannot arm it, so it can
    reflect but never confirm -- pure budget waste)."""
    from xssentinel.core.requester import Requester
    from xssentinel.core.scanner import Scanner
    inert = "zzinert320zz"
    sc = Scanner(requester=Requester(timeout=8), verbose=False,
                 max_payloads=6, max_transforms=4,
                 custom_payloads=[inert])
    sc.scan_target(base + "/", method="GET", params={"q": "probe"})
    assert not any(inert in str(f.data.get("payload", ""))
                   for f in sc.findings)


def test_async_custom_payload_parity(base):
    from xssentinel.core.async_scanner import AsyncScanner
    budgets = dict(max_payloads=10, max_transforms=6)

    async def _run():
        asc = AsyncScanner(max_concurrent=2, per_host_delay=0, jitter=0,
                           timeout=8, dom_engine="off",
                           advanced_layers=False, custom_payloads=[_CUSTOM],
                           **budgets)
        found = []
        async for f in asc.scan(base + "/", method="GET",
                                params={"q": "probe"}):
            found.append(f)
        return asc, found

    try:
        asc, found = asyncio.run(asyncio.wait_for(_run(), timeout=90))
    except asyncio.TimeoutError:
        pytest.fail("async scan did not finish within 90s")
    payload_strs = [str(getattr(f, "data", {}).get("payload", ""))
                    for f in found] + [str(f) for f in found]
    assert any("xssentinel320" in s for s in payload_strs) or any(
        "xssentinel320" in str(getattr(f, "payload", ""))
        for f in found), ("async custom channel never fired -- parity "
                          "regression with sync")


def test_cli_flag_parses():
    from xssentinel.__main__ import build_parser
    ap = build_parser()
    args = ap.parse_args(["-u", "http://t/", "--nuclei-dast",
                          "~/nuclei-templates/dast"])
    assert args.nuclei_dast == "~/nuclei-templates/dast"
    args = ap.parse_args(["-u", "http://t/"])
    assert args.nuclei_dast is None
