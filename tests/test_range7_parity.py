"""Phase 302: one field, one meaning -- across both engines.

range7 found this on its first run: on r7-pos-attr, sync reported
`context=html_attribute_dq` and async reported `context=script_block` for
the same reflection.  Both were true, of different things -- sync reports
the CLASSIFIED reflection context (where the payload lands), async let the
verifier's observed sink override it (what the payload produced once it
closed the attribute).

Fix: async keeps `context` = classified (parity), and the verifier's view
is exposed as an additive `sink_context`.  Nothing selects payloads from
these fields, so detection is unchanged -- only the report.

The integration test below is the durable net: it drives both engines
against the range7 attribute face and asserts the two engines agree on
`context`, with async additionally carrying the sink it observed.
"""
from __future__ import annotations

import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "range7_server", ROOT / "range7" / "server.py")
srv_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv_mod)


@pytest.fixture(scope="module")
def base():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    started = threading.Event()
    threading.Thread(target=srv_mod.run_server, args=(port,),
                     kwargs={"ready_callback": lambda _s: started.set()},
                     daemon=True).start()
    assert started.wait(10), "range7 server did not start"
    return f"http://127.0.0.1:{port}"


def _scan(url: str, engine: str) -> dict:
    out = os.path.join(tempfile.gettempdir(), f"r7_parity_{engine}_{os.getpid()}.json")
    cmd = [sys.executable, "-m", "xssentinel", "-u", url,
           "-f", "json", "-o", out, "--progress", "none",
           "--log-level", "error", "--max-payloads", "10",
           "--max-transforms", "6", "--timeout", "10"]
    if engine == "async":
        cmd += ["--async", "--threads", "4"]
    subprocess.run(cmd, capture_output=True, text=True, timeout=180, cwd=str(ROOT))
    rep = json.load(open(out, encoding="utf-8"))
    try:
        os.unlink(out)
    except OSError:
        pass
    return rep


def test_both_engines_report_the_same_context(base):
    url = f"{base}/search?q=xssentinel"
    sync = _scan(url, "sync")
    async_ = _scan(url, "async")
    s_ctx = {f.get("context") for f in sync.get("findings", [])}
    a_ctx = {f.get("context") for f in async_.get("findings", [])}
    assert s_ctx & a_ctx, (
        f"engines disagree on the reflection context: sync={sorted(s_ctx)} "
        f"async={sorted(a_ctx)} -- one of them is not reporting the "
        "classified context")
    # the divergence this phase fixed, named so a regression is obvious
    assert "html_attribute_dq" in s_ctx and "html_attribute_dq" in a_ctx


def test_async_keeps_the_verifier_sink_as_a_second_field(base):
    url = f"{base}/search?q=xssentinel"
    async_ = _scan(url, "async")
    sinks = {(f.get("context"), f.get("sink_context"))
             for f in async_.get("findings", [])}
    assert any(s and s != c for c, s in sinks), (
        f"no async finding carries a sink_context distinct from its context "
        f"(got {sorted(sinks)}) -- the verifier's observation was lost")


def test_report_shows_the_sink_only_when_it_differs():
    from xssentinel.core.report import _sink_suffix, build_html
    assert _sink_suffix({"context": "a", "sink_context": "a"}) == ""
    assert _sink_suffix({"context": "a"}) == ""
    assert "script_block" in _sink_suffix(
        {"context": "html_attribute_dq", "sink_context": "script_block"})
    html = build_html(
        [{"type": "reflected", "context": "html_attribute_dq",
          "sink_context": "script_block", "severity": "high"}],
        "http://t/", {"generated": "x", "requests": 1})
    assert "script_block" in html
