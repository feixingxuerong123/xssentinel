# -*- coding: utf-8 -*-
"""Range #5 guards: construct validity, vendor integrity, gate semantics,
and the live Lit pair.

Construct validity is the range4 lesson applied at full strength: the
pages are STATIC shells (the param never touches server-side bytes), so
the safe twin cannot reflect the attacker string -- no probe needed to
know that, only a byte-equality assertion over the served responses.

The live pair asserts what the fixtures cannot: the vendored Lit
`unsafeHTML` directive's innerHTML write is observed by the engine's
sink instrumentation on the vulnerable page, and the text-interpolation
twin (a TEXT node by framework semantics) stays silent.

Run: pytest tests/test_range5.py -q
"""
from __future__ import annotations

import json
import os
import socket
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "range5"))

ATTACKER = "<svg/onload=alert('r5probe')>"

# The packages' real entry files: lit and lit-element ship index.js, while
# lit-html and @lit/reactive-element v3 root their package at a single
# module named after the package -- the import map in server.py must point
# at exactly these (a wrong entry 404s the module graph and the page
# silently renders nothing, which the live pair catches).
VENDOR_INDEX_FILES = [
    "lit/index.js", "lit-html/lit-html.js",
    "lit-element/index.js", "reactive-element/reactive-element.js",
]


# ---------------------------------------------------------------------------
# static guards: construct validity + vendor integrity (no browser)
# ---------------------------------------------------------------------------

def _server_response(path: str, port: int) -> tuple[int, bytes]:
    import requests
    r = requests.get(f"http://127.0.0.1:{port}{path}", timeout=10)
    return r.status_code, r.content


@pytest.fixture(scope="module")
def lab_port():
    from server import run_server
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    started = threading.Event()
    threading.Thread(target=run_server, args=(port,),
                     kwargs={"ready_callback": lambda srv: started.set()},
                     daemon=True).start()
    started.wait(5)
    yield port


def test_construct_validity_bytes_are_query_independent(lab_port):
    """range4's first version measured four FPs because its safe twin
    reflected the param into a server-side config line.  This range has
    NO server-side interpolation: the served bytes must be identical for
    every query string, and the attacker string must be absent."""
    for path in ("/unsafe", "/safe", "/"):
        plain = _server_response(path, lab_port)
        attacked = _server_response(f"{path}?q={ATTACKER}", lab_port)
        assert plain == attacked, (
            f"{path} serves different bytes for different queries -- the "
            f"param leaked into the server-side response, which is exactly "
            f"the range4 FP factory")
        assert ATTACKER.encode() not in attacked[1]


def test_vendor_integrity_and_import_map_targets():
    for rel in VENDOR_INDEX_FILES + ["lit/directives/unsafe-html.js"]:
        assert os.path.isfile(os.path.join(ROOT, "range5", "vendor", rel)), \
            f"missing vendored file {rel}"
    readme = open(os.path.join(ROOT, "range5", "vendor", "README.md"),
                  encoding="utf-8").read()
    for pkg in ("lit", "lit-html", "lit-element", "@lit/reactive-element"):
        assert f"`{pkg}`" in readme, f"vendor README does not pin {pkg}"


def test_manifest_pairs_and_gate_standard():
    m = json.loads(open(os.path.join(ROOT, "range5", "manifest.json"),
                        encoding="utf-8").read())
    ids = [c["id"] for c in m["cases"]]
    assert ids == ["r5-pos-lit-unsafehtml", "r5-neg-lit-text"]
    assert all(c["headless"] for c in m["cases"]), (
        "every sink is client-side; the manifest must require headless")
    assert [c["gt"] for c in m["cases"]] == ["vulnerable", "safe"]


def test_score_gate_semantics():
    # Phase 221d: load range5/runner.py BY PATH instead of `from runner
    # import score`.  The bare name resolves by sys.path order, and this
    # repo has a SECOND module called runner -- benchmark/runner.py.  In a
    # full suite some earlier test has already imported one of them into
    # sys.modules, so the bare import silently binds the wrong file and
    # dies with "cannot import name 'score' from 'runner'".  Two modules
    # with the same name and a shared sys.path is a name collision waiting
    # for order; naming the file removes it.
    import importlib.util
    path = os.path.join(ROOT, "range5", "runner.py")
    spec = importlib.util.spec_from_file_location("range5_runner", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    score = mod.score

    vuln = {"gt": "vulnerable"}
    safe = {"gt": "safe"}
    hit = {"findings": [{"type": "dom_dynamic", "severity": "high"}]}
    empty = {"findings": []}
    csp_only = {"findings": [{"type": "csp_header_missing", "severity": "low"}]}
    assert score(hit, vuln) == "TP"
    assert score(empty, vuln) == "FN"
    assert score(empty, safe) == "TN"
    assert score(hit, safe) == "FP"
    assert score(csp_only, safe) == "TN", (
        "low csp meta-findings must not count as FP, mirroring range4")


# ---------------------------------------------------------------------------
# the live pair (real browser)
# ---------------------------------------------------------------------------

def _dom_available() -> bool:
    from xssentinel.core import dom_engine
    return dom_engine.DynamicDomAnalyzer.available()


needs_browser = pytest.mark.skipif(
    not _dom_available(),
    reason="playwright not installed; the live Lit pair cannot run")


def _scan(port: int, path: str):
    from xssentinel.core.requester import Requester
    from xssentinel.core.scanner import Scanner
    sc = Scanner(requester=Requester(timeout=10), use_headless=True)
    sc.scan_endpoint(f"http://127.0.0.1:{port}{path}?q=xssentinel",
                     "GET", {"q": "xssentinel"}, {})
    return [f.data or {} for f in sc.findings]


@needs_browser
def test_vulnerable_page_yields_browser_executed_dom_finding(lab_port):
    found = _scan(lab_port, "/unsafe")
    dyn = [f for f in found
           if f.get("type") == "dom_dynamic"
           and f.get("evidence_class") == "browser-executed"]
    assert dyn, (
        f"no browser-executed DOM finding on /unsafe -- the vendored "
        f"unsafeHTML write path is not observed by the sink "
        f"instrumentation; all findings: "
        f"{[(f.get('type'), f.get('evidence_class')) for f in found]}")


@needs_browser
def test_safe_twin_stays_silent(lab_port):
    found = _scan(lab_port, "/safe")
    dyn = [f for f in found if f.get("type") == "dom_dynamic"]
    assert not dyn, (
        f"DOM finding on the text-interpolation twin: {dyn} -- the "
        f"framework renders a TEXT node; a scanner that reports it cannot "
        f"be trusted on the positive case")
