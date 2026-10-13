# -*- coding: utf-8 -*-
"""Range #6 guards: construct validity, vendor integrity, gate semantics,
the runner's path-loading, and the live sanitizer pair.

Construct validity is the range4 lesson applied at full strength: the
pages are STATIC shells (the param never touches server-side bytes), so
the safe twin cannot reflect the attacker string -- no probe needed to
know that, only a byte-equality assertion over the served responses.
The two pages additionally differ in EXACTLY ONE place (the vendored
version path), which is what makes the pair a measurement of the
sanitizer rather than of two different apps.

The live pair asserts what the fixtures cannot: the CVE-2020-26870
namespace-confusion PoC produces a real dialog through the vendored
2.0.7 build, and the identical payload is stripped by 3.4.17 (no live
element, no dialog).  Without this, "vulnerable"/"safe" would be labels
taken from an advisory table instead of measured browser behaviour --
and the negative case would be a must-not assertion with no sensitivity
anchor.

Run: pytest tests/test_range6.py -q
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# The CVE-2020-26870 namespace-confusion PoC -- the sanitizer's tree never
# contains a real <img>, so onerror survives sanitization on 2.0.7 and the
# serialized output re-parses into a live element.
POC = ("<form><math><mtext></form><form><mglyph><style></math>"
       "<img src onerror=alert(1)>")

VENDOR_FILES = [
    "dompurify/2.0.7/purify.min.js",
    "dompurify/3.4.17/purify.min.js",
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
    """Ephemeral port captured from the server's ready_callback.

    Not the range5 shape (bind -> close -> run on that port): that has a
    TOCTOU window where another process can take the port between the
    close and the bind.  Binding 0 and reading the real port back has no
    window at all (Phase 206 hygiene).
    """
    path = os.path.join(ROOT, "range6", "server.py")
    spec = importlib.util.spec_from_file_location("range6_server_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    box: dict = {}
    started = threading.Event()
    threading.Thread(target=mod.run_server, args=(0,),
                     kwargs={"ready_callback":
                             lambda srv: (box.__setitem__(
                                 "port", srv.server_address[1]),
                                          started.set())},
                     daemon=True).start()
    assert started.wait(10), "range6 server did not report ready"
    yield box["port"]


def test_construct_validity_bytes_are_query_independent(lab_port):
    """range4's first version measured four FPs because its safe twin
    reflected the param into a server-side config line.  This range has
    NO server-side interpolation: the served bytes must be identical for
    every query string, and the attacker string must be absent."""
    for path in ("/unsafe", "/safe", "/"):
        plain = _server_response(path, lab_port)
        attacked = _server_response(f"{path}?q={POC}", lab_port)
        assert plain == attacked, (
            f"{path} serves different bytes for different queries -- the "
            f"param leaked into the server-side response, which is exactly "
            f"the range4 FP factory")
        assert POC.encode() not in attacked[1]


def test_twins_differ_only_in_the_vendored_version(lab_port):
    """The pair measures the sanitizer only if exactly one thing differs:
    the version path in the script tag.  Anything else and a verdict
    could be explained by the page, not the build."""
    _s, unsafe = _server_response("/unsafe", lab_port)
    _s, safe = _server_response("/safe", lab_port)
    norm_u = unsafe.replace(b"2.0.7", b"VER").replace(b"unsafe", b"LABEL")
    norm_s = safe.replace(b"3.4.17", b"VER").replace(b"safe", b"LABEL")
    assert norm_u == norm_s, (
        "the twins differ in more than the vendored version/label -- "
        "the pair no longer isolates the sanitizer")


def test_vendor_integrity_and_pins():
    for rel in VENDOR_FILES:
        assert os.path.isfile(os.path.join(ROOT, "range6", "vendor", rel)), \
            f"missing vendored file {rel}"
    readme = open(os.path.join(ROOT, "range6", "vendor", "README.md"),
                  encoding="utf-8").read()
    for ver in ("2.0.7", "3.4.17"):
        assert f"`{ver}`" in readme, f"vendor README does not pin {ver}"
    # integrity.txt records the upstream tarball + sha512 so a re-fetch is
    # reproducible and a silent swap is detectable.
    for ver in ("2.0.7", "3.4.17"):
        pin = open(os.path.join(ROOT, "range6", "vendor", "dompurify", ver,
                                "integrity.txt"), encoding="utf-8").read()
        assert f"dompurify-{ver}.tgz" in pin and "sha512:" in pin


def test_manifest_pairs_and_gate_standard():
    m = json.loads(open(os.path.join(ROOT, "range6", "manifest.json"),
                        encoding="utf-8").read())
    ids = [c["id"] for c in m["cases"]]
    assert ids == ["r6-pos-dompurify-207", "r6-neg-dompurify-3417"]
    assert [c["gt"] for c in m["cases"]] == ["vulnerable", "safe"]
    # The verdict comes from the static sanitizer layer, so the gate does
    # not need headless to score; the live pair below is what ties the
    # labels to measured browser behaviour.
    assert all(not c["headless"] for c in m["cases"])


def test_score_gate_semantics():
    # Load range6/runner.py BY PATH (Phase 221d: this repo has a SECOND
    # module called runner -- benchmark/runner.py -- and a bare import
    # resolves by sys.path order, so in a full suite an earlier test can
    # bind the wrong file and the import dies).
    path = os.path.join(ROOT, "range6", "runner.py")
    spec = importlib.util.spec_from_file_location("range6_runner_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    score = mod.score

    vuln = {"gt": "vulnerable"}
    safe = {"gt": "safe"}
    hit = {"findings": [{"type": "sanitizer_vulnerable_version",
                         "severity": "high"}]}
    empty = {"findings": []}
    csp_only = {"findings": [{"type": "csp_header_missing",
                              "severity": "low"}]}
    low_note = {"findings": [{"type": "sanitizer_output_to_innerhtml",
                              "severity": "low"}]}
    assert score(hit, vuln) == "TP"
    assert score(empty, vuln) == "FN"
    assert score(empty, safe) == "TN"
    assert score(hit, safe) == "FP"
    assert score(csp_only, safe) == "TN", (
        "low csp meta-findings must not count as FP, mirroring range4/5")
    assert score(low_note, safe) == "TN", (
        "a demoted low mXSS note must not count as FP either -- this is "
        "the shape the version-aware demotion produces on a current "
        "sanitizer, and the negative twin depends on it")


# ---------------------------------------------------------------------------
# the live pair (real browser)
# ---------------------------------------------------------------------------

def _dom_available() -> bool:
    from xssentinel.core import dom_engine
    return dom_engine.DynamicDomAnalyzer.available()


needs_browser = pytest.mark.skipif(
    not _dom_available(),
    reason="playwright not installed; the live sanitizer pair cannot run")


def _visit(port: int, path: str):
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        b = pw.chromium.launch(args=["--no-sandbox"])
        page = b.new_page()
        dialogs = []
        page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
        page.goto(f"http://127.0.0.1:{port}{path}",
                  wait_until="domcontentloaded", timeout=15000)
        page.wait_for_timeout(600)          # events are async; read late
        sanitized = page.evaluate(
            "() => document.getElementById('out').innerHTML")
        live_img = page.evaluate(
            "() => !!document.querySelector('#out img')")
        b.close()
        return sanitized, live_img, dialogs


@needs_browser
def test_vulnerable_build_really_executes_the_poc(lab_port):
    """Sensitivity anchor for the positive label: 2.0.7 must actually
    execute the PoC.  A version string in a script path proves nothing
    about this browser on its own."""
    from urllib.parse import quote
    sanitized, live_img, dialogs = _visit(
        lab_port, f"/unsafe?q={quote(POC)}")
    assert dialogs, (
        f"the PoC did not execute on the vendored 2.0.7 build -- the "
        f"'vulnerable' label would be unmeasured; sanitized="
        f"{sanitized[:120]!r}")
    assert live_img


@needs_browser
def test_current_build_strips_the_identical_poc(lab_port):
    """Sensitivity anchor for the negative label: 3.4.17 must strip the
    identical payload -- no live element, no dialog."""
    from urllib.parse import quote
    sanitized, live_img, dialogs = _visit(
        lab_port, f"/safe?q={quote(POC)}")
    assert not dialogs, (
        f"the PoC executed on 3.4.17 -- either the vendored build is not "
        f"what it claims or the 'safe' label is wrong; sanitized="
        f"{sanitized[:120]!r}")
    assert not live_img, f"a live <img> survived sanitization: {sanitized!r}"
    assert "onerror" not in sanitized
