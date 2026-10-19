# -*- coding: utf-8 -*-
"""Range #3 guards: the gate that never existed, and the manifest it reads.

Why this file exists.  range2/4/5/6 have exited non-zero on FN/FP/ERROR
since the day each was written; range3 printed the same verdict table and
then returned 0 unconditionally.  A runner that always exits 0 cannot be
wired into CI, so the range most likely to rot (real sessions, SQLite
state, carriers) was the one nothing ran on every push.

Two layers are asserted here:

* the manifest contract -- unique ids, declared ground truth, and exactly
  the two cases the async arm is allowed to skip;
* the exit-code contract -- main() returns 0 when every scored case lands
  on TP/TN (SKIP must not count as failure) and 1 when any case lands on
  FN, FP or ERROR.

The end-to-end numbers are not asserted here (they need 26 real scans);
`range3/runner.py --engine both` is the measurement and it now returns a
real exit code.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(ROOT, "range3", "manifest.json")


# ---------------------------------------------------------------------------
# manifest contract
# ---------------------------------------------------------------------------

def test_manifest_ids_are_unique_and_carry_ground_truth():
    m = json.loads(open(MANIFEST, encoding="utf-8").read())
    cases = m["cases"]
    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids)), "duplicate case id would double-score"
    assert all(c.get("gt") in ("vulnerable", "safe", "low") for c in cases)
    # The two carriers the async arm cannot drive are declared, not dropped.
    sync_only = sorted(c["id"] for c in cases if c.get("engines"))
    assert sync_only == ["r3-pos-so2", "r3-pos-stored"]
    assert all(c["engines"] == ["sync"] for c in cases if c.get("engines"))


# ---------------------------------------------------------------------------
# the exit-code contract
# ---------------------------------------------------------------------------

@pytest.fixture
def runner_mod():
    """Load range3/runner.py BY PATH, then undo the sys.path damage.

    The runner inserts its own directory at sys.path[0] and imports a bare
    `server` -- which is exactly what it must do when run as a script
    (`benchmark/server.py` must not shadow it), but inside a full pytest
    session that would leave range3/server.py bound as the global `server`
    for every test collected afterwards.  Snapshot and restore.
    """
    saved_path = list(sys.path)
    saved_server = sys.modules.pop("server", None)
    try:
        path = os.path.join(ROOT, "range3", "runner.py")
        spec = importlib.util.spec_from_file_location("range3_runner_test",
                                                      path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        yield mod
    finally:
        sys.modules.pop("server", None)
        if saved_server is not None:
            sys.modules["server"] = saved_server
        sys.path[:] = saved_path


def _drive(mod, monkeypatch, tmp_path, score_hook=None, error_path=None,
           error_once=False, browser_fired=True):
    """Call main() with the network/CLI boundary faked out.

    What is NOT faked: the manifest read, the start-URL/extra-args builders,
    the per-engine loop, the SKIP rule, the row collection and the exit
    code.  That is the part the gate lives in.

    `browser_fired=False` is the dead-Chromium shape: findings exist, none
    of them carries a `fired` outcome.  `error_once=True` is the wedge
    shape: the first attempt on that URL dies, the retry answers.
    """
    monkeypatch.setattr(mod, "start_range", lambda *a, **k: (18702, 0.0))
    monkeypatch.setattr(mod, "login", lambda base: "r3_session=test")
    seen = {"wedged": 0}

    def fake_invoke(url, timeout=60, max_payloads=10, max_transforms=6,
                    extra_args=None, engine="sync"):
        if error_path and error_path in url:
            if not error_once or seen["wedged"] == 0:
                seen["wedged"] += 1
                return None, 0.1, "timeout after 1s"
        finding = {"type": "reflected", "severity": "high"}
        if browser_fired:
            finding["headless"] = {"outcome": "fired"}
        # `requests` must be non-zero: a clean report that issued no request
        # is the "scanner never spoke" shape and is retried by design.
        return {"findings": [finding], "requests": 3}, 0.1, ""

    monkeypatch.setattr(mod, "_invoke_scanner", fake_invoke)
    if score_hook is not None:
        monkeypatch.setattr(mod, "score", score_hook)
    out = tmp_path / "range3.json"
    monkeypatch.setattr(sys, "argv",
                        ["range3/runner.py", "--engine", "both",
                         "-o", str(out)])
    return mod.main(), out


def test_gate_is_green_when_every_case_scores(runner_mod, monkeypatch,
                                              tmp_path):
    def perfect(report, case):
        return "TN" if case["gt"] == "safe" else "TP"

    rc, out = _drive(runner_mod, monkeypatch, tmp_path, score_hook=perfect)
    assert rc == 0, "an all-TP/TN run must exit 0"
    payload = json.loads(out.read_text(encoding="utf-8"))
    # Retained product, not just terminal scrollback.
    assert set(payload["counts"]) == {"sync", "async"}
    assert payload["counts"]["sync"]["FN"] == 0
    # The two sync-only cases must be recorded as SKIP and must NOT fail
    # the gate -- an honest declaration is not a defect.
    assert payload["counts"]["async"]["SKIP"] == 2
    assert payload["counts"]["async"]["ERROR"] == 0


@pytest.mark.parametrize("bad_verdict", ["FN", "FP"])
def test_gate_fails_on_fn_and_fp(runner_mod, monkeypatch, tmp_path,
                                 bad_verdict):
    sabotaged = {"done": False}

    def one_bad(report, case):
        if not sabotaged["done"] and case["gt"] != "safe":
            sabotaged["done"] = True
            return bad_verdict
        return "TN" if case["gt"] == "safe" else "TP"

    rc, out = _drive(runner_mod, monkeypatch, tmp_path, score_hook=one_bad)
    assert rc == 1, f"a {bad_verdict} must fail the job"
    assert out.exists(), "the report is written before the gate decides"


def test_gate_fails_on_error(runner_mod, monkeypatch, tmp_path):
    def perfect(report, case):
        return "TN" if case["gt"] == "safe" else "TP"

    rc, _ = _drive(runner_mod, monkeypatch, tmp_path, score_hook=perfect,
                   error_path="/search")
    assert rc == 1, "a scanner timeout is not a pass"


def test_gate_fails_when_the_headless_case_has_no_browser_evidence(
        runner_mod, monkeypatch, tmp_path):
    """r3-pos-utf7 declares headless=true.  A TP built from findings that
    never fired is the shape a dead Chromium produces -- the same hole
    measured on range4 (PLAYWRIGHT_BROWSERS_PATH -> empty dir, TP with
    browser-confirmed=0, gate exit 0)."""
    def perfect(report, case):
        return "TN" if case["gt"] == "safe" else "TP"

    rc, out = _drive(runner_mod, monkeypatch, tmp_path, score_hook=perfect,
                     browser_fired=False)
    assert rc == 1, "a browser-gated positive with no fired outcome must fail"
    payload = json.loads(out.read_text(encoding="utf-8"))
    utf7 = [r for r in payload["rows"] if r["case_id"] == "r3-pos-utf7"]
    assert utf7 and all(r["confirmed"] == 0 for r in utf7)


def test_a_wedged_first_attempt_is_retried_and_recorded(runner_mod,
                                                        monkeypatch,
                                                        tmp_path):
    """Phase 269 wiring: the retry must be reachable from main(), not just
    from range_gate's unit tests.  One timeout, then an answer -> exit 0,
    and the row says retries=1 so "recovered" stays distinguishable from
    "clean first time" (benchmark.runner's Phase 176n rule)."""
    def perfect(report, case):
        return "TN" if case["gt"] == "safe" else "TP"

    rc, out = _drive(runner_mod, monkeypatch, tmp_path, score_hook=perfect,
                     error_path="/search", error_once=True)
    assert rc == 0, "a recovered wedge must not leave the gate red"
    payload = json.loads(out.read_text(encoding="utf-8"))
    row = [r for r in payload["rows"]
           if r["case_id"] == "r3-pos-q-raw" and r["engine"] == "sync"][0]
    assert row["verdict"] == "TP"
    assert row["retries"] == 1
