"""Phase 300: the sandbox must stay right about the payloads we SEND.

`tests/test_sandbox_fidelity.py` scores the sandbox against the 1680-cell
main oracle -- but that oracle was built from hand-picked shapes, and
Phase 299 measured the consequence: of the 427 payloads the scanner sends
by default, 168 carried tokens no measured corpus had ever judged.

`benchmark/oracle_default_sent.py` judged those cells (one host per
payload family, Chromium, both arms).  This test scores them with the same
four-way classification the main fidelity test uses, so a future sandbox
change that quietly loses one of these payloads fails here -- and so does
a payload added to the default set without a judgement to back it.

The artifact is small (70 KB) and committed; regenerate with
`python -m benchmark.oracle_default_sent` after changing the corpus.
"""
from __future__ import annotations

import json
import os

import pytest

from xssentinel.core import sandbox

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ART = os.path.join(ROOT, "benchmark", "results", "oracle_default_sent.json")
TOKEN = "__x()"

pytestmark = pytest.mark.skipif(
    not os.path.exists(ART),
    reason="no recorded judgement for the default-sent payloads; run "
           "`python -m benchmark.oracle_default_sent`")


def _rows():
    with open(ART, encoding="utf-8") as fh:
        data = json.load(fh)
    return [r for r in data["rows"] if r.get("sentinel_present")]


def _score(sink, key):
    missed, over, unknown = [], [], []
    live = inert = 0
    for r in _rows():
        browser = r.get(key)
        if browser is None:
            continue
        v = sandbox.judge(r["document"], TOKEN, sink=sink)
        claimed = v.state == "live" and not v.activation
        if v.state == "unknown":
            unknown.append((r["family"], r["host"], v.reason))
        elif browser and not claimed:
            missed.append((r["family"], r["host"], v.reason))
        elif claimed and not browser:
            over.append((r["family"], r["host"], v.reason))
        elif claimed:
            live += 1
        else:
            inert += 1
    return missed, over, unknown, live, inert


@pytest.mark.parametrize("sink,key", (("parser", "exec_parser"),
                                      ("innerhtml", "exec_ihn1")))
def test_we_do_not_send_payloads_the_sandbox_misjudges(sink, key):
    missed, over, unknown, live, inert = _score(sink, key)
    assert not missed, (
        f"{len(missed)} payload(s) we actually send execute in Chromium while "
        f"the sandbox calls them inert:\n"
        + "\n".join(f"  {p} x {h}: {why[:90]}" for p, h, why in missed[:8]))
    assert not over, (
        f"{len(over)} over-claim(s) among default-sent payloads:\n"
        + "\n".join(f"  {p} x {h}: {why[:90]}" for p, h, why in over[:8]))


def test_the_artifact_is_not_vacuous():
    """A truncated or sentinel-less run must fail loudly, not pass quietly."""
    rows = _rows()
    assert len(rows) >= 140, f"only {len(rows)} scored rows in the artifact"
    assert any(r.get("exec_parser") for r in rows), (
        "no cell executed in Chromium -- the sentinel substitution probably "
        "broke and every verdict is vacuously inert")
