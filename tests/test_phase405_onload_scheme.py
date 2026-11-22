# -*- coding: utf-8 -*-
"""Phase 405: onload must not over-claim when the resource can never load.

Phase 404 fed competitor payloads through the sandbox and found one shape
over-stated in real Chromium:

    <img src=x:confirm`` onload=eval(src)>

sandbox said `live` ("img.onload fires when the resource loads"), but the
browser never fires `load` for an unsupported URL scheme -- naturalWidth stays
0 and only `error` fires (measured, benchmark/results/...probe2...json).

The fix is deliberately narrow: only an explicit, non-loadable SCHEME on a
resource element's src is downgraded.  Relative paths, absolute URLs, data:/blob:
and iframe-without-src all stay live, preserving the long-standing corpus
contract (`<img src=x onerror=...>`-is-live, `<iframe onload>`-is-live).

Three failure modes pinned:
  * the over-claim comes back (inert shape judged live again),
  * the fix over-reaches and kills a genuine auto-firing shape,
  * the constant/branch is edited away in source without touching behaviour
    tests (source assertion), so a future refactor cannot silently revert.
"""
import json
from pathlib import Path

import pytest

from xssentinel.core import sandbox as sb

_ROOT = Path(__file__).resolve().parents[1]
_SANDBOX_SRC = _ROOT / "xssentinel" / "core" / "sandbox.py"
_PROBE = _ROOT / "benchmark" / "results" / "src_onload_probe2_20261120.json"
X = "__x()"


def state(html, sink="parser"):
    return sb.judge(html, "", sink=sink).state


# ---------------------------------------------------------- behaviour table

@pytest.mark.parametrize("html", [
    '<div><img src="x:confirm``" onload=%s></div>' % X,   # Phase 404 vector
    '<div><img src="foo:bar" onload=%s></div>' % X,        # clean unknown scheme
    '<div><img src="javascript:void(0)" onload=%s></div>' % X,
])
def test_unloadable_scheme_onload_is_inert(html):
    v = sb.judge(html, "", sink="parser")
    assert v.state == "inert", v.reason
    assert "not loadable" in v.reason or "scheme" in v.reason


@pytest.mark.parametrize("html", [
    '<div><img src=x onload=%s></div>' % X,                # relative (404/200 unknown)
    '<div><img src="/nope" onload=%s></div>' % X,          # root relative
    '<div><img src="http://127.0.0.1:9/a" onload=%s></div>' % X,
    '<div><img src="data:image/svg+xml;base64,PHN2Zy8+" onload=%s></div>' % X,
])
def test_loadable_or_server_dependent_src_stays_live(html):
    assert state(html) == "live"


@pytest.mark.parametrize("html", [
    '<div><iframe onload=%s></iframe></div>' % X,          # about:blank fires load
    '<div><svg onload=%s></svg></div>' % X,                # document-load event
    '<div><img src=x onerror=%s></div>' % X,               # failed fetch fires error
])
def test_genuine_auto_firing_shapes_unchanged(html):
    assert state(html) == "live"


def test_onerror_with_unloadable_scheme_still_live():
    """The failed fetch that kills onload is exactly what TRIGGERS onerror.
    The fix must not touch the onerror branch."""
    assert state('<div><img src="foo:bar" onerror=%s></div>' % X) == "live"


# ----------------------------------------------------------- source pinning

def test_source_pins_the_downgrade_branch():
    src = _SANDBOX_SRC.read_text(encoding="utf-8")
    assert "LOADABLE_RESOURCE_SCHEMES" in src
    assert "_EXPLICIT_SCHEME_RE" in src
    # the branch must live inside the onload block, after the resource_load
    # guard, and must return inert for the un-loadable case
    onload_at = src.index('if ev == "onload":')
    tail = src[onload_at:onload_at + 2000]
    assert "src scheme" in tail and "not loadable" in tail
    assert "return \"inert\"" in tail


def test_whitelist_contains_the_measured_loadable_schemes():
    for scheme in ("http", "https", "data", "blob", "about"):
        assert scheme in sb.LOADABLE_RESOURCE_SCHEMES
    # an arbitrary scheme must NOT be whitelisted
    assert "x" not in sb.LOADABLE_RESOURCE_SCHEMES
    assert "foo" not in sb.LOADABLE_RESOURCE_SCHEMES


# --------------------------------------------------------------- evidence

def test_measurement_evidence_exists_and_supports_the_claim():
    data = json.loads(_PROBE.read_text(encoding="utf-8"))
    rows = {(r["handler"], r["id"]): r for r in data["rows"]}
    # onload never fires for an unknown scheme; onerror does
    assert rows[("onload", "unknown_scheme")]["fired"] == []
    assert "onerror" in rows[("onerror", "unknown_scheme")]["fired"]
    # a genuinely loadable image DOES fire onload (control)
    assert "onload" in rows[("onload", "data_valid_svg")]["fired"]


def test_competitor_fact_table_fix_effect():
    """Re-sandboxing the Phase 404 competitor rows: overstated must reach 0,
    and NO agree_live row may flip (the fix must not kill real detections)."""
    after_path = (_ROOT / "benchmark" / "results" /
                  "competitor_payloads_20261120_after405.json")
    d = json.loads(after_path.read_text(encoding="utf-8"))
    assert d["before_404"]["overstated"] == 2
    assert d["after_405"]["overstated"] == 0
    assert d["agree_live_rows_flipped"] == 0
    ov = d["m1"]["agreement"]["overall"]["counts"]
    assert ov["overstated"] == 0
    assert ov["agree_live"] == 145
