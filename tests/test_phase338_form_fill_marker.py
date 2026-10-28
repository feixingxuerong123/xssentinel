"""Phase 338: form-fill values track --marker-prefix.

Phase 336 finding: ``DEFAULT_TEXT_VALUE`` ("xssentinel_test") is a static
constant, but every other marker system (``xssm_`` DOM markers, ``xssp_``
probe tokens, ``xssentinel_dom_`` sinks) derives its stem through
``stealth.marker()`` so ``--marker-prefix q`` attributes the whole scan.
The form-fill value did not follow -- its lazy accessor
(``_text_value``) had been dead since before Phase 336 and the static
constant replaced it.

Contract pinned here:
  * without a prefix the fill is byte-identical to the historical
    constant (no behavior change on default runs);
  * with a prefix the fill carries the prefix (attribution);
  * an explicit marker argument still wins;
  * the stealth module-global is left untouched (set_marker_prefix(None)
    in finally -- a leaked prefix would contaminate every later test).
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from xssentinel.core import form_miner  # noqa: E402
from xssentinel.core.stealth import set_marker_prefix  # noqa: E402

HTML = """
<html><body>
<form action="/f1" method="GET">
  <input type="text" name="q" value="">
  <input type="hidden" name="csrf" value="tok123">
</form>
</body></html>
"""


@pytest.fixture(autouse=True)
def _restore_prefix():
    yield
    set_marker_prefix(None)


def _fill() -> list[tuple[str, str, dict, dict]]:
    return form_miner.forms_to_endpoints(HTML, "http://x.test")


def test_default_fill_is_byte_identical_to_the_constant():
    params, data = _fill()[0][2], _fill()[0][3]
    assert params["q"] == form_miner.DEFAULT_TEXT_VALUE == "xssentinel_test"
    assert params["csrf"] == "tok123"  # server-provided values kept
    assert data == {}


def test_fill_tracks_marker_prefix():
    set_marker_prefix("q")
    params, _ = _fill()[0][2], _fill()[0][3]
    assert params["q"] == "q_", (
        "the form fill must carry the scan's marker prefix like every "
        "other marker system (deleted lazy accessor restored)")


def test_explicit_marker_argument_wins():
    got = form_miner.fill_form(
        {"method": "POST", "fields": [{"name": "a", "type": "text",
                                       "value": ""}]},
        "custom-value")
    assert got[1]["a"] == "custom-value"


def test_fill_form_none_defaults_to_the_tracked_value():
    set_marker_prefix("q")
    params, _ = form_miner.fill_form(
        {"method": "GET", "fields": [{"name": "a", "type": "text",
                                      "value": ""}]})
    assert params["a"] == "q_"
