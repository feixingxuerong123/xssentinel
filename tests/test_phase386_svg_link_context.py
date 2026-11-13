# -*- coding: utf-8 -*-
"""Phase 386: the SVG anchor's ``xlink:href`` joins its HTML twin.

Measured defect chain (2026-11-13, re-running the Phase 334 window audit
on the 2.0.0 tree):

* the audit's last svg_context DEAD-candidate was
  ``<svg><a xlink:href=javascript:...>`` -- the engine could never confirm
  it, so the reachable slot was guaranteed waste (the Phase 333/334
  definition of a dead slot);
* the Chromium oracle (real trusted click) fires the dialog:
  ``dialog_fired=True`` -- a real XSS shape, not an inert vector;
* the SANDBOX has modelled ``("a", "xlink:href")`` as a measured
  activation-gated sink since the SVG-namespace probe (no execution on
  load, execution on a trusted click, with and without ``xmlns:xlink``);
* only the CONTEXT CLASSIFIER still filed the reflection point as
  ``html_attribute_dq`` ("escaped / non-executable") -- the same sink
  known to two components, recognised by one and refused by the other
  (the "same contract handwritten twice" family again).

Fix: the classifier treats ``xlink:href`` as a URL attribute.  Execution
semantics stay with the verifier's element+attribute tables, so the
non-anchor ``xlink:href`` shapes the corpus also carries (image / script)
keep their inert verdicts -- pinned here as the false-positive guard.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import verifier as V  # noqa: E402

_TOKEN = "xssv_p386"
_JS = f'javascript:alert("{_TOKEN}")'
_HEADERS = {"Content-Type": "text/html"}


def _verify(page: str) -> dict:
    return V.verify_semantic(page, _TOKEN, response_headers=_HEADERS)


def test_svg_anchor_xlink_classifies_as_url_javascript():
    r = _verify(f'<html><body><svg><a xlink:href="{_JS}">'
                '<text x="10" y="10">click</text></a></svg></body></html>')
    assert r["context"] == "url_javascript", r
    assert r["detail"].startswith("sandbox:"), r


def test_html_anchor_is_the_same_verdict_shape():
    """The twin assertion: the HTML anchor keeps its verdict, so the two
    components can never drift apart again unnoticed."""
    html = _verify(f'<html><body><a href="{_JS}">x</a></body></html>')
    svg = _verify(f'<html><body><svg><a xlink:href="{_JS}">'
                  '<text>click</text></a></svg></body></html>')
    assert html["context"] == svg["context"] == "url_javascript", (html, svg)
    assert html["confirmed"] == svg["confirmed"], (html, svg)
    assert html["sandbox_state"] == svg["sandbox_state"], (html, svg)


def test_svg_anchor_plain_url_is_url_href():
    r = _verify('<html><body><svg><a xlink:href="https://example.com/x?'
                't=' + _TOKEN + '"><text>go</text></a></svg></body></html>')
    assert r["context"] == "url_href", r


def test_non_anchor_xlink_shapes_stay_unconfirmed():
    """False-positive guard: the corpus also carries image/script
    xlink:href vectors; the classifier change must not confirm any of
    them (the oracle fires ONLY for the anchor + a trusted click)."""
    for page in (
        f'<html><body><svg><image xlink:href="{_JS}"></svg></body></html>',
        f'<html><body><svg><script xlink:href="{_JS}"></svg></body></html>',
    ):
        r = _verify(page)
        assert r["confirmed"] is False, (page, r)


def test_img_src_baseline_unchanged():
    """The Phase 168 measured baseline: img/src=javascript: classifies as
    url_javascript and is refused -- the classifier change must not have
    widened execution semantics."""
    r = _verify(f'<html><body><img src="{_JS}"></body></html>')
    assert r["confirmed"] is False, r
    assert r["context"] == "url_javascript", r
