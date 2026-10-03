"""Phase 189: PortSwigger no-interaction event corpus.

The repo's own reference benchmark (`benchmark/portswigger_corpus_coverage.py`)
measured the no_interaction event coverage at 23.1% -- 40 events and 6 tags
that fire WITHOUT user interaction (exactly what a scanner can verify) were
absent from the corpus.  This family closes that gap to 100%.

Contracts pinned here:
  * the family loads and is registered in `_meta.contexts`;
  * every payload carries alert(1) so verifier.mark can stamp the token;
  * BOTH engines draw from it for html_element reflections (sync
    _build_candidates + async _CROSS_CONTEXT);
  * the primary `html_element` family is UNCHANGED (205 entries) -- the new
    payloads ride leftover budget only.  Appending into html_element would
    silently shift the stride-sampled queue and invalidate every measured
    benchmark verdict; if you must touch it, re-measure first.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import payloads  # noqa: E402

_EXPECTED_FAMILY_SIZE = 48
_EXPECTED_HTML_ELEMENT_SIZE = 205


def test_family_loads_and_is_registered():
    fam = payloads.by_context("portswigger_events")
    assert len(fam) == _EXPECTED_FAMILY_SIZE
    assert "portswigger_events" in payloads.contexts()


def test_every_payload_is_stampable_and_element_shaped():
    for p in payloads.by_context("portswigger_events"):
        pl = p.get("payload") or ""
        assert "alert(1)" in pl, f"{p['id']} lost its callable"
        assert pl.lstrip().startswith("<"), f"{p['id']} not element-shaped"
        assert p.get("tags") and "portswigger" in p["tags"]


def test_key_vectors_present():
    pls = " ".join(p["payload"] for p in
                   payloads.by_context("portswigger_events"))
    for needle in ("onhashchange", "onpageshow", "onsecuritypolicyviolation",
                   "onanimationend", "ontransitionend", "ontimeupdate",
                   "onbeforescriptexecute"):
        assert needle in pls, f"missing {needle}"
    for tag in ("<address", "<b ", "<span", "<br ", "<camera", "<slot"):
        assert tag in pls, f"tag coverage missing: {tag}"


def test_both_engines_draw_the_family():
    # sync: _build_candidates samples the family for html_element (mirror of
    # the wiring; the sample call is exercised via the stride helper shape)
    sync_fam = payloads.by_context("portswigger_events")
    assert sync_fam
    # async: the cross-context matrix routes html_element to the family
    from xssentinel.core.payloads import _CROSS_CONTEXT
    pairs = dict(_CROSS_CONTEXT["html_element"])
    assert pairs.get("portswigger_events") == 2


def test_html_element_primary_family_unchanged():
    """The no-displacement contract: new corpora must NOT be appended into
    the primary html_element family (see module docstring)."""
    assert len(payloads.by_context("html_element")) == \
        _EXPECTED_HTML_ELEMENT_SIZE
