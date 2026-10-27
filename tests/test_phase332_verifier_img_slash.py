"""Phase 332: the verifier's img-slash verdicts track the real browser.

Phase 331 recorded `<img/src=x/onerror=alert('tok')//>` as a suspected
verifier-classifier gap (reflected verbatim, refused with ctx=url_href).
The browser oracle REVERSED that record (`dev/_p332_img_slash_probe.py`,
real Chromium): the HTML5 tokenizer keeps `/` inside an UNQUOTED attribute
value, so in `<img/src=x/onerror=...>` the src value swallows
`x/onerror=...` -- the token never sits in an event handler and NO dialog
fires.  The refusal is correct.  The quoted-src form
`<img/src="x"/onerror=...//>` DOES fire, and the verifier confirms it
(ctx=event_handler).

Measured three-way contract (Chromium 148, headless):

    <img/src=x/onerror=alert(T)//>      dialog: NO    verifier: refused
    <img/src="x"/onerror=alert(T)//>    dialog: YES   verifier: confirmed
    <img src=x onerror=alert(T)>        dialog: YES   verifier: confirmed

Pinned here so nobody "fixes" the classifier into confirming the inert
form.  The refusal half is DERIVED from the corpus: every ``<img/src=``
shape in html_element must stay refused when reflected raw.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import payloads  # noqa: E402
from xssentinel.core import verifier as verifier_mod  # noqa: E402

_TOKEN = "xssv_332abcde"


def _verify(payload: str) -> dict:
    marked = verifier_mod.mark(payload, _TOKEN)
    body = f"<html><body><p>echo: {marked}</p></body></html>"
    return verifier_mod.verify_semantic(body, _TOKEN)


def test_every_corpus_img_slash_shape_stays_refused():
    """Derived guard: all ``<img/src=`` shapes in html_element are the
    unquoted family -- inert in a real browser (the src value swallows
    `/onerror=...`), so they must never confirm."""
    shapes = [p["payload"] for p in payloads.by_context("html_element")
              if p["payload"].startswith("<img/src=")]
    assert shapes, "the img/slash corpus family disappeared"
    for s in shapes:
        assert not _verify(s)["confirmed"], (
            f"verify_semantic confirmed an INERT shape (browser oracle: no "
            f"dialog for unquoted img/slash): {s}")


def test_quoted_src_img_slash_is_confirmed():
    """The space-less form that actually executes (cheat-sheet intent)
    must keep confirming -- this is the shape the corpus family was
    reaching for and missed."""
    v = _verify('<img/src="x"/onerror=alert(1)//>')
    assert v["confirmed"], "the EXECUTING quoted form must confirm"
    assert v["context"] == "event_handler"


def test_plain_img_onerror_is_confirmed():
    v = _verify("<img src=x onerror=alert(1)>")
    assert v["confirmed"]
    assert v["context"] == "event_handler"


def test_quoted_form_is_absent_from_corpus():
    """The measured corpus gap (Phase 332): the family occupies the
    space-less img niche with inert shapes while the executing quoted form
    is missing.  If this assertion starts failing, someone added the
    quoted form -- the Phase 331-style ledger note and the full-matrix
    re-gate duty then apply."""
    pls = [p["payload"] for p in payloads.by_context("html_element")]
    assert not any(p.startswith('<img/src="') for p in pls), (
        "quoted-src img/slash shape added to the corpus -- verdict-surface "
        "change: re-run the full 194 dual-engine matrix and check the "
        "raw-echo safe fixtures for stale-TN exposure")
