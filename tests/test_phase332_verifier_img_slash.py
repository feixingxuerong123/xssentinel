"""Phase 332/333: the verifier's img-slash verdicts track the real browser.

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

Phase 333 corpus change: the TEMPORARY p173-probe (iframe-src-javascript,
dead in modern Chromium, never confirmable) that occupied slot 0 of the
html_element primary window was replaced IN PLACE (family index 0, no
displacement) by the executing quoted-src form.  Pinned here:
  * every UNQUOTED ``<img/src=`` shape in the corpus must stay refused
    (derived guard);
  * the quoted form leads the primary window and must confirm;
  * the old p173 shape is gone.
"""
from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import payloads  # noqa: E402
from xssentinel.core import verifier as verifier_mod  # noqa: E402

_TOKEN = "xssv_332abcde"
_QUOTED = '<img/src="x"/onerror=alert(1)//>'
_UNQUOTED_RE = re.compile(r"^<img/src=[^\"']")


def _verify(payload: str) -> dict:
    marked = verifier_mod.mark(payload, _TOKEN)
    body = f"<html><body><p>echo: {marked}</p></body></html>"
    return verifier_mod.verify_semantic(body, _TOKEN)


def test_every_unquoted_img_slash_shape_stays_refused():
    """Derived guard: all UNQUOTED ``<img/src=`` shapes in the corpus are
    inert in a real browser (the src value swallows `/onerror=...`), so
    they must never confirm."""
    shapes = [p["payload"] for p in payloads.by_context("html_element")
              if _UNQUOTED_RE.match(p["payload"])]
    assert shapes, "the unquoted img/slash corpus family disappeared"
    for s in shapes:
        assert not _verify(s)["confirmed"], (
            f"verify_semantic confirmed an INERT shape (browser oracle: no "
            f"dialog for unquoted img/slash): {s}")


def test_quoted_form_leads_the_primary_window():
    """Phase 333 swap: slot 0 of the html_element family is the executing
    space-less form (was the never-confirmable p173-probe)."""
    ps = payloads.by_context("html_element")
    assert ps[0]["payload"] == _QUOTED
    assert ps[0]["id"] == "nospace-img-001"
    assert _verify(_QUOTED)["confirmed"], "the quoted form must confirm"


def test_p173_probe_shape_is_gone():
    pls = [p["payload"] for p in payloads.by_context("html_element")]
    assert not any("<<script>Foo</script>iframe" in p for p in pls), (
        "the dead p173 shape is back in the html_element family -- it can "
        "never confirm (iframe-src javascript is dead in modern Chromium) "
        "and its note said TEMPORARY; re-derive the slot-0 contract first")


def test_plain_img_onerror_is_confirmed():
    v = _verify("<img src=x onerror=alert(1)>")
    assert v["confirmed"]
    assert v["context"] == "event_handler"
