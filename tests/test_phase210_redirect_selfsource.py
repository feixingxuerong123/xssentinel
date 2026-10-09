# -*- coding: utf-8 -*-
"""Phase 210b: a redirect sink must not be its own taint source.

Found on OWASP Juice Shop 20.2.0 (a real app, not our fixture).  The report
carried `open_redirect_xss` at **high** whose evidence was this exact text
from `main.js`:

    goToProfilePage(){window.location.replace(L$.hostServer+`/profile`)}
    goToDataErasurePage(){window.location.replace(L$.hostServer+`/dataerasure`)}

Nothing there reads the query string, the hash or a message; the destination
is a config host plus a literal path.  It fired because `USER_INPUT_RE`
contains `window.location`, and the snippet searched is a window AROUND the
sink -- so the sink quoted itself.

Phase 113b already fixed that for the assignment form (blank the left-hand
side).  Two things stayed broken, and the bundle shows both:

  1. the CALL form has no left-hand side -- `window.` sits *before* the match
     and the look-behind reaches exactly it;
  2. the window extended 200 characters past the sink, i.e. into the NEXT
     statement, which in a minified bundle is routinely another sink.
     Masking only the current match left that neighbour to vouch for it.

Measured on the bundle: HEAD reported 6 exploitable sinks, this code reports
0 -- and the true positive (`location.replace(p.get('next'))`) still fires.
"""
from __future__ import annotations

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssentinel.core import redirect_xss as rx  # noqa: E402

# Verbatim from the target's own main.js (the two sibling calls the old
# window let vouch for each other).
BUNDLE_HARDCODED = (
    "goToProfilePage(){window.location.replace(L$.hostServer+`/profile`)}"
    "goToDataErasurePage(){window.location.replace(L$.hostServer+`/dataerasure`)}"
    "onToggleSidenav=()=>{this.sidenavToggle.emit()};")
BUNDLE_OAUTH = (
    "googleLogin(){this.windowRefService.nativeWindow.location.replace("
    "`${Ow}?client_id=${this.clientId}&response_type=token`)}")

#: A redirect that really is attacker-fed -- the shipped sink of the layer.
TP_HASH = "<script>location.replace(location.hash.slice(1));</script>"
TP_PARAM = ("<script>var p=new URLSearchParams(location.search);"
            "location.replace(p.get('next'));</script>")
TP_LOOKBEHIND = ("<script>var t = new URLSearchParams(location.search)"
                 ".get('redirect'); if (t) { location.href = t; }</script>")


def _exploitable(html: str) -> bool:
    return rx.analyze_page(html)["exploitable"]


def test_the_bundle_fragment_is_no_longer_a_finding():
    """The self-quote is still IN the text; the judgment must not read it."""
    assert rx.USER_INPUT_RE.search(BUNDLE_HARDCODED), (
        "sample lost its shape: it no longer contains the indicator the old "
        "code keyed on, so this test would pass for the wrong reason")
    assert not _exploitable("<script>" + BUNDLE_HARDCODED + "</script>"), [
        s for s in rx.find_redirect_sinks(BUNDLE_HARDCODED)
        if s["exploitable"]]
    assert not _exploitable("<script>" + BUNDLE_OAUTH + "</script>")


def test_neighbouring_sink_is_not_this_sinks_source():
    """The only user-input reference sits AFTER our statement's end."""
    html = ("<script>window.location.replace(host+\"/home\");"
            "var q=new URLSearchParams(location.search).toString();"
            "</script>")
    assert not _exploitable(html), (
        "a source that feeds a different sink is not evidence about this one")
    # And the real thing, same file, still reads:
    assert _exploitable(TP_PARAM)


def test_a_previous_sink_in_the_lookbehind_is_not_the_source_either():
    """The other direction, and the one the statement bound cannot catch: in
    minified code `case 1:location.href="/a"` sits inside sink #2's 60-char
    look-behind, so if only the current match is masked, the neighbour's own
    left-hand side -- `location.href` -- vouches for a hardcoded
    `location.replace()`."""
    html = ('<script>switch(r){case 1:location.href="/a";break;'
            'case 2:window.location.replace(h+`/b`)}</script>')
    hits = rx.find_redirect_sinks(html)
    assert len(hits) >= 2, hits
    assert not any(s["exploitable"] for s in hits), [
        s["snippet"] for s in hits if s["exploitable"]]


def test_argument_side_source_still_fires():
    for html in (TP_HASH, TP_PARAM):
        assert _exploitable(html), html


def test_lookbehind_source_still_fires():
    """Taint assigned in the previous statement must still count."""
    assert _exploitable(TP_LOOKBEHIND)


#: One hardcoded destination per DANGER_SINKS row: no argument reads input.
HARDCODED = [
    'window.location = "/home";',
    'window.location.href = "/home";',
    'window.location.assign("/home");',
    'window.location.replace("/home");',
    'window.open("/home");',
    'window.location.search = "?a=1";',
    'window.location.hash = "#top";',
    'document.location = "/home";',
    'top.location = "/home";',
    'self.location = "/home";',
]


def test_no_hardcoded_destination_is_exploitable():
    for text in HARDCODED:
        assert not _exploitable("<script>" + text + "</script>"), text


def test_the_sample_table_covers_every_sink_row_and_nothing_else():
    """Bidirectional: every DANGER_SINKS row has a hardcoded sample, and every
    sample is a row.  A row added without a sample is a row nobody tested --
    the exact drift that let the call form stay unfixed for 97 phases."""
    rows = [pat for pat, _sev, _desc in rx.DANGER_SINKS]
    for pat in rows:
        hits = [t for t in HARDCODED if re.search(pat, t, re.IGNORECASE)]
        assert hits, f"no sample exercises sink row {pat!r}"
    for text in HARDCODED:
        assert any(re.search(pat, text, re.IGNORECASE) for pat in rows), text
    assert len(HARDCODED) == len(rows), (
        f"{len(HARDCODED)} samples vs {len(rows)} rows -- one of them drifted")


def test_judged_region_stays_bounded_on_unbalanced_input():
    """No scanner should claim an unbounded window; the 200-char budget since
    113b is the contract, so a source 400 characters past an unterminated
    call is out of evidence."""
    block = "location.replace(" + " " * 250 + "location.hash"
    assert not any(s["exploitable"]
                   for s in rx.find_redirect_sinks(block))
    assert len(block) > 260


def test_mask_span_includes_a_glued_qualifier_at_any_offset():
    """The qualifier lookup runs in a short window for 1 MB bundles; `pre`
    offsets are slice-relative, so an arithmetic slip un-masks `window.`
    silently -- the bundle tests would then pass only because the sink span
    alone happens to be enough.  Pin the offset directly."""
    block = "goToProfilePage(){window.location.replace(host+`/p`)}"
    m = rx.SINK_RE.search(block)
    s, e = rx._mask_span(block, m)
    assert block[s:e].startswith("window.location.replace("), block[s:e]
    masked = block[:s] + " " * (e - s) + block[e:]
    assert not rx.USER_INPUT_RE.search(masked), masked


def test_mask_span_keeps_the_right_hand_side():
    """The 113b mask stopped at the `=` on purpose: the pattern
    ``location.href =\\s*[^;\\n]`` eats one RHS character, and in
    ``location.href = location.hash`` that character is the ``l`` of the
    source.  Blanking the whole match would silence the true positive."""
    block = "location.href = location.hash.slice(1)"
    m = rx.SINK_RE.search(block)
    assert m.group(0).endswith("l"), m.group(0)   # the eaten character
    s, e = rx._mask_span(block, m)
    assert rx.USER_INPUT_RE.search(block[:s] + " " * (e - s) + block[e:]), \
        "mask ate the source"
    # The counter-example: blanking the match as such is what breaks it.
    whole = block[:m.start()] + " " * (m.end() - m.start()) + block[m.end():]
    assert "ocation.hash" in whole and not rx.USER_INPUT_RE.search(whole)
