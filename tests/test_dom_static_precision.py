# -*- coding: utf-8 -*-
"""Regex sink-rule precision (Phase 354).

The DOM static layer runs an AST channel first and falls back to regex.  The
regex patterns are deliberately broad, and real pages contain three shapes that
were graded medium -- which the scanner REPORTS (low hints are suppressed):

  * `document.title = location.hash`          (router updating the tab title)
  * `setAttribute('aria-label', location...)` (accessibility attribute)
  * `$('#x').attr('title', location...)` / `.val(...)`  (non-markup jQuery)

These tests pin the narrowing: inert shapes must not reach medium/high, while
the executable attribute names and HTML sinks keep their grade.  Anything a
regex cannot decide (computed attribute names, cross-statement object identity)
is documented in README's capability boundary and left to the AST/browser arms.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import dom  # noqa: E402


def _grades(html):
    return [(f.get("sink"), f.get("confidence")) for f in dom.analyze(html, is_html=True)]


def test_title_router_is_text_only():
    html = "<script>document.title = location.hash.slice(1);</script>"
    assert not [g for g in _grades(html) if g[1] in ("medium", "high")]


def test_benign_setattribute_is_not_reported():
    html = ("<script>document.getElementById('m')"
            ".setAttribute('aria-label', location.hash);</script>")
    assert not [g for g in _grades(html) if g[1] in ("medium", "high")]


def test_executable_setattribute_still_reported():
    html = ("<script>document.getElementById('b')"
            ".setAttribute('onclick', location.hash);</script>")
    assert any("onclick" in (s or "") and c == "medium" for s, c in _grades(html))


def test_jquery_title_attr_is_not_reported_but_href_is():
    title = "<script>$('#m').attr('title', location.hash);</script>"
    href = "<script>$('#m').attr('href', location.hash);</script>"
    assert not [g for g in _grades(title) if g[1] in ("medium", "high")]
    assert any(c == "medium" for _, c in _grades(href))


def test_jquery_val_is_not_a_markup_sink():
    html = "<script>$('#m').val(location.hash);</script>"
    assert not [g for g in _grades(html) if g[1] in ("medium", "high")]


def test_jquery_prop_innerhtml_is_still_a_sink():
    html = "<script>$('#m').prop('innerHTML', location.hash);</script>"
    assert any("innerHTML" in (s or "") and c == "medium" for s, c in _grades(html))


def test_appendchild_capped_to_low():
    html = "<script>var l = location.hash; document.body.appendChild(l);</script>"
    rows = [g for g in _grades(html) if "appendChild" in (g[0] or "")]
    assert rows and all(c == "low" for _, c in rows), rows


def test_html_sinks_keep_their_grade():
    inner = "<script>document.getElementById('o').innerHTML = location.hash;</script>"
    write = "<script>document.write(location.hash);</script>"
    assert any(s == ".innerHTML" and c == "medium" for s, c in _grades(inner))
    assert any(s == "document.write" and c == "high" for s, c in _grades(write))
