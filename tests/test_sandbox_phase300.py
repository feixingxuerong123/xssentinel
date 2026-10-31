"""Phase 300: three sandbox verdicts that contradicted measured Chromium.

All three were found by judging the payloads the scanner actually sends
(benchmark/oracle_default_sent.py: 160 cells, one host per family).  Each
was a MISSED or OVER in that set, and each has a browser measurement
behind it:

  1. `--!>` ends an HTML comment (WHATWG 13.2.5.43, comment-end-bang).
     The tokenizer knew only `-->`, so `<!--` + `--!><svg/onload=...>`
     stayed one comment and the breakout read as inert.  Chromium runs it
     (html_comment family, parser arm).

  2. `onerror="__x()//"` compiles.  `_js_parses(..., wrapped=True)` built
     `function __h(){ __x()// }`, where the line comment eats the closing
     brace -> "not valid JavaScript".  Chromium accepts the same value
     (markdown + html5_new families, both arms); `alert(1)//` is a
     standard corpus shape, so the false inert was not exotic.

  3. A `<script>` in the MathML namespace never executes; the same inside
     `annotation-xml[encoding=text/html]` does (integration point), and
     SVG's does.  Measured in Chromium for all four shapes.  The sandbox
     credited every `script` node regardless of namespace, which made
     `<math><annotation encoding=text/html><script>...</script>` a live
     claim the browser denies (one OVER in the same set).
"""
from __future__ import annotations

import pytest

from xssentinel.core import sandbox

TOKEN = "__x()"


def test_comment_end_bang_closes_the_comment():
    """The breakout payload the oracle says Chromium executes."""
    doc = "<html><body><!----!><svg/onload=__x()>--></body></html>"
    assert sandbox.judge(doc, TOKEN, sink="parser").state == "live"


def test_plain_comment_still_swallows_the_payload():
    doc = "<html><body><!--<svg/onload=__x()>--></body></html>"
    assert sandbox.judge(doc, TOKEN, sink="parser").state == "inert"


def test_handler_trailing_line_comment_compiles():
    """`__x()//` is valid JS; the wrapper must not swallow its own brace."""
    # `_js_parses` is tri-state: None means "no parser installed", not "inert".
    # Asserting `is True` without this guard makes a core-only install (no
    # `ast` extra) report a failure that says nothing about the sandbox.
    if sandbox._js_parses("1") is None:
        pytest.skip("esprima not installed (pip install xssentinel[ast])")
    assert sandbox._js_parses("__x()//", wrapped=True) is True
    doc = "<html><body><div><img src=x onerror=__x()//></div></body></html>"
    assert sandbox.judge(doc, TOKEN, sink="parser").state == "live"
    assert sandbox.judge(doc, TOKEN, sink="innerhtml").state == "live"


@pytest.mark.parametrize("doc,expect", [
    ("<html><body><math><script>__x()</script></math></body></html>",
     "inert"),
    ("<html><body><math><annotation encoding=text/html>"
     "<script>__x()</script></annotation></math></body></html>", "inert"),
    ("<html><body><math><annotation-xml encoding=text/html>"
     "<script>__x()</script></annotation-xml></math></body></html>", "live"),
    ("<html><body><svg><script>__x()</script></svg></body></html>", "live"),
    ("<html><body><script>__x()</script></body></html>", "live"),
])
def test_script_namespace_decides(doc, expect):
    assert sandbox.judge(doc, TOKEN, sink="parser").state == expect
