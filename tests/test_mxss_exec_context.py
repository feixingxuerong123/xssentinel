# -*- coding: utf-8 -*-
"""Phase 128: the mXSS confirmation path was escaping-blind.

`verifier._mxss_confirm` used to ask "does the token appear anywhere in the
response AND does the page carry a mutating sink?".  `mutation.analyze`'s
`reflected` flag is a bare substring test, so an **HTML-escaped** token
sitting in a text node counted as reflected -- and any page with
innerHTML/DOMParser in a script then produced a high-severity `reflected`
finding the moment the token appeared.  That fires on every ordinary app
that escapes its output while carrying a mutating sink.

The fix requires the token to have landed in a genuinely EXECUTABLE context
in the served bytes (`verifier._marker_in_exec_context`), which itself had
to be escape-aware: its handler/URI patterns originally scanned the whole
document, so `&lt;img src=x onerror=alert(&#x27;TOKEN&#x27;)&gt;` inside a
text node matched.
"""
from __future__ import annotations

import html as html_mod
import os
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import mutation
from xssentinel.core.verifier import _marker_in_exec_context, _mxss_confirm

TOKEN = "xssv_abc123"

# Phase 257: a mutating sink has to be able to turn a string into live
# markup.  ``DOMParser.parseFromString`` alone only PARSES -- the parsed tree
# has to be INSERTED for any of it to reach the live DOM (the Phase 185
# rebuild chain), so the fixture now completes the chain.  A page that merely
# mentions parseFromString is not a sink; see
# TestMutatingSinkNeedsTheInsertionStep.
_SINK_SCRIPT = ("<script>var d = new DOMParser().parseFromString("
                "document.getElementById('stage').textContent, 'text/html');"
                " document.body.appendChild(d.body);</script>")

# The parse half on its own: parses the CONSTANT 'x' and does nothing with the
# result.  This is what the /fuzz/render ``sink=dom`` feature is, and it is
# what the layer used to count as a mutating sink.
_PARSE_ONLY_SCRIPT = ("<script>var d = new DOMParser().parseFromString('x',"
                      "'text/html');</script>")

_LIVE = "<img src=x onerror=alert(1)>"


def _esc(value: str) -> str:
    return html_mod.escape(value, quote=True)


class TestMarkerInExecContext:
    """The static exec-context judgement must not see through escaping."""

    def test_raw_reflected_handler_counts(self):
        page = "<div><img src=x onerror=alert('%s')></div>" % TOKEN
        assert _marker_in_exec_context(page, TOKEN) is True

    def test_escaped_text_node_does_not_count(self):
        page = ("<div id=stage>%s</div>"
                % _esc("<img src=x onerror=alert('%s')>" % TOKEN))
        assert _marker_in_exec_context(page, TOKEN) is False

    def test_handler_inside_another_attribute_value_does_not_count(self):
        page = '<img alt="x onerror=alert(\'%s\')">' % TOKEN
        assert _marker_in_exec_context(page, TOKEN) is False

    def test_live_script_block_counts(self):
        page = '<script>var x = "%s";</script>' % TOKEN
        assert _marker_in_exec_context(page, TOKEN) is True

    def test_javascript_uri_counts(self):
        page = "<a href=\"javascript:alert('%s')\">x</a>" % TOKEN
        assert _marker_in_exec_context(page, TOKEN) is True

    def test_quoted_handler_value_counts(self):
        page = "<svg onload=\"alert('%s')\"></svg>" % TOKEN
        assert _marker_in_exec_context(page, TOKEN) is True

    def test_absent_marker(self):
        assert _marker_in_exec_context(
            "<div>nothing</div>", TOKEN) is False
        assert _marker_in_exec_context("", TOKEN) is False


class TestMxssConfirmIsNotEscapingBlind:
    """The verifier branch that produced the false positive."""

    def test_escaped_reflection_beside_a_sink_is_not_confirmed(self):
        page = ("<div id=stage>%s</div>%s"
                % (_esc("<img src=x onerror=alert('%s')>" % TOKEN),
                   _SINK_SCRIPT))
        assert _mxss_confirm(page, TOKEN, page.find(TOKEN)) is None

    def test_raw_reflection_beside_a_sink_is_confirmed(self):
        page = ("<div id=stage><img src=x onerror=alert('%s')></div>%s"
                % (TOKEN, _SINK_SCRIPT))
        verdict = _mxss_confirm(page, TOKEN, page.find(TOKEN))
        assert verdict and verdict.get("confirmed") is True

    def test_escaped_reflection_without_a_sink_is_not_confirmed(self):
        page = "<div id=stage>%s</div>" % _esc(
            "<img src=x onerror=alert('%s')>" % TOKEN)
        assert _mxss_confirm(page, TOKEN, page.find(TOKEN)) is None


class TestMutatingSinkNeedsReachableInput:
    """Phase 257: a parser that only ever sees a constant is not a sink.

    The mXSS question is "can the reflected value reach the parser?", not
    "is a mutation-capable API mentioned?".  A ``parseFromString('x', ...)``
    parses attacker-independent bytes, so on its own it is not a mutating
    sink; a ``parseFromString(stage.textContent, ...)`` can carry attacker
    bytes and still is, even though this benchmark writes the result back
    with textContent.

    The INSERTION half is deliberately NOT required: pos-mx-01's sink is
    ``parseFromString(document.getElementById('stage').textContent,
    'text/html')`` and its result is written with textContent.  An earlier
    cut of this fix required an insertion API and turned that case FN -- the
    full 192-case matrix caught it, the 64-case quick slice did not.

    Measured by the FN net's FP arm on /fuzz/render -- ctx=script_dq and
    ctx=script_sq x esc=encode_quotes x sink=dom: the payload lands inside a
    JS string literal, where the sandbox calls it INERT ("token sits in a JS
    string literal that is data, not a call argument") and the round-trip
    serialisation is byte-identical, while the page parses the CONSTANT 'x'
    and writes it out with textContent.  There is no path from the reflected
    value to the parser at all, yet the layer reported mutation_xss, because
    ``MUTATING_SINKS`` counted ``DOMParser`` and ``parseFromString`` as
    mutating sinks in their own right.

    Same family as the Phase 251 SVG pattern: the layer fired on a PAGE
    FEATURE instead of on the reflection.
    """

    def test_parse_only_is_not_a_mutating_sink(self):
        page = "<div id=stage>%s</div>%s" % (_LIVE, _PARSE_ONLY_SCRIPT)
        assert mutation.has_mutating_sink(page) == []

    def test_parse_of_dynamic_content_is_a_mutating_sink(self):
        """This is pos-mx-01's shape, and it must keep counting.

        Parses ``stage.textContent`` (attacker bytes) and writes the result
        back with textContent -- no markup insertion anywhere.  The scanner
        reports the mutation RISK, not a proven insertion.
        """
        reparse = ("<script>var doc = new DOMParser().parseFromString("
                   "document.getElementById('stage').textContent,"
                   " 'text/html');"
                   "document.getElementById('out').textContent ="
                   " doc.body.textContent;</script>")
        page = "<div id=stage>%s</div><div id=out></div>%s" % (_LIVE, reparse)
        assert mutation.has_mutating_sink(page) != []

    def test_a_concatenated_argument_counts_too(self):
        page = ("<div>%s</div><script>var d = new DOMParser()"
                ".parseFromString('a' + q, 'text/html');</script>" % _LIVE)
        assert mutation.has_mutating_sink(page) != []

    def test_direct_markup_sink_needs_no_chain(self):
        page = ("<div id=stage>%s</div><script>e.innerHTML = s;</script>"
                % _LIVE)
        assert mutation.has_mutating_sink(page) == ["innerHTML"]

    def test_analyse_refuses_a_parse_only_page(self):
        r = mutation.analyze(
            "<div>%s</div>%s" % (_LIVE, _PARSE_ONLY_SCRIPT), _LIVE)
        assert r["exploitable"] is False

    def test_analyse_accepts_dynamic_input(self):
        r = mutation.analyze(
            "<div>%s</div>%s" % (_LIVE, _SINK_SCRIPT), _LIVE)
        assert r["exploitable"] is True

    def test_an_importnode_chain_counts_too(self):
        chain = ("<script>var d = new DOMParser().parseFromString(s,"
                 "'text/html'); document.body.appendChild("
                 "document.importNode(d.body, true));</script>")
        r = mutation.analyze("<div>%s</div>%s" % (_LIVE, chain), _LIVE)
        assert r["exploitable"] is True

    def test_confirm_credits_no_mutation_on_a_parse_only_page(self):
        """A parse-only page earns no mXSS credit.

        The live reflection itself is still picked up by the ordinary
        reflected path -- the strict gate stays FP0/FN0 with this change --
        what it does not get is an mXSS finding for a mutation that cannot
        happen.
        """
        page = ("<div id=stage><img src=x onerror=alert('%s')></div>%s"
                % (TOKEN, _PARSE_ONLY_SCRIPT))
        assert _mxss_confirm(page, TOKEN, page.find(TOKEN)) is None
