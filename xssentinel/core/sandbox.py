"""Pure-Python HTML sandbox: decide whether reflected markup is LIVE, no browser.

Why this exists
---------------
`verifier.verify_semantic` answers "is the token inside an executable context"
from a BeautifulSoup tree plus hand-maintained sink tables.  `dom_engine` answers
the same question by launching Chromium at ~5.6 s per probe page, and
`mxss_verify` needs a browser for the parse->serialise->re-parse round-trip that
defines mutation XSS.  On an engagement that ordering is backwards twice over:
the browser is the slow, fragile, sometimes-unavailable path, and the question
"does `<img src=x onerror=...>` inside a `class="..."` value fire?" does not
need one -- it needs a parser that agrees with the browser about tokenisation
and serialisation.

This module is that parser.  It never *executes* a payload -- no JS engine runs,
and the only thing JavaScript is used for is reading a script body's lexical
states and syntax tree, so an XSS verdict becomes a structural fact about a DOM.
Three states, deliberately:

    LIVE      a node the browser would run is present, with the reason attached
    INERT     the token is present but cannot run (raw text, attribute value,
              dropped tag, ...).  Safe to report as a non-finding, and safe to
              skip the browser for.
    UNKNOWN   the sandbox does not model what it met.  Callers MUST fall back
              to the browser.  A sandbox that never says UNKNOWN is not
              conservative, it is wrong with more confidence.

Fidelity is measured, not assumed: `benchmark/sandbox_fidelity.py` scores every
row of `benchmark/results/browser_dom_oracle.json` (Chromium ground truth,
payload x context x sink) against this module, and every disagreement is a test.
`tests/test_sandbox_fidelity.py` replays that corpus in CI so a rule changed for
one payload cannot silently flip another.

What it models
--------------
* Tokeniser states the XSS decisions actually depend on: tag/attribute
  quote-state recovery, RAWTEXT (script/style/xmp/iframe/noembed/noframes),
  RCDATA (title/textarea), PLAINTEXT, <noscript> under scripting, bogus
  comments, CDATA in foreign content, character references consumed per state.
  U+0000 is per-context too, and the two halves point opposite ways: it becomes
  U+FFFD in tag names, attribute names, attribute values, comments, RCDATA and
  RAWTEXT, and is *dropped* in document text (benchmark/probe_nul.py).  Getting
  either half backwards manufactures a live <script> or a live javascript: URI
  out of a payload that cannot run.
* Foreign content: <svg>/<math> subtrees, MathML text integration points
  (mtext/mi/mn/mo/ms...) and SVG HTML integration points (foreignObject,
  desc, title), and the *measured* break-out set (benchmark/probe_breakout.py:
  40 names, identical for both namespaces).  Two consequences worth stating
  because they contradict the folklore: <style> inside <svg> is NOT raw text, so
  `<svg><style><img onerror=...>` is live on the FIRST parse rather than a
  mutation vector; and HTML void-ness does not cross the foreign boundary, so a
  `<base>` in SVG takes children.
* Insertion modes that move nodes: implicit <p> closing, the implied
  <tbody>/<tr>, **foster parenting** out of table scope, <select>/<option>
  scoping (measured name by name, 105 names x 3 contexts,
  benchmark/probe_option.py -- and it is *not* the spec's list: only `input`
  leaves an open select, 12 names are discarded outright, everything else stays
  where it sits), <template> content, the <body> attribute merge, stray end tags.
  Foster parenting matters beyond tidiness: moving an empty <table> is what
  re-orders a serialisation, and the re-order is what flips a namespace on the
  next parse (see `judge_roundtrip` and tests/test_sandbox.py's mutation test).
* Event semantics per element and per sink: which handler can fire without user
  interaction (`onerror` needs a src that can fail, `ontoggle` is a <details>
  event, `onload` on <svg>/<body> is a document event that does not re-fire for
  an innerHTML-inserted node), and whether the element's namespace gives it the
  HTML behaviour at all.
* The serialiser, because the round-trip is what mutation is judged on: text is
  escaped for & < > and nbsp everywhere *including* foreign content (measured --
  `<svg>` text is not an &-only zone), except inside the HTML no-escaping
  elements, which write verbatim; attribute values escape & " < > and controls.
* JavaScript, read but not run: whether a script body or an inline handler
  compiles at all, and whether the token sits in code, in a data string, or in
  the argument of the alert-family call the marker was stamped into.

Usage
-----
    from xssentinel.core import sandbox
    v = sandbox.judge(document_html, token)        # -> Verdict(state, reason)
    sandbox.roundtrip(html)                        # -> [ser1, ser2, ...]

    python -m xssentinel.core.sandbox --payload '<img src=x onerror=alert(1)>' \\
            --host attr_dq --token alert
"""
from __future__ import annotations

import json
import re
from typing import Optional

try:                          # optional extra; js validity gating degrades to
    import esprima as _esprima  # type: ignore[import-untyped]  # "cannot decide" without it
except ImportError:           # noqa: E402
    _esprima = None

# ---------------------------------------------------------------------------
# Element classification tables
# ---------------------------------------------------------------------------

#: <script> and <style> contents are tokenised as raw text: no entities, and
#: only the matching close tag ends them.

# Re-exported so every name that used to live in this module is
# still reachable as `sandbox.<name>` -- external callers include
# benchmark/probe_svg_case.py (_SVG_ATTR_CASE, _MATHML_ATTR_CASE)
# and benchmark/probe_breakout.py (FOREIGN_BREAK).
from .sandbox_common import (
    Doc,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    MATHML_TEXT_INTEGRATION,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    NO_ESCAPE_TEXT,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    Node,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    SVG_HTML_INTEGRATION,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    VOID,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    serialize_text,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
)
from .sandbox_parser import (
    AUTO_CLOSE,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    FOREIGN_BREAK,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    FRAMESET_OK_KILLERS,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    FRAMESET_ONLY_STARTS,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    OPTION_SCOPE,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    PLAINTEXT,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    P_CLOSERS,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    RAWTEXT,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    RCDATA,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    SELECT_DROPPED,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    SELECT_END_OPTION,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    SELECT_END_SCOPE,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    SELECT_EXITS,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    TABLE_CONTEXT,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    TABLE_OK_IN,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    TABLE_ONLY_STARTS,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    TABLE_SCOPE,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    Token,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    _MATHML_ATTR_CASE,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    _NAMED,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    _Parser,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    _SVG_ATTR_CASE,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    _SVG_CASE,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    _adjust_foreign,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    _adjust_foreign_attr,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    _attr_value_end,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    _close_rawtext,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    _comment,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    _decode_ref,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    _read_name,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    _skip_ws,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
    decode_entities,  # noqa: F401  (re-export:外部按 sandbox.<name> 访问)
)

#: Scripting is enabled in every browser we care about, so <noscript> is
#: raw text -- the vector family that depends on it only bites after a
#: serialise/re-parse into a *scripting-disabled* context.
NOSCRIPT_RAWTEXT = frozenset({"noscript"})


# ---------------------------------------------------------------------------
# Sink semantics -- which attribute/element pairs can actually RUN.
#
# Every entry below is traceable to a measurement, not to memory:
#   benchmark/sink_execution.py  (2026-09-18, headless Chromium, per-shape)
#   benchmark/results/browser_dom_oracle.json (payload x context x sink)
# An unmeasured shape is UNKNOWN and the caller is told so; that is the whole
# reason the three-state Verdict exists.
# ---------------------------------------------------------------------------

#: javascript: URI sinks that execute with no user activation.
JS_URI_EXECUTES = {("iframe", "src"), ("frame", "src")}


#: javascript: URI sinks that are real XSS behind a user gesture.  Chromium
#: will not run a javascript: URI from a script-synthesised click at all
#: (measured: `a.href = javascript:CODE (synthetic click)` and even the
#: trusted-click shape both no-exec in that harness), so only a human clicking
#: the link completes the chain -- hence "activation", never "executes".
JS_URI_ACTIVATION = {
    ("a", "href"), ("area", "href"), ("form", "action"),
    ("button", "formaction"), ("input", "formaction"), ("select", "formaction"),
    # An SVG anchor's `xlink:href` is the same sink as its `href`: measured no
    # execution on load, execution on a trusted mouse click, with and without the
    # `xmlns:xlink` declaration (benchmark/probe_svg_ns.py).  The row only means
    # anything once the `<a>` has a box to click, which is why those payloads
    # carry a sized `<svg>` and a `<text>` child.
    ("a", "xlink:href"),
}


#: Measured NOT to execute a javascript: URI.  Listed because the absence of a
#: table entry would be UNKNOWN, and "unknown" is expensive: it sends the
#: scanner back to a 5.6 s browser probe for a shape we have proved inert.
#: `frame.src` is deliberately absent -- it executes (see JS_URI_EXECUTES), and
#: having it in both tables once meant the rule below was reachable only by the
#: order of two dict lookups.
JS_URI_INERT = {
    ("img", "src"), ("link", "href"), ("script", "src"), ("base", "href"),
    ("embed", "src"), ("object", "data"), ("source", "src"),
    ("track", "src"), ("video", "src"), ("audio", "src"),
    ("input", "src"),
    # meta refresh to a javascript: URL: measured no-exec (Chromium dropped
    # javascript: in meta refresh long ago).
    ("meta", "content"),
    # The foreign-content resource sinks: `<svg><image href>`, `<use xlink:href>`
    # and `<feImage href>` all measured no-exec, and none of them has a gesture
    # that could make them run -- a user click cannot re-resolve an image
    # reference the way it can follow an anchor (benchmark/probe_svg_ns.py).  The
    # MathML `<maction xlink:href>` sibling is deliberately NOT here: relocate
    # wants a click on a MathML element that gets no box to click, so the
    # question stayed unasked and the verdict stays UNKNOWN.
    ("image", "href"), ("image", "xlink:href"),
    ("use", "xlink:href"), ("feimage", "href"),
    # The attribute-absorption shapes.  In an unquoted attribute context the
    # payload's own tag never becomes an element: `<div class=<a href="javascript:
    # CODE">` builds a DIV that carries an attribute called `href`, and a div has no
    # navigation machinery to give it -- measured on the `attr_unq` rows of the
    # stamped oracle (benchmark/results/browser_dom_oracle.json), False on the
    # parser arm AND on both innerHTML arms, and no user gesture can turn a `div`
    # into an anchor after the fact, so this is the bounded kind of False.
    # `img.href` is the same story one step along: `<image>` renames to `img` in
    # HTML content, and `img` loads `src`, never `href`.
    ("div", "href"), ("div", "src"), ("div", "data"), ("div", "action"),
    ("img", "href"),
}


#: Events that fire without user interaction, and the elements they can fire on
#: once the node has been inserted by the *parser*.  A handler on anything not
#: listed here is a real vulnerability one click away -> activation, not inert.
AUTO_FIRING_EVENTS = {
    "onerror": {"img", "script", "iframe", "source", "video", "audio", "link",
                "object", "embed", "input", "track"},
    "onload": {"svg", "body", "frameset", "iframe", "frame", "object", "img",
               "script", "link", "vmlframe"},
    "ontoggle": {"details"},
    "onfocus": {"*"},            # only with autofocus; see _handler_state
    "onbrowsersubmit": {"*"},
    "onbeforetoggle": {"details"},
    "onscroll": {"*"},           # fires on restore; treat as auto
}


#: SMIL timing events.  These were listed as auto-firing on `{'*'}` while
#: `judge` simultaneously demanded user interaction -- and both halves were
#: wrong: a SMIL timeline belongs to the animation element, not to any element.
#: Measured element x event x `begin` value in
#: benchmark/results/smil_probe.json (23 shapes, both sinks).
SMIL_TIMING_EVENTS = frozenset({"onbegin", "onend", "onrepeat"})


#: The SMIL elements that really do start a timeline on their own: `<animate
#: onbegin>` fires within 300 ms of the parse with no interaction, in the
#: document parse *and* through innerHTML.
SMIL_TIMING_ELEMENTS = frozenset({"animate", "set", "animatetransform",
                                  "animatemotion"})


#: SMIL-adjacent elements measured NOT to fire their timing handler.  `<discard>`
#: is the instructive one: it is an animation element, and it still does not
#: raise `begin` here, so the set above is a measured list rather than "anything
#: SMIL-looking".
SMIL_TIMING_INERT = frozenset({"discard", "svg", "circle", "rect"})


#: A SMIL clock value: `0s`, `2s`, `1.5s`, or a bare number (seconds implied).
#: Anything else in `begin` is offset/event/syncbase syntax and is not measured.
_SMIL_CLOCK_RE = re.compile(r"^\d+(\.\d+)?(s|ms)?$")


#: `begin="<dom event>"` waits for that event, which is what `activation` means
#: here: not inert, but not something the gate may promote either.
SMIL_GESTURE_TRIGGERS = frozenset({
    "mouseover", "mouseout", "mousedown", "mouseup", "click", "dblclick",
    "focus", "blur", "keypress",
})


#: Media *loading* events, measured on `<audio>` with a loadable src: they fire
#: with no user interaction, in every context that instantiates the element
#: (plain div, `<select><option>`, `<table><td>`, `<svg><foreignObject>`) and in
#: neither a `<template>` nor an unquoted-attribute swallow.  See
#: benchmark/results/media_probe.json -- 19 shapes x 6 reflection contexts.
#:
#: Deliberately only these six.  `onplaying`/`onended`/`ontimeupdate` belong to
#: playback, which autoplay policy gates (`video ontimeupdate` measured no-exec
#: in all six contexts), so they stay in the generic tail rather than being swept
#: in by the family name.  `<video>` uses the same loading machinery but was not
#: measured for these events, so it is not claimed either.
MEDIA_LOAD_EVENTS = frozenset({
    "onloadstart", "ondurationchange", "onloadedmetadata", "onloadeddata",
    "oncanplay", "oncanplaythrough",
})


#: The only elements a media event can be dispatched to.  `<audio>` is the one
#: measured here; the rest keep the sandbox out of claiming a verdict for a
#: loading path it has not watched.
MEDIA_EVENT_TARGETS = frozenset({"audio", "video", "source", "track"})


#: CSS animation events.  Both sides measured and they cancel out: an inline
#: `animation:` fires by itself only where the `@keyframes` rule actually exists,
#: and deciding that needs stylesheet resolution, which this module does not do.
#: So `_css_animation_state` declines; the name is kept here as the marker for
#: which it declines.
CSS_ANIMATION_EVENTS = frozenset({"onanimationstart", "onanimationend",
                                  "onanimationiteration"})


#: Elements the HTML spec makes focusable without help.  Anything else becomes
#: focusable with `tabindex`, which is why `_handler_state` has to test both --
#: a form-control-only list called `<span tabindex=1 autofocus onfocus=...>`
#: inert, and that shape fired in Chromium.
FOCUSABLE_CONTROLS = frozenset({
    "input", "button", "select", "textarea", "a", "area", "summary",
    "details", "dialog", "audio", "video", "object", "embed", "label",
    "legend", "option", "optgroup", "slot",
})


#: `on` + letters.  A NUL in a handler name becomes U+FFFD and a `<x one-error>`
#: style name is not a handler at all; both must be rejected before they can be
#: scored as an event.
_HANDLER_NAME_RE = re.compile(r"^on[a-z]+$")



def _svg_case(name: str) -> tuple[str, str]:
    """Foreign content adjusts a handful of tag names and camel-cases SVG
    elements.  Getting `foreignObject`/`annotation-xml` wrong changes whether a
    subtree is HTML or foreign, i.e. whether a payload is live."""
    low = name.lower()
    if low in ("foreignobject",):
        return "foreignObject", "svg"
    if low in ("desc", "title"):
        return low, "svg"
    return low, "svg"



def parse(html: str, fragment: bool = True) -> Doc:
    """Build a DOM from `html` the way a browser parser would.

    `fragment=True` is `div.innerHTML = html` (a client-side template sink);
    `fragment=False` is the document the server sent.  They differ on two
    measured points: the fragment parser throws away <html>/<head>/<body>
    themselves while keeping their children, and the document parser merges a
    second <body>'s attributes onto the live one -- which is the difference
    between inert and a real `<body onload=...>` finding.

    Not a full spec implementation: insertion behaviour is modelled where it
    changes whether markup ends up live (raw-text/RCDATA content models, foreign
    content and its break-out set, implicit <p> closing, <select>/<option>
    scoping, <template>) and skipped where it cannot.  What the parser could not
    decide lands in `notes`, and `judge()` turns that into UNKNOWN instead of a
    guess.
    """
    # Input preprocessing, before the tokenizer sees anything: every CRLF and
    # every lone CR becomes LF.  Measured, and it survives into the DOM -- an
    # attribute value written as `x="\r"` is read back and re-serialised as
    # `x="\n"` (benchmark/results/attr_escape.json), so modelling it here rather
    # than in the serialiser is what keeps the second round-trip honest.
    html = html.replace("\r\n", "\n").replace("\r", "\n")
    return _Parser(html, fragment=fragment).run()



def _is_integration(node: Node) -> bool:
    lname = node.name.lower()
    if node.ns == "svg" and lname in SVG_HTML_INTEGRATION:
        return True
    if node.ns == "mathml" and lname in MATHML_TEXT_INTEGRATION:
        return True
    return False



def _serialize_attr_value(v: str) -> str:
    # Exactly what Chromium escapes in an attribute value, measured character by
    # character across all three quoting styles
    # (benchmark/results/attr_escape.json): `&`, `"`, `<`, `>` and U+00A0 --
    # and *nothing else*.  Two directions were wrong here before:
    #   * tab / newline / carriage return were being turned into `&#9;` /
    #     `&#10;` / `&#13;`.  Chromium writes them raw, so inventing character
    #     references changes the bytes a round-trip is judged on.
    #   * U+00A0 was written raw, where Chromium emits `&nbsp;`.
    # Every other C0 control (0x01, 0x0C, 0x1F, measured) passes through unharmed,
    # so this is deliberately not "escape all controls".
    return (v.replace("&", "&amp;").replace('"', "&quot;")
             .replace("<", "&lt;").replace(">", "&gt;")
             .replace("\xa0", "&nbsp;"))



def serialize(node: Node) -> str:
    out: list[str] = []
    for c in node.children:
        if c.kind == "text":
            out.append(serialize_text(c))
        elif c.kind == "comment":
            out.append(f"<!--{c.name}-->")
        elif c.kind == "element":
            tag = c.name
            attrs = "".join(f' {k}="{_serialize_attr_value(v)}"'
                            for k, v in c.attrs)
            if c.ns == "html" and tag in VOID:
                out.append(f"<{tag}{attrs}>")
                continue
            out.append(f"<{tag}{attrs}>")
            out.append(serialize(c))
            out.append(f"</{tag}>")
    return "".join(out)



def roundtrip(html: str, times: int = 3) -> list[str]:
    """parse -> serialise -> parse -> ...  Returns each serialisation.

    Two consecutive entries that differ but yield a *different* liveness verdict
    is mutation XSS; the list is what makes that visible rather than guessed.
    """
    cur = html
    out: list[str] = []
    for _ in range(times):
        cur = serialize(parse(cur).root)
        out.append(cur)
    return out



# ---------------------------------------------------------------------------
# Liveness / verdict
# ---------------------------------------------------------------------------

class Verdict:
    __slots__ = ("state", "reason", "node", "activation", "evidence")

    def __init__(self, state: str, reason: str, node: Optional[Node] = None,
                 activation: bool = False, evidence: str = ""):
        self.state = state          # live | inert | unknown
        self.reason = reason
        self.node = node
        self.activation = activation
        self.evidence = evidence

    def __bool__(self) -> bool:
        return self.state == "live"

    def to_dict(self) -> dict:
        return {"state": self.state, "reason": self.reason,
                "requires_activation": self.activation,
                "evidence": self.evidence}

    def __repr__(self) -> str:
        return f"Verdict({self.state},{self.reason!r})"



def _smil_state(el: Node, ev: str, nested: bool = False) -> tuple[str, str]:
    """Does a SMIL timing handler (`onbegin`/`onend`/`onrepeat`) ever start?

    The answer belongs to the *element*, its namespace and its `begin` value, not
    to the handler name.  Measured 23 shapes in both sinks, then re-measured
    across 20 reflection hosts (1200-row oracle):
    `<svg><animate onbegin=CODE>` executes within the load itself and again
    through innerHTML; the same attribute on a `<div>`, `<p>`, `<input>`, on the
    `<svg>` root, on the animation's target `<circle>`, or on `<discard>` never
    fires; `begin="indefinite"` never fires, `begin="mouseover"` waits for the
    mouse, and `begin="2s"` needs time rather than a gesture.
    """
    name = el.name.lower()
    # Namespace first, and the reflection hosts are what prove it: an
    # unquoted `class=<svg><animate onbegin=...>` swallows the `<svg>` into the
    # attribute value and leaves `<animate>` as an HTML element.  The browser's
    # own serialisation shows that shape and does not execute it -- an element
    # merely *named* animate has no SMIL timeline.
    if name in SMIL_TIMING_ELEMENTS and el.ns == "svg":
        if nested:
            # Decline, and here is what has been ruled OUT, because the obvious
            # explanations are all false (benchmark/results/smil_probe.json):
            #   * "nested timelines do not run" -- `<iframe srcdoc='...animate
            #     onbegin...attributeName="x"...'` executes, both arms.
            #   * "the quote truncation empties the handler" -- the outer parse
            #     is byte-identical to the browser's here, and the nested value
            #     really is `<svg><animate onbegin=__x() attributeName=`.
            #   * "an empty or absent attributeName kills the timeline" -- the
            #     same truncated markup in a complete document DOES fire:
            #     `attributeName=""`, bare `attributeName`, and no
            #     attributeName at all are all live.
            # What is left is a difference between an unterminated start tag at
            # the end of a nested document and the same markup in a complete one.
            # Nothing here explains it, so nothing claims a verdict either way.
            return "unknown", (f"{name}.{ev} in an attribute-parsed nested "
                               f"document: measured no-exec, unexplained")
        begin = (el.get("begin") or "").strip().lower()
        if not begin or _SMIL_CLOCK_RE.match(begin):
            return "live", (f"{name}.{ev} starts on its own "
                            f"(begin={begin or 'default'}, measured)")
        if begin == "indefinite":
            return "inert", (f'{name}.{ev}: begin="indefinite" only starts when '
                             f"a script calls beginElement()")
        if begin in SMIL_GESTURE_TRIGGERS:
            return "activation", f"{name}.{ev} waits for {begin}"
        return "unknown", f'{name}.{ev} with begin="{begin}" is not measured'
    if name in SMIL_TIMING_INERT or el.ns == "html":
        return "inert", (f"{name}.{ev} has no SMIL timeline of its own "
                         f"(measured no-exec)")
    return "unknown", f"{name}.{ev} is not measured on a {el.ns} element"



def _css_animation_state(el: Node, ev: str) -> tuple[str, str]:
    """`onanimationstart` needs a running animation, which is a CSS answer.

    Measured both sides: `<style>@keyframes k{...}</style>` plus an inline
    `animation:k 1s` fires with no interaction, while reflecting the *same two
    declarations* through an unquoted attribute or a `<style>` host fires nothing,
    because the `@keyframes` rule never comes into existence -- it is text.  An
    inline `animation:` therefore proves nothing by itself, and deciding which
    animation names a page's stylesheets define is outside this module.
    Declining is the only claim both measurements support.
    """
    return "unknown", (f"{el.name}.{ev} needs a running CSS animation whose "
                       f"@keyframes is actually defined; stylesheets are not "
                       f"resolved here")



def _handler_state(el: Node, attr: str, sink: str = "parser",
                   nested: bool = False) -> tuple[str, str]:
    """Can this on* handler fire without the user touching anything?

    Three things gate the answer, and a rule that checks only the handler name
    gets all three wrong:

      * the element.  `ontoggle` is a <details> event; on a div it never fires.
        Attribute-context payloads routinely move a handler onto the wrong
        element (an unquoted `class=` swallows `<details open ontoggle=...>`
        into the div's own attribute list), which is where the over-claims came
        from.
      * the trigger.  `onerror` needs a resource that can fail; `onfocus` needs
        `autofocus` on something focusable.
      * the sink.  `onload` on <svg>/<body> fires when the *document* loads and
        does not re-fire for a node a script inserted via innerHTML -- both
        measured, in benchmark/results/browser_dom_oracle.json.
    """
    ev = attr.lower()
    name = el.name.lower()
    # SMIL and CSS-animation events gate on the element and its own attributes,
    # not on the namespace, so they are settled before the foreign check --
    # `<animate>` is always in the SVG namespace, and the old blanket "not
    # measured" answer there is what left this whole payload family unjudged.
    if ev in SMIL_TIMING_EVENTS:
        return _smil_state(el, ev, nested)
    if ev in CSS_ANIMATION_EVENTS:
        return _css_animation_state(el, ev)
    st, why = _foreign_handler_state(el, ev, sink)
    if st:
        return st, why
    if ev == "onerror":
        if name not in AUTO_FIRING_EVENTS["onerror"]:
            return "activation", f"{name}.{ev} needs an element that can error"
        if name in ("source", "track"):
            # A <source>/<track> is only processed inside a media element (or
            # <picture>); on its own it never attempts a load, so there is no
            # error to fire.  `<track>` is the measured one: an unquoted
            # `class=<video><track onerror=CODE src=...>` leaves the track as a
            # child of the div, and the browser fetches nothing.
            parent = (el.parent.name.lower() if el.parent else "")
            if parent not in ("video", "audio", "picture"):
                return "inert", (f"{name}.onerror needs a <video>/<audio>/"
                                 f"<picture> parent; a bare {name} is never "
                                 f"processed")
            return "live", (f"{name}.onerror fires when the media source fails"
                            if name == "source" else
                            f"{name}.onerror fires when the track file fails")
        # No src/href means no fetch is ever attempted, so there is no error
        # event to fire.  This is what actually kills the `sr<NUL>c=` bypass:
        # the handler survives, but the attribute that would have failed to
        # load no longer exists under that name.
        # For most elements no src means no fetch and therefore no error event.
        # <source> is the exception, and it is the one a media-element payload
        # relies on: a <source> whose src is absent fires `error` anyway.
        src_attr = "href" if name in ("link", "iframe") else "src"
        src = el.get(src_attr)
        if src is None and name != "source":
            return "inert", (f"{name}.{ev} is present but {src_attr} is absent, "
                             f"so nothing is fetched and no error fires")
        if src == "":
            return "inert", (f"{name}.{ev} has an empty {src_attr}: no load is "
                             f"attempted, so no error fires")
        return "live", f"{name}.{ev} fires when the {src_attr} resource fails"
    if ev == "onload":
        resource_load = name in ("img", "iframe", "frame", "link", "script",
                                 "object", "embed")
        if name in ("svg", "body"):
            # Measured: live through the parser, inert through innerHTML.  A
            # document-load event has already happened by the time a template
            # sink inserts the node.
            if sink == "parser":
                return "live", f"{name}.{ev} fires when the document loads"
            return "inert", (f"{name}.{ev} is a document-load event and does not "
                             f"re-fire for a node inserted via innerHTML")
        if resource_load:
            return "live", f"{name}.{ev} fires when the resource loads"
        return "activation", f"{name}.{ev} may not fire on an injected node"
    if ev == "onfocus":
        # What makes an element focusable is `autofocus` plus focusability, and
        # focusability is NOT limited to form controls: `tabindex` makes any
        # element focusable.  Measured over benchmark/results/autofocus_probe.json
        # -- span / a / img / li / button / textarea / video / input all fire with
        # `tabindex=1 autofocus`, so restricting this list to form controls was a
        # false negative waiting for the first `<div tabindex=1 autofocus
        # onfocus=...>` payload (a staple) to come through.
        attrs = dict(el.attrs)
        focusable = name in FOCUSABLE_CONTROLS or "tabindex" in attrs
        if not focusable:
            return "inert", (f"{name}.onfocus cannot fire: no tabindex and "
                             f"{name} is not a focusable control")
        if "autofocus" not in attrs:
            return "activation", "onfocus needs focus (autofocus attribute absent)"
        if name == "div":
            # Measured the opposite way twice: every other element with the same
            # attributes fired, `div` did not, and the difference is not
            # something this module can explain.  Guessing "inert" here would
            # bury a common payload, so the contradiction is reported rather than
            # resolved by a coin flip.
            return "unknown", ("div with tabindex+autofocus measured inconsistently "
                               "against every other element; needs the browser")
        return "live", f"{name}.onfocus fires via autofocus (focusable element)"
    if ev in ("ontoggle", "onbeforetoggle"):
        if name != "details":
            return "inert", (f"{name}.{ev} cannot fire: toggle is a <details> "
                             f"event")
        if "open" in dict(el.attrs):
            return "live", f"details.{ev} fires for details[open]"
        return "activation", "ontoggle needs the element to be toggled"
    if ev in MEDIA_LOAD_EVENTS:
        if name not in MEDIA_EVENT_TARGETS:
            # A media event is dispatched to a media element; a `<div>` cannot be
            # its target.  Measured, not read off the spec: an unquoted
            # `class=<audio oncanplay=CODE ...>` never forms the `<audio>`, the
            # handler lands on the div, and the browser executes nothing.
            return "inert", (f"{name}.{ev}: media events are only dispatched to "
                             f"media elements (measured no-exec)")
        if name != "audio":
            return "activation", (f"{name}.{ev} is not measured; only the six "
                                  f"<audio> loading events were")
        src = (el.get("src") or "").strip()
        if not src:
            # Nothing is fetched, so the load never starts and no load event can
            # fire.  Measured in all six contexts: `<audio oncanplay=CODE>` with
            # no src is dead, and so is `src=""`.
            return "inert", (f"audio.{ev} has no src: nothing loads, so no load "
                             f"event fires (measured)")
        if ev == "onloadstart":
            # `loadstart` is the one event that does not care what happens next:
            # measured live both with a decodable data: URI *and* with a src that
            # 404s, because the attempt to load is the event.
            return "live", ("audio.onloadstart fires as soon as the load begins, "
                            "which a 404 does not prevent (measured)")
        # The rest of the family needs the resource to actually decode.  Measured:
        # live with a valid `data:audio/wav`, dead with the same markup pointing
        # at a missing file, and dead with an undecodable data: URI.  Whether a
        # reflected `src` loads is not a fact about the markup, so this declines
        # rather than guessing a direction.
        return "unknown", (f"audio.{ev} needs the src to load and decode; measured "
                           f"live with a decodable src and dead with a 404, so a "
                           f"URL cannot be judged from markup")
    if ev == "onscroll":
        return "activation", "onscroll needs scroll position restoration"
    return "activation", f"{name}.{ev} requires user interaction"



def _js_uri_state(el: Node, attr: str, value: str) -> tuple[str, str]:
    key = (el.name.lower(), attr.lower())
    if key in JS_URI_EXECUTES:
        return "live", f"{key[0]}.{key[1]}=javascript: executes (measured)"
    if key in JS_URI_ACTIVATION and key not in JS_URI_EXECUTES:
        return "activation", f"{key[0]}.{key[1]}=javascript: runs only when activated"
    if key in JS_URI_INERT:
        return "inert", f"{key[0]}.{key[1]}=javascript: measured no-exec in Chromium"
    return "unknown", f"{key[0]}.{key[1]}=javascript: not measured"



# Browsers strip ASCII control characters (and space) from a URL before the
# scheme is resolved, which is the whole of `jav&#x09;ascript:` and
# `javascript:`.  Match on the normalised value, never the raw one: a
# regex over the raw text cannot express "the parser deletes these bytes first".
_JS_URI_RE = re.compile(r"^javascript:", re.I)

# C0 controls (0x00-0x1F), space and DEL: removed by the URL parser
# before it looks at the scheme.
_URL_STRIP_SET = frozenset(chr(c) for c in list(range(0x00, 0x21)) + [0x7F])



def normalize_uri(value: str) -> str:
    """The scheme-relevant form of a URL attribute, after the byte deletions a
    browser performs before parsing it."""
    return "".join(ch for ch in value if ch not in _URL_STRIP_SET)


#: Characters after which a `/` opens a regex literal.  Missing a keyword here
#: (return, typeof, ...) only ever misreads a regex as division or the reverse,
#: and both land in "unknown" when the token is inside the span -- the safe
#: direction.  A word-boundary matcher would be more accurate and buys nothing
#: that a fallback to the browser does not already cover.
_REGEX_PREV_CHARS = frozenset("(,=:[!&|?{};+-*%<>~^\n\r")



def js_state_at(text: str, needle: str) -> str:
    """Where does `needle` sit inside a <script> body: code, string, comment,
    template, regex/unknown, or absent?

    This is the check that stops `<script>var a = "<img src=x onerror=T>"</script>`
    being reported as executable.  The token is present and a `<script>` element
    exists, so a tree-shaped rule alone says live -- but the bytes are inside a
    JS string literal and no code path reaches them.  `verifier` solved this by
    counting unescaped quotes and pattern-matching `alert(`, which over-fits to
    alert payloads; a linear scan of the real lexical states is both smaller and
    right, and it still reports a payload that *closes* the quote (`';fetch(1)`),
    because closing the quote is exactly what the scan observes.

    "unknown" is returned when the scan cannot decide -- a regex-vs-division
    ambiguity covering the token, or an unterminated construct.  Callers must
    treat that as "ask the browser", never as inert.
    """
    idx = text.find(needle)
    if idx < 0:
        return "absent"
    i = 0
    n = len(text)
    prev = ""
    state = "code"
    quote = ""
    while i < n:
        if i == idx:
            return state
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == "/" and nxt == "/":
                state = "line-comment"
                i += 2
                continue
            if c == "/" and nxt == "*":
                state = "block-comment"
                i += 2
                continue
            if c in "'\"":
                state, quote = "string", c
                i += 1
                continue
            if c == "`":
                state, quote = "template", "`"
                i += 1
                continue
            if c == "/" and (prev == "" or prev in _REGEX_PREV_CHARS):
                j = _skip_regex(text, i)
                if j < 0:
                    return "unknown"
                if i < idx < j:
                    return "unknown"
                i = j
                continue
            if not c.isspace():
                prev = c
            i += 1
            continue
        if c == "\\":
            i += 2
            continue
        if state == "line-comment" and c == "\n":
            state = "code"
        elif state == "block-comment" and c == "*" and nxt == "/":
            state = "code"
            i += 1
        elif state == "string" and (c == quote or c == "\n"):
            # A raw newline ends a JS string literal: an unterminated quote in
            # the payload is what turns data back into code.
            state, quote = "code", ""
        elif state == "template" and c == quote:
            state, quote = "code", ""
        elif state == "template" and c == "$" and nxt == "{":
            # `${...}` is code again -- the template-literal bypass.
            state, quote = "code", ""
            i += 1
        i += 1
    return "unknown" if state != "code" else "code"



def _skip_regex(text: str, i: int) -> int:
    """End index of a regex literal starting at text[i] == '/', or -1."""
    n = len(text)
    j = i + 1
    in_class = False
    while j < n:
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == "\n":
            return -1
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
        elif c == "/":
            return j + 1
        j += 1
    return -1



def _in_template(el: Node) -> bool:
    """Inside an HTML <template>.  The namespace test is the whole point: a
    `<template>` created inside `<svg>` is an SVG element that happens to be
    spelled that way -- it has no content document, and a `<script>` under it is
    a plain SVG script the parser runs.  Measured: `<svg><style><template>
    <script>CODE` executes, `<template><script>CODE` does not."""
    p = el.parent
    while p is not None:
        if p.kind == "element" and p.name == "template" and p.ns == "html":
            return True
        p = p.parent
    return False



#: Element names that only exist as HTML behaviours.  Carrying one of these
#: names inside `<svg>`/`<math>` produces an element the HTML spec has nothing
#: to say about: it is not focusable, has no `open` state, does not load a
#: resource -- so a handler written on it never fires.  Each name here is a row
#: of benchmark/results/browser_dom_oracle.json where Chromium created the
#: element, kept the handler attribute, and executed nothing.
HTML_ONLY_ELEMENTS = frozenset({
    "input", "button", "select", "textarea", "details", "summary", "source",
    "video", "audio", "iframe", "frame", "object", "embed", "marquee",
    "keygen", "output", "progress", "meter", "form", "a", "img", "div", "p",
    "span", "table", "td", "tr", "option", "label", "legend", "dialog",
})


#: SVG elements that reference no resource, so `onload` has nothing that could
#: ever raise it.  Each name is a row of `benchmark/probe_svg_ns.py`: served in a
#: document, handler attached, sentinel never reached -- and unlike a click-gated
#: sink there is no interaction that changes the answer, so the False is the
#: bounded kind that licenses INERT rather than the one that hides a finding.
#: `<use onload>` and `<image onload>` are deliberately absent: both take an href,
#: so a load event is at least conceivable, and what was measured was a broken
#: reference (`href="/nope"`, `xlink:href="#nope"`).  A broken reference proves
#: the failure path, not that a resolving one stays quiet.
SVG_UNLOADABLE_ELEMENTS = frozenset({
    "desc", "g", "clippath", "ellipse", "filter", "lineargradient", "path",
    "foreignobject",
})



def _foreign_handler_state(el: Node, ev: str, sink: str) -> tuple[str, str]:
    """Handler on an element in the svg/mathml namespace; ('', '') if not.

    Foreign content is where reflected-XSS claims go to die quietly: the
    attribute survives, the element is in the tree, and nothing can ever raise
    the event.  `<svg onload>` is the exception that is actually loadable, and
    it is measured as executing.
    """
    if el.ns == "html":
        return "", ""
    name = el.name.lower()
    if ev == "onload" and name in ("svg", "math"):
        # Measured, and the split is not intuitive: a fresh `<svg onload>`
        # reaching the page through the parser fires; the same element inserted
        # through innerHTML does not (its document already loaded) *unless* it is
        # nested inside another element of its own namespace, where it is a new
        # SVG document root and does fire.  `<math><mtext><svg onload>` is the
        # near-miss: an HTML-integration-point ancestor is not the same thing.
        if sink == "parser":
            return "live", (f"{el.ns}<{name}> load event fires when the document "
                            f"parses it (measured)")
        p = el.parent
        while p is not None:
            if p.kind == "element" and p.ns == el.ns:
                return "live", (f"nested <{name}> inside another {el.ns} element "
                                f"starts its own load (measured)")
            p = p.parent
        return "inert", (f"{el.ns}<{name}> inserted via innerHTML: its document "
                         f"has already loaded, so onload never fires (measured)")
    if name in HTML_ONLY_ELEMENTS:
        return "inert", (f"<{name}> here is in the {el.ns} namespace, so it "
                         f"implements none of the HTML behaviour that would "
                         f"raise {ev} (measured no-exec)")
    if ev == "onload" and name in SVG_UNLOADABLE_ELEMENTS:
        # Nothing behind these elements can finish loading, so the event has no
        # source at all -- and no gesture raises it either, which is what makes
        # the measured False a real inert instead of the bounded kind.
        return "inert", (f"<{name}> in the {el.ns} namespace loads nothing, so "
                         f"onload is never raised (measured)")
    return "unknown", (f"{name}[{ev}] in the {el.ns} namespace is not "
                       f"measured, and foreign elements do not inherit HTML "
                       f"event rules")



def _js_parses(body: str, wrapped: bool = False) -> Optional[bool]:
    """Can the JS engine even compile this?  None means "no parser available".

    Reflected markup inside a <script> block, or inside an inline handler, is
    only code if it *parses*.  `<script><img src=x onerror=T></script>` puts the
    token at code position and still runs nothing: `<img ...>` is a syntax
    error, the script never compiles, and the browser reports the error instead
    of executing.  Claiming that shape is the largest single source of reflected
    XSS false positives in the payloads a scanner likes best, and only a JS
    parser can settle it -- so `esprima` moves from optional to expected here.
    """
    if _esprima is None or len(body) > 20000:
        return None
    # Phase 300: the wrapped form puts the closing brace on its OWN line.
    # `onerror="__x()//"` is a classic corpus shape and Chromium compiles it
    # (the line comment ends at the newline the handler wrapper has), but
    # `function __h(){ __x()// }` comments out the brace and reads as a
    # syntax error -- measured: 3 of 153 oracle cells (markdown + html5_new
    # families, both arms) were called inert while the browser executed them.
    src = f"function __h(){{\n{body}\n}}" if wrapped else body
    try:
        _esprima.parseScript(src, tolerant=False)
    except Exception:
        return False
    return True



#: Callees whose argument, if it carries the token, proves the token was
#: *reached*.  Deliberately the same family `verifier.mark()` stamps tokens
#: into: the token only means anything inside the call the scanner wrote it
#: into, so "is it an argument of any call at all" is the wrong question.
#: `console.log("...TOKEN...")` is a call carrying the token and it proves
#: nothing but that a string was printed -- measured the hard way, when that
#: reading turned the defended cases `neg-js-02` and `neg-sanitizer-01` into
#: false positives.
_EXECUTING_CALLEES = frozenset({
    "alert", "confirm", "prompt", "eval", "setTimeout", "setInterval",
    "Function", "write", "writeln", "unescape",
})



def _callee_name(callee) -> str:
    """`alert`, `window.alert`, `top.alert`, `document.write` -> last segment."""
    if not isinstance(callee, dict):
        return ""
    while callee.get("type") == "MemberExpression":
        callee = callee.get("property") or {}
    if isinstance(callee, dict) and callee.get("type") == "Identifier":
        return callee.get("name") or ""
    return ""



def _token_in_executing_call(body: str, token: str) -> str:
    """Is the token an argument of a call that would *demonstrate* execution?

    Returns "call", "data", or "no-parser".

    "The token sits inside a string literal" is not the same as "the token is
    data".  `alert('TOKEN')` puts the token in a string *and* executes it, which
    is the payload landing exactly where it was meant to land.  Reading the
    lexical state alone calls that inert -- and that cost the benchmark's
    `pos-cdata-01` a false negative on the first run of the gate that wraps this
    module, because the confirming payload was
    `]]></script><script>alert('TOKEN')</script><![CDATA[`.

    The opposite error is just as costly, and was the second lesson: the callee
    has to belong to the family markers are stamped into, not merely be callable.

    "no-parser" is returned only when the decision needs a JS parser that is not
    installed; the caller must then answer UNKNOWN, because a veto it cannot
    justify is worse than no veto at all.
    """
    if _esprima is None or len(body) > 20000:
        return "no-parser"
    idx = body.find(token)
    if idx < 0:
        return "data"
    span = (idx, idx + len(token))
    try:
        tree = _esprima.parseScript(body, range=True)
        data = json.loads(json.dumps(tree.toDict()))
    except Exception:
        return "no-parser"
    found = [False]

    def walk(node):
        if isinstance(node, dict):
            if node.get("type") in ("CallExpression", "NewExpression"):
                r = node.get("range")
                if r and r[0] <= span[0] and span[1] <= r[1] \
                        and _callee_name(node.get("callee")) in \
                        _EXECUTING_CALLEES:
                    found[0] = True
                    return
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(data)
    return "call" if found[0] else "data"



def _script_candidate(el: Node, body: str, token: str, sink: str,
                      inert_host: bool) -> dict:
    """Decide a <script> element.

    Two independent reasons a script does not run, and a scanner that knows only
    one of them reports the other's cases as findings:

      * the sink.  A script element created by `innerHTML` is inserted but never
        started -- measured no-exec, and a serialise/re-parse round-trip does not
        change it (`div.innerHTML = <script>CODE` stays no-exec).
      * the position.  The token may be inside a JS string literal or a comment,
        where it is data, not code.
    """
    if inert_host:
        return {"node": "script[template]", "state": "inert",
                "why": "script inside <template> content never executes", "el": el}
    if el.get("src"):
        return {"node": "script[src]",
                "state": "live" if sink == "parser" else "inert",
                "why": "external script fetched by the parser; an innerHTML-"
                       "inserted script element is never started",
                "el": el}
    if sink != "parser":
        return {"node": "script[inert-sink]", "state": "inert",
                "why": "script created via innerHTML never executes (measured)",
                "el": el}
    # Nothing in a script that fails to compile executes -- not the part before
    # the error either.  Reflected markup that never broke out of its container
    # lands here, and this is the single largest family of reflected-XSS
    # over-claims.  Checked first, so the position analysis below only ever runs
    # on a body the engine will actually execute.
    compiles = _js_parses(body)
    if compiles is False:
        return {"node": "script[syntax-error]", "state": "inert",
                "why": "the script body is not valid JavaScript: markup "
                       "reflected into a script block without breaking out of "
                       "it is a syntax error, and nothing in the block runs",
                "el": el}
    pos = js_state_at(body, token) if token else "code"
    if pos == "code":
        return {"node": "script", "state": "live",
                "why": "<script> body reached by the parser, token at code "
                       "position" + ("" if compiles else " (JS validity "
                                                    "unchecked)"), "el": el}
    if pos == "unknown":
        return {"node": "script[undecided]", "state": "unknown",
                "why": "cannot tell code from regex/comment position at the "
                       "token; needs the browser", "el": el}
    # The token is inside a string / comment / template literal.  Whether that is
    # data or the payload landing exactly where it was meant to land is a
    # question about the syntax tree, not about quoting: `alert('TOKEN')`
    # executes, `var a = 'TOKEN'` does not.
    role = _token_in_executing_call(body, token) if token else "no-parser"
    if role == "call":
        return {"node": "script[argument]", "state": "live",
                "why": "token is an argument of the alert-family call the script "
                       "reaches: the literal is the payload landing where it was "
                       "meant to", "el": el}
    if role == "no-parser":
        return {"node": "script[undecided]", "state": "unknown",
                "why": "token sits in a JS literal whose role cannot be decided "
                       "without a JS parser installed (esprima); needs the "
                       "browser", "el": el}
    return {"node": "script[data]", "state": "inert",
            "why": f"token sits in a JS {pos} literal that is data, not a call "
                   f"argument, and the payload never breaks out of it",
            "el": el}



def find_live_nodes(root: Node, token: str = "", *,
                    nested: bool = False,
                    sink: str = "parser") -> tuple[str, list[dict]]:
    """Classify every candidate execution point in the tree.

    `sink` is not cosmetic.  A `<script>` element created by the *parser*
    executes; the same element created by `innerHTML` does not, ever, and a
    round-trip does not change that (both measured).  Reporting an inert
    script element as a finding is the single most common reflected-XSS false
    positive in the wild, and it is why the verdict carries its sink.

    Returns (worst_state, details) where worst_state folds live > unknown >
    activation > inert.
    """
    cands: list[dict] = []
    for el in root.walk():
        if el.kind != "element":
            continue
        name = el.name.lower()
        inert_host = _in_template(el)
        for an, av in el.attrs:
            al = an.lower()
            if not isinstance(av, str):
                av = " ".join(str(x) for x in av) if av else ""
            # `on` + letters only.  A U+FFFD from a NUL, or an `one-*`-style
            # name, is not an event handler and must not be scored as one.
            if _HANDLER_NAME_RE.match(al):
                if token and token not in av:
                    continue
                if inert_host:
                    cands.append({"node": f"{name}[{al}]", "state": "inert",
                                  "why": "handler inside <template> content "
                                         "is never rendered or run", "el": el})
                    continue
                st, why = _handler_state(el, al, sink, nested)
                if st == "live":
                    # An inline handler is compiled as a function body at parse
                    # time.  If the value does not compile -- typically because
                    # the attribute was truncated by its own quote and the tail
                    # landed outside it -- the handler is dead on arrival, which
                    # is why "the token is in an onerror= value" is not by
                    # itself a finding.
                    compiles = _js_parses(av, wrapped=True)
                    if compiles is False:
                        st = "inert"
                        why = (f"{name}.{al} value is not valid JavaScript "
                               f"(truncated by its own quote, or markup rather "
                               f"than code), so the handler never compiles")
                cands.append({"node": f"{name}[{al}]", "state": st, "why": why,
                              "el": el})
            elif al in ("href", "src", "action", "formaction", "data", "code",
                        "xlink:href") and _JS_URI_RE.match(normalize_uri(av or "")):
                if token and token not in av:
                    continue
                st, why = _js_uri_state(el, al, av)
                cands.append({"node": f"{name}[{al}]", "state": st, "why": why,
                              "el": el})
            elif al == "srcdoc" and name == "iframe" \
                    and el.ns == "html":
                # Only an iframe's `srcdoc` is a nested document.  A `<frame>`
                # does not have the attribute -- `<frame srcdoc="<img onerror=...>">`
                # measured no execution, because the frame gets no `src` and loads
                # about:blank (benchmark/probe_frame.py).  And in an unquoted
                # attribute context a payload's `srcdoc=` lands on a div instead,
                # and a div.srcdoc parses nothing -- claiming it "executes in a
                # nested document" is an over-statement.
                if token and token not in av:
                    continue
                if inert_host:
                    cands.append({"node": f"{name}[srcdoc]", "state": "inert",
                                  "why": "srcdoc inside <template> content is "
                                         "never instantiated", "el": el})
                    continue
                sub = parse(av or "", fragment=False)
                st, _sub = find_live_nodes(sub.root, token, sink="parser",
                                            nested=True)
                cands.append({"node": f"{name}[srcdoc]",
                              "state": st,
                              "why": "srcdoc value is parsed as a whole document"
                                     if st == "live" else
                                     "srcdoc value carries no live node",
                              "el": el})
        if name == "script":
            # Phase 300: namespace decides.  A <script> in the MathML
            # namespace never executes (measured in Chromium:
            # <math><script>__x()</script></math> and the same inside
            # <annotation encoding=text/html> are both inert, while
            # <svg><script> executes).  Without this check the corpus
            # payload <math><annotation encoding=text/html><script>...</...
            # was claimed live -- one over-claim among the default-sent
            # cells.  annotation-xml[encoding=text/html] IS an integration
            # point, so its children parse as HTML and keep executing.
            if el.ns == "mathml":
                continue
            body = "".join(c.name for c in el.children if c.kind == "text")
            if not token or token in body:
                cands.append(_script_candidate(el, body, token, sink,
                                               inert_host))
                continue

    if not cands:
        return "inert", []
    order = {"live": 0, "unknown": 1, "activation": 2, "inert": 3}
    cands.sort(key=lambda c: order.get(c["state"], 4))
    worst = cands[0]["state"]
    return worst, cands



def judge(html: str, token: str = "", *, sink: str = "parser") -> Verdict:
    """Decide whether `html` (as served, or as re-parsed by a DOM sink) is live.

    `token` scopes the search to the payload we reflected, so an unrelated
    handler already present on the page cannot be credited to our payload.
    """
    if sink not in ("parser", "innerhtml"):
        raise ValueError(f"unknown sink {sink!r}")
    # The sink selects the parser, not just a scoring rule: a document parse and
    # a fragment parse disagree about <body>, and both measurements are in the
    # oracle.
    doc = parse(html, fragment=(sink == "innerhtml"))
    if token and token not in html:
        return Verdict("inert", "token absent from the document")
    state, detail = find_live_nodes(doc.root, token, sink=sink)
    if not detail:
        why = "no executable node carries the token"
        if doc.notes:
            return Verdict("unknown", "; ".join(doc.notes))
        return Verdict("inert", why)
    top = detail[0]
    ev = "; ".join(f"{d['node']} {d['state']} ({d['why']})" for d in detail[:4])
    if state == "live":
        return Verdict("live", top["why"], top["el"], False, ev)
    if state == "activation":
        return Verdict("live", top["why"], top["el"], True, ev)
    if state == "unknown":
        return Verdict("unknown", top["why"], None, False, ev)
    # INERT is the only verdict here that *costs* something to get wrong -- it
    # tells the scanner to stop looking, and (via the verify gate) it can retract
    # a confirmation.  So a parse that met something it had to note as
    # un-modelled may not conclude inert, even when a candidate was found and
    # each candidate looked dead.  Measured: the table-scope-inside-MathML shapes
    # were browser-live on the FIRST parse while every candidate read as inert,
    # and only this rule turns that from a wrong answer into a deferred one.
    if doc.notes:
        return Verdict("unknown", "parser met a construct it does not model: "
                       + "; ".join(doc.notes[:3]), None, False, ev)
    return Verdict("inert", "every token-bearing sink is inert: "
                   + "; ".join(f"{d['node']} {d['why']}" for d in detail[:3]),
                   None, False, ev)



def judge_roundtrip(html: str, token: str = "", *,
                    sink: str = "innerhtml", depth: int = 3) -> Verdict:
    """The mXSS question: does the payload become live only after the browser
    serialises and re-parses it?

    Each iteration is the real thing: parse -> serialise -> parse the
    serialisation.  A verdict that flips inert -> live at any depth is a
    mutation vector; that flip is what `mxss_verify` currently pays a browser
    launch for.
    """
    cur = html
    best = Verdict("inert", "no round-trip produced a live node")
    trail: list[tuple[str, str]] = []
    for k in range(depth):
        v = judge(cur, token, sink=sink)
        trail.append((f"round{k + 1}", f"{v.state}:{v.reason}"))
        if v.state == "live":
            if k == 0:
                return v
            v.evidence = (v.evidence or "") + " |MUTATED " + " ; ".join(
                f"{a}:{b}" for a, b in trail)
            return v
        if v.state == "unknown":
            best = v
        cur = serialize(parse(cur).root)
    return best



# ---------------------------------------------------------------------------
# Host templates for the CLI: mirrors benchmark/browser_dom_oracle.py
# ---------------------------------------------------------------------------

HOSTS = {
    "text": "<div>__P__</div>",
    "attr_dq": '<div class="__P__">t</div>',
    "attr_sq": "<div class='__P__'>t</div>",
    "attr_unq": "<div class=__P__>t</div>",
    "title": "<title>__P__</title>",
    "textarea": "<textarea>__P__</textarea>",
    "style": "<style>__P__</style>",
    "svg_style": "<svg><style>__P__</style></svg>",
    "math_mtext": "<math><mtext>__P__</mtext></math>",
    "script_dq": '<script>var a = "__P__";</script>',
    "script_block": "<script>__P__</script>",
    "comment": "<!--__P__-->",
    "noscript": "<noscript>__P__</noscript>",
    "xmp": "<xmp>__P__</xmp>",
    "template": "<template>__P__</template>",
    "table_td": "<table><tr><td>__P__</td></tr></table>",
    "select": "<select><option>__P__</option></select>",
    "event_dq": '<img src="__P__" alt="a">',
    "href_dq": '<a href="__P__">t</a>',
    "iframe_srcdoc": '<iframe srcdoc="__P__"></iframe>',
}



def main(argv: Optional[list[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(
        prog="xssentinel.core.sandbox",
        description="Offline HTML sandbox: is this reflected payload live?")
    ap.add_argument("--payload", help="payload to evaluate")
    ap.add_argument("--host", default="text",
                    help=f"reflection context: {', '.join(sorted(HOSTS))}")
    ap.add_argument("--token", default="",
                    help="marker the payload reflects (default: the payload itself)")
    ap.add_argument("--sink", default="parser", choices=("parser", "innerhtml"))
    ap.add_argument("--file", help="judge a whole saved response body instead")
    ap.add_argument("--roundtrip", action="store_true",
                    help="also parse->serialise->re-parse (mXSS)")
    args = ap.parse_args(argv)

    if args.file:
        html = open(args.file, "r", encoding="utf-8", errors="replace").read()
    elif args.payload:
        html = HOSTS[args.host].replace("__P__", args.payload) \
            if args.host in HOSTS else args.payload
    else:
        ap.error("--payload or --file is required")

    token = args.token or (args.payload[:24] if args.payload else "")
    v = judge(html, token, sink=args.sink)
    print(f"sink={args.sink}  state={v.state.upper()}  activation={v.activation}")
    print(f"  why     : {v.reason}")
    print(f"  evidence: {v.evidence[:300]}")
    if args.roundtrip:
        r = judge_roundtrip(html, token, sink=args.sink)
        print(f"round-trip: state={r.state.upper()}  {r.reason}")
        for k, ser in enumerate(roundtrip(html)):
            print(f"  ser{k + 1}: {ser[:220]}")
    return 0 if v.state != "unknown" else 2



if __name__ == "__main__":
    raise SystemExit(main())
