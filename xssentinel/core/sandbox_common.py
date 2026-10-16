"""Structures shared by both halves of the sandbox.

Split out of ``core/sandbox.py`` (docs 1.3).  Holds only what both the parser
half and the judging half need, so neither has to import the other.  See
``sandbox.py``'s docstring for what this sandbox models and how its fidelity is
measured against Chromium.
"""

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
from typing import Iterable, Optional

try:                          # optional extra; js validity gating degrades to
    import esprima as _esprima  # type: ignore[import-untyped]  # "cannot decide" without it
except ImportError:           # noqa: E402
    _esprima = None

# ---------------------------------------------------------------------------
# Element classification tables
# ---------------------------------------------------------------------------

#: <script> and <style> contents are tokenised as raw text: no entities, and
#: only the matching close tag ends them.

MATHML_TEXT_INTEGRATION = frozenset(
    {"mtext", "mi", "mo", "mn", "ms", "mmultiscripts", "mprescripts",
     "none", "annotation-xml"})

SVG_HTML_INTEGRATION = frozenset({"foreignobject", "desc", "title"})

VOID = frozenset({
    "area", "base", "basefont", "bgsound", "br", "col", "embed", "frame",
    "hr", "img", "input", "keygen", "link", "meta", "param", "source",
    "track", "wbr", "image", "menuitem", "command", "!--",
})

class Node:
    """Minimal element/document/fragment node."""

    __slots__ = ("kind", "name", "attrs", "parent", "children", "ns", "self_closing")

    def __init__(self, kind: str, name: str = "", ns: str = "html"):
        self.kind = kind                 # document | element | text | comment
        self.name = name
        self.attrs: list[tuple[str, str]] = []
        self.parent: Optional[Node] = None
        self.children: list[Node] = []
        self.ns = ns                     # html | svg | mathml
        self.self_closing = False

    # -- tree helpers ------------------------------------------------------
    def append(self, node: "Node") -> None:
        node.parent = self
        self.children.append(node)

    def get(self, attr: str) -> Optional[str]:
        al = attr.lower()
        for k, v in self.attrs:
            if k.lower() == al:
                return v
        return None

    def has_attr(self, attr: str) -> bool:
        return self.get(attr) is not None

    def walk(self) -> Iterable["Node"]:
        for c in self.children:
            yield c
            yield from c.walk()

    def __repr__(self) -> str:  # debugging aid; the fidelity harness reads it
        if self.kind == "text":
            return f"#text({serialize_text(self)!r})"
        if self.kind == "comment":
            return f"<!--{self.name!r}-->"
        return f"<{self.name}>"

class Doc:
    """Parse result: the fragment root plus what the parser dropped or moved."""

    __slots__ = ("root", "notes")

    def __init__(self, root: Node, notes: Optional[list] = None):
        self.root = root
        self.notes = notes if notes is not None else []

def serialize_text(node: Node) -> str:
    data = node.name
    parent = node.parent
    # Only the HTML "no-escaping" elements (script/style/xmp/iframe/noembed/
    # noframes/plaintext/noscript) write their text out verbatim.  Foreign
    # content does NOT get an exemption: `<svg><![CDATA[<img ...>]]></svg>`
    # serialises as `<svg>&lt;img ...&gt;</svg>` (measured), and the &-only
    # shortcut the spec's wording tempts you into is what makes a CDATA payload
    # look like it mutates into a live tag on re-parse.  It does not.
    p = parent
    while p is not None:
        if p.kind == "element" and p.name in NO_ESCAPE_TEXT and p.ns == "html":
            return data
        if p.ns == "html":
            break
        p = p.parent
    return (data.replace("&", "&amp;")
                .replace("<", "&lt;").replace(">", "&gt;")
                .replace(" ", "&nbsp;"))
