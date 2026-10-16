"""The tokeniser and tree-builder half of the sandbox.

Split out of ``core/sandbox.py`` (docs 1.3) as a pure move -- nothing here was
rewritten while moving.  Callers keep going through ``sandbox.parse()``.
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

from .sandbox_common import (
    AUTO_CLOSE,
    Doc,
    FOREIGN_BREAK,
    FRAMESET_OK_KILLERS,
    FRAMESET_ONLY_STARTS,
    MATHML_TEXT_INTEGRATION,
    Node,
    OPTION_SCOPE,
    PLAINTEXT,
    P_CLOSERS,
    RAWTEXT,
    RCDATA,
    SELECT_DROPPED,
    SELECT_END_OPTION,
    SELECT_END_SCOPE,
    SELECT_EXITS,
    SVG_HTML_INTEGRATION,
    TABLE_CONTEXT,
    TABLE_OK_IN,
    TABLE_ONLY_STARTS,
    TABLE_SCOPE,
    Token,
    VOID,
    _adjust_foreign,
    _adjust_foreign_attr,
    _attr_value_end,
    _close_rawtext,
    _comment,
    _read_name,
    _skip_ws,
    decode_entities,
)

class _Parser:
    """HTML fragment parser, sized to the XSS question.

    State lives on the instance because the tokenizer's position has to move
    under the tree builder when it enters a raw-text content model -- `</script>`
    is found by the *tokenizer*, and the payload gets to choose where that is.
    """

    def __init__(self, html: str, fragment: bool = True):
        self.s = html
        self.n = len(html)
        self.i = 0
        self.root = Node("document", "#document")
        self.stack: list[Node] = [self.root]
        self.notes: list[str] = []
        # Fragment mode is `div.innerHTML = <a whole document>`, which is what a
        # client-side template sink does.  There, <html>/<head>/<body> are
        # dropped and their children land in the container -- measured, where
        # the browser's serialisation of the same bytes is
        # `<div>...</div>` with no body node at all.  Document mode is the
        # server's response, where a second <body> MERGES its attributes onto
        # the live one, and `<body onload=...>` reflected mid-page really runs.
        self.fragment = fragment
        # The HTML parser's `frameset-ok` flag, and the reason a `<frameset>` is
        # not simply "an element": a served page that already has body content
        # ignores the tag, so a `<frame src="javascript:CODE">` inside it opens
        # nothing.  Modelled from `benchmark/probe_frame.py` (which contexts
        # honour it) and `benchmark/probe_frameset_ok.py` (which tags clear it).
        # A fragment parse never builds one, so this only speaks for documents.
        self.frameset_ok = True

    # -- tree state ---------------------------------------------------------
    def current(self) -> Node:
        return self.stack[-1]

    def integration(self, node: Node) -> bool:
        """True when node is foreign but its CHILDREN parse as HTML."""
        lname = node.name.lower()
        if node.ns == "svg":
            return lname in SVG_HTML_INTEGRATION
        if node.ns == "mathml":
            if lname == "annotation-xml":
                return (node.get("encoding") or "").lower() in (
                    "text/html", "application/xhtml+xml")
            return lname in MATHML_TEXT_INTEGRATION
        return False

    def in_foreign(self) -> bool:
        cur = self.current()
        return cur.ns in ("svg", "mathml") and not self.integration(cur)

    def pop_foreign(self) -> None:
        """The break-out: the svg/math subtree closes and parsing continues in
        HTML.  probe_foreign.py shows the surviving shape -- `<svg></svg><img>`
        -- an empty svg followed by the HTML sibling.

        It stops at an integration point rather than at the nearest HTML element,
        and that difference is itself a vector: for `<math><mtext><mglyph>
        <style><img onerror>` the browser puts the live img **inside `mtext`**,
        as a sibling of `mglyph`.  Popping all the way to the document would
        mis-parent the node and change what is reachable."""
        while len(self.stack) > 1 and self.stack[-1].ns != "html" \
                and not self.integration(self.stack[-1]):
            self.stack.pop()

    def pop_to(self, name: str) -> bool:
        for k in range(len(self.stack) - 1, 0, -1):
            if self.stack[k].name == name:
                del self.stack[k:]
                return True
        return False

    def close_scoped(self, name: str) -> None:
        """li/dd/dt/option/optgroup/td/th/tr close their siblings and a
        block-level start tag closes an open <p>.  Skipping this loses exactly
        the breakout `<noscript><p title="...` payloads rely on."""
        targets = AUTO_CLOSE.get(name)
        if targets:
            for k in range(len(self.stack) - 1, 0, -1):
                if self.stack[k].name in targets and self.stack[k].ns == "html":
                    del self.stack[k:]
                    return
        if name in P_CLOSERS:
            for k in range(len(self.stack) - 1, 0, -1):
                if self.stack[k].name == "p" and self.stack[k].ns == "html":
                    del self.stack[k:]

    def _imply_table_rows(self, name: str) -> None:
        """Create the <tbody>/<tr> the parser implies.  Chromium always shows
        `<table><tbody><tr><td>` in its serialisation even when the bytes said
        `<table><tr><td>`; a serialiser that omits tbody therefore disagrees
        with the browser on every table-shaped response, and the round-trip is
        what mXSS is judged by.  It does not change liveness -- the payload is
        live either way -- but it is 46 of the serialisation diffs."""
        cur = self.current()
        if cur.ns != "html":
            return
        if name == "tr" and cur.name == "table":
            tb = Node("element", "tbody", "html")
            cur.append(tb)
            self.stack.append(tb)
        elif name in ("td", "th"):
            if cur.name in ("table", "tbody", "thead", "tfoot"):
                if cur.name == "table":
                    tb = Node("element", "tbody", "html")
                    cur.append(tb)
                    self.stack.append(tb)
                    cur = self.current()
                tr = Node("element", "tr", "html")
                cur.append(tr)
                self.stack.append(tr)

    def foster_insert(self, node: Node) -> bool:
        """Insert `node` immediately before the open <table>, per foster parenting.

        Returns False when no table-scope element is open, i.e. this is not a
        foster-parenting situation.
        """
        for k in range(len(self.stack) - 1, 0, -1):
            if self.stack[k].name == "table" and self.stack[k].ns == "html":
                tbl = self.stack[k]
                parent = tbl.parent
                if parent is None:
                    return False
                try:
                    at = parent.children.index(tbl)
                except ValueError:
                    at = len(parent.children)
                node.parent = parent
                parent.children.insert(at, node)
                return True
        return False

    def add_text(self, data: str, decode: bool = True) -> None:
        if not data:
            return
        if decode:
            data = decode_entities(data)
            # A NUL in ordinary document text is *dropped* -- `<p>a<NUL>b</p>`
            # holds `61 62`, not `61 fffd 62`.  RCDATA/RAWTEXT do the opposite
            # (see `consume_rawtext`), so the two paths must not share one rule;
            # both read from benchmark/results/nul_probe.json.
            data = data.replace("\x00", "")
        else:
            # Foreign content is not measured for NUL; left exactly as it was so
            # this change cannot move a foreign verdict on an unmeasured corner.
            data = data.replace("\x00", "\ufffd")
        if data.strip() and not any(st.ns == "html" and st.name == "template"
                                    for st in self.stack[1:]):
            # A character token with something in it closes the frameset window:
            # `<html>x<frameset>` measured ignored where
            # `<html><!--x--><frameset>` was honoured, and
            # `<html><svg>text</svg><frameset>` measured ignored too, so text in
            # FOREIGN content counts as well.  The one exemption the measurements
            # give is template contents: a frameset after
            # `<template>t</template>` is still built, because a template's
            # characters never become body text.  Whitespace-only runs do not
            # count, and neither do raw-text contents (style, title) -- those go
            # through `consume_rawtext`, and both measured honoured.
            self.frameset_ok = False
        self.current().append(Node("text", data))

    # -- tokenizer ----------------------------------------------------------
    def read_tag(self, j: int) -> tuple[Token, int]:
        s, n = self.s, self.n
        name, j = _read_name(s, j, " \t\n\r\f/>")
        # NUL becomes U+FFFD in a start-tag name, exactly as it does in an end
        # tag name and in an attribute name.  Dropping it made the OPEN tag the
        # one half of the pair where the bypass worked: `<scr<NUL>ipt>` really
        # creates an unknown element named `scr\ufffdipt` (measured code points
        # `73 63 72 fffd 69 70 74`, contents = plain text, nothing executes),
        # while the sandbox turned it into a live <script> whose `</scr<NUL>ipt>`
        # then failed to close -- a confirmed finding out of a dead payload.
        # See benchmark/results/nul_probe.json.
        name = name.lower().replace("\x00", "\ufffd")
        attrs: list[tuple[str, str]] = []
        self_closing = False
        while j < n:
            j = _skip_ws(s, j)
            if j >= n:
                break
            if s[j] == ">":
                j += 1
                break
            if s[j] == "/":
                if j + 1 < n and s[j + 1] == ">":
                    self_closing = True
                    j += 2
                    break
                j += 1
                continue
            an, j = _read_name(s, j, " \t\n\r\f/=><")
            if not an:
                j += 1
                continue
            # NUL becomes U+FFFD in an attribute name, so `sr<NUL>c=` is NOT
            # `src` -- the payload dies instead of bypassing the filter.
            an = an.replace("\x00", "\ufffd").lower()
            j = _skip_ws(s, j)
            val = ""
            if j < n and s[j] == "=":
                j = _skip_ws(s, j + 1)
                if j < n and s[j] in "\"'":
                    q = s[j]
                    e = _attr_value_end(s, j + 1, q)
                    val = decode_entities(s[j + 1:e], in_attr=True)
                    j = e + 1 if e < n else e
                else:
                    e = _attr_value_end(s, j, "")
                    val = decode_entities(s[j:e], in_attr=True)
                    j = e
            if not any(k == an for k, _ in attrs):
                attrs.append((an, val.replace("\x00", "\ufffd")))
        return Token("start", name, attrs, self_closing=self_closing), j

    def consume_rawtext(self, node: Node, name: str, decode: bool,
                        to_eof: bool = False) -> None:
        """Swallow content up to `</name` (or EOF for <plaintext>).

        The closer is supplied by the PAYLOAD in the RCDATA-breakout vectors,
        so this is the step that decides whether `</title><img ...>` is markup
        or a string of characters.
        """
        if to_eof:
            raw, self.i = self.s[self.i:], self.n
        else:
            end = _close_rawtext(self.s, self.i, name)
            raw = self.s[self.i:end]
            k = self.s.find(">", end)
            self.i = self.n if k < 0 else k + 1
        if decode:
            raw = decode_entities(raw)
        # RCDATA and RAWTEXT both turn a NUL into U+FFFD -- `<title>a<NUL>b</title>`
        # holds `61 fffd 62`, `<style>a<NUL>{...}` holds `61 fffd 7b` -- which is
        # the opposite of document text (see `add_text`).  Deleting it here is
        # what made a NUL-bearing title breakout serialise to different bytes than
        # the browser's, i.e. a round-trip judged on markup no browser ever held.
        raw = raw.replace("\x00", "\ufffd")
        if raw:
            node.append(Node("text", raw))
        if self.stack and self.stack[-1] is node:
            self.stack.pop()

    # -- content models -----------------------------------------------------
    def enter_content_model(self, node: Node, name: str) -> None:
        if name == "script" or name in RAWTEXT or name == "noscript":
            # <noscript> is raw text while scripting is enabled -- every browser
            # a scan runs against.  The vector family that depends on the
            # scripting-disabled form only bites after a round-trip.
            self.consume_rawtext(node, name, decode=False)
        elif name in RCDATA:
            self.consume_rawtext(node, name, decode=True)
        elif name in PLAINTEXT:
            self.consume_rawtext(node, name, decode=False, to_eof=True)

    # -- HTML content -------------------------------------------------------
    def html_start(self, tok: Token) -> None:
        name = tok.name
        if name == "image":
            # In HTML content `image` is renamed to `img` by the tree builder, so
            # `<image src=x onerror=CODE>` is a normal failing image and fires.
            # Left as `image` this element fell outside every onerror table and
            # the payload read as inert -- a missed detection, not a naming
            # quibble.  Inside <svg> the element really is SVG `image` and this
            # branch is not reached.  Measured in all four contexts of
            # benchmark/results/option_probe.json (browser chain `...>img`).
            name = tok.name = "img"
        if name in FRAMESET_OK_KILLERS:
            # Before the `html`/`head`/`body` early returns: `body` is one of
            # these names, and its branch would otherwise swallow the rule.
            self.frameset_ok = False
        if name in ("html", "head"):
            return
        if name == "body":
            if self.fragment:
                # A fragment parser keeps the children and discards the tag.
                return
            if any(st.name == "template" and st.ns == "html" for st in self.stack[1:]):
                # Template contents are parsed by their own rules, where
                # <html>/<head>/<body> are dropped -- so a reflected
                # <body onload> inside a <template> creates no body and fires
                # nothing (measured: the whole template serialises empty).
                return
            existing = None
            for c in self.root.children:
                if c.kind == "element" and c.name == "body":
                    existing = c
                    break
            if existing is None:
                b = Node("element", "body", "html")
                b.attrs = list(tok.attrs)
                self.root.append(b)
                # The body has to become the insertion point, not just a node in
                # the tree.  Without this every element of a served page landed
                # as a SIBLING of <body>, which kept liveness verdicts right by
                # accident (an img fires wherever it sits) while making every
                # ancestor-dependent rule -- select scope, table scope, foreign
                # integration, template -- read a flat tree.
                self.stack.append(b)
                return
            # Document mode: a second <body> merges its attributes onto the one
            # already open, for every name the first body did not carry.  This
            # is why `<body onload=CODE>` reflected into the middle of a page
            # executes -- measured live through the parser, inert through
            # innerHTML, so the two modes must not share this branch.
            have = {k for k, _ in existing.attrs}
            for k, v in tok.attrs:
                if k not in have:
                    existing.attrs.append((k, v))
            return
        if name == "frameset":
            if self.fragment:
                # Inside a fragment (`innerHTML`), a stray `<frameset>` is
                # discarded -- measured as dropped in the div/option/select
                # contexts of benchmark/results/option_probe.json, and as no
                # execution in every fragment arm of benchmark/probe_frame.py.
                return
            # In a *document* parse the frameset really is built, and a
            # `<frame src="javascript:CODE">` inside it executes -- measured, with
            # a positive control (a frame that loads a child document carrying the
            # handler), in benchmark/probe_frame.py.  But only while the page has
            # not committed to body content: `<html><frameset>` opens a browsing
            # context, `<html><body><frameset>` and `<html>x<frameset>` do not,
            # and treating those two alike was an OVER on every served page that
            # reflects below its own markup.  A frameset nested in an open
            # frameset is a different rule -- `in frameset` accepts it -- and a
            # second frameset at document level after one has been honoured is
            # not (`<frameset></frameset><frameset>` measured ignored).
            nested = any(st.ns == "html" and st.name == "frameset"
                         for st in self.stack[1:])
            if not (nested or self.frameset_ok):
                return
            self.frameset_ok = False
            fs = Node("element", "frameset", "html")
            fs.attrs = list(tok.attrs)
            self.current().append(fs)
            self.stack.append(fs)
            return
        if name in TABLE_ONLY_STARTS and not any(
                st.ns == "html" and st.name in TABLE_CONTEXT
                for st in self.stack[1:]):
            # No table open: the token is discarded, and no element of any kind
            # appears.  Doing this before `close_scoped` matters -- the implied
            # close those names do in table context must not happen here either.
            return
        if name in FRAMESET_ONLY_STARTS and not any(
                st.ns == "html" and st.name == "frameset"
                for st in self.stack[1:]):
            return
        self.close_scoped(name)
        # --- <select> scope, measured name by name ---------------------------
        # What follows is what `benchmark/probe_option.py` came back with over
        # 152 names x {div, select, option, optgroup} x both sinks, every shape
        # round-trip stable.  An element reflected into an <option> *stays
        # inside that option* -- 133 of the 152 measured names are not special
        # at all.  The rule this replaces hoisted every non-option name out of the
        # select, which is correct for exactly one name (`input`) and wrong for
        # the rest, and in document mode it also carried the content past
        # <body>, because popping "to select" popped the body with it.
        if any(st.name == "select" and st.ns == "html" for st in self.stack[1:]):
            if name in SELECT_DROPPED:
                return
            if name in SELECT_EXITS:
                # `<select><option><input autofocus onfocus=...>` really does
                # put a firing input beside the select rather than a buried one
                # inside it -- the measurement that started this branch.
                while len(self.stack) > 1:
                    popped = self.stack.pop()
                    if popped.name == "select" and popped.ns == "html":
                        break
            else:
                closers: Iterable[str] = ()
                if name in SELECT_END_OPTION:
                    closers = SELECT_END_OPTION
                elif name in SELECT_END_SCOPE:
                    closers = OPTION_SCOPE
                while self.current().ns == "html" \
                        and self.current().name in closers:
                    self.stack.pop()
        self._imply_table_rows(name)
        # <svg> and <math> are the entry doors to foreign content: everything
        # about break-out, integration points and CDATA depends on this node
        # carrying the right namespace, not on the tag name alone.
        ns = "svg" if name == "svg" else ("mathml" if name == "math" else "html")
        if name in ("mglyph", "malignmark") \
                and self.current().ns == "mathml" \
                and self.current().name in MATHML_TEXT_INTEGRATION:
            # The one exception to "children of a MathML text integration point
            # are HTML": <mglyph> and <malignmark> are created in the MathML
            # namespace even there.  Not cosmetic.  It is what makes a <style>
            # inside them a MathML element rather than an HTML raw-text element,
            # so the `<img>` written in it stops being text and becomes a live
            # tag on the NEXT parse -- the namespace flip that
            # benchmark/sanitizer_probe.py measured as a real mutation vector.
            ns = "mathml"
        node = Node("element", name, ns)
        if ns == "html" and name in TABLE_SCOPE \
                and any(st.ns == "mathml" and st.name in MATHML_TEXT_INTEGRATION
                        for st in self.stack[1:]):
            # Honest limit.  A table container opened inside a MathML text
            # integration point makes the foster-parenting rule interact with the
            # integration-point rule in a way this parser does not model: the
            # browser moves the mglyph subtree out of the table *and* lands it
            # under the integration point, and the payload fires on the FIRST
            # parse.  Measured over benchmark/mxss_family_probe.py (120 of 360
            # combinations), so the shape is recorded and `judge` refuses to call
            # it inert -- it says UNKNOWN and the browser gets asked.
            self.notes.append("table scope inside a MathML integration point "
                              "(foster parenting across that boundary not "
                              "modelled)")
        node.attrs = ([(_adjust_foreign_attr(an, ns), av)
                       for an, av in tok.attrs]
                      if ns != "html" else tok.attrs)
        cur = self.current()
        if cur.ns == "html" and cur.name in TABLE_SCOPE \
                and name not in TABLE_OK_IN.get(cur.name, set()) \
                and self.foster_insert(node):
            # Foster parenting: this element does not belong in the open table
            # container, so it goes *before* the table and the table stays empty.
            if name in VOID or tok.self_closing:
                return
            self.stack.append(node)
            self.enter_content_model(node, name)
            return
        cur.append(node)
        if name in VOID or tok.self_closing:
            return
        self.stack.append(node)
        self.enter_content_model(node, name)

    def html_end(self, name: str) -> None:
        if name in ("html", "body", "head"):
            return
        if name == "br":
            # `</br>` acts as `<br>`; only the serialised shape turns on it.
            self.current().append(Node("element", "br"))
            return
        if name == "p":
            if not self.pop_to("p"):
                # in-body `</p>` with no open <p> inserts one.  Reached by
                # `<svg></p>...` after the break-out (probe_foreign).
                p = Node("element", "p", "html")
                self.current().append(p)
            return
        self.pop_to(name)

    # -- main loop ----------------------------------------------------------
    def run(self) -> Doc:
        s, n = self.s, self.n
        while self.i < n:
            c = s[self.i]
            if c != "<":
                j = s.find("<", self.i)
                j = n if j < 0 else j
                data = s[self.i:j]
                # Foreign text does not consume character references: the two
                # `&lt;` payloads in the oracle are inert only because of that.
                if self.in_foreign():
                    self.add_text(data, decode=False)
                else:
                    self.add_text(data, decode=True)
                self.i = j
                continue

            nxt = s[self.i + 1] if self.i + 1 < n else ""

            if nxt == "!":
                if s[self.i:self.i + 4] == "<!--":
                    end = s.find("-->", self.i + 4)
                    if end < 0:
                        self.current().append(_comment(s[self.i + 4:]))
                        self.notes.append(
                            "unterminated comment swallowed the remainder")
                        return Doc(self.root, self.notes)
                    self.current().append(_comment(s[self.i + 4:end]))
                    self.i = end + 3
                    continue
                if s[self.i:self.i + 9].upper() == "<![CDATA[":
                    if self.in_foreign():
                        end = s.find("]]>", self.i + 9)
                        end = n if end < 0 else end
                        self.current().append(Node("text", s[self.i + 9:end]))
                        self.i = end + 3 if end < n else n
                        continue
                    # CDATA in HTML content is a bogus comment up to `>`.
                    end = s.find(">", self.i)
                    end = n if end < 0 else end
                    self.current().append(_comment(s[self.i + 2:end]))
                    self.i = end + 1
                    continue
                end = s.find(">", self.i)
                end = n if end < 0 else end
                self.current().append(_comment(s[self.i + 2:end]))
                self.i = end + 1
                continue

            if nxt == "/":
                nxt2 = s[self.i + 2] if self.i + 2 < n else ""
                if not ("a" <= nxt2.lower() <= "z"):
                    # `</` followed by anything that is not an ASCII letter is
                    # not an end tag at all -- it opens a BOGUS COMMENT that
                    # swallows everything up to the next `>`.  Skipping the
                    # whitespace first (as this used to) made `</ foreignObject>`
                    # look like a harmless close tag, so markup the browser keeps
                    # alive inside a comment vanished here, and `</</</OPTGROUP>`
                    # produced nothing.  Measured with the random differential
                    # fuzzer; the browser's own serialisation is
                    # `<!-- foreignObject-->`, `<!--]]-->`, `<!--</</OPTGROUP-->`.
                    k = s.find(">", self.i + 2)
                    if k < 0:
                        self.current().append(_comment(s[self.i + 2:]))
                        return Doc(self.root, self.notes)
                    self.current().append(_comment(s[self.i + 2:k]))
                    self.i = k + 1
                    continue
                j = _skip_ws(s, self.i + 2)
                name, j = _read_name(s, j, " \t\n\r\f/>")
                # Same rule as attribute names: NUL becomes U+FFFD, so
                # `</scr<NUL>opt>` does not close a <script>.  Dropping it here
                # would make end tags the one place the bypass works.
                name = name.lower().replace("\x00", "\ufffd")
                k = s.find(">", j)
                end_i = n if k < 0 else k + 1
                if not name:
                    # `</>` is a bogus comment.
                    self.i = end_i
                    continue
                if self.in_foreign():
                    cur = self.current()
                    if cur.name == name:
                        self.stack.pop()
                    elif self._pop_foreign_named(name):
                        pass
                    else:
                        # Unmatched end tag in foreign content breaks out and is
                        # reprocessed as HTML -- how `<svg></p><style>` yields
                        # live markup on the FIRST parse.
                        self.pop_foreign()
                        self.i = end_i
                        self.html_end(name)
                        continue
                    self.i = end_i
                    continue
                self.i = end_i
                self.html_end(name)
                continue

            if not nxt.isalpha():
                # `<?php`, a bare `<`, `< 3`: text or a bogus comment.
                k = s.find(">", self.i)
                if k < 0:
                    self.add_text(s[self.i:], decode=not self.in_foreign())
                    return Doc(self.root, self.notes)
                if nxt in ("?", "!"):
                    self.current().append(_comment(s[self.i + 1:k]))
                else:
                    self.current().append(Node("text", s[self.i:k + 1]
                                               .replace("\x00", "\ufffd")))
                self.i = k + 1
                continue

            tok, j = self.read_tag(self.i + 1)
            self.i = j
            if not tok.name:
                continue

            if self.in_foreign():
                if tok.name in FOREIGN_BREAK:
                    self.pop_foreign()
                    self.html_start(tok)
                    continue
                node = Node("element", _adjust_foreign(tok.name,
                                                       self.current().ns),
                            self.current().ns)
                node.attrs = [(_adjust_foreign_attr(an, self.current().ns), av)
                              for an, av in tok.attrs]
                self.current().append(node)
                # HTML void-ness does not cross into foreign content: `<base>`,
                # `<link>`, `<input>` are simply unknown SVG/MathML elements
                # there, they are not void, and they take children.  Measured --
                # Chromium nests the following `<a>` *inside* a foreign `<base>`
                # while the HTML void table would close it immediately.
                if not tok.self_closing:
                    self.stack.append(node)
                continue

            self.html_start(tok)

        return Doc(self.root, self.notes)

    def _pop_foreign_named(self, name: str) -> bool:
        for k in range(len(self.stack) - 1, 0, -1):
            if self.stack[k].name == name and self.stack[k].ns != "html":
                del self.stack[k:]
                return True
        return False
