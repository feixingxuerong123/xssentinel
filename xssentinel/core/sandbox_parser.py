"""The tokeniser and tree-builder half of the sandbox.

Split out of ``core/sandbox.py`` (docs 1.3) as a pure move -- nothing here was
rewritten while moving.  Callers keep going through ``sandbox.parse()``.
"""

from __future__ import annotations

from typing import Iterable

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
    Doc,
    MATHML_TEXT_INTEGRATION,
    Node,
    SVG_HTML_INTEGRATION,
    VOID,
)

RAWTEXT = frozenset({"style", "xmp", "iframe", "noembed", "noframes"})

#: Like RAWTEXT but character references ARE consumed.
RCDATA = frozenset({"title", "textarea"})

#: Everything to end-of-input is text.
PLAINTEXT = frozenset({"plaintext"})

#: Start tags that BREAK OUT of foreign content: the parser leaves the svg/math
#: subtree and the element becomes HTML beside it.
#:
#: MEASURED, not recalled from the spec.  Every name in a 120-element candidate
#: list was opened inside `<svg>` and inside `<math>` and the element's own
#: position in the resulting tree decided the answer
#: (benchmark/probe_breakout.py -> results/foreign_breakout.json).  Both
#: namespaces returned the identical 40 names.
#:
#: Getting this wrong costs in both directions, which is why it is measured
#: rather than guessed.  `<select>`, `<template>`, `<style>`, `<script>`,
#: `<iframe>`, `<form>`, `<input>`, `<button>`, `<option>`, `<td>`/`<tr>`,
#: `<a>`, `<title>` and `<noscript>` do NOT break out -- listing them as
#: breakers collapses the foreign subtree into HTML and manufactures liveness
#: (that was the bug behind the `mxss-select-style x svg_style` miss).  And
#: `<span>`, `<s>`, `<tt>`, `<var>`, `<em>`, `<ruby>`, `<small>`, `<dd>` DO --
#: leaving them out loses the real `<svg><span><img onerror>` breakout.
#: `code`/`nobr` are in the spec's list and unprobed here; `body`/`head` are in
#: the spec's list but create no element inside a div, so this harness cannot
#: observe them -- both are included because the break-out *decision* is what
#: the tree builder acts on.
FOREIGN_BREAK = frozenset({
    "b", "big", "blockquote", "body", "br", "center", "code", "dd", "div",
    "dl", "dt", "em", "embed", "h1", "h2", "h3", "h4", "h5", "h6", "head",
    "hr", "i", "img", "li", "listing", "menu", "meta", "nobr", "ol", "p",
    "pre", "ruby", "s", "small", "span", "strike", "strong", "sub", "sup",
    "table", "tt", "u", "ul", "var",
})


#: Elements that auto-dismiss the next <p>.
P_CLOSERS = frozenset({
    "address", "article", "aside", "blockquote", "center", "details",
    "dialog", "dir", "div", "dl", "fieldset", "figcaption", "figure",
    "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header",
    "hgroup", "main", "menu", "nav", "ol", "p", "pre", "section",
    "summary", "ul", "table", "span", "hr", "iframe", "noscript",
    "button", "input", "select", "textarea", "li", "dd", "dt",
})


#: End tags that close a <p> even though they are not themselves <p>.
AUTO_CLOSE = {
    "li": {"li"},
    "dd": {"dd", "dt"},
    "dt": {"dd", "dt"},
    "tr": {"td", "th", "tr"},
    "td": {"td", "th"},
    "th": {"td", "th"},
    "p": {"p"},
    "option": {"option"},
    "optgroup": {"option", "optgroup"},
}


#: Start tags that the tree builder ignores unless a table is already open.
#: Measured name by name in a bare `<div>`, and again inside `<select>`,
#: `<option>` and `<optgroup>` (152 names x 4 contexts,
#: benchmark/results/option_probe.json): the browser creates no element at all,
#: so a payload reflected as `<td>` is not merely inert, it is absent -- and a
#: model that inserts it sees a node the DOM does not have.
TABLE_ONLY_STARTS = frozenset({
    "caption", "col", "colgroup", "tbody", "td", "tfoot", "th", "thead", "tr",
})


#: The tags a `<frameset>` owns.  `frame` measured dropped in all four contexts;
#: `frameset` itself is handled where it is noted as changing the model.
FRAMESET_ONLY_STARTS = frozenset({"frame"})


#: Start tags that switch the parser's `frameset-ok` flag off, so a `<frameset>`
#: after one of them is IGNORED -- no frameset element, no browsing context, and
#: a `<frame src="javascript:CODE">` inside it runs nothing.  Measured name by
#: name in `benchmark/probe_frameset_ok.py`: one served page per element
#: (`<html><NAME>` then a frameset holding `<frame src="javascript:__x()">`), a
#: hit meaning the frameset was still honoured -- 125 names, because a sample of
#: them is how the `<option>` rule was once written wrong.
#:
#: The names *absent* here are the other half of that measurement and the
#: surprising half: `<div>`, `<span>`, `<p>`, `<a>`, `<svg>`, `<math>`, `<menu>`,
#: the head metadata tags and `<caption>`/`<col>` all leave the flag alone, so a
#: frameset that follows one of them really is built.  `<textarea>`, `<xmp>` and
#: `<plaintext>` are listed although their raw text also swallows the payload:
#: `<html><xmp></xmp><frameset><frame src=javascript:CODE>` measured ignored, so
#: the tag clears the flag on its own.
#:
#: Character tokens clear it too (see `add_text`), which is why `<html>x<frameset>`
#: is dead while `<html><!--x--><frameset>` lives: a comment is not a character
#: token, whitespace-only text has its own rule, and text inside a `<template>`
#: is not body text -- measured honoured, unlike text inside `<svg>`.
FRAMESET_OK_KILLERS = frozenset({
    "area", "body", "br", "button", "dd", "dt", "embed", "hr", "iframe", "img",
    "input", "keygen", "li", "listing", "marquee", "object", "plaintext", "pre",
    "select", "table", "textarea", "xmp",
})


#: Elements whose presence means "a table is open" for the rule above.
TABLE_CONTEXT = frozenset({"table", "tbody", "thead", "tfoot", "tr"})



#: What may legally appear inside each table-scope container.  Anything else is
#: **foster-parented**: inserted *before* the table rather than inside it.
#: This is not a cosmetic reordering -- it is the step that turns
#: `<math><mtext><table><mglyph><style><img onerror>` from inert into a live
#: vector, because moving the empty <table> out of the way lets the re-parse hit
#: the mglyph MathML exception (see `html_start`) and flip <style>'s namespace.
TABLE_SCOPE = frozenset({"table", "tbody", "thead", "tfoot", "tr"})

TABLE_OK_IN = {
    "table": {"caption", "col", "colgroup", "tbody", "tfoot", "thead", "tr",
              "td", "th", "form", "style", "script", "template", "slot"},
    "tbody": {"tr", "td", "th", "style", "script", "template", "slot"},
    "thead": {"tr", "td", "th", "style", "script", "template", "slot"},
    "tfoot": {"tr", "td", "th", "style", "script", "template", "slot"},
    "tr": {"td", "th", "caption", "style", "script", "template", "slot"},
}


#: Start tags the tree builder throws away outright while a <select> is open --
#: whether the insertion point is the select itself or an <option>/<optgroup>
#: inside it.  Measured per name (152 names x 4 contexts, both sinks) in
#: benchmark/results/option_probe.json.  This is deliberately NOT the spec's
#: list: the spec *pops the select closed* for caption/col/colgroup/tbody/
#: tfoot/th/thead/tr and re-processes them in body, Chromium discards the token.
SELECT_DROPPED = frozenset({
    "body", "caption", "col", "colgroup", "head", "html", "select", "tbody",
    "tfoot", "th", "thead", "tr",
})


#: The one measured name that leaves an open <select> entirely: it closes the
#: select and is then inserted outside it.
SELECT_EXITS = frozenset({"input"})


#: Names that close an open <option> (and <optgroup> for `optgroup`/`hr`) and
#: land in the select itself.  `option` closes only an open <option>, which is
#: what keeps `<optgroup><option>` an option *inside* the group.
SELECT_END_OPTION = frozenset({"option"})

SELECT_END_SCOPE = frozenset({"optgroup", "hr"})


#: The elements that *are* the option scope, i.e. what `optgroup` and `hr` close
#: down to.  Distinct from SELECT_END_SCOPE, which is the set of names that
#: trigger that close -- conflating the two is what left `<option><hr>` nested
#: in the option instead of landing in the select.
OPTION_SCOPE = frozenset({"option", "optgroup"})



# ---------------------------------------------------------------------------
# Character references
# ---------------------------------------------------------------------------

_NAMED = {
    "amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'",
    "nbsp": " ", "tab": "\t", "newline": "\n", "colon": ":",
    "semi": ";", "sol": "/", "lparen": "(", "rparen": ")",
    "num": "#", "commat": "@", "period": ".",
    "excl": "!", "quest": "?", "plus": "+", "equals": "=",
    "lcub": "{", "rcub": "}", "lsqb": "[", "rsqb": "]",
    "bsol": "\\", "hyphen": "-", "lowbar": "_", "dollar": "$",
    "percnt": "%", "ast": "*", "copy": "©", "reg": "®",
    "amp;": "&", "lt;": "<", "gt;": ">",
}



def _decode_ref(s: str, i: int, in_attr: bool) -> tuple[str, int]:
    """Decode one character reference at s[i] ('&').  Returns (text, consumed)."""
    n = len(s)
    if i + 1 >= n or s[i + 1] != "#":
        j = i + 1
        while j < n and (s[j].isalnum()):
            j += 1
            if j - i > 32:
                break
        name = s[i + 1:j]
        if not name:
            return "&", 1
        # The named-reference matcher tries the longest known name first, and a
        # reference without ';' still decodes in text -- which is how
        # `&lt` (no semicolon) becomes '<' and then a live tag start.
        for ln in range(min(len(name), 31), 0, -1):
            cand = name[:ln]
            if cand in _NAMED:
                consumed = 1 + ln
                if j < n and s[i + 1 + ln] == ";":
                    consumed += 1
                return _NAMED[cand], consumed
        return "&", 1
    # numeric
    j = i + 2
    radix = 10
    if j < n and s[j] in "xX":
        radix = 16
        j += 1
    ds = j
    while j < n and (s[j] in "0123456789" if radix == 10
                     else s[j] in "0123456789abcdefABCDEF"):
        j += 1
    if j == ds:
        return "&", 1
    try:
        cp = int(s[ds:j], radix)
    except ValueError:
        return "&", 1
    if j < n and s[j] == ";":
        j += 1
    elif in_attr:
        # In an attribute value a bare `&` followed by alphanumerics is left
        # alone; the whole point is that `&lt` there is NOT '<'.
        pass
    if cp == 0:
        # `&#0;` / `&#x00;` decodes to U+FFFD, NOT to nothing.  Deleting it is
        # what turned `<a href="jav&#x00;ascript:...">` -- which Chromium holds as
        # `jav\ufffdascript:`, an inert relative URL -- into a live `javascript:`
        # URI in the sandbox.  Measured in benchmark/results/nul_probe.json.
        return "\ufffd", j - i
    if cp > 0x10FFFF or 0xD800 <= cp <= 0xDFFF:
        return "", j - i
    try:
        return chr(cp), j - i
    except ValueError:
        return "", j - i



def decode_entities(s: str, in_attr: bool = False) -> str:
    out = []
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c == "&":
            t, consumed = _decode_ref(s, i, in_attr)
            out.append(t)
            i += consumed
        else:
            out.append(c)
            i += 1
    return "".join(out)



# ---------------------------------------------------------------------------
# Tokeniser
# ---------------------------------------------------------------------------

class Token:
    __slots__ = ("kind", "name", "attrs", "data", "self_closing")

    def __init__(self, kind, name="", attrs=None, data="", self_closing=False):
        self.kind = kind          # start | end | text | comment | doctype
        self.name = name
        self.attrs = attrs or []
        self.data = data
        self.self_closing = self_closing

    def __repr__(self) -> str:
        return f"Token({self.kind},{self.name!r},{len(self.attrs)}a)"



def _skip_ws(s: str, i: int) -> int:
    n = len(s)
    while i < n and s[i] in " \t\n\r\f":
        i += 1
    return i



def _read_name(s: str, i: int, stop: str) -> tuple[str, int]:
    n = len(s)
    j = i
    while j < n and s[j] not in stop:
        j += 1
    return s[i:j], j



def _attr_value_end(s: str, i: int, quote: str) -> int:
    n = len(s)
    if quote:
        j = s.find(quote, i)
        return n if j < 0 else j
    j = i
    while j < n and s[j] not in " \t\n\r\f>":
        j += 1
    return j



def _comment(data: str) -> Node:
    """A comment node, with the NUL adjustment the tokenizer makes for it.

    `<!--a<NUL>b-->` holds `61 fffd 62` (benchmark/results/nul_probe.json).  It
    matters because comment text is re-serialised verbatim, so a raw NUL that
    survives here is fed to the *next* parse as bytes no browser ever produced --
    which is how a `-->`-escaping mXSS vector would be judged on fiction.
    """
    return Node("comment", data.replace("\x00", "\ufffd"))



def _close_rawtext(s: str, i: int, name: str) -> int:
    """Return the index where `</name` appears, tolerating `< / name` and
    `< /name` -- the slash-after-langle variants that bypass naive filters."""
    n = len(s)
    j = i
    low = name.lower()
    while j < n:
        k = s.find("<", j)
        if k < 0:
            return n
        m = k + 1
        # The slash is required.  Treating it as optional makes `<style>` close
        # on `<style`, i.e. on the payload's own nested start tag, and the whole
        # raw-text region collapses to nothing -- which is how `<noscript>` hosts
        # reported every RCDATA-breakout payload as inert.
        if m >= n or s[m] != "/":
            j = k + 1
            continue
        m += 1
        # The name may be any case and must be followed by ws / `>` / `/`.
        ln = 0
        while m + ln < n and ln < len(low) and s[m + ln].lower() == low[ln]:
            ln += 1
        if ln == len(low):
            after = s[m + ln] if m + ln < n else ">"
            if after in " \t\n\r\f/>":
                return k
        j = k + 1
    return n



#: SVG element names carry capitals, and the tree builder restores them from the
#: lowercased tag name it read: `<clippath>` becomes `clipPath`, `<fegaussianblur`
#: becomes `feGaussianBlur`.  Every row was measured by
#: `benchmark/probe_svg_case.py` (68 names, one element per page, compared against
#: Chromium's own `innerHTML` byte for byte), including the two halves that make
#: the table safe to use: `hatchpath`, `mpath`, `tspan` and 27 others really do
#: stay lowercase, and an already-capital input (`<viewBox>`, `<FEgaussianBlur>`)
#: is looked up by its lowercased form -- so the key column is what the tokenizer
#: produces and never the bytes as sent.
#:
#: This is not cosmetic.  A serialiser that prints a name the DOM does not hold
#: yields a second parse of a document that never existed, and mXSS is judged on
#: exactly that second parse.
_SVG_CASE = {
    "animatecolor": "animateColor",
    "animatemotion": "animateMotion",
    "animatetransform": "animateTransform",
    "clippath": "clipPath",
    "feblend": "feBlend",
    "fecolormatrix": "feColorMatrix",
    "fecomponenttransfer": "feComponentTransfer",
    "fecomposite": "feComposite",
    "feconvolvematrix": "feConvolveMatrix",
    "fediffuselighting": "feDiffuseLighting",
    "fedisplacementmap": "feDisplacementMap",
    "fedistantlight": "feDistantLight",
    "fedropshadow": "feDropShadow",
    "feflood": "feFlood",
    "fefunca": "feFuncA",
    "fefuncb": "feFuncB",
    "fefuncg": "feFuncG",
    "fefuncr": "feFuncR",
    "fegaussianblur": "feGaussianBlur",
    "feimage": "feImage",
    "femerge": "feMerge",
    "femergenode": "feMergeNode",
    "femorphology": "feMorphology",
    "feoffset": "feOffset",
    "fepointlight": "fePointLight",
    "fespecularlighting": "feSpecularLighting",
    "fespotlight": "feSpotLight",
    "fetile": "feTile",
    "feturbulence": "feTurbulence",
    "foreignobject": "foreignObject",
    "lineargradient": "linearGradient",
    "radialgradient": "radialGradient",
    "textpath": "textPath",
}


#: SVG attribute names are case-adjusted by the tree builder, not lowercased like
#: HTML ones: `<animate attributename=...>` reaches the DOM as `attributeName`,
#: and `innerHTML` prints the adjusted form.  The sandbox used to print what the
#: tokenizer read, which is why `svg-animate` was the largest remaining
#: serialisation family in `benchmark/sandbox_fidelity.py` (5 of its 6 contexts
#: diverged).  Every row is checked name by name against a real browser by
#: `benchmark/probe_svg_case.py`, so the table is a measurement and not a
#: recollection -- including the one MathML name, which is the only entry the
#: MathML side of the rule contributes.
_SVG_ATTR_CASE = {
    "attributename": "attributeName",
    "attributetype": "attributeType",
    "basefrequency": "baseFrequency",
    "baseprofile": "baseProfile",
    "calcmode": "calcMode",
    "clippathunits": "clipPathUnits",
    "diffuseconstant": "diffuseConstant",
    "edgemode": "edgeMode",
    "filterunits": "filterUnits",
    "glyphref": "glyphRef",
    "gradienttransform": "gradientTransform",
    "gradientunits": "gradientUnits",
    "kernelmatrix": "kernelMatrix",
    "kernelunitlength": "kernelUnitLength",
    "keypoints": "keyPoints",
    "keysplines": "keySplines",
    "keytimes": "keyTimes",
    "lengthadjust": "lengthAdjust",
    "limitingconeangle": "limitingConeAngle",
    "markerheight": "markerHeight",
    "markerunits": "markerUnits",
    "markerwidth": "markerWidth",
    "maskcontentunits": "maskContentUnits",
    "maskunits": "maskUnits",
    "numoctaves": "numOctaves",
    "pathlength": "pathLength",
    "patterncontentunits": "patternContentUnits",
    "patterntransform": "patternTransform",
    "patternunits": "patternUnits",
    "pointsatx": "pointsAtX",
    "pointsaty": "pointsAtY",
    "pointsatz": "pointsAtZ",
    "preservealpha": "preserveAlpha",
    "preserveaspectratio": "preserveAspectRatio",
    "primitiveunits": "primitiveUnits",
    "refx": "refX",
    "refy": "refY",
    "repeatcount": "repeatCount",
    "repeatdur": "repeatDur",
    "requiredextensions": "requiredExtensions",
    "requiredfeatures": "requiredFeatures",
    "specularconstant": "specularConstant",
    "specularexponent": "specularExponent",
    "spreadmethod": "spreadMethod",
    "startoffset": "startOffset",
    "stddeviation": "stdDeviation",
    "stitchtiles": "stitchTiles",
    "surfacescale": "surfaceScale",
    "systemlanguage": "systemLanguage",
    "tablevalues": "tableValues",
    "targetx": "targetX",
    "targety": "targetY",
    "textlength": "textLength",
    "viewbox": "viewBox",
    "viewtarget": "viewTarget",
    "xchannelselector": "xChannelSelector",
    "ychannelselector": "yChannelSelector",
    "zoomandpan": "zoomAndPan",
}


#: The same rule on the MathML side, and `definitionurl` -> `definitionURL` is
#: the only pair with a case difference worth modelling.
_MATHML_ATTR_CASE = {"definitionurl": "definitionURL"}



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



def _adjust_foreign(name: str, ns: str) -> str:
    if ns != "svg":
        return name
    return _SVG_CASE.get(name, name)



def _adjust_foreign_attr(aname: str, ns: str) -> str:
    """The foreign-content case adjustment for ATTRIBUTE names.

    Names arrive here already lowercased by the tokenizer, which is exactly the
    form the adjustment table is keyed on: `<animate ATTRIBUTENAME=...>`,
    `attributename` and `attributeName` all reach the DOM as `attributeName`.  A
    prefixed name (`xlink:href`) has no entry and stays as read.
    """
    if ns == "svg":
        return _SVG_ATTR_CASE.get(aname, aname)
    if ns == "mathml":
        return _MATHML_ATTR_CASE.get(aname, aname)
    return aname
