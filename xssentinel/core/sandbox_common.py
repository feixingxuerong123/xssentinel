"""Structures shared by both halves of the sandbox.

Split out of ``core/sandbox.py`` (docs 1.3).  Holds only what both the parser
half and the judging half need, so neither has to import the other.  See
``sandbox.py``'s docstring for what this sandbox models and how its fidelity is
measured against Chromium.
"""

from __future__ import annotations

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


#: Elements whose serialised text children are written verbatim (no escaping).
#: Taken from the HTML parsing spec's "serialise an HTML fragment" step; this is
#: the exact set that lets text turn back into markup on re-parse.
NO_ESCAPE_TEXT = frozenset(
    {"script", "style", "xmp", "iframe", "noembed", "noframes", "plaintext",
     "noscript"})


#: MathML integration points: children are parsed as HTML, not MathML.
MATHML_TEXT_INTEGRATION = frozenset(
    {"mtext", "mi", "mo", "mn", "ms", "mmultiscripts", "mprescripts",
     "none", "annotation-xml"})

#: SVG integration points: children are parsed as HTML.
SVG_HTML_INTEGRATION = frozenset({"foreignobject", "desc", "title"})


#: Void elements never take children and swallow no close tag.
VOID = frozenset({
    "area", "base", "basefont", "bgsound", "br", "col", "embed", "frame",
    "hr", "img", "input", "keygen", "link", "meta", "param", "source",
    "track", "wbr", "image", "menuitem", "command", "!--",
})



# ---------------------------------------------------------------------------
# DOM
# ---------------------------------------------------------------------------

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



# ---------------------------------------------------------------------------
# Tree construction
# ---------------------------------------------------------------------------

class Doc:
    """Parse result: the fragment root plus what the parser dropped or moved."""

    __slots__ = ("root", "notes")

    def __init__(self, root: Node, notes: Optional[list] = None):
        self.root = root
        self.notes = notes if notes is not None else []



# ---------------------------------------------------------------------------
# Serialisation (innerHTML-compatible)
# ---------------------------------------------------------------------------

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


# Phase 253: this trio was rolled back to the consistent pre-wipe set
# (2959a34).  The workspace wipe destroyed the post-225 refactor's
# sandbox_common.py (the tokenizer that sandbox_parser.py imports) and
# NO copy of that version exists anywhere on this machine -- verified
# against the Desktop copy, D:\qoder\_recovery, D:	rae and D:\op.
# The refactor was a code MOVE (behaviour unchanged, same public API:
# the rest of the tree imports only `judge`), so function is restored
# ahead of structure; the split can be redone later from this file.
