# -*- coding: utf-8 -*-
"""Phase 328b: a hostile sitemap must not expand entities inside the parser.

Measured before the fix (dev/_p328_parser_caps.py): a **585-byte**
billion-laughs document expanded in stdlib ElementTree to >720 MB RSS --
the 8 MB document cap is irrelevant because expansion happens after the
bytes arrive.  External entities were already unreachable; the internal
side was not.  Sitemaps never need custom entities, so documents that
declare one are refused before parsing, at both the root and child paths.
"""
from __future__ import annotations

import ast
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import sitemap_import                    # noqa: E402
from xssentinel.core.sitemap_import import sitemap_to_urls    # noqa: E402

URLSET = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://t/a</loc></url>
</urlset>"""

ENTITY_URLSET = """<?xml version="1.0"?>
<!DOCTYPE urlset [
  <!ENTITY target "http://t/entity-expanded">
]>
<urlset><url><loc>&target;</loc></url></urlset>"""


def _billion_laughs(levels: int = 5) -> str:
    parts = ['<?xml version="1.0"?>', '<!DOCTYPE urlset [',
             '<!ENTITY lol "lol">']
    prev = "lol"
    for i in range(1, levels + 1):
        parts.append(f'<!ENTITY lol{i} "{("&" + prev + ";") * 10}">')
        prev = f"lol{i}"
    parts.append("]>")
    return "".join(parts) + (
        f"<urlset><url><loc>http://t/&{prev};</loc></url></urlset>")


def _fetch(docs):
    def fetch(url):
        return docs[url]
    return fetch


def test_a_declared_entity_is_refused_not_expanded():
    # Without the guard this document yields "http://t/entity-expanded";
    # the assertion is therefore load-bearing, not just "no crash".
    urls = sitemap_to_urls("http://t/s.xml",
                           fetch=_fetch({"http://t/s.xml": ENTITY_URLSET}))
    assert urls == []


def test_billion_laughs_is_refused_before_expansion():
    # Level 5 expands to ~300k characters (measured ~33 MB RSS) in the
    # unguarded parser; the guard must keep this a fast empty answer.
    doc = _billion_laughs(5)
    urls = sitemap_to_urls("http://t/s.xml",
                           fetch=_fetch({"http://t/s.xml": doc}))
    assert urls == []


def test_a_child_sitemap_gets_the_same_guard():
    index = """<?xml version="1.0"?>
    <sitemapindex>
      <sitemap><loc>http://t/evil.xml</loc></sitemap>
      <sitemap><loc>http://t/good.xml</loc></sitemap>
    </sitemapindex>"""
    urls = sitemap_to_urls("http://t/index.xml", fetch=_fetch({
        "http://t/index.xml": index,
        "http://t/evil.xml": ENTITY_URLSET,
        "http://t/good.xml": URLSET,
    }))
    assert urls == ["http://t/a"]


def test_a_normal_urlset_still_parses():
    urls = sitemap_to_urls("http://t/s.xml",
                           fetch=_fetch({"http://t/s.xml": URLSET}))
    assert urls == ["http://t/a"]


def test_a_doctype_without_entities_is_still_accepted():
    # The guard targets entity DECLARATIONS, not the DOCTYPE itself.
    doc = ('<!DOCTYPE urlset><urlset><url><loc>http://t/b</loc></url>'
           '</urlset>')
    urls = sitemap_to_urls("http://t/s.xml",
                           fetch=_fetch({"http://t/s.xml": doc}))
    assert urls == ["http://t/b"]


def test_every_parse_goes_through_the_guard():
    """A future call site must not bypass _parse_xml with ET.fromstring."""
    path = os.path.abspath(sitemap_import.__file__)
    with open(path, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    fromstrings = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "fromstring"
    ]
    guard_calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_parse_xml"
    ]
    assert len(fromstrings) == 1, "raw ET.fromstring outside _parse_xml"
    assert len(guard_calls) == 2, "both root and child parse paths must use it"
