# -*- coding: utf-8 -*-
"""Link extraction: one scheme contract for both engines.

The two pipelines each hand-wrote a blacklist and they DRIFTED: sync
``scanner_crawl.py`` skips ``("#","javascript:","mailto:","tel:","data:")``,
async ``_extract_links`` skips only ``("#","javascript:","mailto:")`` (and
form actions skip even fewer).  Both are blacklists, so ``vbscript:``,
``blob:``, ``file:``, case / tab variants slip through the extractor and
are only caught later by a ``netloc != origin`` check -- a second, implicit
line of defence that a future refactor can remove.

The fix is a single allowlist in ``url_safety``; this file locks the
behaviour and the two call sites.
"""
import ast
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.async_scanner_common import _extract_links  # noqa: E402
from xssentinel.core.url_safety import is_crawlable_link  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BASE = "http://h/dir/page?q=1"

DANGEROUS = [
    "data:text/html,x",
    "vbscript:msgbox(1)",
    "JAVASCRIPT:alert(1)",
    "java\tscript:alert(1)",
    "blob:http://h/u",
    "file:///etc/passwd",
    "mailto:a@b",
    "tel:123",
    "about:blank",
]

LEGAL = ["/next", "../up", "./here", "?q=2", "//h/cdn", "http://h/abs",
         "https://h/abs"]


# -- behaviour -------------------------------------------------------------

@pytest.mark.parametrize("href", DANGEROUS)
def test_async_extractor_drops_non_http_schemes(href):
    html = f'<a href="{href}">x</a><form action="{href}"></form>'
    assert _extract_links(html, _BASE) == [], (
        f"unsafe href {href!r} reached the crawl queue")


@pytest.mark.parametrize("href", LEGAL)
def test_async_extractor_keeps_legal_links(href):
    html = f'<a href="{href}">x</a>'
    assert _extract_links(html, _BASE), f"legal href {href!r} was dropped"


def test_extractor_drops_pure_fragments():
    assert _extract_links('<a href="#section">x</a>', _BASE) == []


@pytest.mark.parametrize("href", DANGEROUS)
def test_shared_helper_rejects_non_http(href):
    assert not is_crawlable_link(_BASE, href)


@pytest.mark.parametrize("href", LEGAL)
def test_shared_helper_keeps_legal(href):
    assert is_crawlable_link(_BASE, href)


def test_shared_helper_handles_empty_and_fragment():
    assert not is_crawlable_link(_BASE, None)
    assert not is_crawlable_link(_BASE, "")
    assert not is_crawlable_link(_BASE, "#frag")


# -- source contract -------------------------------------------------------

def _source(rel):
    with open(os.path.join(_ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


# function name -> (file, containing function name or None for module level)
_CALLSITES = (
    ("xssentinel/core/scanner_crawl.py", None),
    ("xssentinel/core/async_scanner_common.py", "_extract_links"),
)


def _calls(rel, fn):
    tree = ast.parse(_source(rel))
    if fn is None:
        node = tree
    else:
        node = next((n for n in ast.walk(tree)
                     if isinstance(n, ast.FunctionDef) and n.name == fn), None)
        assert node is not None, f"{rel}:{fn} not found"
    return {n.func.id for n in ast.walk(node)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}


@pytest.mark.parametrize("rel,fn", _CALLSITES)
def test_both_engines_use_the_shared_allowlist(rel, fn):
    assert "is_crawlable_link" in _calls(rel, fn), (
        f"{rel} must use the one shared link allowlist")


@pytest.mark.parametrize("rel,fn", _CALLSITES)
def test_neither_engine_handwrites_a_scheme_blacklist(rel, fn):
    tree = ast.parse(_source(rel))
    node = tree if fn is None else next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == fn)
    lits = {s.strip().lower() for s in (
        n.value for n in ast.walk(node)
        if isinstance(n, ast.Constant) and isinstance(n.value, str))}
    for bad in ("javascript:", "mailto:", "tel:", "data:", "vbscript:"):
        assert bad not in lits, (
            f"{rel} still hand-writes {bad!r} -- use url_safety instead")


def test_callsite_set_is_not_silently_shrunk():
    assert len(_CALLSITES) == 2
    for rel, fn in _CALLSITES:
        assert os.path.isfile(os.path.join(_ROOT, rel))
