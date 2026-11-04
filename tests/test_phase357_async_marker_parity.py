# -*- coding: utf-8 -*-
"""Phase 357: async/sync marker-form parity + parser-independent inert tags.

Two independent regressions are pinned here.

1. ``async_scanner_layers._fire_probe_variants`` used to stamp every payload
   with ``verifier.mark(payload, marker)`` and verify with that same base
   marker.  Phase 356 gave the sync engine a quote-form fan-out (bWAPP
   medium / PHP ``addslashes`` kills ``alert('tok')`` but not ``alert(123)``);
   Phase 357 ports it to async.  The dangerous part is not the helper -- it
   is the CALL SITE drifting back to hand-rolled code: a future edit that
   reintroduces ``verify_semantic(text, marker)`` would silently verify the
   wrong token on every extra form, and the numeric shape (whose effective
   token is a 10-digit alias) would never confirm.  So, in addition to
   behaviour, the call sites are asserted against the parsed SOURCE (the
   Phase 259/176u lesson: the function body does not rot, the caller does).

2. CI run 41699972311 was red on one test only:
   ``test_null_byte_tag_name_is_not_executable``.  Linux libxml2 kept
   ``<svg%00/onload=...>`` as an element with its handler, the Windows wheel
   dropped the tag, and the structural rule below the parse therefore gave
   opposite verdicts for the same source.  ``_token_in_mangled_tag_head``
   decides on the RAW SOURCE before any parser runs.  The tests below pin
   both the raw-source decision and its position ahead of the BeautifulSoup
   parse -- otherwise the same cross-platform divergence can come back.
"""
from __future__ import annotations

import ast
import asyncio
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from xssentinel.core import verifier
from xssentinel.core.async_scanner import AsyncScanner

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CORE = os.path.join(_ROOT, "xssentinel", "core")
TOK = "xssv_11223344"


# ---------------------------------------------------------------------------
# Source-level guards (AST, so comments and docstrings cannot satisfy them)
# ---------------------------------------------------------------------------

def _read(name):
    with open(os.path.join(_CORE, name), encoding="utf-8") as fh:
        return fh.read()


def _tree(name):
    src = _read(name)
    return src, ast.parse(src, filename=name)


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _dotted(node.value) + "." + node.attr
    return ""


def _method(src, cls, func):
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == cls:
            for sub in node.body:
                if (isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and sub.name == func):
                    return sub
    raise AssertionError("missing %s.%s" % (cls, func))


def _function(src, func):
    """Module-level function only -- no class method may satisfy the guard."""
    for node in ast.parse(src).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.name == func:
            return node
    raise AssertionError("missing module-level function %s" % func)


def _calls(node):
    return [n for n in ast.walk(node) if isinstance(n, ast.Call)]


_LAYERS_SRC = _read("async_scanner_layers.py")
_SCANNER_SRC = _read("scanner.py")
_VERIFIER_SRC = _read("verifier.py")
_FIRE = _method(_LAYERS_SRC, "AsyncDetectionLayersMixin",
                "_fire_probe_variants")
_FIRE_CALLS = _calls(_FIRE)


def _to_thread(target):
    return [c for c in _FIRE_CALLS
            if _dotted(c.func) == "asyncio.to_thread" and c.args
            and _dotted(c.args[0]) == target]


def test_async_call_site_uses_the_shared_marker_form_helper() -> None:
    """No hand-rolled ``mark(payload, marker)`` as the primary stamp."""
    helper = [c for c in _FIRE_CALLS
              if _dotted(c.func) == "verifier.stamp_forms_or_legacy"]
    assert len(helper) == 1
    args = helper[0].args
    assert len(args) == 3 and isinstance(args[2], ast.Name)
    assert args[2].id == "_budget"


def test_sync_call_sites_use_the_same_definitions() -> None:
    """Both engines ask the same two questions, not two copies of them."""
    probe = _method(_SCANNER_SRC, "Scanner", "_scan_param")
    try_payload = _method(_SCANNER_SRC, "Scanner", "_try_payload")
    probe_names = {_dotted(c.func) for c in _calls(probe)}
    try_names = {_dotted(c.func) for c in _calls(try_payload)}
    assert "self._detect_quote_escaping" in probe_names
    assert "verifier.stamp_forms_or_legacy" in try_names


def test_quote_escaping_probe_is_awaited_once_per_parameter() -> None:
    awaits = [n for n in ast.walk(_FIRE) if isinstance(n, ast.Await)
              and isinstance(n.value, ast.Call)
              and _dotted(n.value.func).endswith(
                  "_detect_quote_escaping_async")]
    assert len(awaits) == 1


def test_variants_are_verified_with_their_own_effective_token() -> None:
    """The numeric form verifies on a 10-digit alias, not the base marker."""
    verify = _to_thread("verifier.verify_semantic")
    assert verify, "async no longer verifies through asyncio.to_thread?"
    assert any(len(c.args) >= 3 and isinstance(c.args[2], ast.Name)
               and c.args[2].id == "_tok" for c in verify), (
        "a caller fell back to verify_semantic(text, marker) -- extra marker "
        "forms would be unverifiable")


def test_transform_ladder_receives_the_effective_token() -> None:
    build = _to_thread("self._build_variants")
    assert build and len(build[0].args) >= 4
    third = build[0].args[3]
    assert isinstance(third, ast.Name) and third.id == "token"


def test_extra_forms_are_inserted_as_named_plain_variants() -> None:
    consts = [n.value for n in ast.walk(_FIRE)
              if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    assert any(s.startswith("marker:") for s in consts)
    assert any(isinstance(n, ast.Subscript) and _dotted(n.value)
               == "variant_tokens" for n in ast.walk(_FIRE))


def test_concat_retry_is_disabled_on_quote_escaping_targets() -> None:
    """Sync parity: the concat stamp is dead there, do not pay for it."""
    hits = []
    for node in ast.walk(_FIRE):
        if not isinstance(node, ast.If):
            continue
        names = {n.id for n in ast.walk(node.test)
                 if isinstance(n, ast.Name)}
        body_names = {n.id for stmt in node.body for n in ast.walk(stmt)
                      if isinstance(n, ast.Name)}
        if "quote_escaped" in names and "concat_marked" in body_names:
            hits.append(node)
    assert len(hits) == 1


# ---------------------------------------------------------------------------
# Inert mangled tag: the verdict must not depend on the installed parser
# ---------------------------------------------------------------------------

def test_mangled_tag_check_runs_before_the_html_parser() -> None:
    impl = _function(_VERIFIER_SRC, "_verify_semantic_impl")
    checks = [c for c in _calls(impl)
              if _dotted(c.func) == "_token_in_mangled_tag_head"]
    parses = [n for n in ast.walk(impl)
              if isinstance(n, ast.ImportFrom) and (n.module or "").startswith("bs4")]
    assert checks and parses, "guard or parser disappeared"
    assert min(c.lineno for c in checks) < min(p.lineno for p in parses), (
        "the raw-source check must run BEFORE BeautifulSoup sees the page")


def test_mangled_tag_helper_does_not_use_a_parser() -> None:
    helper = _function(_VERIFIER_SRC, "_token_in_mangled_tag_head")
    body = ast.get_source_segment(_VERIFIER_SRC, helper) or ""
    for banned in ("BeautifulSoup", "lxml", "fromstring", "HTMLParser",
                   "soup."):
        assert banned not in body, banned


@pytest.mark.parametrize("html_text", [
    # the exact CI failure (run 41699972311)
    "<table><tr><td>%00<svg%00/onload=alert(%00'" + TOK + "%00')%00>"
    "</td></tr></table>",
    # Linux libxml2 shape: element survives with its handler attribute
    '<div><svg%00 onload="alert(\'' + TOK + '\')"></div>',
    # raw NUL in the tag name
    "<sv\x00g/onload=alert('" + TOK + "')>",
    # Windows wheel shape: the tag is dropped, only inert text remains
    "Welcome " + TOK + " to the page",
])
def test_mangled_tag_never_confirms_on_either_platform(html_text) -> None:
    assert verifier.verify_semantic(html_text, TOK)["confirmed"] is False


def test_clean_tag_with_percent_in_attribute_still_confirms() -> None:
    """Only the tag NAME decides; attributes may legitimately contain %00."""
    html_text = '<svg data-x="%00" onload="alert(\'' + TOK + '\')">'
    assert verifier._token_in_mangled_tag_head(html_text, TOK) is False
    assert verifier.verify_semantic(html_text, TOK)["confirmed"] is True


def test_token_outside_any_tag_head_is_not_flagged() -> None:
    assert verifier._token_in_mangled_tag_head(
        "<p>hello</p> " + TOK, TOK) is False
    assert verifier._token_in_mangled_tag_head(
        "<svg/onload=alert('" + TOK + "')>", TOK) is False


# ---------------------------------------------------------------------------
# Behaviour: drive the real async entry point against an addslashes target
# ---------------------------------------------------------------------------

class _Resp:
    status = 200
    headers = {}

    def __init__(self, text):
        self._t = text

    async def text(self):
        return self._t

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _EchoSession:
    """Echoes the submitted value through the target's filter."""

    def __init__(self, shape):
        self.shape = shape
        self.calls: list[str] = []

    def request(self, method, url, params=None, data=None, **kw):
        value = ""
        for src in (params, data):
            if src:
                value += "".join(str(v) for v in src.values())
        self.calls.append(value)
        return _Resp("<html><body><div>Welcome "
                     + self.shape(value) + "</div></body></html>")


def _addslashes(value: str) -> str:
    return value.replace("'", "\\'").replace('"', '\\"')


def _probe(shape):
    """Real ``_probe_param``; only the sync L7 hand-off is stubbed out.

    Observed tokens and form budgets are captured by wrapping the two
    verifier entry points: the async engine resolves both through the module
    at dispatch time (verify via ``asyncio.to_thread``), so the wrappers see
    exactly what production passes.  Budget=1 means no fan-out, 4 means the
    quote-escaping target bought the extra shapes.
    """
    original_scan = AsyncScanner._scan_advanced_param_layers
    original_verify = verifier.verify_semantic
    original_stamp = verifier.stamp_forms_or_legacy
    seen: list[str] = []
    budgets: list[int] = []

    async def _noop(self, *a, **k):
        if False:                       # pragma: no cover -- async generator
            yield None

    def _record(text, token, **kw):
        seen.append(str(token))
        return original_verify(text, token, **kw)

    def _record_budget(payload, token, budget=4):
        budgets.append(budget)
        return original_stamp(payload, token, budget)

    AsyncScanner._scan_advanced_param_layers = _noop
    verifier.verify_semantic = _record
    verifier.stamp_forms_or_legacy = _record_budget
    try:
        async def run():
            asc = AsyncScanner(max_concurrent=4, per_host_delay=0, jitter=0)
            asc._semaphore = asyncio.Semaphore(4)
            session = _EchoSession(shape)
            out = [f async for f in asc._probe_param(
                session, "http://t/x", "GET", "q", {"q": "probe"}, {},
                False, "html_element")]
            return out, session
        findings, session = asyncio.run(run())
        return findings, session, seen, budgets
    finally:
        AsyncScanner._scan_advanced_param_layers = original_scan
        verifier.verify_semantic = original_verify
        verifier.stamp_forms_or_legacy = original_stamp


def test_async_confirms_addslashes_target_with_numeric_alias() -> None:
    findings, session, seen, _budgets = _probe(_addslashes)
    assert findings, "addslashes target is exploitable; async must report it"
    numeric = [v for v in session.calls
               if re.search(r"alert\(\d{10}\)", v)]
    assert numeric, session.calls
    assert any(re.fullmatch(r"\d{10}", t) for t in seen), (
        "verifier was called with the base marker instead of the effective "
        "numeric alias -- the extra forms cannot confirm")


def test_quote_probe_costs_exactly_one_request() -> None:
    _findings, session, _seen, _budgets = _probe(_addslashes)
    probes = [v for v in session.calls if "xssq_" in v]
    assert len(probes) == 1


def test_fanout_only_on_a_quote_escaping_target() -> None:
    """Healthy endpoints keep their old request count (budget=1)."""
    _, _healthy, _seen, healthy_budgets = _probe(lambda v: v)
    _, _filtered, _seen2, filtered_budgets = _probe(_addslashes)
    assert healthy_budgets, "the shared stamp helper was never called"
    assert all(b == 1 for b in healthy_budgets), healthy_budgets
    assert any(b == 4 for b in filtered_budgets), filtered_budgets


def test_ab_switch_off_keeps_the_legacy_single_marker(monkeypatch) -> None:
    monkeypatch.setenv("XSS_MARKER_FORMS", "0")
    _findings, session, seen, _budgets = _probe(lambda v: v)
    assert seen, "no verification happened"
    assert not any(re.fullmatch(r"\d{10}", t) for t in seen)
    assert not any(re.search(r"alert\(\d{10}\)", v) for v in session.calls)


# ---------------------------------------------------------------------------
# Headless replay token: the numeric form must stay attributable.
# CI run 41799682389 lost range3's only browser-fired row because the async
# primary form became alert(<10-digit alias>) and extract_replay_token only
# knew quoted / xss-prefixed tokens, so _headless_verify_finding returned
# early on "unattributable replay".
# ---------------------------------------------------------------------------

def test_numeric_alias_form_yields_its_replay_token() -> None:
    from xssentinel.core.findings import extract_replay_token
    marker = "xssentinel_async_q_2813"
    for payload in ("<script>alert(1)</script>",
                    "+ADw-script+AD4-alert(1)+ADw-/script+AD4-",
                    "<img src=x onerror=confirm(1)>"):
        form, eff, marked = verifier.stamp_forms_or_legacy(
            payload, marker, 4)[0]
        assert form == "numeric", (payload, form)
        assert re.fullmatch(r"\d{10}", eff)
        assert extract_replay_token(marked) == eff, marked


def test_quote_form_still_yields_its_replay_token() -> None:
    from xssentinel.core.findings import extract_replay_token
    marker = "xssv_357aabbcc"
    for form in ("single", "double", "backtick"):
        marked, eff, _used = verifier.stamp_form(
            "<svg/onload=alert(1)>", marker, form)
        assert extract_replay_token(marked) == eff, (form, marked)


def test_short_numeric_literal_is_not_a_replay_token() -> None:
    """An operator's alert(999) is not a Phase 356 numeric alias."""
    from xssentinel.core.findings import extract_replay_token
    assert extract_replay_token("<svg/onload=alert(999)>") is None
    assert extract_replay_token("<script>alert(1234567890)</script>") \
        == "1234567890"
