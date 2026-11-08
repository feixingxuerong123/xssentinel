# -*- coding: utf-8 -*-
"""One definition of the addslashes / quote-escaping probe contract.

A function-level test alone would not have caught this bug family: the
shared function never rots, the *call sites* drift back to hand-written
copies.  So this file asserts both the behaviour and the parsed SOURCE of
the two engines, following test_phase357_async_marker_parity.py.
"""
from __future__ import annotations

import ast
import os
import re

import pytest

from xssentinel.core import quote_escaping as qe

_CORE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "xssentinel", "core")

# (filename, method name).  Listed explicitly (not globbed) so renaming a
# call site shows up as a failure instead of silently leaving the set.
_CALLSITES = (
    ("scanner.py", "_detect_quote_escaping"),
    ("async_scanner_layers.py", "_detect_quote_escaping_async"),
)

_PROBE_LITERAL = "<script>alert('%s');alert(\"%s\")</script>"
_REGEX_LITERAL = r"\\+['\"]"


def _source(name):
    with open(os.path.join(_CORE, name), encoding="utf-8") as fh:
        return fh.read()


def _method(name, fn):
    tree = ast.parse(_source(name))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.name == fn:
            return node
    raise AssertionError(
        f"{name}:{fn} not found -- call site renamed or moved")


def _constants(node):
    return [n.value for n in ast.walk(node)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def _dotted_calls(node):
    """All ``a.b(...)`` names called inside a function body."""
    out = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
            base = n.func.value
            out.add(f"{getattr(base, 'id', '?')}.{n.func.attr}")
    return out


# ---- behaviour -----------------------------------------------------------

def test_probe_returns_two_distinct_hex_tokens():
    t1, t2, payload = qe.build_quote_probe()
    assert t1 != t2
    assert re.fullmatch(r"xssq_[0-9a-f]{6}", t1)
    assert re.fullmatch(r"xssq_[0-9a-f]{6}", t2)
    assert t1 in payload and t2 in payload
    assert "'" in payload and '"' in payload


def test_probe_tokens_are_not_reused():
    """Two probes must not share tokens (replay / attribution safety)."""
    a = qe.build_quote_probe()
    b = qe.build_quote_probe()
    assert (a[0], a[1]) != (b[0], b[1])


@pytest.mark.parametrize("body", [
    r"<script>alert(\'T1\')</script>",
    r'<script>alert(\"T2\")</script>',
    r"<script>alert(\\\'T1\')</script>",
])
def test_detects_backslash_before_a_quote(body):
    t1, t2, _ = qe.build_quote_probe()
    text = body.replace("T1", t1).replace("T2", t2)
    assert qe.quote_escaping_detected(text, t1, t2) is True


@pytest.mark.parametrize("body", [
    "<script>alert('T1');alert(\"T2\")</script>",
    "<script>alert(&#39;T1&#39;)</script>",
    "<script>alert(`T1`)</script>",
    "T1 T2",
    "",
])
def test_does_not_detect_clean_or_encoded_reflection(body):
    t1, t2, _ = qe.build_quote_probe()
    text = body.replace("T1", t1).replace("T2", t2)
    assert qe.quote_escaping_detected(text, t1, t2) is False


def test_detection_is_bound_to_our_tokens_not_page_features():
    """A backslash before somebody else's token is not our signal."""
    t1, t2, _ = qe.build_quote_probe()
    assert qe.quote_escaping_detected(
        r"alert(\'somebody_else_zzzz\')", t1, t2) is False
    assert qe.quote_escaping_detected(None, t1, t2) is False


def test_payload_and_rule_agree_end_to_end():
    """The rule must be able to read the payload it just built."""
    t1, t2, payload = qe.build_quote_probe()
    mutated = payload.replace("'", "\\'").replace('"', '\\"')
    assert qe.quote_escaping_detected(mutated, t1, t2) is True


# ---- source contracts ----------------------------------------------------

@pytest.mark.parametrize("name,fn", _CALLSITES)
def test_callsite_uses_the_shared_contract(name, fn):
    node = _method(name, fn)
    calls = _dotted_calls(node)
    assert "qe_mod.build_quote_probe" in calls, (
        f"{name}:{fn} must build its probe from the shared contract")
    assert "qe_mod.quote_escaping_detected" in calls, (
        f"{name}:{fn} must grade the response with the shared contract")


@pytest.mark.parametrize("name,fn", _CALLSITES)
def test_callsite_has_no_handwritten_copy(name, fn):
    node = _method(name, fn)
    strings = _constants(node)
    assert not any(_PROBE_LITERAL in s for s in strings), (
        f"{name}:{fn} hand-wrote the probe payload")
    assert not any(_REGEX_LITERAL in s for s in strings), (
        f"{name}:{fn} hand-wrote the response regex")
    calls = _dotted_calls(node)
    assert "re.search" not in calls, f"{name}:{fn} grades the response itself"
    assert "secrets.token_hex" not in calls, (
        f"{name}:{fn} mints its own probe tokens")


def test_shared_module_is_the_only_definition():
    """The contract cannot be deleted and re-homed without this going red."""
    tree = ast.parse(_source("quote_escaping.py"))
    fns = {n.name: n for n in tree.body
           if isinstance(n, ast.FunctionDef)}
    assert {"build_quote_probe", "quote_escaping_detected"} <= set(fns)
    assert any(_PROBE_LITERAL in s
               for s in _constants(fns["build_quote_probe"]))
    assert any(_REGEX_LITERAL in s
               for s in _constants(fns["quote_escaping_detected"]))


def test_callsite_set_is_not_silently_shrunk():
    """A third engine or a renamed method must be registered, not skipped."""
    assert len(_CALLSITES) == 2
    for name, fn in _CALLSITES:
        assert os.path.isfile(os.path.join(_CORE, name))
        _method(name, fn)
