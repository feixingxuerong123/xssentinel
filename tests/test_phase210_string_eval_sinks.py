# -*- coding: utf-8 -*-
"""Phase 210: the implicit-eval timer sinks must not claim "string" blind.

Found by scanning OWASP Juice Shop 20.2.0 -- a real application, not our
fixture.  The report carried `postmessage_xss` and `websocket_xss` at **high**
severity whose own text said "setTimeout(string) from postMessage payload",
against a `main.js` that contains:

    addEventListener('message'  -> 0 occurrences
    setTimeout(                 -> 37 occurrences, every one passing a function

Both layers decided "sink reached" from
``r'setTimeout\\s*\\(\\s*[^,)]*[a-zA-Z]'``, which matches the normal, safe shape
of the call.  So the finding asserted a property the pattern never tested, and
`evidence_class` was ``browser-unavailable`` with ``proof=None`` -- the weakest
evidence carrying the loudest volume.

Each rule here is written as a pair, and the first test proves the OLD pattern
was the broken one: if that assertion ever goes green-by-accident, this file has
stopped guarding anything.
"""
from __future__ import annotations

import ast
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssentinel.core import postmessage, websocket_xss  # noqa: E402
from xssentinel.core.string_eval_sinks import (  # noqa: E402
    timer_string_eval_sites, has_timer_string_eval)

# The exact shapes measured in the target's own bundle.
SAFE_MINIFIED = (
    "var i={};i.open=function(){},this._zone.runOutsideAngular(()=>{"
    "setTimeout(()=>{n.classList.remove(i)},1e3)});"
    "setTimeout(this.dispose,500);setTimeout(c,0);")
# The shape that genuinely is string-eval.
UNSAFE_DATA = (
    "window.addEventListener('message',function(e){"
    "if(!e.origin)return;setTimeout(e.data);});")
UNSAFE_LITERAL = (
    "ws.onmessage=function(ev){setTimeout(\"alert(\"+ev.data+\")\",0);};")

# The regexp both layers used before this change.
OLD_TIMER = re.compile(r'setTimeout\s*\(\s*[^,)]*[a-zA-Z]')


def test_the_old_pattern_is_what_was_broken():
    """Known-bad sample: the removed regexp fires on all-function calls.

    Without this, a future 'simplification' back to a loose pattern would keep
    every other test in this file green.
    """
    assert OLD_TIMER.search(SAFE_MINIFIED), "sample lost its shape"
    assert not has_timer_string_eval(SAFE_MINIFIED)
    assert has_timer_string_eval(UNSAFE_DATA)
    assert has_timer_string_eval(UNSAFE_LITERAL)


def test_descriptions_name_the_transport_and_stay_honest():
    (desc,) = timer_string_eval_sites(UNSAFE_DATA, "postMessage")
    assert desc == "setTimeout(string) from postMessage payload", desc
    (desc,) = timer_string_eval_sites(UNSAFE_LITERAL, "WebSocket message")
    assert desc == "setTimeout(string) from WebSocket message payload", desc


def test_callback_arguments_are_never_sinks():
    for src in ("setTimeout(()=>{use(evt.data)},0)",
                "setTimeout(function(){location.hash=ev.data},0)",
                "setTimeout(this.flush.bind(this),10)",
                "setTimeout((0,i.render)(),0)"):
        assert not has_timer_string_eval(src), src
    # A callback that reads event.data is a *callback*: nothing is compiled.
    assert not has_timer_string_eval(
        "addEventListener('message',e=>{setTimeout(()=>console.log(e.data))})")


def test_string_and_concatenation_forms_still_fire():
    for src in ('setTimeout("alert(1)")',
                "setTimeout(ev.data)",
                'setTimeout("a"+b)',
                "setTimeout(`x${y}`)"):
        assert has_timer_string_eval(src), src


def test_bare_identifier_is_deliberately_not_claimed():
    """`setTimeout(msg)` and minified `setTimeout(c,0)` are indistinguishable
    to a regexp; the browser layer owns that call.  Locked as a test so the
    trade-off is a decision on record, not an oversight."""
    assert not has_timer_string_eval("var msg=evt;setTimeout(msg,0)")


def test_postmessage_layer_ignores_the_minified_bundle_shape():
    """The measured false positive, end to end through the layer's API."""
    out = postmessage.find_message_listeners(SAFE_MINIFIED)
    assert all(not li["exploitable"] for li in out), [
        li["sinks_found"] for li in out]
    assert postmessage.analyze_page(SAFE_MINIFIED)["vulnerable_count"] == 0


def test_postmessage_layer_still_finds_the_real_handler():
    out = postmessage.analyze_page(UNSAFE_DATA.replace(
        "if(!e.origin)return;", ""))          # drop the origin check
    assert out["vulnerable_count"] >= 1, out
    assert any("setTimeout(string)" in s
               for li in out["listeners"] for s in li["sinks_found"]), out


def test_websocket_layer_ignores_and_still_detects():
    assert websocket_xss.find_websocket_handlers(SAFE_MINIFIED) == [] \
        or all(not h["exploitable"]
               for h in websocket_xss.find_websocket_handlers(SAFE_MINIFIED))
    handlers = websocket_xss.find_websocket_handlers(
        "var ws=new WebSocket('wss://x/y');ws.onmessage=function(e){"
        "setTimeout(e.data);};")
    assert handlers and any(h["exploitable"] for h in handlers), handlers


def test_shared_rule_has_one_implementation():
    """Both layers must delegate to string_eval_sinks, not keep their own copy.

    The two identical loose patterns in two files are how this shipped in the
    first place: fixing one and forgetting the other is the same bug with a
    head start.

    Checked over the AST's string constants, not the raw text: the modules now
    carry the old pattern in a *comment* explaining the mistake, and a
    substring search over the file would flag honest documentation.
    """
    for mod in (postmessage, websocket_xss):
        path = os.path.join(ROOT, "xssentinel", "core",
                            f"{mod.__name__.split('.')[-1]}.py")
        src = open(path, encoding="utf-8").read()
        assert "string_eval_sinks." in src, mod.__name__
        consts = [n.value for n in ast.walk(ast.parse(src))
                  if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        offenders = [c for c in consts if "[^,)]*[a-zA-Z]" in c]
        assert not offenders, (
            f"{mod.__name__} carries its own loose timer pattern: {offenders}")
