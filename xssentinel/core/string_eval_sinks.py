"""Shared rule for the implicit-eval timers (``setTimeout`` / ``setInterval``).

Two layers carry their own copy of a "string-eval sink" pattern -- the
postMessage analyzer and the WebSocket analyzer -- and both copies had the same
false positive, found by scanning a real application (OWASP Juice Shop 20.2.0):

    r'setTimeout\\s*\\(\\s*[^,)]*[a-zA-Z]'      # "any letters after the paren"

That matches the ordinary, safe shape of the call. Measured in the target's
own ``main.js``: 37 ``setTimeout(`` calls, every one of them passing a
function (``setTimeout(()=>{n.classList.remove(i)},1e3)``,
``setTimeout(this.dispose,500)``, ``setTimeout(c,0)``), and the bundle contains
**no** ``addEventListener('message'`` at all -- yet the scan emitted
``postmessage_xss`` / ``websocket_xss`` at **high** severity whose description
said "setTimeout(string)". The description asserted something the pattern never
checked.

What the argument shape can and cannot tell us:

  * a string literal, a concatenation, or an argument naming ``data`` is the
    implicit-eval shape -> report it;
  * a function, an arrow, or a member expression (``this.dispose``) cannot be
    evaluated as a string by the browser -> not a sink;
  * a bare identifier is **ambiguous**: ``setTimeout(msg)`` (attacker data) and
    ``setTimeout(c,0)`` (a minified function variable) look identical to a
    regexp. Minified bundles are full of the second form, which is exactly
    where this layer runs, so guessing here manufactures highs.

The last case is deliberately not reported by this rule. Real postMessage
execution is the browser layer's call to make (L8_postmessage dispatches a
message from an attacker origin and watches instrumented sinks); this text rule
is advisory, and an advisory check must not speak in high-severity voices about
something it cannot see.
"""
from __future__ import annotations

import re

_TIMER_ARG_RE = re.compile(
    r'''\b(?:setTimeout|setInterval)\s*\(\s*([^,()]{0,80})''',
    re.IGNORECASE)

_DATA_RE = re.compile(r'\bdata\b', re.IGNORECASE)
_MEMBER_RE = re.compile(r'[A-Za-z_$][\w$]*\s*(?:\.\s*[A-Za-z_$][\w$]*)+\s*$')
_STRING_EVAL_TEMPLATE = "setTimeout(string) from {transport} payload"


def timer_string_eval_sites(js_or_html: str, transport: str = "postMessage"
                            ) -> list[str]:
    """Descriptions for implicit-eval timer calls, empty when there are none.

    One description per matching call, with the caller's transport named in the
    text so the postMessage and WebSocket layers keep their own wording while
    sharing the single judgement here.
    """
    if not js_or_html:
        return []
    return [_STRING_EVAL_TEMPLATE.format(transport=transport)
            for m in _TIMER_ARG_RE.finditer(js_or_html)
            if _arg_is_string_eval(m.group(1))]


def has_timer_string_eval(js_or_html: str) -> bool:
    return bool(timer_string_eval_sites(js_or_html))


def _arg_is_string_eval(arg: str) -> bool:
    a = arg.strip()
    if not a:
        return False
    # Callback first: an arrow, a `function` expression or a body-closing brace
    # can never be string-evaluated. This test has to come before the
    # parenthesized-expression shape below, because `setTimeout(()=>{x()})`
    # starts with `(` too -- and the real bundle is full of that form.
    if "=>" in a or a.startswith("function") or a.endswith("}"):
        return False
    if a[0] in ("'", '"', "`"):
        return True                       # literal string: always evaluated
    if "+" in a:
        return True                       # concatenation builds a string
    if _DATA_RE.search(a):
        return True                       # names the message payload
    if _MEMBER_RE.match(a):
        return False                      # `this.dispose` -- a method reference
    if re.fullmatch(r"[A-Za-z_$][\w$]*", a):
        # Ambiguous: could be the payload or a minified function name. See the
        # module docstring -- reporting it here is what produced the FP.
        return False
    # Anything else (including `(0,i.foo)()`, a webpack call form) stays
    # unreported: this layer is advisory, and the browser layer decides.
    return False
