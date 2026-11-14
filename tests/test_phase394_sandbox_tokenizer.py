# -*- coding: utf-8 -*-
"""Phase 394: the tokenizer's invalid-first-character recovery stays spec-exact.

Measured on the Phase 392 corpus (owasp-evasion text row, oracle EXEC while
the sandbox read inert): `<<SCRIPT>alert("XSS")...` is TEXT `<` plus a live
<SCRIPT> element under WHATWG 13.2.5.1 -- the old rule swallowed everything
up to the next `>` into one text node, so the script never existed and the
sandbox answered "no executable node carries the token".  The same swallow
lost `<3<svg onload=...>` and any other markup after a non-letter `<`.

Also pinned: the iframe-focusability fix for the corpus row where a
srcdoc="" quote breakout lands `autofocus/onfocus=...` on the host iframe
itself (Chromium fired; the sandbox read "not a focusable control"), and the
regressions the old rules got RIGHT (`<?php` bogus comment, plain `a < b`
text, src-less onerror inert).
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from xssentinel.core.sandbox import judge  # noqa: E402

SHELL = '<!doctype html><html><body><div id="c">%s</div></body></html>'
TOKEN = "xssv_p394t"


def test_double_lt_recovers_a_live_script():
    page = SHELL % '<&;<x><<SCRIPT>alert("XSS");//\\</SCRIPT></x>'
    v = judge(page, "XSS", sink="parser")
    assert v.state == "live", v.reason


def test_non_letter_lt_no_longer_swallows_following_markup():
    # `<3` used to swallow `<svg onload=...>` up to the next `>`
    page = SHELL % f'<3<svg onload=alert("{TOKEN}")>'
    v = judge(page, TOKEN, sink="parser")
    assert v.state == "live", v.reason


def test_tokenless_double_lt_defers_not_inerts():
    page = SHELL % '<<SCRIPT>alert("XSS");//\\</SCRIPT>'
    v = judge(page, "", sink="parser")
    assert v.state == "unknown", v.reason


def test_question_mark_still_opens_a_bogus_comment():
    # `<?php ... ?>` swallows to `>`; the handler after it must not survive
    page = SHELL % '<?php junk <svg onload=alert(1) ?> x'
    v = judge(page, "1", sink="parser")
    assert v.state == "inert", v.reason


def test_plain_lt_text_is_unchanged():
    page = SHELL % "1 &lt; 2 and 3 > 2"
    v = judge(page, "nothing-here", sink="parser")
    assert v.state == "inert", v.reason


def test_iframe_is_focusable_for_autofocus_onfocus():
    page = SHELL % '<iframe srcdoc="" autofocus/onfocus=alert("T")></iframe>'
    v = judge(page.replace("alert(\"T\")", f"alert('{TOKEN}')"), TOKEN,
              sink="parser")
    assert v.state == "live", v.reason


def test_iframe_onfocus_without_autofocus_stays_activation():
    # activation surfaces as live-with-flag in judge()'s folded verdict
    page = SHELL % f"<iframe srcdoc='' onfocus=alert('{TOKEN}')></iframe>"
    v = judge(page, TOKEN, sink="parser")
    assert v.state == "live" and v.activation, (v.state, v.reason)
