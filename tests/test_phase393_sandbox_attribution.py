# -*- coding: utf-8 -*-
"""Phase 393: the sandbox fixes measured on the external corpus stay fixed.

Four judgment changes, each anchored to a Phase 392/393 measurement:

  * token-less script judgment -> UNKNOWN (was: any compiling script body was
    "live at code position" -- measured over-claim on 97+19 corpus rows whose
    payload sat in a string literal or whose alert argument threw first);
  * empty/valueless `src` + onerror -> LIVE (the old "no load attempted" rule
    was an inference, not a measurement; `<audio src/onerror=...>` and
    `<img src/onerror=...>` both dialoged);
  * `<source>` child starts a media load -> onloadstart LIVE without a src
    attribute (measured on the corpus);
  * `<template shadowrootmode=open>` renders its content -> not an inert host
    (measured: `<slot onslotchange=...>` fired).

Plus the regression pins: everything the old rules got RIGHT must stay right
(src-absent onerror inert, plain template inert, engine-path tokened script
live, src="" under load events inert).
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from xssentinel.core.sandbox import judge  # noqa: E402

SHELL = ('<!doctype html><html><body><div id="c">%s</div></body></html>')

TOKEN = "xssv_p393token"


def _judge(page: str, token: str = TOKEN):
    return judge(page, token, sink="parser")


def test_tokenless_script_defers_instead_of_overclaiming():
    # payload sitting in a string literal: valid JS, dialog never fires
    page = SHELL % '<script>var a = "<img src=x onerror=alert(1)>";</script>'
    v = _judge(page, token="")
    assert v.state == "unknown", v.reason
    # a src'd script without a token defers too
    v2 = judge(SHELL % '<script src="/x.js"></script>', "", sink="parser")
    assert v2.state == "unknown", v2.reason


def test_tokened_script_positions_are_unchanged():
    # engine path: token at code position -> live (the engine always passes
    # a marker, so this is the verdict that matters in scans)
    v = _judge(SHELL % f'<script>alert("{TOKEN}")</script>')
    assert v.state == "live", v.reason
    # token inside a string literal that is not a call argument -> inert
    v2 = _judge(SHELL % f'<script>var a = "{TOKEN}";</script>')
    assert v2.state == "inert", v2.reason
    # invalid JS body -> inert regardless of token (nothing runs)
    v3 = _judge(SHELL % f'<script><b>{TOKEN}</b></script>')
    assert v3.state == "inert", v3.reason


def test_empty_src_onerror_is_live():
    # token embedded in the handler call, as the engine's markers always are
    for el in (f"<audio src/onerror=alert('{TOKEN}')>",
               f"<img/src/onerror=.1|alert('{TOKEN}')>",
               f'<img src="" onerror=alert("{TOKEN}")>'):
        v = _judge(SHELL % el)
        assert v.state == "live", f"{el}: {v.reason}"


def test_src_absent_onerror_stays_inert():
    # the old rule was RIGHT for a genuinely absent attribute
    v = _judge(SHELL % "<img onerror=alert(1)>")
    assert v.state == "inert", v.reason


def test_media_loadstart_with_source_child_is_live():
    v = _judge(SHELL % f"<audio onloadstart=\"alert('{TOKEN}')\"><source></audio>")
    assert v.state == "live", v.reason
    # without a source child and without src: still inert (old rule kept)
    v2 = _judge(SHELL % f"<audio onloadstart=\"alert('{TOKEN}')\"></audio>")
    assert v2.state == "inert", v2.reason


def test_declarative_shadow_root_is_not_an_inert_host():
    v = _judge(SHELL % f"<template shadowrootmode=open>"
                       f"<slot onslotchange=alert('{TOKEN}')></template>")
    assert v.state == "live", v.reason
    # a plain template stays inert (old rule kept)
    v2 = _judge(SHELL % f"<template><slot onslotchange=alert('{TOKEN}')>"
                       f"</template>")
    assert v2.state == "inert", v2.reason


def test_contenteditable_is_focusable_and_attr_names_fold_case():
    # measured on the corpus polyglot: contenteditable makes <K> focusable,
    # autofocus fires it, and camelCase attribute names must fold
    v = _judge(SHELL % "<K/contentEditable/autoFocus/OnFocus="
                       f"alert('{TOKEN}')>")
    assert v.state == "live", v.reason
    # without any focusability signal: unchanged (not focusable -> inert,
    # the old rule kept)
    v2 = _judge(SHELL % f"<K/OnFocus=alert('{TOKEN}')>")
    assert v2.state == "inert", v2.reason
