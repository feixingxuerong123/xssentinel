"""Phase 356: marker injection must survive quote-escaping filters.

The bug (measured on bWAPP ``security_level=1``/medium, whose PHP uses
``addslashes``): every marker was stamped as ``alert('xssv_…')``.  The
filter turns ``'`` into ``\\'``, so ``alert(\\'xssv_…\\')`` is a JS syntax
error -- the payload never runs, the verifier refuses, and the scanner
reports nothing on a target that IS exploitable with ``alert(1)``.

Two contracts are pinned here:
  * an operator payload keeps its own alert-argument style (``alert(999)``
    must stay unquoted, not be rewritten to a quoted token);
  * the marker fan-out offers the unquoted / double / backtick / single
    shapes for the same injection point, and the unquoted shape confirms
    on an addslashes target while the single-quoted shape does not.
"""
from __future__ import annotations

import re

from xssentinel.core import verifier
from xssentinel.core.scanner import Scanner

TOK = "xssv_11223344"


class _Resp:
    status_code = 200
    headers = {}
    url = "http://t/p"

    def __init__(self, text: str):
        self.text = text


class _FakeReq:
    """Echoes the submitted value; ``shape`` models the target's filter."""

    def __init__(self, shape):
        self.shape = shape
        self.submitted: list[str] = []

    def _one(self, params, data):
        vals = []
        for src in (params, data):
            if src:
                vals.extend(str(v) for v in src.values())
        return vals[0] if vals else ""

    def request(self, method, url, params=None, data=None, **kw):
        value = self._one(params, data)
        self.submitted.append(value)
        return _Resp("Welcome " + self.shape(value))

    def get(self, url, **kw):
        return _Resp("")


def _run(payload, shape, context="html_element", marker_forms=4,
         preserve_style=False):
    req = _FakeReq(shape)
    sc = Scanner(requester=req, max_payloads=14, max_transforms=12,
                 dom_engine="static", verbose=False)
    confirmed = sc._try_payload(
        req, "http://t/p", "GET", {}, {}, "q", False, payload, context, {},
        marker_forms=marker_forms, preserve_style=preserve_style)
    return confirmed, req.submitted


# --------------------------------------------------------------------------
# Marker shape generation
# --------------------------------------------------------------------------

def test_custom_payload_keeps_its_own_unquoted_style() -> None:
    payload = "<svg/onload=alert(999)>"
    forms = verifier.stamp_forms(payload, TOK, budget=4)
    form, eff, marked = forms[0]
    assert form == "numeric"
    assert "'" not in marked and '"' not in marked
    assert re.search(r"alert\(\d{10}\)", marked)
    assert eff == verifier.numeric_alias(TOK)


def test_custom_single_quoted_payload_keeps_single_quotes() -> None:
    payload = "<svg/onload=alert('x')>"
    forms = verifier.stamp_forms(payload, TOK, budget=4)
    form, eff, marked = forms[0]
    assert form == "single"
    assert "alert('%s')" % TOK in marked
    assert eff == TOK


def test_fanout_offers_every_quote_shape() -> None:
    forms = verifier.stamp_forms("<svg/onload=alert(1)>", TOK, budget=5)
    shapes = {f for f, _e, _m in forms}
    assert {"single", "double", "backtick", "numeric"} <= shapes
    by_shape = {f: (eff, marked) for f, eff, marked in forms}
    assert "alert('%s')" % TOK in by_shape["single"][1]
    assert 'alert("%s")' % TOK in by_shape["double"][1]
    assert "alert`%s`" % TOK in by_shape["backtick"][1]
    assert "alert(%d)" % int(by_shape["numeric"][0]) in by_shape["numeric"][1]


def test_confirm_payload_is_stamped_too() -> None:
    forms = verifier.stamp_forms("<img src=x onerror=confirm(1)>", TOK,
                                 budget=4)
    assert forms[0][0] == "numeric"
    assert re.search(r"confirm\(\d{10}\)", forms[0][2])


# --------------------------------------------------------------------------
# addslashes: the single-quoted shape is dead, the unquoted shape confirms
# --------------------------------------------------------------------------

def _addslashes(value: str) -> str:
    return value.replace("'", "\\'").replace('"', '\\"')


def test_single_quote_marker_is_dead_under_addslashes() -> None:
    payload = "<script>alert(1)</script>"
    marked, eff, _ = verifier.stamp_form(payload, TOK, "single")
    escaped = _addslashes(marked)
    assert "alert(\\'%s\\')" % TOK in escaped
    assert verifier.verify_semantic(escaped, eff)["confirmed"] is False


def test_unquoted_marker_survives_addslashes() -> None:
    payload = "<script>alert(1)</script>"
    marked, eff, _ = verifier.stamp_form(payload, TOK, "numeric")
    escaped = _addslashes(marked)
    assert verifier.verify_semantic(escaped, eff)["confirmed"] is True


def test_scanner_confirms_addslashes_target_with_unquoted_form() -> None:
    confirmed, submitted = _run("<script>alert(1)</script>", _addslashes)
    assert confirmed is True
    numeric = [v for v in submitted if re.search(r"alert\(\d{10}\)", v)]
    assert numeric, submitted
    assert all("'" not in v for v in numeric)


def test_scanner_keeps_custom_payload_unquoted_on_addslashes_target() -> None:
    confirmed, submitted = _run("<svg/onload=alert(999)>", _addslashes,
                                preserve_style=True)
    assert confirmed is True
    first = submitted[0]
    assert re.search(r"alert\(\d{10}\)", first)
    assert "'" not in first and '"' not in first


def test_high_escape_still_reports_nothing() -> None:
    def html_escape(value: str) -> str:
        return (value.replace("<", "&lt;").replace(">", "&gt;")
                .replace("'", "&#039;").replace('"', "&quot;"))
    confirmed, _submitted = _run("<script>alert(1)</script>", html_escape)
    assert confirmed is False


# --------------------------------------------------------------------------
# Secondary fix: the null-byte tag shape is inert
# --------------------------------------------------------------------------

def test_null_byte_tag_name_is_not_executable() -> None:
    html = ("<table><tr><td>%00<svg%00/onload=alert(%00'"
            + TOK + "%00')%00></td></tr></table>")
    out = verifier.verify_semantic(html, TOK)
    assert out["confirmed"] is False


def test_null_byte_script_does_not_swallow_later_tokens() -> None:
    later = "xssv_99999999"
    html = ("<table><tr><td>%00<script%00>alert(%00'old'%00)%00"
            "%00<%00/script%00></td></tr>"
            "<tr><td>%00<svg%00/onload=alert(%00'"
            + later + "%00')%00></td></tr></table>")
    assert verifier.verify_semantic(html, later)["confirmed"] is False


def test_plain_slash_form_svg_still_confirms() -> None:
    html = "<svg/onload=alert('%s')>" % TOK
    assert verifier.verify_semantic(html, TOK)["confirmed"] is True
