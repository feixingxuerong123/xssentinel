# -*- coding: utf-8 -*-
"""Phase 189: CSP3 delivery families -- elem, attr, and what a nonce covers.

Why this is a correctness fix and not a feature: ``script-src-elem`` and
``script-src-attr`` do not add to ``script-src``, they REPLACE it for their
own delivery type.  Everything in this project that asked "does inline run
under this CSP?" read ``script-src`` (falling back to ``default-src``) and
answered for all shapes at once, which is wrong in both directions:

  script-src 'self'; script-src-attr 'unsafe-inline'
      -> a reflected on* handler DOES execute; the old answer was "nothing
         inline runs", which gated the payload budget and refuted findings.
  script-src 'nonce-abc' 'unsafe-inline'; script-src-attr 'unsafe-inline'
      -> the nonce inert-izes 'unsafe-inline' only inside the list that
         carries it.  Elements are blocked, handlers are not.
  script-src https://cdn.example.com
      -> no 'unsafe-inline' anywhere means inline <script> is blocked; the
         old block-regex looked for 'none'/'self'/'nonce-' and so confirmed a
         reflected <script> that a browser refuses to run.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import csp as c   # noqa: E402
from xssentinel.core.verifier import (  # noqa: E402
    _csp_blocks_attr, _csp_blocks_inline, _csp_blocks_js_uri, verify_semantic)

SPLIT = "script-src 'self'; script-src-attr 'unsafe-inline'"
NONCE_PLUS_ATTR = ("script-src 'nonce-abc123' 'unsafe-inline'; "
                   "script-src-attr 'unsafe-inline'")
HDR = lambda csp_value: {"Content-Security-Policy": csp_value}  # noqa: E731


# ---------------------------------------------------------------------------
# the family lookup itself
# ---------------------------------------------------------------------------
def test_elem_and_attr_directives_replace_script_src():
    d = c.parse_csp(SPLIT)
    assert c.governing_directive(d, "attr") == "script-src-attr"
    assert c.governing_directive(d, "elem") == "script-src"
    assert c.family_sources(d, "attr") == ["'unsafe-inline'"]


def test_script_src_elem_governs_elements_only():
    d = c.parse_csp("script-src 'none'; script-src-elem 'unsafe-inline'")
    assert c.family_allows_inline(d, "elem") is True
    assert c.family_allows_inline(d, "attr") is False


def test_a_nonce_does_not_cross_into_the_other_family():
    d = c.parse_csp(NONCE_PLUS_ATTR)
    assert c.family_allows_inline(d, "elem") is False   # nonce eats unsafe-inline
    assert c.family_allows_inline(d, "attr") is True    # its list has no nonce


def test_unrestricted_policy_blocks_nothing():
    d = c.parse_csp("frame-ancestors 'none'; img-src 'self'")
    assert all(c.family_allows_inline(d, fam) for fam in c.SCRIPT_FAMILIES)
    assert not c.governing_directive(d, "elem")


# ---------------------------------------------------------------------------
# verifier gates, per family
# ---------------------------------------------------------------------------
def test_event_handler_allowed_while_script_blocked():
    headers = HDR(SPLIT)
    assert _csp_blocks_inline(headers) is True
    assert _csp_blocks_attr(headers) is False


def test_handler_reflection_confirms_under_the_split_policy():
    html = '<div id=x></div><img src=y onerror="x.textContent=\'tok99\'">'
    verdict = verify_semantic(html, "tok99", response_headers=HDR(SPLIT))
    assert verdict["confirmed"] is True, verdict
    assert verdict["context"] == "event_handler"


def test_script_element_refuted_under_the_same_policy():
    """The twin assertion: same header, opposite answer for <script>."""
    html = "<script>var t = 'tok99'; alert(t)</script>"
    verdict = verify_semantic(html, "tok99", response_headers=HDR(SPLIT))
    assert verdict["confirmed"] is False, verdict
    assert "CSP" in verdict["detail"]


def test_nonce_in_script_src_does_not_refute_a_handler():
    html = '<img src=y onerror="alert(\'tok99\')">'
    assert verify_semantic(html, "tok99",
                           response_headers=HDR(NONCE_PLUS_ATTR))["confirmed"]
    # ... while the element form is still (correctly) refuted.
    assert not verify_semantic("<script>alert('tok99')</script>", "tok99",
                               response_headers=HDR(NONCE_PLUS_ATTR))["confirmed"]


def test_host_allowlist_without_unsafe_inline_blocks_inline():
    """Old block-regex looked for 'none'/'self'/'nonce-' and missed this."""
    headers = HDR("script-src https://cdn.example.com")
    assert _csp_blocks_inline(headers) is True
    assert not verify_semantic("<script>alert('tok99')</script>", "tok99",
                               response_headers=headers)["confirmed"]


def test_js_uri_uses_its_own_family():
    headers = HDR("script-src 'self'; script-src-attr 'unsafe-inline'")
    assert _csp_blocks_js_uri(headers) is True


def test_no_csp_header_blocks_nothing():
    assert _csp_blocks_inline({}) is False
    assert _csp_blocks_attr(None) is False


# ---------------------------------------------------------------------------
# analysis / budget gating
# ---------------------------------------------------------------------------
def test_analyze_reports_which_family_still_runs():
    rep = c.analyze(SPLIT)
    assert any("script-src-attr" in w for w in rep.weak), rep.weak
    inline = [b for b in rep.bypasses if b["type"] == "inline"]
    assert len(inline) == 1
    assert "onerror" in inline[0]["payload"], inline
    assert "<script>" not in inline[0]["payload"]


def test_gadget_hosts_are_found_behind_script_src_elem():
    rep = c.analyze("script-src-elem 'self' ajax.googleapis.com")
    assert any(b["type"] == "script_gadget" for b in rep.bypasses), rep.weak


def test_unsafe_hashes_is_called_out():
    rep = c.analyze("script-src 'sha256-abc' 'unsafe-hashes'")
    assert any("unsafe-hashes" in w for w in rep.weak), rep.weak


def test_split_policy_is_not_budget_strict():
    """A route exists, so the early-stop budget gate must not fire."""
    assert c.is_strict_inline(SPLIT) is False


def test_strict_still_strict_and_permissive_still_permissive():
    assert c.is_strict_inline("script-src 'self'") is True
    assert c.is_strict_inline("script-src 'self' 'unsafe-inline'") is False
    assert c.is_strict_inline("default-src 'none'") is True
    assert c.is_strict_inline("script-src 'nonce-abc'") is False  # nonce layer
    assert c.is_strict_inline("") is False


def test_gadget_chain_needs_inline_dead_for_every_family():
    gadget = "script-src 'self' ajax.googleapis.com"
    assert c.gadget_chain_relevant(gadget) is True
    assert c.gadget_chain_relevant(
        gadget + "; script-src-attr 'unsafe-inline'") is False


def test_unsafe_inline_overridden_stays_element_scoped():
    assert c.unsafe_inline_overridden("script-src 'nonce-a' 'unsafe-inline'")
    assert not c.unsafe_inline_overridden(
        "script-src 'nonce-a' 'unsafe-inline'; script-src-attr 'unsafe-inline'",
        family="attr")
