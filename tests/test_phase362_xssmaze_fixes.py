# -*- coding: utf-8 -*-
"""Phase 362: the three XSSMaze-derived detection fixes, each with its
measured anchor.

Phase 361 attributed the residual 69 FNs (dev/_xssmaze/
FN_ATTRIBUTION_20261106.md).  Three fixes landed from that evidence:

  * ``build_test_url`` whole-segment replacement -- the first-occurrence
    SUBSTRING replace rebuilt ``/p<payload>th/level1/a`` on
    ``/path/level1/a`` (the first ``a`` lives inside the directory name
    ``path``), so L8_path never touched the terminal segment.  dalfox
    confirms 3/4 and nuclei 4/4 of those endpoints under the same
    URL-only contract; after the fix all four confirm live
    (``path_xss`` medium, lab-verified 2026-11-06).
  * verifier UTF-7 charset gate -- a handler value riding UTF-7
    sequences only executes when the BROWSER decodes the document as
    UTF-7, i.e. when the document declares that charset.  Measured on
    eventhandler/level3: no charset declared, structurally real
    attribute, scan-time confirm high, the scanner's own PoC replay
    refused the same finding ("not_reproduced") -- an oracle split.
    range3's true UTF-7 page declares ``charset=UTF-7`` (server.py:192),
    so the gate keeps the honest case.
  * bracket-dead queue injection -- when the reflection profile shows
    ``<`` stripped, bare attribute-NAME handler shapes (corpus tag
    ``attr_name_injection``) lead the queue ahead of the generative
    javascript:-URI block, which presumes a URL-position reflection a
    bracket-dead element reflection cannot offer.  Live result:
    eventhandler/level3/4 confirm ``ondblclick=alert('xssv_...')`` at
    the DEFAULT budget; 27/27 lab controls stay silent.

Both engines run the same rule (Phase 357's parity lesson), pinned here
at source level; the behavioural unit gates run against the real
functions, not stand-ins.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from xssentinel.core import path_xss as px  # noqa: E402
from xssentinel.core import reflection_profile as rp  # noqa: E402
from xssentinel.core import verifier  # noqa: E402


# --------------------------------------------------------------------------
# Fix: build_test_url replaces the TERMINAL WHOLE segment
# --------------------------------------------------------------------------

class TestBuildTestUrlWholeSegment:
    LAB_URL = "http://127.0.0.1:3001/path/level1/a"

    def test_short_segment_does_not_hit_the_directory_name(self):
        """The measured lab shape: segment 'a' first occurs inside the
        literal directory name 'path'.  The built URL must weaponise the
        TERMINAL segment -- exact equality, so neither the append branch
        nor a substring replace can satisfy it."""
        url = px.build_test_url(self.LAB_URL, "a", "PAY")
        assert url == "http://127.0.0.1:3001/path/level1/PAY", url

    def test_last_whole_segment_wins_when_value_repeats(self):
        url = px.build_test_url("http://h/tag/a/sub/a", "a", "PAY")
        assert url == "http://h/tag/a/sub/PAY", url

    def test_multi_char_segment_still_replaced_in_place(self):
        """Pre-existing contract (Phase 109 tests): a long unique segment
        is replaced wherever it lives as a whole segment."""
        url = px.build_test_url("http://h.example/r/pth01?q=1", "pth01",
                                "PAY")
        assert url.startswith("http://h.example/r/"), url
        assert "/PAY" in url and "pth01" not in url, url
        assert "?q=1" in url, "original query must survive"

    def test_no_whole_match_appends_as_before(self):
        url = px.build_test_url("http://h.example/r/idx", "zz", "PAY")
        assert url.endswith("/PAY"), url

    def test_slash_still_encoded(self):
        url = px.build_test_url(self.LAB_URL, "a", "<svg/onload=alert(1)>")
        assert "%2F" in url and "<" not in url and ">" not in url, url


# --------------------------------------------------------------------------
# Fix: verifier UTF-7 charset gate (event-handler confirm sites)
# --------------------------------------------------------------------------

def _utf7_page(token: str) -> str:
    return ("<div +ADw-marquee onstart=alert+ACg-+ACc-" + token
            + "+ACc-+ACk-+AD4->hi</div>")


class TestVerifierUtf7CharsetGate:
    TOKEN = "xssv_deadbeef"

    def test_utf7_value_without_charset_is_refused(self):
        v = verifier.verify_semantic(_utf7_page(self.TOKEN), self.TOKEN)
        assert v["confirmed"] is False, v
        assert "UTF-7" in v.get("detail", ""), v

    def test_utf7_value_with_header_charset_confirms(self):
        v = verifier.verify_semantic(
            _utf7_page(self.TOKEN), self.TOKEN,
            response_headers={"Content-Type": "text/html; charset=UTF-7"})
        assert v["confirmed"] is True, v

    def test_utf7_value_with_meta_charset_confirms(self):
        page = ('<meta http-equiv="Content-Type" '
                'content="text/html; charset=utf-7">' + _utf7_page(self.TOKEN))
        v = verifier.verify_semantic(page, self.TOKEN)
        assert v["confirmed"] is True, v

    def test_plain_handler_value_unaffected(self):
        """The gate only fires on UTF-7-shaped values; the ordinary
        quoted-token handler shape confirms exactly as before."""
        page = f"<div ondblclick=alert('{self.TOKEN}')>hi</div>"
        v = verifier.verify_semantic(page, self.TOKEN)
        assert v["confirmed"] is True, v
        assert v["context"] == "event_handler", v

    def test_svg_math_site_wired_too(self):
        """The svg/math confirm site (Phase 84 slash-form attrs) shares the
        same gate helper -- pinned at source level because behaviourally
        the sandbox may veto such shapes first (svg-namespace refusal),
        which is also a refusal."""
        src = (REPO / "xssentinel/core/verifier.py").read_text(
            encoding="utf-8")
        assert src.count("_utf7_shaped_without_basis(") >= 3, (
            "gate helper must be called at BOTH event-handler confirm "
            "sites (main + svg/math) plus its definition site")

    def test_utf7_helper_direct(self):
        val = "alert+ACg-+ACc-xssv_deadbeef+ACc-+ACk-+AD4-"
        assert verifier._utf7_shaped_without_basis(val, None, None) is True
        assert verifier._utf7_shaped_without_basis(
            val, {"Content-Type": "text/html; charset=utf-7"}, None) is False
        assert verifier._utf7_shaped_without_basis(
            val, None, '<meta charset="utf-7">') is False
        # a plain quoted-token value carries no utf7 sequence: never gated
        assert verifier._utf7_shaped_without_basis(
            "alert('xssv_deadbeef')", None, None) is False


# --------------------------------------------------------------------------
# Fix: bracket-dead queue injection (shared helpers + both engines)
# --------------------------------------------------------------------------

class TestBracketDeadHelpers:
    def test_bracket_dead_true_when_lt_stripped(self):
        prof = {"reflected": True, "full_reflection": False,
                "chars_kept": ["\"", "'", "="],
                "chars_stripped": ["<", ">"]}
        assert rp.bracket_dead(prof) is True

    def test_bracket_dead_false_when_probe_never_came_back(self):
        """profile_reflection returns chars_kept=[] for a probe the target
        never echoed -- that is 'unknown filtering', not bracket-dead
        (measured on the Phase 315 HPP fixture's filter-checked slot)."""
        prof = {"reflected": False, "full_reflection": False,
                "chars_kept": [], "chars_stripped": list("\"'<>()=/;")}
        assert rp.bracket_dead(prof) is False

    def test_bracket_dead_false_when_lt_encoded_not_stripped(self):
        """A page that HTML-ENCODES the probe has a working encoder; the
        bare shapes cannot confirm there either, and the escaped page's
        minimal probe budget must not be spent on them (Phase 311
        escaped-echo fixture, measured)."""
        prof = {"reflected": True, "full_reflection": False,
                "chars_kept": ["\"", "'", "="],
                "chars_stripped": [],
                "chars_encoded": ["<", ">"]}
        assert rp.bracket_dead(prof) is False

    def test_bracket_dead_false_on_full_reflection(self):
        assert rp.bracket_dead({"full_reflection": True}) is False
        assert rp.bracket_dead(None) is False

    def test_bracket_dead_false_when_lt_kept(self):
        prof = {"reflected": True, "full_reflection": False,
                "chars_kept": ["<", ">", "\"", "'"]}
        assert rp.bracket_dead(prof) is False

    def test_corpus_carries_bare_attrname_shapes(self):
        shapes = rp.bare_attrname_payloads("html_element")
        assert len(shapes) >= 3, shapes
        for p in shapes:
            pl = p["payload"]
            # every shape is bracket-free and carries a live on*= assignment
            assert "<" not in pl and ">" not in pl, pl
            assert "on" in pl and "=" in pl, pl

    def test_bare_shapes_absent_for_other_context(self):
        # the tag is html_element-scoped; another context must not inherit it
        assert rp.bare_attrname_payloads("script_block") == []


class TestBothEnginesWireTheInjection:
    """Phase 357's lesson: one contract, two engines.  The sync side gets
    a BEHAVIOURAL test through the real ``_prioritize_bases`` (a source
    substring pin alone survives a behaviour-killing mutation -- measured
    during this round's own mutation check), the async side gets an
    exact-statement source pin (its queue builder is session-bound)."""

    @staticmethod
    def _fn_slice(rel_path: str, def_name: str) -> str:
        src = (REPO / rel_path).read_text(encoding="utf-8")
        start = src.index(f"def {def_name}")
        nxt = src.find("\n    def ", start + 1)
        return src[start:nxt if nxt != -1 else None]

    def test_sync_queue_leads_with_bare_shapes_when_bracket_dead(self):
        from xssentinel.core.scanner import Scanner
        s = Scanner(max_payloads=14)
        prof = {"reflected": True, "full_reflection": False,
                "chars_kept": ["\"", "'", "="],
                "chars_stripped": ["<", ">"],
                "chars_encoded": []}
        s._probe_reflection_profile = lambda *a, **k: dict(prof)
        bases = [{"id": "html-001", "context": "html_element",
                  "payload": "<script>alert(1)</script>"}]
        out, _tp, got = s._prioritize_bases(
            None, "http://t/x", "GET", {}, {}, "q", False,
            list(bases), "html_element", False)
        heads = [b.get("payload", "") for b in out[:14]]
        # the bare shapes join the DEFAULT budget window (the measured
        # arrangement: generative still leads, bare shapes right behind)
        bare = [p for p in heads
                if p.startswith("on") and "=" in p and "<" not in p]
        assert len(bare) >= 2, out[:14]
        assert any(b.get("payload") == "<script>alert(1)</script>"
                   for b in out), "original base must survive"
        assert got == prof

    def test_sync_queue_untouched_when_brackets_alive(self):
        from xssentinel.core.scanner import Scanner
        s = Scanner(max_payloads=14)
        prof = {"full_reflection": False,
                "chars_kept": ["<", ">", "\"", "'"],
                "chars_stripped": [],
                "chars_encoded": []}
        s._probe_reflection_profile = lambda *a, **k: dict(prof)
        bases = [{"id": "html-001", "context": "html_element",
                  "payload": "<script>alert(1)</script>"}]
        out, _tp, _got = s._prioritize_bases(
            None, "http://t/x", "GET", {}, {}, "q", False,
            list(bases), "html_element", False)
        payloads_out = [b.get("payload") for b in out]
        assert payloads_out.count("ondblclick=alert(1)") == 0, payloads_out

    def test_sync_source_pin_exact_statement(self):
        body = self._fn_slice("xssentinel/core/scanner.py",
                              "_prioritize_bases")
        assert "if rp_mod.bracket_dead(profile):" in body, body
        # the injection prepends BEFORE the generative prepend -- the
        # measured lab arrangement keeps corpus polyglot entries inside
        # the default budget window (eventhandler/level5)
        assert body.index("if rp_mod.bracket_dead(profile):") \
            < body.index("gen_mod.generate(profile, context)"), body

    def test_async_param_layers_inject(self):
        src = (REPO / "xssentinel/core/async_scanner_layers.py").read_text(
            encoding="utf-8")
        assert "if rp_mod.bracket_dead(prof):" in src, "async wiring missing"
        assert "bare_attrname_payloads" in src, "async helper call missing"


if __name__ == "__main__":  # pragma: no cover
    sys.exit(pytest.main([__file__, "-v"]))
