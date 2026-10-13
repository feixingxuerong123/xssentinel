# -*- coding: utf-8 -*-
"""Phase 189: the sanitizer corpus must describe the sanitizer of now.

The version table used to stop at 2020 (``DOMPurify < 2.0.8``) while every
advisory published for DOMPurify in 2026 reaches its bypass through a CONFIG
option -- IN_PLACE, CUSTOM_ELEMENT_HANDLING, SAFE_FOR_TEMPLATES,
setConfig()/hook pollution, function-form ADD_TAGS predicates.  An app on a
3.4.x build with ``IN_PLACE: true`` was invisible to us: too new for the
version rule, and no pattern looked at the option.

Ranges and IDs were taken from the vendor's published advisory list
(api.github.com/repos/cure53/DOMPurify/security-advisories, 25 entries as of
2026-09-23, latest release 3.4.16), not from recollection.

The negative controls matter as much as the detections: this layer feeds
reports, and "you use DOMPurify, that's risky" is noise.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import sanitizer_bypass as sb  # noqa: E402


def _types(html):
    return [v["type"] for v in sb.analyze_page(html)["violations"]]


def _titles(html):
    return [v.get("title", "") + v.get("desc", "")
            for v in sb.analyze_page(html)["violations"]]


# ---------------------------------------------------------------------------
# version lines
# ---------------------------------------------------------------------------
def test_2020_line_still_reports():
    html = "<script>/*! @license DOMPurify 1.0.11 | (c) cure53 */</script>"
    assert "sanitizer_vulnerable_version" in _types(html)


def test_2024_line_caught_by_the_npm_path_shape():
    html = '<script src="/static/npm/dompurify@3.0.5/dist/purify.min.js"></script>'
    found = sb.analyze_page(html)["vulnerable_versions"]
    assert len(found) == 1, found          # one finding, not one per pattern
    assert found[0]["version"] == "3.0.5"
    assert "CVE-2024-47875" in found[0]["cve"]


def test_2026_line_reports_the_config_surface_not_just_a_number():
    html = "<script>// DOMPurify 3.4.15</script>"
    found = sb.analyze_page(html)["vulnerable_versions"]
    assert len(found) == 1
    assert found[0]["affected_range"] == "3.1.3 - 3.4.15"
    assert "IN_PLACE" in found[0]["cve"]


def test_current_release_is_clean():
    html = "<script>// DOMPurify 3.4.16</script>"
    assert _types(html) == [], _titles(html)


def test_boundaries_are_not_double_or_zero_counted():
    """3.1.2 belongs to the 2024 line, 3.1.3 to the 2026 line -- never both."""
    for version, expect_id in (("2.0.7", "CVE-2020-26870"),
                               ("2.0.8", "CVE-2024-45801"),
                               ("3.1.2", "CVE-2024-45801"),
                               ("3.1.3", "CVE-2026-41238")):
        found = sb.analyze_page(f"<script>/*! DOMPurify {version} */</script>")["vulnerable_versions"]
        assert len(found) == 1, (version, found)
        assert expect_id in found[0]["cve"], (version, found[0]["cve"])


# ---------------------------------------------------------------------------
# configuration surface
# ---------------------------------------------------------------------------
def test_in_place_option_detected():
    html = "DOMPurify.sanitize(dirty, {IN_PLACE: true});"
    assert "sanitizer_config_in_place" in _types(html)


def test_custom_element_handling_detected():
    html = ("DOMPurify.sanitize(dirty, {CUSTOM_ELEMENT_HANDLING: "
            "{tagNameCheck: /^x-/, attributeNameCheck: /.}});")
    assert "sanitizer_config_custom_element_handling" in _types(html)


def test_setconfig_persistence_detected():
    html = "DOMPurify.setConfig({ALLOWED_TAGS: ['b']});"
    assert "sanitizer_config_setconfig_persistence" in _types(html)


def test_allowlisted_event_handler_attribute_is_high():
    html = "DOMPurify.sanitize(x, {ADD_ATTR: ['onclick']});"
    hits = [v for v in sb.analyze_page(html)["violations"]
            if v["type"] == "sanitizer_config_add_attr_handler"]
    assert hits and hits[0]["severity"] == "high"


def test_use_profiles_and_uri_grants_detected():
    assert "sanitizer_config_use_profiles" in _types(
        "DOMPurify.sanitize(x, {USE_PROFILES: {html: true}});")
    assert "sanitizer_config_add_uri_safe_attr" in _types(
        "DOMPurify.sanitize(x, {ADD_URI_SAFE_ATTR: ['data-src']});")
    assert "sanitizer_config_allowed_uri_regexp" in _types(
        "DOMPurify.sanitize(x, {ALLOWED_URI_REGEXP: '/^http/'});")


# ---------------------------------------------------------------------------
# negative controls: a hardened page must stay silent
# ---------------------------------------------------------------------------
def test_plain_allowlist_config_is_not_a_finding():
    html = """
    <script src="/static/npm/dompurify@3.4.16/dist/purify.min.js"></script>
    <script>
      const clean = DOMPurify.sanitize(raw, {
        ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
        ALLOWED_ATTR: ['href', 'title'],
      });
      el.innerHTML = clean;
    </script>"""
    types = _types(html)
    assert "sanitizer_config_add_attr_handler" not in types, types
    assert "sanitizer_config_in_place" not in types, types
    assert "sanitizer_config_add_uri_safe_attr" not in types, types
    # The sanitizer-output-to-innerHTML note is expected and unrelated --
    # but since Phase 225 it is graded by evidence: this page's sanitizer
    # version IS recognised and is not in any vulnerable range, so the
    # mXSS-class note is low (see test_mxss_note_is_graded_by_version).
    assert "sanitizer_vulnerable_version" not in types, types
    sev = {v["type"]: v["severity"]
           for v in sb.analyze_page(html)["violations"]}
    assert sev["sanitizer_output_to_innerhtml"] == "low", sev


# ---------------------------------------------------------------------------
# Phase 225: the mXSS note is graded by the page's own sanitizer version
# ---------------------------------------------------------------------------
# Range #6 measured the previous behaviour: the note was an unconditional
# medium on every sanitize()->innerHTML flow, so the canonical CORRECT
# usage (a current sanitizer, output to innerHTML) was reported as a
# medium "mXSS risk" on a page whose CVE-2020-26870 payload is provably
# stripped.  Unbacked severity is a false positive for any consumer that
# triages by level.

def test_mxss_note_is_graded_by_version():
    shell = ('<script src="/vendor/dompurify/%s/purify.min.js"></script>'
             '<script>var q = new URLSearchParams(location.search).get("q");'
             'var clean = DOMPurify.sanitize(q);'
             'el.innerHTML = clean;</script>')

    def sev(html):
        return {v["type"]: v["severity"]
                for v in sb.analyze_page(html)["violations"]}

    # current build, correct usage: the class is known, this page is not a
    # member of it -> low
    assert sev(shell % "3.4.17")["sanitizer_output_to_innerhtml"] == "low"
    # a version INSIDE a vulnerable range keeps the medium note (and gets
    # the high version finding alongside it)
    s = sev(shell % "2.0.7")
    assert s["sanitizer_output_to_innerhtml"] == "medium", s
    assert s["sanitizer_vulnerable_version"] == "high", s
    # no version visible -> nothing argues against the class -> medium
    assert sev(shell % "NOPE")["sanitizer_output_to_innerhtml"] == "medium"


def test_mxss_note_grading_needs_a_current_and_a_known_version():
    """Reverse guard: the demotion must not fire on evidence it does not
    have.  A page that merely mentions a current version in prose while
    its sanitize() flow has no recognisable build keeps the note at
    medium; likewise a page carrying BOTH a current and a vulnerable
    reference (the vulnerable one decides)."""
    both = ('<script src="/vendor/dompurify/3.4.17/purify.min.js"></script>'
            '<script src="/legacy/dompurify@2.0.7/purify.min.js"></script>'
            '<script>var c = DOMPurify.sanitize(q); el.innerHTML = c;</script>')
    sev = {v["type"]: v["severity"]
           for v in sb.analyze_page(both)["violations"]}
    assert sev["sanitizer_output_to_innerhtml"] == "medium", sev
    assert sev["sanitizer_vulnerable_version"] == "high", sev
    # recognised versions are reported so a consumer can see the basis
    assert sb.analyze_page(both)["detected_versions"] == ["3.4.17", "2.0.7"]


def test_ordinary_event_handler_name_in_code_is_not_a_config():
    """``onclick`` appearing in JS must not read as ADD_ATTR: ['onclick']."""
    html = "button.addEventListener('click', handler); a.onclick = f;"
    assert "sanitizer_config_add_attr_handler" not in _types(html)


def test_existing_patterns_still_fire():
    assert "sanitizer_config_add_script" in _types(
        "DOMPurify.sanitize(x, {ADD_TAGS: ['script']});")
    assert "sanitizer_config_return_dom" in _types(
        "DOMPurify.sanitize(x, {RETURN_DOM: true});")
