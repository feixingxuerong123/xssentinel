"""Phase 364: regression tests for the four measured reflection shapes.

Each helper below exists because of a specific XSSMaze query gap; the tests
pin the measurement so a later corpus/engine edit cannot silently drop it.
"""
import json
from pathlib import Path

from xssentinel.core import context
from xssentinel.core import reflection_profile as rp
from xssentinel.core import verifier

TOKEN = "xssv_phase364"


def test_prefix_encoded_marker_only_matches_a_leading_span():
    # The edge encoder entity-encodes the first ten characters of the input
    # and leaves digits / punctuation alone.
    marker = "xssm_ab12cd34"
    encoded = "".join(
        f"&#x{ord(c.lower()):x};" if c.isalpha() else c
        for c in marker[:10])
    text = f"<div>{encoded}{marker[10:]}</div>"
    got = context.find_prefix_encoded_marker(text, marker)
    assert got == (marker, 10)
    # A fully entity-encoded marker is the ordinary escaped case, not this one.
    full = "".join(f"&#x{ord(c):x};" for c in marker)
    assert context.find_prefix_encoded_marker(f"<b>{full}</b>", marker) is None
    # An untouched marker is not reported either.
    assert context.find_prefix_encoded_marker(f"<b>{marker}</b>", marker) is None


def test_noscript_rawtext_detection():
    body = f"<noscript><div>{TOKEN}</div></noscript>"
    idx = body.find(TOKEN)
    assert rp.detect_noscript_rawtext(body, idx) is True
    closed = f"<noscript></noscript><div>{TOKEN}</div>"
    assert rp.detect_noscript_rawtext(closed, closed.find(TOKEN)) is False


def test_srcdoc_host_detection():
    inside = f'<iframe srcdoc="<img src=x onerror={TOKEN}>"></iframe>'
    assert rp.detect_srcdoc_host(inside, inside.find(TOKEN)) is True
    outside = f'<div>{TOKEN}</div>'
    assert rp.detect_srcdoc_host(outside, outside.find(TOKEN)) is False


def test_entity_spell_handler():
    assert rp.entity_spell_handler("<img src=x onerror=alert(1)>") == \
        "<img src=x on&#101;rror=alert(1)>"


def test_surface_prefix_bypasses_lead_the_queue():
    bases = [{"payload": "<img src=x onerror=alert(1)>", "context": "html_element"}]
    out, tag = rp.surface_prefix_bypasses(bases)
    assert tag == "prefix_bypass"
    assert out[0]["payload"].startswith("\x00")
    assert out[1]["payload"].startswith("0" * 10)
    assert out[-1] is bases[0]


def test_surface_noscript_breakouts_use_supplied_seeds():
    prof = {"noscript_tag": True}
    bases = [{"payload": "javascript:alert(1)", "context": "url_href"}]
    seeds = [{"payload": "<img src=x onerror=alert(1)>", "context": "html_element"}]
    out, tag = rp.surface_noscript_breakouts(prof, bases, seeds=seeds)
    assert tag == "noscript"
    assert out[0]["payload"].startswith("</noscript><img")
    assert "</NOSCRIPT>" in out[1]["payload"]
    assert out[-1] is bases[0]


def test_meta_csp_only_applies_after_the_tag():
    before = (f'<html><body><div><script>alert("{TOKEN}")</script></div>'
              '<meta http-equiv="Content-Security-Policy" '
              "content=\"script-src 'none'\"></body></html>")
    v = verifier.verify_semantic(before, TOKEN)
    assert v.get("confirmed") is True
    after = (f'<html><head><meta http-equiv="Content-Security-Policy" '
             "content=\"script-src 'none'\"></head><body>"
             f'<script>alert("{TOKEN}")</script></body></html>')
    v2 = verifier.verify_semantic(after, TOKEN)
    assert v2.get("confirmed") is False


def test_javascript_media_type_confirms_a_callback_sink():
    body = f"alert`{TOKEN}`//({{\"data\":\"test\"}})"
    v = verifier.verify_semantic(
        body, TOKEN, response_headers={"Content-Type": "application/javascript"})
    assert v.get("confirmed") is True
    assert v.get("context") == "javascript_response"
    v2 = verifier.verify_semantic(
        body, TOKEN, response_headers={"Content-Type": "text/html"})
    assert v2.get("confirmed") is False


def test_phase364_corpus_is_unchanged():
    data = json.loads(
        (Path(__file__).resolve().parents[1] / "xssentinel" / "data"
         / "payloads.json").read_text(encoding="utf-8"))
    assert len(data["payloads"]) == 1205
    assert len(data["polyglots"]) == 36
