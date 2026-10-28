"""Phase 337: every primary-window payload must be LIVE in its own context.

Phase 334 audited all 40 context windows with faithful per-context
reflection harnesses and adjudicated ~16 dead slots (payloads that cannot
execute in a modern browser even on the most permissive page shape for
their own context -- legacy-only elements, mistyped vector names, shapes
inert by construction).  Phase 337 swapped every one of them for a
browser-oracle-verified live vector (dev/_p337_swap_probe.py).

This test is that audit as a standing regression net: for every context
with a semantic confirmation path, every payload in the primary window
(``head[:max(6, max_payloads // 2)]``) must CONFIRM on its faithful
harness.  A red here means a dead shape entered a reachable window again
-- the exact failure mode that wasted slot 0 of every html_element scan
(the p173-probe, Phase 331) and the error_page/svg/math slots (Phase 334).

Excluded from the semantic contract (different confirmation machinery --
a refusal there proves nothing):
  * layer-confirmed: dom_clobber, dangling_markup, script_gadget,
    prototype_gadget, postmessage_source, service_worker, blind_oob,
    css_exfil (CSSI observation);
  * interaction-confirmed: url_javascript, url_href, meta_refresh,
    markdown (click / renderer-dependent);
  * framework/probe payloads: framework_* and template_* (executed by the
    client framework or used as detection probes, e.g. ``{{7*7}}``);
  * no faithful harness defined: cdata, data_uri, header_reflection.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


from xssentinel.core import payloads  # noqa: E402
from xssentinel.core import verifier as verifier_mod  # noqa: E402

TOKEN = "xssv_liveness01"

HARNESS = {
    "html_element": lambda s: f"<html><body><p>echo: {s}</p></body></html>",
    "script_block": lambda s: (f"<html><body><script>{s}</script>"
                               f"</body></html>"),
    "script_string_dq": lambda s: (f'<html><body><script>var x = "{s}";'
                                   f"</script></body></html>"),
    "script_string_sq": lambda s: (f"<html><body><script>var x = '{s}';"
                                   f"</script></body></html>"),
    "script_template": lambda s: (f"<html><body><script>var t = `{s}`;"
                                  f"</script></body></html>"),
    "html_attribute_dq": lambda s: (f'<html><body><input value="{s}">'
                                    f"</body></html>"),
    "html_attribute_sq": lambda s: (f"<html><body><input value='{s}'>"
                                    f"</body></html>"),
    "html_attribute_noquote": lambda s: (f"<html><body><input value={s}>"
                                         f"</body></html>"),
    "event_handler": lambda s: (f'<html><body><img src=x onerror="{s}">'
                                f"</body></html>"),
    "css_context": lambda s: (f"<html><head><style>{s}</style></head>"
                              f"<body></body></html>"),
    "html_comment": lambda s: f"<html><body><!-- {s} --></body></html>",
    "svg_context": lambda s: f"<html><body><svg>{s}</svg></body></html>",
    "math_context": lambda s: f"<html><body><math>{s}</math></body></html>",
    "error_page": lambda s: f"<html><body><p>echo: {s}</p></body></html>",
    # path payloads are percent-encoded markup: the server decodes the
    # path before reflecting, so the browser sees decoded markup.
    "path_xss": lambda s: (f"<html><body><p>echo: "
                           f"{__import__('urllib.parse', fromlist=['unquote']).unquote(s)}"
                           f"</p></body></html>"),
    "portswigger_events": lambda s: (f"<html><body><p>echo: {s}</p>"
                                     f"</body></html>"),
    "interaction_events": lambda s: (f"<html><body><p>echo: {s}</p>"
                                     f"</body></html>"),
    "html5_new": lambda s: f"<html><body><p>echo: {s}</p></body></html>",
}

EXCLUDED = {
    "layer-confirmed": {"dom_clobber", "dangling_markup", "script_gadget",
                        "prototype_gadget", "postmessage_source",
                        "service_worker", "blind_oob", "css_exfil"},
    "interaction-confirmed": {"url_javascript", "url_href", "meta_refresh",
                              "markdown"},
    "framework-or-probe": {"framework_angular", "framework_vue",
                           "framework_react", "framework_svelte",
                           "framework_mustache", "template_angular",
                           "template_vue"},
    "no-harness": {"cdata", "data_uri", "header_reflection"},
}


# (payload, harness) rows per context, materialised once
_WINDOW_CACHE: dict[str, list[tuple[str, str]]] = {}



def _tags_for(ctx: str, payload: str) -> list:
    for p in payloads.by_context(ctx):
        if p.get("payload") == payload:
            return p.get("tags") or []
    return []

def _windows() -> dict[str, list[tuple[str, str]]]:
    if not _WINDOW_CACHE:
        for ctx, harness in HARNESS.items():
            ps = payloads.by_context(ctx)
            win = ps[:max(6, 10 // 2)]
            _WINDOW_CACHE[ctx] = [(p["payload"], harness) for p in win
                                  if p.get("payload")]
    return _WINDOW_CACHE


def test_every_window_payload_is_markable_and_live():
    checked = 0
    interaction_tagged = 0
    for ctx, rows in _windows().items():
        for payload, harness in rows:
            tags = _tags_for(ctx, payload)
            if "interaction" in tags:
                # click-required vector: confirmed by the headless click
                # path, not by auto-execution -- outside this contract.
                interaction_tagged += 1
                continue
            marked = verifier_mod.mark(payload, TOKEN)
            assert marked != payload, (
                f"{ctx} window payload cannot carry the token: {payload!r}")
            v = verifier_mod.verify_semantic(harness(marked), TOKEN,
                                              response_headers={})
            assert v.get("confirmed"), (
                f"DEAD slot in the {ctx} primary window: {payload!r} "
                f"refuses on its faithful harness (detail={v.get('detail')}) "
                f"-- a payload that cannot execute on the most permissive "
                f"page shape for its own context is a wasted probe slot "
                f"(Phase 331/334 lesson)")
            checked += 1
    assert checked >= 60, f"window census shrank unexpectedly: {checked}"
    assert interaction_tagged >= 1, (
        "no interaction-tagged payload in any window -- the skip branch is "
        "dead and the tag contract is untested")


def test_no_dead_family_slipped_into_the_exclusions():
    """The exclusion set must not become a dumping ground: every covered
    context (harness or exclusion) must exist in the corpus, and every
    corpus context must be accounted for -- a new context needs either a
    faithful harness or a reasoned exclusion, not silence."""
    import json

    all_ctxs = {e.get("context") for e in
                json.load(open(os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "xssentinel", "data", "payloads.json"),
                    encoding="utf-8"))["payloads"]
                if e.get("context")}
    known = set(HARNESS) | set().union(*EXCLUDED.values())
    unknown = known - all_ctxs
    assert not unknown, (f"exclusion names that are not corpus contexts: "
                         f"{unknown}")
    unaccounted = all_ctxs - known
    assert not unaccounted, (
        f"corpus contexts not covered by harness-or-exclusion: {unaccounted}")
