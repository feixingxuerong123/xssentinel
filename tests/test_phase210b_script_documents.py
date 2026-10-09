# -*- coding: utf-8 -*-
"""Phase 210b: a JavaScript resource is not a page.

The crawler legitimately fetches bundles (that is how it found the SPA routes
in Phase 209).  Every page-shaped static layer then answered as if it had a
page, and on OWASP Juice Shop 20.2.0 the report grew, next to the one
browser-confirmed DOM XSS:

    /scripts.js          trusted_types_no_policy   medium
    /main.js             trusted_types_no_policy   medium
    /chunk-DAJ4olp_.js   trusted_types_no_policy   medium
    /chunk-eYAgyLdn.js   framework_angular_xss     high
    /main.js             open_redirect_xss         high   (redirect self-source)
    /main.js             postmessage_xss           high   (timer self-source)
    /main.js             websocket_xss             high   (timer self-source)

Two of those claims are structurally unfalsifiable rather than merely
over-confident:

  * "the page registers no Trusted Types policy" is read from the
    document's CSP header, and a ``.js`` response has none to read -- the
    statement is true of every script on earth;
  * "Angular disables sanitization" is a real pattern in that chunk, but
    which page binds it, with what input, and whether the branch runs here
    are questions a bundle cannot answer.

So the media type becomes part of the judgement, once, in one place
(``document_kind``), for both engines -- they share
``advanced_layers.run_page_layers``, which is why this file also locks that
dispatch's argument contract: the repo has been bitten three times by a layer
signature drifting from its call site and the ``TypeError`` being eaten by
the per-layer guard.
"""
from __future__ import annotations

import ast
import inspect
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssentinel.core import advanced_layers  # noqa: E402
from xssentinel.core import document_kind as dk  # noqa: E402
from xssentinel.core.layers import client_layers, content_layers  # noqa: E402

JS_CT = "application/javascript; charset=utf-8"
BUNDLE_URL = "http://127.0.0.1:18900/main.js"

#: The pattern Juice Shop's chunk actually contains (measured, not invented):
#: an Angular marker (required by the framework detector) plus the real
#: bypass call.
ANGULAR_UNSAFE = (
    "import{DomSanitizer}from'@angular/core';"
    "class e{getSafeHtml(){return this.sanitizer"
    ".bypassSecurityTrustHtml(this.raw)}}")

#: A dangerous sink with no user-controlled source: the layer's `no_policy`
#: class -- "the page registers no Trusted Types policy" -- and nothing else.
NO_POLICY_ONLY = "<script>document.body.innerHTML = render();</script>"
#: ... and one that DOES read code-level taint, which must survive.
TAINT_FLOW = ("<script>var u=location.search;"
              "document.body.innerHTML=u;</script>")


def _fake_scanner():
    class _Cov:
        def touch_layer(self, *a, **k):
            pass

        def record_finding(self, *a, **k):
            pass

    class _S:
        verbose = False
        requests_made = 0

        def __init__(self):
            self.added = []
            self.coverage = _Cov()

        def _add(self, f):
            self.added.append(f)

        def _bump(self, *a, **k):
            pass

    return _S()


# --------------------------------------------------------------------------
# the predicate itself
# --------------------------------------------------------------------------

def test_media_type_decides_and_beats_the_path():
    assert dk.is_script_document("/whatever", JS_CT)
    assert dk.is_script_document("http://h/app.mjs", "text/javascript")
    # A .js URL that answers HTML is an error page, not a bundle -- and that
    # distinction is the whole reason the header is consulted first.
    assert not dk.is_script_document(BUNDLE_URL, "text/html; charset=utf-8")
    assert not dk.is_script_document("http://h/index.html", "application/json")


def test_path_is_the_fallback_when_no_header_spoke():
    assert dk.is_script_document("http://h/static/main.js")
    assert dk.is_script_document("http://h/static/chunk-Q7.js?v=3")
    assert not dk.is_script_document("http://h/search?q=x")
    assert not dk.is_script_document("http://h/main.js.map")
    # No header AND no extension: we do not guess.  A path-less bundle is
    # then judged as a page, which is the conservative direction for the TT
    # claim (it gets reported) and the loud one for the framework one (it
    # stays medium/high) -- recorded so the next person fixes it by plumbing
    # the header, not by widening this predicate.
    assert not dk.is_script_document("http://h/assets/dynamic-bundle")
    # unparseable input must answer "not a script", never raise
    assert not dk.is_script_document("http://[bad")


# --------------------------------------------------------------------------
# behaviour: the two page-policy claims
# --------------------------------------------------------------------------

def test_no_policy_claim_is_not_made_about_a_script():
    """The claim is answered by the *document's* CSP header; a ``.js``
    response has none, so on a bundle it is true by construction and says
    nothing about the app."""
    sc = _fake_scanner()
    content_layers._scan_trusted_types(sc, BUNDLE_URL, NO_POLICY_ONLY, "", JS_CT)
    assert [f.data.get("type") for f in sc.added] == [], sc.added

    sc2 = _fake_scanner()
    content_layers._scan_trusted_types(sc2, "http://h/", NO_POLICY_ONLY, "")
    types = [f.data.get("type") for f in sc2.added]
    assert types == ["trusted_types_no_policy"], (
        "the same claim on a real page must still be reported -- the fix is "
        "about the document kind, not about silencing the layer")


def test_code_reading_tt_claims_survive_on_a_script():
    """taint_flow / policy_bypass read code, and a bundle is code."""
    sc = _fake_scanner()
    content_layers._scan_trusted_types(sc, BUNDLE_URL, TAINT_FLOW, "", JS_CT)
    types = [f.data.get("type") for f in sc.added]
    assert "trusted_types_taint_flow" in types, types
    assert "trusted_types_no_policy" not in types, types
    # the cap applies AFTER the filter, so a real flow sitting behind two
    # unanswerable claims still reaches the report
    sc2 = _fake_scanner()
    content_layers._scan_trusted_types(
        sc2, BUNDLE_URL,
        "document.body.innerHTML = render();" * 3 + TAINT_FLOW, "", JS_CT)
    assert any(f.data.get("type") == "trusted_types_taint_flow"
               for f in sc2.added), [f.data.get("type") for f in sc2.added]


def test_framework_pattern_stays_a_lead_on_a_script():
    sc = _fake_scanner()
    client_layers._scan_framework(sc, BUNDLE_URL, ANGULAR_UNSAFE, JS_CT)
    assert sc.added, "the pattern is real; hiding it would lose the lead"
    for f in sc.added:
        d = f.data
        assert d["severity"] == "low", d
        assert d["confidence"] == "low", d
    assert any("no page context" in d["detail"]
               for d in (f.data for f in sc.added)), [
                   f.data["detail"][:120] for f in sc.added]
    assert any("bypassSecurityTrustHtml" in f.data["detail"] for f in sc.added)


def test_framework_pattern_keeps_its_grade_on_a_page():
    sc = _fake_scanner()
    client_layers._scan_framework(sc, "http://h/", ANGULAR_UNSAFE, "text/html")
    assert sc.added
    assert any(f.data["severity"] == "high" for f in sc.added), [
        (f.data["severity"], f.data["detail"][:60]) for f in sc.added]
    assert all("no page context" not in f.data["detail"] for f in sc.added)


def test_no_finding_loses_its_evidence_class():
    """Every added finding must carry an evidence tier the report can print;
    the demotion path must not drop it (Phase 198's polyglot metadata bug)."""
    sc = _fake_scanner()
    client_layers._scan_framework(sc, BUNDLE_URL, ANGULAR_UNSAFE, JS_CT)
    assert sc.added and all(f.data.get("evidence_class") for f in sc.added), \
        [f.data for f in sc.added]


# --------------------------------------------------------------------------
# the dispatch contract (both engines reach these layers only through here)
# --------------------------------------------------------------------------

def _page_layer_dispatch_calls():
    """(layer-name, function-name, positional-arg-count, keyword-names) for
    every ``run_layer`` call inside ``run_page_layers``."""
    src = inspect.getsource(advanced_layers.run_page_layers)
    tree = ast.parse(src)
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        # the dispatch spells it ``layer_guard.run_layer(...)``
        func = node.func
        name = (func.attr if isinstance(func, ast.Attribute)
                else getattr(func, "id", ""))
        if name != "run_layer" or len(node.args) < 3:
            continue
        # run_layer(scanner, "name", fn, *args, **kwargs)
        layer = node.args[1]
        fn = node.args[2]
        if not isinstance(layer, ast.Constant) or not isinstance(fn, ast.Name):
            continue
        out.append((layer.value, fn.id, len(node.args) - 3,
                    {kw.arg for kw in node.keywords if kw.arg}))
    return out


def test_every_page_layer_accepts_what_the_dispatch_passes():
    """A layer whose signature drifted from its call site dies inside
    ``layer_guard`` at DEBUG level -- the loop keeps going and the scan keeps
    reporting, which is how three separate async gaps stayed invisible."""
    calls = _page_layer_dispatch_calls()
    assert calls, "no run_layer() calls parsed -- this test guards nothing"
    offenders = []
    for layer_name, fn_name, npos, kwnames in calls:
        fn = getattr(advanced_layers, fn_name, None)
        if fn is None:
            offenders.append(f"{layer_name}: {fn_name} is not exported")
            continue
        try:
            inspect.signature(fn).bind(*([object()] * npos),
                                       **{k: object() for k in kwnames})
        except TypeError as e:
            offenders.append(f"{layer_name} ({fn_name}) takes "
                             f"{inspect.signature(fn)} but the dispatch "
                             f"passes {npos} positional + {sorted(kwnames)}: {e}")
    assert not offenders, "\n".join(offenders)


def test_the_content_type_reaches_both_demoted_layers():
    """The whole fix is one argument; if the dispatch stops passing it, the
    bundle findings come back at high.  Checked on the parsed call sites, not
    on a re-computed copy of them."""
    calls = {name: (npos, kwnames)
             for name, fn_name, npos, kwnames in _page_layer_dispatch_calls()}
    for layer_name in ("framework", "trusted_types"):
        npos, _kw = calls[layer_name]
        assert npos >= 4, (
            f"{layer_name} is dispatched with only {npos} argument(s) after "
            "the function -- the media type no longer reaches it")


class _FakeResponse:
    def __init__(self, headers: dict, text: str):
        self._h = headers
        self.text = text

    @property
    def headers(self):
        return self._h


class _FakeReq:
    """One canned response for every GET, so the dispatch path runs without
    a socket.  Header case comes from the caller on purpose."""

    def __init__(self, headers: dict, text: str):
        self._resp = _FakeResponse(headers, text)
        self.calls = 0

    def get(self, url, *a, **k):
        self.calls += 1
        return self._resp

    def request(self, *a, **k):      # a few layers go through this instead
        self.calls += 1
        return self._resp


def test_dispatch_extracts_the_media_type_whatever_case_the_header_uses():
    """End to end through ``run_page_layers`` -- not a direct layer call.

    The dispatch copies ``resp.headers`` into a plain dict, so a
    case-sensitive ``.get("Content-Type")`` loses the information as soon as
    a proxy rewrites the header (``CONTENT-TYPE``).

    The URL deliberately has **no ``.js`` extension**: a bundle served off a
    path-less route (a build asset, ``/api/render``, a CDN-prefixed URL with a
    query-string name) is the shape where losing the header means losing the
    document kind outright.  On ``/main.js`` the suffix fallback quietly covers
    for the bug -- a test there would pass either way, which is the guard-shape
    mistake this project has recorded four times ("声称防 A,实际测 B").
    """
    pathless = "http://127.0.0.1:18900/assets/dynamic-bundle"
    body = ANGULAR_UNSAFE + NO_POLICY_ONLY
    for hdr_name in ("Content-Type", "CONTENT-TYPE", "content-type"):
        sc = _fake_scanner()
        req = _FakeReq({hdr_name: JS_CT}, body)
        advanced_layers.run_page_layers(sc, req, pathless, body)
        fw = [f for f in sc.added
              if str(f.data.get("type", "")).startswith("framework_")]
        assert fw, (hdr_name, [f.data.get("type") for f in sc.added])
        assert all(f.data["severity"] == "low" for f in fw), (
            hdr_name, [(f.data["severity"], f.data["detail"][:60])
                       for f in fw])
        # the body DOES contain a TT sink with no policy, so on a page this
        # would be reported -- here it must not be
        assert not [f for f in sc.added
                    if f.data.get("type") == "trusted_types_no_policy"], (
            hdr_name, [f.data.get("type") for f in sc.added])
