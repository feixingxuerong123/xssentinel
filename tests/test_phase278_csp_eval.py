# -*- coding: utf-8 -*-
"""Phase 278: ``'unsafe-eval'`` is not an inline bypass.

XSSMaze's CSP control pages exposed a claim the analyzer could not support.
``csp-bypass-level3`` and ``cspbypass-level3`` serve

    default-src 'self'; script-src 'unsafe-eval'

i.e. scripts are restricted to same-origin *and* inline is blocked.  The old
analyzer appended a ``type="eval"`` bypass with the payload
``eval('alert(1)')`` and set ``bypassable=True``, so both engines emitted a
``csp_bypass`` finding -- and the higher layers, reading "CSP is bypassable",
kept their own conclusions alive.  The finding was wrong in a way that reads
plausible: ``'unsafe-eval'`` really does allow ``eval()``.

But ``eval()`` is only reachable *from a script that already executes*.  On an
eval-only policy the only scripts that execute are same-origin ones; an
attacker's reflected ``<script>`` never runs, and no ``on*`` handler runs
either.  A header, read statically, cannot show that one of *our* reflected
payloads lands inside an executing script -- that would be a different finding
(script-injection into an existing script body), not a CSP bypass.  So the
entry was an assertion the analyzer had no evidence for.

Phase 278 removes the bypass entry and keeps an honest weak note saying what
``'unsafe-eval'`` does and does not authorise.  A policy whose only weakness is
``'unsafe-eval'`` therefore reports ``bypassable=False`` / ``bypasses == []``,
and both emitters early-return without a finding.

This file pins three things, in the project's usual order -- measured values
first, then the not-too-wide direction, then the emitters:

1. the two XSSMaze headers produce no bypass at all, in every script family;
2. removing that entry did **not** silence the paths that are real
   (``'unsafe-inline'``, gadget hosts, wildcards, ``script-src-attr``);
3. both engines stay silent on the control headers and still emit on
   ``'unsafe-inline'`` -- one behavior, two call sites.
"""

from __future__ import annotations

import asyncio
import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import csp                                       # noqa: E402
from xssentinel.core.async_scanner_layers import (                      # noqa: E402
    AsyncDetectionLayersMixin)
from xssentinel.core.scanner_layers import AdvancedLayerMixin            # noqa: E402

# The two observed XSSMaze control headers.  Kept verbatim: the first has no
# ``'self'`` on script-src, the second does.  Both mean "same-origin scripts
# plus eval", and both used to report a bypass.
XSSMAZE_EVAL_ONLY = [
    "default-src 'self'; script-src 'unsafe-eval'",
    "default-src 'self'; script-src 'self' 'unsafe-eval'",
]

INLINE_OK = "default-src 'self'; script-src 'unsafe-inline'"
ATTR_ONLY = "script-src 'unsafe-eval'; script-src-attr 'unsafe-inline'"
GADGET_HOST = ("default-src 'self'; script-src 'self' "
               "https://ajax.googleapis.com/ajax/libs/prototype/1.7.3.0/"
               "prototype.js")


# ---------------------------------------------------------------------------
# 1. the control headers carry no bypass at all
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("header", XSSMAZE_EVAL_ONLY)
def test_eval_only_policy_is_not_bypassable(header):
    """The core claim of Phase 278: nothing to bypass, so nothing to report."""
    rep = csp.analyze(header)
    assert rep.directives, header
    assert rep.bypassable is False, (header, rep.bypasses)
    assert rep.bypasses == [], (header, rep.bypasses)
    assert csp.best_bypass(header) is None, header


@pytest.mark.parametrize("header", XSSMAZE_EVAL_ONLY)
def test_eval_only_policy_blocks_inline_in_every_family(header):
    """``is_strict_inline`` must agree with ``bypassable``.

    Both read the same analysis, so a future edit that re-adds an entry would
    show up here as "strict inline says True while bypasses is non-empty" --
    the contradictory state the old code was in.
    """
    assert csp.is_strict_inline(header) is True, header
    for family in ("elem", "attr", "uri"):
        assert csp.inline_blocked(header, family) is True, (header, family)


@pytest.mark.parametrize("header", XSSMAZE_EVAL_ONLY)
def test_eval_note_is_still_surfaced(header):
    """Removing the finding must not remove the observation.

    An auditor still wants to know the policy carries ``'unsafe-eval'``; the
    note just has to describe what that actually buys.
    """
    rep = csp.analyze(header)
    note = [w for w in rep.weak if "unsafe-eval" in w]
    assert note, rep.weak
    joined = " ".join(note).lower()
    assert "inline" in joined       # says what it does NOT authorise
    assert "eval(" in joined        # says what it does authorise


@pytest.mark.parametrize("header", XSSMAZE_EVAL_ONLY + [INLINE_OK, ATTR_ONLY])
def test_no_bypass_entry_is_typed_eval(header):
    """No path may resurrect an ``eval`` bypass type.

    This is deliberately broader than the two control headers: if any other
    branch starts producing ``type="eval"``, ``best_bypass``'s preference list
    no longer names it and the payload would silently reach a finding anyway.
    """
    rep = csp.analyze(header)
    assert [b["type"] for b in rep.bypasses if b["type"] == "eval"] == [], \
        (header, rep.bypasses)
    for b in rep.bypasses:
        assert "eval(" not in b.get("payload", ""), (header, b)


# ---------------------------------------------------------------------------
# 2. the real paths are untouched -- this fix is not a general mute
# ---------------------------------------------------------------------------
def test_unsafe_inline_still_yields_the_inline_bypass():
    rep = csp.analyze(INLINE_OK)
    assert rep.bypassable is True
    best = csp.best_bypass(INLINE_OK)
    assert best is not None and best["type"] == "inline", best
    assert "<script" in best["payload"], best
    assert csp.is_strict_inline(INLINE_OK) is False


def test_gadget_host_still_yields_a_script_gadget_bypass():
    best = csp.best_bypass(GADGET_HOST)
    assert best is not None and best["type"] == "script_gadget", best
    assert csp.analyze(GADGET_HOST).bypassable is True


def test_wildcard_source_is_still_bypassable():
    header = "default-src 'self'; script-src *.example.com"
    rep = csp.analyze(header)
    assert rep.bypassable is True, rep.bypasses
    assert [b["type"] for b in rep.bypasses] == ["wildcard"], rep.bypasses


def test_unsafe_inline_and_unsafe_eval_count_once():
    """The eval keyword must not inflate the bypass count.

    Both engine reports summarise ``report.weak``; a duplicate entry would
    read as "two independent weaknesses" when the policy has one.
    """
    header = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'"
    rep = csp.analyze(header)
    assert [b["type"] for b in rep.bypasses] == ["inline"], rep.bypasses
    assert csp.best_bypass(header)["type"] == "inline"


def test_attr_family_unsafe_inline_is_still_a_bypass_beside_unsafe_eval():
    """Family granularity: eval on ``script-src`` must not mask attr inline.

    ``script-src-attr 'unsafe-inline'`` permits handler attributes even though
    ``<script>`` elements are blocked; the finding has to survive, or the fix
    would have widened eval-only silence into attr silence.
    """
    rep = csp.analyze(ATTR_ONLY)
    assert [b["type"] for b in rep.bypasses] == ["inline"], rep.bypasses
    assert "on*" in rep.bypasses[0]["reason"], rep.bypasses
    assert csp.inline_blocked(ATTR_ONLY, "elem") is True
    assert csp.inline_blocked(ATTR_ONLY, "attr") is False
    assert csp.is_strict_inline(ATTR_ONLY) is False


def test_policies_without_a_script_restriction_are_not_called_bypassable():
    """Three shapes measured by the probe that are NOT bypasses.

    They are here as generalization guards, not as Phase 278 evidence: the
    ``bypassable`` flag must stay tied to a concrete payload, otherwise the
    emitters report a mechanism they cannot name.
    """
    assert csp.analyze("").bypassable is False
    assert csp.analyze("script-src *").bypassable is False
    assert csp.analyze(
        "script-src 'self' https://cdn.unregistered.example/x.js"
    ).bypassable is False


# ---------------------------------------------------------------------------
# 3. both emitters: silent on the control, loud on the real bypass
# ---------------------------------------------------------------------------
class _Hdrs(dict):
    def get(self, key, default=None):
        return super().get(key, default) or super().get(key.lower(), default)


class _Resp:
    def __init__(self, headers, text=""):
        self.headers = _Hdrs(headers)
        self.text = text


class _Req:
    def __init__(self, resp):
        self._resp = resp

    def get(self, url):                          # noqa: ARG002
        return self._resp


class _Cov:
    def __init__(self):
        self.layers, self.findings = [], []

    def touch_layer(self, url, layer, method, detail=None):  # noqa: ARG002
        self.layers.append(layer)

    def record_finding(self, url, method):
        self.findings.append((url, method))

    def record_request(self, url, method):       # noqa: ARG002
        pass


class _Scanner:
    """Enough surface for ``AdvancedLayerMixin._scan_csp``."""

    def __init__(self, headers, text=""):
        self.coverage = _Cov()
        self.findings = []
        self.verbose = False
        self._lock = threading.RLock()
        self._resp = _Resp(headers, text)

    def _bump(self):
        pass


def _sync_csp_findings(headers, text=""):
    sc = _Scanner(headers, text)
    AdvancedLayerMixin._scan_csp(sc, _Req(sc._resp), "http://t/x")
    return [f.data if hasattr(f, "data") else f for f in sc.findings]


class _AsyncLayerStub(AsyncDetectionLayersMixin):
    """Enough surface for ``AsyncDetectionLayersMixin._scan_csp_async``.

    The bare ``object()`` this helper used to pass stopped working when
    Phase 290 added the ``self._touch_coverage`` call at the layer's
    entry: a plain ``object`` does not even have the mixin method.  The
    mixin's own docstring defines the contract -- the wrapper tolerates
    scanners without a ``coverage`` -- so inheriting the mixin (and
    providing the one other attribute the layer reads) is the whole job.
    """

    verbose = False


def _async_csp_findings(headers, text=""):
    async def run():
        out = []
        agen = AsyncDetectionLayersMixin._scan_csp_async(
            _AsyncLayerStub(), "http://t/x", headers, text)
        async for f in agen:
            out.append(f.data if hasattr(f, "data") else f)
        return out

    return asyncio.run(run())


@pytest.mark.parametrize("header", XSSMAZE_EVAL_ONLY)
def test_sync_emitter_is_silent_on_eval_only(header):
    assert _sync_csp_findings({"Content-Security-Policy": header}) == []


@pytest.mark.parametrize("header", XSSMAZE_EVAL_ONLY)
def test_async_emitter_is_silent_on_eval_only(header):
    assert _async_csp_findings({"Content-Security-Policy": header}) == []


def test_sync_emitter_still_reports_unsafe_inline():
    got = _sync_csp_findings({"Content-Security-Policy": INLINE_OK})
    assert [f["type"] for f in got] == ["csp_bypass"], got
    assert got[0]["bypass_type"] == "inline", got[0]
    assert got[0]["severity"] == "medium", got[0]


def test_async_emitter_still_reports_unsafe_inline():
    got = _async_csp_findings({"Content-Security-Policy": INLINE_OK})
    assert [f["type"] for f in got] == ["csp_bypass"], got
    assert got[0]["bypass_type"] == "inline", got[0]
    assert got[0]["severity"] == "medium", got[0]


def test_both_engines_agree_on_the_control_header():
    """The parity contract for this layer: identical verdict, both sides.

    ``test_engine_parity_gate`` covers the matrix endpoints; this is the
    narrower statement that the two CSP emitters read the same analysis.
    """
    headers = {"Content-Security-Policy": XSSMAZE_EVAL_ONLY[1]}
    assert _sync_csp_findings(headers) == _async_csp_findings(headers) == []
