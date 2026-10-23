# -*- coding: utf-8 -*-
"""Per-layer async variants: pre-encoded, DOM, advanced page / param / request
layers, CSP, CORS, XS-Leaks, upload, JSONP, and blind/OOB collection.

Phase 191: pure movement out of ``async_scanner.py``.  No method body
was edited here -- ``dev/_p191_baseline.py after`` hashes every method's
source and compares it against the pre-split snapshot.
"""
from __future__ import annotations
import asyncio
import secrets
from typing import AsyncIterator
from urllib.parse import urlencode
from .scanner import Finding, json_leaf_paths
from .findings import (EVIDENCE_MODEL,
                       EVIDENCE_NO_BROWSER, EVIDENCE_OOB, dom_dynamic_finding)
from .requester import CountingRequester
from . import payloads as payloads_mod
from . import reflection_profile as rp_mod   # Phase 37: reflection-profile parity
from . import generator as gen_mod            # Phase 37: generative payload parity
from . import bypass as bypass_mod            # Phase 29-2: WAF bypass chains
from . import verifier
from . import pre_encode as pre_mod
from . import cors_check as cors_mod   # Phase 54: sync CORS audit parity
from . import dom_engine as dom_engine_mod  # Phase 65: DOM-dynamic parity
from . import xs_leaks as xsleak_mod   # Phase 54: sync XS-Leaks audit parity
from . import polyglot as poly_mod        # Phase 91/208: polyglot probe + grading
from . import transform as transform_mod  # Phase 166: concat-stamp retry
from .budget import BudgetExhausted, CircuitOpen
from .stealth import (marker as _stem_marker)
from .async_scanner_common import (
    _AsyncScannerShim, _JSONP_CALLBACK_NAMES, _body_kwargs, _content_type,
    _log, _non_html_grade, _polyglot_grade, _read_text,
)


class AsyncDetectionLayersMixin:
    """The async engine's per-layer detection methods.

    Mixed into ``AsyncScanner``; every method below is verbatim from the
    pre-split file.
    """

    def _touch_coverage(self, url, layer_id, method="GET", detail=""):
        """Phase 290: coverage touch that tolerates __new__-built scanners.

        Several tests construct AsyncScanner via ``__new__`` (no __init__)
        and drive a single layer; they have no tracker, and a bare
        ``self.coverage.touch_layer`` raised AttributeError inside the
        layer (measured: 3 async tests failed).  Same getattr discipline
        the rest of the code uses for those test doubles.
        """
        cov = getattr(self, "coverage", None)
        if cov is not None:
            cov.touch_layer(url, layer_id, method, detail)

    def _drop_skip_params(self, params, data):
        """Phase 185: strip operator --skip-param names from a request pair.

        Async parity of the sync ``_skip_filtered``.  Phase 184 filtered the
        iteration list only, so every request the async engine sent still
        carried the operator's skipped names.  Filters the raw dicts -- never
        an encoded URL, which would rewrite ``<`` as ``%3C`` and neuter
        payloads.  Returns the same objects when no skip set is configured,
        so the no-flag path allocates nothing extra.
        """
        skip = getattr(self, "skip_params", None) or set()
        if not skip:
            return params, data
        if params:
            params = {k: v for k, v in params.items()
                      if str(k).lower() not in skip}
        if data:
            data = {k: v for k, v in data.items()
                    if str(k).lower() not in skip}
        return params, data

    async def _try_pre_encoded_async(self, session, url, method, param,
                                     params, data, is_body, orig_value,
                                     struct, context, marker
                                     ) -> AsyncIterator[Finding]:
        """Phase 35: container-encoded probes (base64/JWT/JSON), parity
        with the sync scanner's _try_pre_encoded (Phase 34).  The base
        payload is token-marked first, then re-wrapped into the container
        the original value used; no transform chains -- the container
        encoding IS the transformation."""
        for base in pre_mod.PRE_ENCODE_BASES:
            marked = verifier.mark(base, marker)
            enc = await asyncio.to_thread(
                pre_mod.encode_payload, orig_value, struct, marked)
            if not enc:
                continue
            send_params, send_data = self._probe_kv(
                params, data, param, enc, is_body)
            try:
                async with self._semaphore:
                    await self._throttle(url)
                    async with session.request(
                        method, url, params=send_params or None,
                        headers=self._req_headers(self.headers), proxy=self._next_proxy(),
                        **_body_kwargs(send_data),
                    ) as resp:
                        text = await _read_text(resp)
                        resp_headers = dict(getattr(resp, "headers", None) or {})  # CSP gate parity
                        self.requests_made += 1
                        self._record_status(getattr(resp, "status", 200))
            except (BudgetExhausted, CircuitOpen):
                raise            # Phase 86: stop instead of "next base"
            except Exception:
                continue
            v = await asyncio.to_thread(verifier.verify_semantic,
                                        text, marker,
                                        response_headers=resp_headers)
            # Phase 178c: NO payload_survived here (sync parity -- sync's
            # _try_pre_encoded never had one).  The container-wrapped form
            # can never appear verbatim in a decode-echo response, and
            # _survival_candidates cannot see inside a JWT's middle
            # segment, so this check silently killed EVERY jwt container
            # confirmation (Range3 measured: encode fires, verify
            # confirms, gate rejects, 0 findings).  Filter rewrites are
            # still caught: the sandbox inside verify_semantic calls a
            # mangled script inert.
            if v["confirmed"]:
                idx = text.find(marker)
                yield Finding(
                    url=url, method=method, param=param,
                    # Phase 302: `context` stays the CLASSIFIED
                    # reflection context (what sync reports); the
                    # verifier's own view goes to `sink_context`.
                    # They disagree on purpose: a payload that
                    # closes an attribute and lands in a script
                    # block has an attribute reflection context
                    # AND a script-block sink.
                    context=context,
                    sink_context=v.get("context"),
                    payload=enc,
                    severity=_non_html_grade(resp_headers)[0],
                    evidence=text[max(0, idx - 30):idx + len(marker) + 30],
                    type="reflected",
                    confidence=_non_html_grade(resp_headers)[1],
                    content_type=_content_type(resp_headers),
                    transform=[f"pre_encode:{struct}"],
                    param_in="body" if is_body else "query",
                    evidence_class=EVIDENCE_MODEL,
                )
                return

    async def _try_encoding_first_async(self, session, url, method, param,
                                        params, data, is_body, resp_headers
                                        ) -> AsyncIterator[Finding]:
        """Phase 306 sync parity: bounded encoded probes for decode-then-reflect.

        The plain marker is not reflected when the app decodes the parameter
        before echoing it, so no candidate carries the right encoding.  Same
        gate and budget as sync: GET query + HTML only, one canonical payload
        under three decode shapes -> at most 3 requests per parameter.
        Evidence goes through the same verifier chain.
        """
        if is_body:
            return
        ctype = (_content_type(resp_headers) or "").lower()
        if ctype and "text/html" not in ctype and "application/xhtml" not in ctype:
            return
        token = "xssv_" + secrets.token_hex(4)
        payload = "<script>alert(1)</script>"
        marked = verifier.mark(payload, token)
        if marked == payload:
            return
        for name in ("base64", "double_url_encode", "triple_url_encode"):
            try:
                variant = transform_mod.apply(name, marked)
            except Exception:
                continue
            send_params, send_data = self._probe_kv(
                params, data, param, variant, is_body)
            send_params, send_data = self._drop_skip_params(
                send_params, send_data)
            try:
                async with self._semaphore:
                    await self._throttle(url)
                    async with session.request(
                        method, url, params=send_params or None,
                        headers=self._req_headers(self.headers),
                        proxy=self._next_proxy(),
                        **_body_kwargs(send_data),
                    ) as resp:
                        text = await _read_text(resp)
                        hdrs = dict(getattr(resp, "headers", None) or {})
                        self.requests_made += 1
                        self._record_status(getattr(resp, "status", 200))
            except (BudgetExhausted, CircuitOpen):
                raise
            except Exception:
                continue
            v = await asyncio.to_thread(
                verifier.verify_semantic, text, token,
                response_headers=hdrs)
            if not v.get("confirmed"):
                continue
            idx = text.find(token)
            sev, conf = _non_html_grade(hdrs)
            self._touch_coverage(url, "L1_pre_encoded", method,
                                 detail=f"encoding-first:{name}")
            yield Finding(
                url=url, method=method, param=param,
                context=v.get("context") or "html_element",
                sink_context=v.get("context"),
                payload=variant,
                severity=sev,
                evidence=text[max(0, idx - 30):idx + len(token) + 30],
                type="reflected",
                confidence=conf,
                content_type=_content_type(hdrs),
                transform=[name],
                param_in="body" if is_body else "query",
                evidence_class=EVIDENCE_MODEL,
            )
            return

    def _resolve_dom_engine(self):
        """Phase 65: mirror the sync _resolve_dom_engine for L6 parity."""
        de = self.dom_engine
        if de == "static":
            return None
        if de == "auto" and not dom_engine_mod.DynamicDomAnalyzer.available():
            return None
        try:
            return dom_engine_mod.DynamicDomAnalyzer(
                auth_headers=self.auth_headers,
                auth_cookies=self.auth_cookies,
                auth_local_storage=self.auth_local_storage)
        except Exception:
            return None

    async def _scan_dom_async(self, url: str, page_text: str,
                              method: str = "GET",
                              params: dict | None = None,
                              redirect_landing: bool = False,
                              no_script_exec: bool = False
                              ) -> AsyncIterator[Finding]:
        """L3 static + L6 real-browser DOM layer -- sync _scan_dom parity.

        Phase 65 fixes two divergences from the sync layer: the static
        analysis was invoked with the URL as the ``is_html`` flag (an
        accidental truthy pass-through that broke for empty URLs), and the
        real-browser dynamic confirmation (dom_dynamic) never ran in async
        mode at all.

        Phase 176t adds the third one, and it is the kind that cannot be
        spotted from a finding count: the browser was navigated to ``url``,
        which in async does NOT contain the endpoint's query string (the
        engine keeps ``url`` and ``params`` apart -- see _scan_reflected).
        So ``location.search`` was empty at read time, and every DOM vector
        whose source is the query string was structurally unconfirmable --
        reported as a clean page, not as a degraded scan.  Sync already
        re-attaches params before this call (scanner.py:479-486); the guard
        below is copied from there, including the GET-only condition.
        """
        # Phase 290: coverage parity (the sync layer touches the
        # same id at its entry; without this the async report
        # listed the layer as never having run).
        self._touch_coverage(url, "L3_dom_static", method)
        self._touch_coverage(url, "L6_dom_dynamic", method)
        try:
            from . import dom as dom_mod
            if redirect_landing or no_script_exec:
                # Sync parity (scanner_layers._scan_dom): the page hints
                # describe a different resource when a redirect dropped the
                # injected parameters, and no JS-dependent hint is supportable
                # when the CSP blocks every script route.  Dynamic delivery
                # still runs below.
                static_results = []
                _why = ("redirect landing page dropped the injected parameters"
                        if redirect_landing else
                        "CSP blocks every script route on this page")
                _cov = getattr(self, "coverage", None)
                if _cov is not None:
                    _cov.record_layer(url, "L3_dom_static", method,
                                      status="skipped", detail=_why)
            else:
                static_results = await asyncio.to_thread(
                    dom_mod.analyze, page_text, is_html=True)
                # Sync parity: low static hints (no-source inventories,
                # URL-property loads) are not emitted as findings.
                static_results = [r for r in static_results
                                  if r.get("confidence") != "low"]
            engine = await asyncio.to_thread(self._resolve_dom_engine)
            dyn_findings: list = []
            # Phase 154 (sync parity, scanner_layers.py): page_has_client_js
            # alone lets pages with JS but no possible sink pay for a whole
            # browser session; page_can_run_sink keeps every external-script
            # page (SPA bundles) so this only skips provably dead passes.
            # Phase 159: that function is "is the page provably inert?", not
            # "did we recognise a sink" -- the whitelist version silently
            # disabled browser verification for unlisted sinks (srcdoc).
            # Keep both call sites identical: this is a sync/async parity pair.
            if engine is not None and await asyncio.to_thread(
                    lambda t: (dom_engine_mod.page_has_client_js(t)
                               and dom_engine_mod.page_can_run_sink(t)),
                    page_text):
                page_url = url
                if method == "GET" and params:
                    try:
                        qs = urlencode(params)
                        if qs:
                            page_url = url + ("&" if "?" in url
                                              else "?") + qs
                    except Exception:
                        pass
                dyn_findings = await asyncio.to_thread(engine.analyze,
                                                       page_url)

            dyn_sinks: set = set()
            for d in dyn_findings:
                s = (d.get("sink") or "").lower()
                dyn_sinks.add(s)
                dyn_sinks.add(s.split(".")[-1])

            def _suppressed(r) -> bool:
                hay = ((r.get("type") or "") + " " + (r.get("context") or "")
                       + " " + (r.get("detail") or "")).lower()
                if not hay:
                    return False
                return any(s and s in hay for s in dyn_sinks)

            for r in static_results:
                if _suppressed(r):
                    continue  # confirmed dynamically; dynamic finding covers it
                yield Finding(
                    url=url, method="GET", param=None,
                    context=r.get("type"),
                    payload=r.get("snippet", ""),
                    severity="medium" if r.get("confidence") == "medium"
                    else "low",
                    confidence=r.get("confidence", "low"),
                    detail=r.get("detail", ""),
                    type="dom",
                    evidence_class=EVIDENCE_NO_BROWSER,
                )
            for d in dyn_findings:
                # Phase 265: same class chooser as sync's _scan_dom
                # (findings.dom_dynamic_finding).  Execution observed ->
                # dom_dynamic/high; delivery only -> dom_sink_reachability/low
                # with no proof.  Keeping the old high/proof shape here would
                # re-create the range6 false positive and the sync/async
                # parity split.
                _emit = dom_dynamic_finding(d)
                yield Finding(
                    url=url, method="GET",
                    # Phase 213: delivered key (``q`` / ``q@hash`` /
                    # ``__xss__``), None when the probe had no key position.
                    param=d.get("param"),
                    context=d.get("sink"),
                    payload=d.get("snippet", ""),
                    severity=_emit["severity"],
                    confidence=_emit["confidence"],
                    detail=_emit["detail"],
                    type=_emit["type"],
                    headless=_emit["headless"],
                    proof=_emit["proof"],
                    evidence_class=_emit["evidence_class"],
                )
        except Exception as e:
            _log.warning("async DOM layer error: %s", e, exc_info=self.verbose)

    async def _scan_advanced_page(self, url: str, page_text: str,
                                  params: dict | None = None
                                  ) -> AsyncIterator[Finding]:
        """L5 advanced page-level layers (postMessage / prototype / SW / etc).

        Delegates to the sync ``advanced_layers.run_page_layers`` in a
        thread, then streams any findings produced.

        Phase 87: forward the endpoint params -- import map / CSSI /
        dangling markup sub-layers use them to detect user-controlled
        reflection; the old call left them at None (sync parity:
        scanner.py passes ``params=params``).

        Phase 176s: pass a REAL requester instead of ``None``.  Several page
        layers need a follow-up GET -- most visibly cookie tossing, which
        reads the ``Set-Cookie`` response headers (``layers/content_layers.py``
        does ``req.get(url)`` then ``resp.raw.headers.getlist``).  With
        ``req=None`` that call raised AttributeError, the layer's own
        ``except Exception: pass`` swallowed it, and the layer went on with
        an empty header list -- so it could never report the one thing it
        exists to report.  The shim's old comment called this "degrades
        gracefully"; it degrades *silently*, which is how the gap survived
        until a benchmark case (pos-ctoss-01) measured it.
        """
        try:
            from . import advanced_layers
            # Create a lightweight sync scanner shim to collect findings.
            shim = _AsyncScannerShim(self)
            # CountingRequester, not the bare requester: some sub-layers bump
            # the scanner themselves and some do not, and either way the
            # traffic has to land in the scan's request accounting instead of
            # sailing past it (Phase 142).
            shim.req = CountingRequester(self._get_sync_requester(),
                                         shim._bump)
            await asyncio.to_thread(
                advanced_layers.run_page_layers, shim, shim.req, url,
                page_text, params=params)
            self.requests_made += shim.requests_made
            for f in shim._findings:
                yield f
        except Exception as e:
            _log.warning("async advanced page layers error: %s", e, exc_info=self.verbose)

    async def _scan_time_based(self, url: str, method: str, params: dict,
                               data: dict, param: str, is_body: bool
                               ) -> AsyncIterator[Finding]:
        """Phase 176s: time-based (OOB resource-fetch) fallback.

        Sync reaches this at the end of ``_scan_param`` (scanner.py:1122):
        the marker reflected, every standard payload failed to confirm, so a
        strict CSP is the prime suspect.  ``<style>@import</style>`` /
        ``<img src>`` / onerror-fetch payloads make the browser fetch a
        resource whether or not inline script is allowed, and the OOB
        listener turns that fetch into proof of execution.

        Async never had this step at all.  It matters precisely because it
        is the ONLY thing that fires on a CSP-locked endpoint -- without it
        those are silent false negatives, not degraded detections.
        """
        shim = None
        try:
            from . import time_xss as tx_mod
            shim = _AsyncScannerShim(self)
            # Same requester wiring as the other thread-offloaded sync
            # layers: a real one, wrapped so its traffic is counted.
            shim.req = CountingRequester(self._get_sync_requester(),
                                         shim._bump)
            await asyncio.to_thread(
                tx_mod.scan_time_based, shim, shim.req, url, method,
                params, data, param, is_body)
            self.requests_made += shim.requests_made
            for f in shim._findings:
                yield f
        except (BudgetExhausted, CircuitOpen):
            raise        # a budget stop is not a layer bug
        except Exception as e:
            # Same failed-row rule as _scan_request_layers above: silence
            # here reads as "this param had no CSP fallback", not "it died".
            if shim is not None:
                shim.coverage.record_layer(
                    url, "L7_time_based", status="failed",
                    detail=f"{type(e).__name__}: {str(e)[:140]}")
            _log.warning("async time-based fallback error: %s", e,
                         exc_info=self.verbose)

    async def _scan_request_layers(self, url: str, method: str,
                                   params: dict, data: dict
                                   ) -> AsyncIterator[Finding]:
        """L8 request-injection layers (header / path / cookie / error XSS).

        Phase 87: async mode never called
        ``advanced_layers.run_request_layers``, so four whole XSS carrier
        classes (User-Agent/Referer/XFF header injection, URL path segment
        XSS, cookie value XSS, error page XSS) were never tested in
        --async scans -- an entire layer of missed findings.  Mirror the
        sync scan_endpoint wiring: run the sync layer in a thread against
        a real sync Requester (the transport layers issue blocking
        ``requests`` calls), then stream the shim's findings.

        Budget/circuit semantics (Phase 86): a BudgetExhausted /
        CircuitOpen raised inside the thread is a deliberate scan stop,
        not a layer bug -- it propagates (through _drain_agen) like every
        other layer instead of being swallowed.
        """
        shim = None
        try:
            from . import advanced_layers
            shim = _AsyncScannerShim(self)
            req = self._get_sync_requester()
            await asyncio.to_thread(
                advanced_layers.run_request_layers,
                shim, req, url, method, params, data)
            # Coverage visibility: the shim's NullCoverage only records in
            # memory, but tests/debugging inspect shim.coverage.touched to
            # prove the L8 request layers ran -- which is exactly why the
            # touch happens AFTER the call now.  Recorded before it, an
            # entry-time failure still left "L8_request: touched" behind, so
            # the introspection that exists to catch a silently dead layer was
            # itself fooled by one.  (sync: scanner.py L7_time_based, same
            # fix, same reason.)
            shim.coverage.touch_layer(url, "L8_request", method,
                                      "async request-injection layers")
            for f in shim._findings:
                yield f
        except (BudgetExhausted, CircuitOpen):
            raise        # Phase 86: a budget/circuit stop is NOT a layer bug
        except Exception as e:
            # Phase 176u: a swallowed failure must leave a failed row, not
            # silence -- "no row" reads as "this endpoint had no such layer",
            # which is exactly how a dead layer stayed invisible.  shim is
            # None precisely when the failure was on entry (bad import /
            # constructor), which is the case this row exists to reveal.
            if shim is not None:
                shim.coverage.record_layer(
                    url, "L8_request", status="failed",
                    detail=f"{type(e).__name__}: {str(e)[:140]}")
            _log.warning("async request layers error: %s", e,
                         exc_info=self.verbose)

    async def _scan_advanced_param_layers(self, url: str, method: str,
                                          params: dict, data: dict,
                                          param: str, is_body: bool,
                                          marker: str,
                                          resp_text: str,
                                          param_confirmed: bool = False
                                          ) -> AsyncIterator[Finding]:
        """L7 parameter layers (mutation / DOM clobber / template /
        polyglot / markdown).

        Phase 132: ``--async`` never ran these.  ``_probe_param`` did the
        payload loop, the position shift and the CSP-nonce exploit, then
        stopped -- so five whole detection families (mutation XSS, DOM
        clobbering, client-side template injection, polyglot, and the
        markdown/BBCode markup layers) were reported by sync and silently
        missed by async.

        These sub-layers issue blocking ``requests`` calls, so this mirrors
        ``_scan_request_layers``: a real sync Requester plus the
        ``AdvancedLayerMixin``-backed shim, run in a worker thread, with
        the shim's findings streamed back.

        Unlike the payload loop this is a *step* the sync engine always
        takes once the marker reflected -- even when the reflection is
        HTML-escaped.  It is deliberately NOT gated on ``marker_escaped``
        so the two engines stay in step (see scanner.py ``_scan_param``,
        which reaches ``_run_advanced_layers`` unconditionally).
        """
        shim = _AsyncScannerShim(self)
        try:
            req = self._get_sync_requester()
            shim.req = req
            # Phase 198: the shim's findings accumulator starts EMPTY and
            # the async engine does not accumulate main-loop verdicts at
            # all (findings are yielded straight to the consumer) -- so
            # the shared ``_run_advanced_layers`` fallback guard ("the
            # polyglot layer only runs when no other finding was confirmed
            # for this (url, param)") always saw an empty list here and
            # the fallback fired on async while sync correctly skipped it
            # (first catch of the OPTIMIZATION 2.1 parity gate).  Seed the
            # view instead: the parent's own findings for this (url,
            # param), plus -- because async yields verdicts without ever
            # storing them -- a sentinel Finding when the main loop
            # reported param_confirmed.  The sentinel exists ONLY for the
            # guard; the yield below skips every seeded entry.
            _seed = [f for f in (self.findings or [])
                     if (f.data.get("url") == url
                         and f.data.get("param") == param)]
            if param_confirmed and not _seed:
                # guard-only sentinel: it satisfies the shared fallback
                # check and is never yielded (the seed slice is skipped).
                # evidence_class is stated because the evidence-coverage
                # gate audits every Finding() site, and "main loop
                # confirmed via the semantic model" is exactly what it
                # represents.
                _seed = [Finding(url=url, method=method, param=param,
                                 type="reflected",
                                 evidence_class=EVIDENCE_MODEL)]
            shim.findings.extend(_seed)
            await asyncio.to_thread(
                shim._run_advanced_layers,
                req, url, method, params, data, param, is_body, marker,
                resp_text)
            # The sub-layers bump the shim's own counter; fold it in so the
            # scan's request accounting stays honest.
            self.requests_made += shim.requests_made
            for f in shim._findings[len(_seed):]:
                yield f
        except (BudgetExhausted, CircuitOpen):
            raise        # a budget/circuit stop is NOT a layer bug
        except Exception as e:
            _log.warning("async advanced param layers error: %s", e,
                         exc_info=self.verbose)

    async def _scan_csp_async(self, url: str, resp_headers: dict,
                              html: str = "",
                              method: str = "GET"
                              ) -> AsyncIterator[Finding]:
        """L6 CSP analysis (runs in thread) -- sync _scan_csp parity.

        Phase 196: `html` carries the page body because a policy can also
        arrive as `<meta http-equiv="Content-Security-Policy">`, which
        Chromium enforces exactly like the header (measured, 196b).  Report-
        Only is not consulted: it blocks nothing, so "bypassable CSP" would
        describe a protection that is not in force.  Sync reached this state
        first; the two engines now resolve policies through the same
        `csp.policies()` call rather than each reading a different header set.

        Phase 62: the previous version treated the CSPReport OBJECT returned
        by csp_mod.analyze as a dict (results.get('bypassable')), so every
        async scan logged a TypeError and async mode NEVER reported a
        bypassable CSP.  Mirror the sync layer: read report.bypassable /
        report.weak and emit the same medium csp_bypass finding.
        """
        # Phase 290: coverage parity (the sync layer touches the
        # same id at its entry; without this the async report
        # listed the layer as never having run).
        self._touch_coverage(url, "L7_csp", method)
        try:
            from . import csp as csp_mod
            # Same policy resolution as sync `_scan_csp`: the browser acts on
            # the response header AND a `<meta http-equiv=...>`, while
            # Report-Only enforces nothing and is therefore not a protection
            # we can claim to bypass.
            policy = ""
            for candidate in csp_mod.policies(resp_headers, html)["enforcing"]:
                policy = candidate
                break
            if not policy:
                return
            # Run CSP analysis in a thread.
            report = await asyncio.to_thread(csp_mod.analyze, policy)
            if not report.bypassable:
                return
            best = await asyncio.to_thread(csp_mod.best_bypass, policy) or {}
            yield Finding(
                url=url, method="GET", param="(header)",
                context="csp_header",
                payload=best.get("payload", ""),
                severity="medium",
                evidence="; ".join(report.weak),
                type="csp_bypass",
                confidence="medium",
                csp_header=policy,
                bypass_type=best.get("type", ""),
                bypass_reason=best.get("reason", ""),
                evidence_class=EVIDENCE_NO_BROWSER,
            )
        except Exception as e:
            _log.warning("async CSP layer error: %s", e, exc_info=self.verbose)

    async def _scan_cors_async(self, session, url: str, method: str
                               ) -> AsyncIterator[Finding]:
        """Phase 54: CORS origin-reflection audit -- sync _scan_cors parity.

        One finding per origin (dedup set on the scanner), two cheap probes
        (GET with the attacker Origin, then an OPTIONS preflight when the
        GET did not reflect).  Runs whenever advanced_layers is on, exactly
        like the sync L7 CORS layer.
        """
        # Phase 290: coverage parity (the sync layer touches the
        # same id at its entry; without this the async report
        # listed the layer as never having run).
        self._touch_coverage(url, "L7_cors", method)
        checked = getattr(self, "_cors_checked", None)
        if checked is None:
            checked = set()
            self._cors_checked = checked
        try:
            from urllib.parse import urlparse
            p = urlparse(url)
            origin = f"{p.scheme}://{p.netloc}"
        except Exception:
            return
        if not origin or origin in checked:
            return
        checked.add(origin)
        evil = cors_mod.EVIL_ORIGIN
        for probe_method, extra in cors_mod.PROBES:
            resp_headers = {}
            try:
                async with self._semaphore:
                    await self._throttle(url)
                    headers = self._req_headers(self.headers)
                    headers.update(extra)
                    async with session.request(
                        probe_method, url, params=None, headers=headers,
                        proxy=self._next_proxy(),
                    ) as resp:
                        await resp.read()          # drain (headers enough)
                        resp_headers = dict(resp.headers)
                        self.requests_made += 1
                        self._record_status(getattr(resp, "status", 200))
            except (BudgetExhausted, CircuitOpen):
                raise        # Phase 86: stop instead of "next probe"
            except Exception:
                continue
            acao = resp_headers.get("Access-Control-Allow-Origin") or ""
            acac = resp_headers.get("Access-Control-Allow-Credentials") or ""
            verdict = cors_mod.classify(acao, acac, evil)
            if verdict is None:
                continue
            sev, reason = verdict
            evidence = (f"probe: {probe_method} {url}\n"
                        f"Origin: {evil}\n"
                        f"-> Access-Control-Allow-Origin: {acao or '(absent)'}\n"
                        f"-> Access-Control-Allow-Credentials: "
                        f"{acac or '(absent)'}")
            yield Finding(
                url=url, method=probe_method, param="", payload=evil,
                context="cors_header", severity=sev,
                type="cors_misconfig", confidence="firm",
                evidence=evidence, detail=reason,
                evidence_class=EVIDENCE_NO_BROWSER,
            )
            return  # one finding per origin is enough

    async def _scan_xsleak_audit_async(self, url: str, resp_headers: dict,
                                       method: str = "GET"
                                       ) -> AsyncIterator[Finding]:
        """Phase 54: XS-Leaks surface audit -- sync _scan_xsleak_audit parity.

        Opt-in (self.xsleak_audit); reuses the baseline response headers
        already fetched by scan() (zero extra requests); one low
        xs_leak_surface finding per origin.
        """
        if not self.xsleak_audit:
            return
        # Phase 290: coverage parity (the sync layer touches the
        # same id at its entry; without this the async report
        # listed the layer as never having run).
        self._touch_coverage(url, "L7_xsleak", method)
        checked = getattr(self, "_xsleak_audited", None)
        if checked is None:
            checked = set()
            self._xsleak_audited = checked
        try:
            from urllib.parse import urlparse
            p = urlparse(url)
            origin = f"{p.scheme}://{p.netloc}"
        except Exception:
            return
        if not origin or origin in checked:
            return
        checked.add(origin)
        try:
            verdict = xsleak_mod.audit_mitigations(resp_headers or {})
        except Exception:
            return
        if verdict is None:
            return
        yield Finding(
            url=url, method="GET", param="", payload="",
            context=verdict.get("context", "response_headers"),
            severity=verdict.get("severity", "low"),
            type=verdict.get("type", "xs_leak_surface"),
            confidence=verdict.get("confidence", "firm"),
            evidence=verdict.get("evidence", ""),
            detail=verdict.get("detail", ""),
            evidence_class=EVIDENCE_NO_BROWSER,
        )

    async def _probe_upload_async(self, session, url: str, params: dict,
                                  data: dict) -> AsyncIterator[Finding]:
        """Phase 58: multipart upload-filename XSS probing -- sync
        upload_probe.probe_upload parity over aiohttp.

        Fires on POST scans when the operator named upload fields
        (upload_fields).  Weaponised filenames are uploaded for each field;
        an immediate filename echo in an executable context confirms
        upload_xss, otherwise a marker-bearing stored URL from the response
        is fetched once to confirm stored_upload.  Mirrors the sync logic
        candidate-for-candidate so the dual engines report the same.
        """
        from .upload_probe import _first_url_with, _name_candidates
        from urllib.parse import urljoin
        if not self.upload_fields:
            return
        # Phase 290: coverage parity (the sync layer touches the
        # same id at its entry; without this the async report
        # listed the layer as never having run).
        self._touch_coverage(
            url, "L9_upload_filename",
            getattr(self, "_upload_method", "POST"))
        for field in self.upload_fields:
            marker = f"{_stem_marker('xssup_')}{field}_{secrets.token_hex(2)}"
            for filename in _name_candidates(marker):
                text = ""
                resp_headers = {}
                try:
                    # Raw multipart body, NOT aiohttp.FormData: FormData
                    # percent-encodes the filename (%3Cimg...) and a server
                    # echoing the raw name then shows encoded markup that
                    # verify_semantic cannot confirm.  Mirror the sync
                    # requests wire instead: boundary is a bare token, the
                    # filename is verbatim except double quotes -> %22
                    # (urllib3 does the same), which is what the Phase-48
                    # sync probe sends.
                    boundary = secrets.token_hex(8)
                    safe_name = filename.replace('"', "%22")
                    body = (f"--{boundary}\r\n"
                            f'Content-Disposition: form-data; name="{field}"; '
                            f'filename="{safe_name}"\r\n'
                            "Content-Type: text/plain\r\n\r\n"
                            "xssentinel upload probe\r\n"
                            f"--{boundary}--\r\n").encode("utf-8")
                    hdrs = self._req_headers(self.headers)
                    hdrs["Content-Type"] = \
                        f"multipart/form-data; boundary={boundary}"
                    async with self._semaphore:
                        await self._throttle(url)
                        async with session.request(
                            getattr(self, "_upload_method", "POST"), url,
                            params=params or None, data=body,
                            headers=hdrs, proxy=self._next_proxy(),
                        ) as resp:
                            text = await _read_text(resp)
                            resp_headers = dict(resp.headers)
                            self.requests_made += 1
                            self._record_status(getattr(resp, "status", 200))
                except (BudgetExhausted, CircuitOpen):
                    raise        # Phase 86: stop instead of "next filename"
                except Exception:
                    continue
                if not text or marker not in text:
                    continue
                try:
                    v = await asyncio.to_thread(
                        verifier.verify_semantic, text, marker,
                        response_headers=resp_headers)
                except Exception:
                    v = {"confirmed": False}
                idx = text.find(marker)
                evidence = text[max(0, idx - 60):idx + len(marker) + 120] \
                    if idx >= 0 else ""
                if v.get("confirmed"):
                    yield Finding(
                        url=url, method="POST",
                        param=f"{field}[filename]",
                        type="upload_xss", context="multipart_filename",
                        payload=filename, severity="high", confidence="high",
                        detail=(v.get("detail") or "") +
                               " (filename echoed in upload response)",
                        evidence=evidence,
                        transform=["multipart_filename"],
                        evidence_class=EVIDENCE_MODEL,
                    )
                    return  # one confirmed filename echo is enough
                stored_url = _first_url_with(text, marker)
                if not stored_url:
                    continue
                target = urljoin(url, stored_url)
                try:
                    async with self._semaphore:
                        await self._throttle(target)
                        async with session.get(
                            target, headers=self._req_headers(self.headers),
                            proxy=self._next_proxy(),
                        ) as sresp:
                            stext = await _read_text(sresp)
                            s_headers = dict(sresp.headers)
                            self.requests_made += 1
                            self._record_status(getattr(sresp, "status", 200))
                except (BudgetExhausted, CircuitOpen):
                    raise        # Phase 86: stop instead of "next filename"
                except Exception:
                    continue
                if marker in stext:
                    try:
                        sv = await asyncio.to_thread(
                            verifier.verify_semantic, stext, marker,
                            response_headers=s_headers)
                    except Exception:
                        sv = {"confirmed": False}
                    if sv.get("confirmed"):
                        yield Finding(
                            url=target, method="GET",
                            param=f"{field}[filename]",
                            type="stored_upload", context="uploaded_file",
                            payload=filename, severity="high",
                            confidence="high",
                            detail=(sv.get("detail") or "") +
                                   f" (stored file {stored_url} served "
                                   "attacker markup)",
                            evidence=stext[max(0, stext.find(marker) - 60):
                                           stext.find(marker)
                                           + len(marker) + 120],
                            transform=["multipart_filename", "stored"],
                            evidence_class=EVIDENCE_MODEL,
                        )
                        return

            # Phase 90 (P2): filename vectors exhausted on this field --
            # probe weaponised file CONTENT (HTML/SVG whose handler fires
            # alert(marker)) served back at a stored URL.  Mirrors the
            # sync probe_upload_content one candidate at a time.
            from .upload_probe import _content_candidates as _cc
            cmarker = f"{_stem_marker('xssupc_')}{secrets.token_hex(2)}"
            for filename, content, mime in _cc(cmarker):
                text = ""
                resp_headers = {}
                try:
                    boundary = secrets.token_hex(8)
                    body = (f"--{boundary}\r\n"
                            f'Content-Disposition: form-data; name="{field}"; '
                            f'filename="{filename}"\r\n'
                            f"Content-Type: {mime}\r\n\r\n"
                            .encode("utf-8") + content +
                            f"\r\n--{boundary}--\r\n".encode("utf-8"))
                    hdrs = self._req_headers(self.headers)
                    hdrs["Content-Type"] = \
                        f"multipart/form-data; boundary={boundary}"
                    async with self._semaphore:
                        await self._throttle(url)
                        async with session.request(
                            getattr(self, "_upload_method", "POST"), url,
                            params=params or None, data=body,
                            headers=hdrs, proxy=self._next_proxy(),
                        ) as resp:
                            text = await _read_text(resp)
                            resp_headers = dict(resp.headers)
                            self.requests_made += 1
                            self._record_status(
                                getattr(resp, "status", 200))
                except (BudgetExhausted, CircuitOpen):
                    raise        # Phase 86: stop instead of "next file"
                except Exception:
                    continue
                if not text or cmarker not in text:
                    continue
                stored_url = _first_url_with(text, cmarker)
                if not stored_url:
                    continue
                target = urljoin(url, stored_url)
                try:
                    async with self._semaphore:
                        await self._throttle(target)
                        async with session.get(
                            target, headers=self._req_headers(self.headers),
                            proxy=self._next_proxy(),
                        ) as sresp:
                            stext = await _read_text(sresp)
                            s_headers = dict(sresp.headers)
                            self.requests_made += 1
                            self._record_status(getattr(sresp, "status", 200))
                except (BudgetExhausted, CircuitOpen):
                    raise        # Phase 86: stop instead of "next file"
                except Exception:
                    continue
                if cmarker not in stext:
                    continue
                try:
                    sv = await asyncio.to_thread(
                        verifier.verify_semantic, stext, cmarker,
                        response_headers=s_headers)
                except Exception:
                    sv = {"confirmed": False}
                if sv.get("confirmed"):
                    yield Finding(
                        url=target, method="GET",
                        param=f"{field}[content]",
                        type="stored_upload",
                        context="uploaded_file_content",
                        payload=filename, severity="high",
                        confidence="high",
                        detail=(sv.get("detail") or "") +
                               f" (stored file {stored_url} serves weaponised "
                               "HTML/SVG content)",
                        evidence=stext[max(0, stext.find(cmarker) - 60):
                                       stext.find(cmarker)
                                       + len(cmarker) + 120],
                        transform=["uploaded_file_content", "stored"],
                        evidence_class=EVIDENCE_MODEL,
                    )
                    return

    async def _scan_jsonp_async(self, url: str, method: str,
                                params: dict, data: dict
                                ) -> AsyncIterator[Finding]:
        """L6 JSONP callback XSS detection (fully async, no sync fallback).

        Phase 24-1: rewritten to use the aiohttp ClientSession directly
        instead of spinning up a synchronous Requester in a thread.
        The old implementation negated the async throughput advantage
        because each of the 7 callback-name probes blocked a thread on
        ``requests.request()``.
        """
        try:
            import aiohttp  # type: ignore
        except ImportError:
            return
        # Phase 290: coverage parity (the sync layer touches the
        # same id at its entry; without this the async report
        # listed the layer as never having run).
        self._touch_coverage(url, "L7_jsonp", method)
        # Build a query string carrying the existing params so the JSONP
        # endpoint sees the same context the reflection layer saw.
        for cb_name in _JSONP_CALLBACK_NAMES:
            if cb_name in params or cb_name in data:
                continue  # already being tested by the reflection layer
            marker = f"xsjsonp_{secrets.token_hex(3)}"
            probe_params = dict(params)
            probe_params[cb_name] = marker
            try:
                async with self._semaphore:
                    await self._throttle(url)
                    async with aiohttp.ClientSession(
                        headers=self._req_headers(self.headers),
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        **self._session_kwargs(url),
                    ) as sess:
                        async with sess.get(
                            url, params=probe_params, proxy=self._next_proxy(),
                        ) as resp:
                            text = await _read_text(resp)
                            self.requests_made += 1
                            self._record_status(getattr(resp, "status", 200))
                if marker not in text:
                    continue
                # Reflection found -- check if it lands in a JS-executable
                # context (callback function position).  verify_semantic
                # is CPU-bound but fast; run inline.
                v = verifier.verify_semantic(text, marker,
                                             response_headers=dict(resp.headers))
                if v["confirmed"]:
                    yield Finding(
                        url=url, method="GET", param=cb_name,
                        context="jsonp_callback",
                        payload=marker,
                        severity="high",
                        evidence=f"JSONP callback reflection: {v['detail']}",
                        type="jsonp_xss",
                        confidence="high",
                        evidence_class=EVIDENCE_MODEL,
                    )
                    return  # one confirmed JSONP finding is enough
            except (BudgetExhausted, CircuitOpen):
                raise    # Phase 86: stop instead of "next callback name"
            except Exception as e:
                _log.debug("JSONP probe failed for %s: %s", cb_name, e)
                continue

    async def _inject_blind_async(self, session, url: str, method: str,
                                  params: dict, data: dict
                                  ) -> AsyncIterator[Finding]:
        """L4 blind XSS injection -- sync _inject_blind parity (Phase 64).

        The old async version fired a hardcoded payload at EVERY parameter
        unconditionally (no reflection gate -> wasted probes on escaped
        endpoints), used ONE token for the whole endpoint (callbacks could
        not be attributed to a parameter) and a stray "');fetch" fragment.
        It now mirrors the sync layer exactly:

        * one reflection probe per param -- the real OOB payload is only
          fired where an UNESCAPED executable tag came back;
        * payloads come from the blind_oob corpus with __OOB__ replaced by
          a per-param token callback;
        * injections are recorded in _oob_pending and attributed by
          collect_oob_async() at the end of the scan (batch poll, same
          Finding shape as the sync collect_oob).
        """
        try:
            if not self.oob:
                return
            # Phase 290: coverage parity (the sync layer touches the
            # same id at its entry; without this the async report
            # listed the layer as never having run).
            self._touch_coverage(url, "L5_blind_oob", method)
            if self._semaphore is None:
                self._semaphore = asyncio.Semaphore(self.max_concurrent)
            blind_bases = payloads_mod.by_context("blind_oob")
            if not blind_bases:
                return
            raw_tags = ("<script", "<svg", "<img", "<iframe", "<body ")
            # JSON mode: blind payloads ride the document leaves (Phase 47).
            if self.json_body is not None:
                blind_items = [(p, False) for p in params] + \
                              [(path, True)
                               for path in json_leaf_paths(self.json_body)]
            else:
                blind_items = [(p, False) for p in params] + \
                              [(p, True) for p in data]
            probe_variant = (blind_bases[0]["payload"]
                             .replace("https://__OOB__",
                                      self.oob.callback_url("__T__"))
                             .replace("http://__OOB__",
                                      self.oob.callback_url("__T__")))
            for param, is_body in blind_items:
                send_params, send_data = self._probe_kv(
                    params, data, param, probe_variant, is_body)
                try:
                    async with self._semaphore:
                        await self._throttle(url)
                        async with session.request(
                            method, url, params=send_params or None,
                            headers=self._req_headers(self.headers),
                            proxy=self._next_proxy(),
                            **_body_kwargs(send_data),
                        ) as resp:
                            text = await _read_text(resp)
                            self.requests_made += 1
                            self._record_status(getattr(resp, "status", 200))
                except (BudgetExhausted, CircuitOpen):
                    raise        # Phase 86: stop instead of "next param"
                except Exception:
                    continue
                if not any(t in text for t in raw_tags):
                    continue  # escaped echo can never execute -- skip
                if not self._oob_started:
                    try:
                        self.oob.start()
                        self._oob_started = True
                    except Exception as e:
                        _log.warning("OOB listener failed to start: %s", e,
                                     exc_info=self.verbose)
                        return
                # One blind payload per (url, param): N payloads on the same
                # parameter all beacon to the same sink -- duplicates only.
                token = self.oob.token()
                cb = self.oob.callback_url(token)
                variant = (blind_bases[0]["payload"]
                           .replace("https://__OOB__", cb)
                           .replace("http://__OOB__", cb))
                send_params, send_data = self._probe_kv(
                    params, data, param, variant, is_body)
                try:
                    async with self._semaphore:
                        await self._throttle(url)
                        async with session.request(
                            method, url, params=send_params or None,
                            headers=self._req_headers(self.headers),
                            proxy=self._next_proxy(),
                            **_body_kwargs(send_data),
                        ) as resp:
                            await _read_text(resp)
                            self.requests_made += 1
                            self._record_status(getattr(resp, "status", 200))
                except (BudgetExhausted, CircuitOpen):
                    raise        # Phase 86: stop instead of "next param"
                except Exception:
                    continue
                async with self._get_lock():
                    self._oob_pending.append({
                        "token": token, "url": url, "method": method,
                        "param": param, "payload": variant,
                        "context": "blind_oob",
                    })
        except (BudgetExhausted, CircuitOpen):
            raise        # Phase 86: do not swallow the inner stop
        except Exception as e:
            _log.warning("async blind layer error: %s", e, exc_info=self.verbose)
        # Injection-only: this stays an async GENERATOR (page tasks drain
        # generators via _drain_agen); findings come from collect_oob_async.
        return
        yield  # pragma: no cover -- generator marker

    async def collect_oob_async(self, timeout: float | None = None
                                ) -> AsyncIterator[Finding]:
        """Batch-poll the OOB listener and emit confirmed blind findings.

        Mirrors the sync collect_oob: only callbacks count (a real browser
        executed the payload), injections are attributed to their param via
        the per-param token, oob_keep_listening re-arms late candidates, and
        the poll runs in a thread so the event loop never blocks.
        """
        if not self.oob:
            return
        timeout = float(timeout if timeout is not None
                        else getattr(self, "oob_timeout", 12))
        async with self._get_lock():
            expected = {p["token"] for p in self._oob_pending}
        if not expected:
            return
        try:
            received = await asyncio.to_thread(
                self.oob.poll, expected, timeout=timeout) or set()
        except Exception as e:
            _log.warning("OOB poll failed: %s", e, exc_info=self.verbose)
            received = set()
        async with self._get_lock():
            pending = list(self._oob_pending)
            self._oob_pending = []
        confirmed = {t for t in received if t in expected}
        by_token = {p["token"]: p for p in pending}
        for tok in sorted(confirmed):
            p = by_token.get(tok)
            if not p:
                continue
            yield Finding(
                url=p["url"], method=p["method"], param=p["param"],
                type="blind", context="blind_oob",
                payload=p["payload"], transform=[],
                severity="high", confidence="high",
                detail=(f"Blind XSS CONFIRMED via out-of-band callback. The "
                        f"injected payload beaconed to the callback host "
                        f"('{self.oob.name}'); a victim's browser executed it, "
                        f"proving the input renders in an executable context "
                        f"(classic blind/stored flow)."),
                headless=None,
                proof={"callback": self.oob.callback_url(tok)},
                evidence_class=EVIDENCE_OOB,
            )
        unconfirmed = [p for p in pending if p["token"] not in confirmed]
        if getattr(self, "oob_keep_listening", False):
            async with self._get_lock():
                self._oob_pending.extend(unconfirmed)
            if unconfirmed:
                _log.info("[*] blind: %d payload(s) still armed -- the "
                          "listener stays up", len(unconfirmed))
        elif unconfirmed and self.verbose:
            _log.debug(f"[*] blind: {len(unconfirmed)} OOB payload(s) never "
                       f"beaconed within {timeout}s")

    async def _poll_oob(self, token: str) -> bool:
        """Poll the OOB listener for a callback with the given token.

        Phase 24-1: replaced the fixed 1s sleep with exponential backoff
        (0.5, 1.0, 2.0, 4.0, 8.0 = 15.5s total) and removed the
        unnecessary ``asyncio.to_thread(getattr, ...)`` for a plain
        attribute read.
        """
        if not self.oob:
            return False
        delay = 0.5
        for _ in range(5):
            try:
                callbacks = getattr(self.oob, "callbacks", []) or []
                if any(token in str(c) for c in callbacks):
                    return True
            except Exception as e:
                _log.debug("OOB poll error: %s", e)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 8.0)  # exponential backoff, cap 8s
        return False

    # ------------------------------------------------------------------
    # Phase 211 first cut: three self-contained tail stages of
    # ``_probe_param``, moved out verbatim.  Each is gated on
    # ``not param_confirmed`` by the CALLER and only ever yields -- none of
    # them mutates the caller's locals, which is what makes them safe to
    # move.  The caller still owns ``param_confirmed``; threading it in and
    # out would be a behaviour change, so it stays there.
    # ------------------------------------------------------------------

    async def _probe_csp_nonce(self, session, url, method, param, params,
                               data, is_body, marker, context, csp_hdr,
                               probe_text, text, resp_headers,
                               ) -> AsyncIterator[Finding]:
        """Phase 100: CSP nonce-leak exploitation (sync _try_csp_nonce parity).

        A nonce CSP blocks plain inline payloads, so the payload loop ends
        unconfirmed -- but when the nonce itself is echoed into the page
        (the classic "nonce in a template/JSON blob" leak) a script carrying
        the REAL nonce executes.  The async path had no equivalent, so
        --async silently missed every nonce-leak endpoint that sync reported
        (pos-csp-01: sync TP, async FN).

        The verifier allowlists the nonce against the response's own CSP
        header, so a server that rotates nonces per request still cannot be
        falsely confirmed.
        """
        from . import csp as csp_mod
        try:
            _nonces = csp_mod.extract_nonces_from_csp(csp_hdr)
        except Exception:
            _nonces = []
        if not _nonces:
            return
        try:
            _near = csp_mod.detect_nonce_near_marker(
                csp_hdr, probe_text or text or "", marker)
        except Exception:
            _near = {}
        if not _near.get("nonce_exposed_near_marker"):
            return
        _n = _near.get("nonce_value") or _nonces[0]
        _ntok = "xssv_" + secrets.token_hex(4)
        _npay = (f"<script nonce='{_n}'>alert('{_ntok}')</script>")
        _nparams, _ndata = self._probe_kv(
            params, data, param, _npay, is_body)
        try:
            async with self._semaphore:
                await self._throttle(url)
                async with session.request(
                    method, url, params=_nparams or None,
                    headers=self._req_headers(self.headers),
                    proxy=self._next_proxy(),
                    **_body_kwargs(_ndata),
                ) as nresp:
                    _ntext = await _read_text(nresp)
                    _nhdrs = dict(getattr(nresp, "headers", None) or {})
                    self.requests_made += 1
                    self._record_status(getattr(nresp, "status", 200))
        except (BudgetExhausted, CircuitOpen):
            raise
        except Exception:
            _ntext = ""
            _nhdrs = {}
        if not _ntext:
            return
        _nv = await asyncio.to_thread(
            verifier.verify_semantic, _ntext, _ntok,
            response_headers=_nhdrs)
        if not (_nv.get("confirmed")
                and verifier.payload_survived(_ntext, _npay)):
            return
        _idx = _ntext.find(_ntok)
        yield Finding(
            url=url, method=method, param=param,
            context=context,
            sink_context=_nv.get("context"),
            payload=_npay,
            severity=_non_html_grade(resp_headers)[0],
            evidence=_ntext[max(0, _idx - 30):_idx + len(_ntok) + 30],
            type="reflected",
            confidence=_non_html_grade(resp_headers)[1],
            content_type=_content_type(resp_headers),
            transform=["csp_nonce"],
            param_in="body" if is_body else "query",
            evidence_class=EVIDENCE_MODEL,
        )

    async def _probe_csp_gadget(self, session, url, method, param, params,
                                data, is_body, context, csp_hdr,
                                ) -> AsyncIterator[Finding]:
        """Phase 187: CSP gadget chain (sync _try_csp_gadget parity).

        A strict script-src that still allowlists a known gadget host
        (JSONP endpoint, Angular CDN, ...) re-opens script execution;
        inline payloads cannot confirm it.  Framework-gadget payloads
        (Angular template expression) confirm through the SAME static
        template_angular machinery the corpus uses; JSONP-shaped ones have
        no honest static verdict (the token rides a src attribute) -- sync
        measures those under headless, the async emission stays on the
        static machinery like every other finding here.  Capped at two
        gadget payloads per (url, param).
        """
        from . import csp as csp_mod
        try:
            _gadgets = csp_mod.gadget_bypass_payloads(csp_hdr)
        except Exception:
            _gadgets = []
        _gtried = getattr(self, "_csp_gadget_tried", None)
        if _gtried is None:
            _gtried = set()
            self._csp_gadget_tried = _gtried
        if ((url, param) in _gtried
                or not csp_mod.gadget_chain_relevant(csp_hdr)):
            return
        _gtried.add((url, param))
        for _g in _gadgets[:2]:
            _gtok = "xssv_" + secrets.token_hex(4)
            _gpay = verifier.mark(_g["payload"], _gtok)
            if _gpay == _g["payload"]:
                continue  # nothing stampable -> no attributable proof
            _gparams, _gdata = self._probe_kv(
                params, data, param, _gpay, is_body)
            try:
                async with self._semaphore:
                    await self._throttle(url)
                    async with session.request(
                        method, url, params=_gparams or None,
                        headers=self._req_headers(self.headers),
                        proxy=self._next_proxy(),
                        **_body_kwargs(_gdata),
                    ) as gresp:
                        _gtext = await _read_text(gresp)
                        _ghdrs = dict(getattr(gresp, "headers", None) or {})
                        self.requests_made += 1
                        self._record_status(getattr(gresp, "status", 200))
            except (BudgetExhausted, CircuitOpen):
                raise
            except Exception:
                continue
            if not _gtext or _gtok not in _gtext:
                continue
            _gv = await asyncio.to_thread(
                verifier.verify_semantic, _gtext, _gtok,
                response_headers=_ghdrs)
            if not _gv.get("confirmed"):
                # JSONP-shaped gadgets have no honest static verdict (the
                # token rides a src attribute).  Sync measures those under
                # headless; here the Phase-183 wrapper is the browser -- but
                # only when one EXISTS.  Without Playwright the emission
                # would be a browserless claim sync never makes, so stay
                # silent instead.
                if not dom_engine_mod.DynamicDomAnalyzer.available():
                    continue
                _gidx = _gtext.find(_gtok)
                yield Finding(
                    url=url, method=method, param=param,
                    context=context,
                    payload=_gpay,
                    severity="high",
                    evidence=_gtext[max(0, _gidx - 30):
                                    _gidx + len(_gtok) + 30],
                    type="reflected",
                    confidence="low",
                    transform=["csp_gadget"],
                    param_in="body" if is_body else "query",
                    evidence_class=EVIDENCE_NO_BROWSER,
                    detail=(
                        "CSP allowlists "
                        f"'{_g['host']}' which hosts {_g['gadget']}; the "
                        "JSONP gadget payload reflected.  Static verdict is "
                        "honestly silent (the token rides a src attribute) "
                        "-- browser confirmation pending."),
                )
                break
            if not verifier.payload_survived(_gtext, _gpay):
                continue
            _gidx = _gtext.find(_gtok)
            yield Finding(
                url=url, method=method, param=param,
                context=context,
                sink_context=_gv.get("context"),
                payload=_gpay,
                severity=_non_html_grade(_ghdrs)[0],
                evidence=_gtext[max(0, _gidx - 30):
                                _gidx + len(_gtok) + 30],
                type="reflected",
                confidence=_non_html_grade(_ghdrs)[1],
                content_type=_content_type(_ghdrs),
                transform=["csp_gadget"],
                param_in="body" if is_body else "query",
                evidence_class=EVIDENCE_MODEL,
            )
            break

    async def _probe_hpp(self, session, url, method, param, params, data,
                         is_body, context, cands) -> AsyncIterator[Finding]:
        """Phase 193/196: HPP -- HTTP Parameter Pollution (sync _try_hpp parity).

        The parameter is sent twice -- first occurrence benign, second the
        payload; a filter inspecting only the first occurrence passes the
        request while the backend renders the payload occurrence.  WAF gate
        mirrors sync; both positions (query pairs / raw urlencoded body);
        capped at two payloads per (url, param).
        """
        _htried = getattr(self, "_hpp_tried", None)
        if _htried is None:
            _htried = set()
            self._hpp_tried = _htried
        if (url, param) in _htried:
            return
        _htried.add((url, param))
        for _cand in cands[:2]:
            _htok = "xssv_" + secrets.token_hex(4)
            _hpay = verifier.mark(_cand, _htok)
            if _hpay == _cand:
                continue
            if is_body:
                _bpairs = [(k, v) for k, v in (data or {}).items()
                           if k != param]
                _bpairs.append((param, "xsssafe"))
                _bpairs.append((param, _hpay))
                _hparams = params
                _hdata = urlencode(_bpairs)
                _hheaders = dict(self._req_headers(self.headers))
                _hheaders["Content-Type"] = \
                    "application/x-www-form-urlencoded"
            else:
                _hparams = [(k, v) for k, v in (params or {}).items()
                            if k != param]
                _hparams.append((param, "xsssafe"))
                _hparams.append((param, _hpay))
                _hdata = data
                _hheaders = self._req_headers(self.headers)
            try:
                async with self._semaphore:
                    await self._throttle(url)
                    async with session.request(
                        method, url, params=_hparams or None,
                        headers=_hheaders,
                        proxy=self._next_proxy(),
                        **_body_kwargs(_hdata),
                    ) as hresp:
                        _htext = await _read_text(hresp)
                        _hhdrs = dict(getattr(hresp, "headers", None) or {})
                        self.requests_made += 1
                        self._record_status(getattr(hresp, "status", 200))
            except (BudgetExhausted, CircuitOpen):
                raise
            except Exception:
                continue
            if not _htext or _htok not in _htext:
                continue
            _hv = await asyncio.to_thread(
                verifier.verify_semantic, _htext, _htok,
                response_headers=_hhdrs)
            if not _hv.get("confirmed"):
                continue
            _hidx = _htext.find(_htok)
            yield Finding(
                url=url, method=method, param=param,
                context=context,
                sink_context=_hv.get("context"),
                payload=_hpay,
                severity="high",
                evidence=_htext[max(0, _hidx - 30):
                                _hidx + len(_htok) + 30],
                type="reflected",
                confidence="high",
                transform=["hpp"],
                param_in="body" if is_body else "query",
                evidence_class=EVIDENCE_MODEL,
                detail=(
                    "HPP: the parameter was sent twice (first occurrence "
                    "benign, second the payload) and the payload-carrying "
                    "occurrence is what the application rendered -- a "
                    "filter inspecting only the first occurrence was "
                    "bypassed"),
            )
            break

    async def _build_probe_candidates(self, session, url, method, param,
                                      params, data, is_body, context,
                                      marker, marker_escaped,
                                      _extra_contexts):
        """Phase 211 round 2: stages B2-B5 of _probe_param, moved verbatim.

        Corpus sampling (Phase 43) -> reflection profile + generative
        payloads (Phase 37/95) -> RCDATA breakout surfacing (Phase 96) ->
        WAF bypass prepend (Phase 29-2).

        Returns ``(cands, marker_escaped, prof)``:
        - ``marker_escaped`` comes back because the profile convergence can
          SET it mid-way (Phase 95), and every later stage reads it;
        - ``prof`` comes back because the RCDATA stage reads it.
        No yields and no early returns -- which is why this stage could move
        as a plain function while B1 could not (B1 yields pre-encoded
        findings and returns out of the caller).
        """
        # Build payload candidates (CPU-bound) -- run in thread.
        # Phase 43: multi-corpus cross-context sampling (sync _scan_param
        # parity) -- primary corpus stride-sample + sibling corpora +
        # polyglots.  The old single-corpus slice missed payloads like the
        # recursive <sscriptcript> strip (neg-filter-01 FN).
        # Phase 93: on an escaped reflection the sync engine drops the
        # candidate budget to 2 (``primary_budget``) and only fires 3 of
        # them -- a small probe set that still catches double-encoding
        # bugs and attribute-context escapes without burning 168 requests
        # on a param that is almost certainly safe.
        cand_budget = 3 if marker_escaped else self.max_payloads
        try:
            cands = await asyncio.to_thread(
                payloads_mod.cross_context_candidates, context,
                cand_budget)
        except Exception:
            cands = payloads_mod.for_context("html_element")[:cand_budget]
        # Phase 177: multi-reflection parity with sync -- append a small
        # slice for each additional reflection context after the primary
        # queue; the payload-loop budget decides whether they ever fire.
        if _extra_contexts:
            _seen = set(cands)
            for _xc in _extra_contexts:
                for p in payloads_mod.for_context(_xc):
                    if p not in _seen:
                        _seen.add(p)
                        cands.append(p)

        # Phase 37: reflection profile + generative payloads (sync parity).
        # One sandwich probe reveals surviving characters; payloads whose
        # critical characters are gone move to the back, and payloads built
        # ONLY from surviving characters lead the queue (dedup'd).
        # Phase 93: skipped on an escaped reflection, like the sync
        # `_prioritize_bases` does -- the sandwich probe costs a request and
        # generative payloads cannot help when the encoder eats them.
        prof = None
        if not marker_escaped:
            try:
                ptok = "xssap_" + secrets.token_hex(3)
                pval = rp_mod.build_probe(ptok)
                sp, sd = self._probe_kv(params, data, param, pval, is_body)
                async with self._semaphore:
                    await self._throttle(url)
                    async with session.request(
                        method, url, params=sp or None,
                        headers=self._req_headers(self.headers),
                        proxy=self._next_proxy(),
                        **_body_kwargs(sd),
                    ) as resp2:
                        ptext = await _read_text(resp2)
                        self.requests_made += 1
                        self._record_status(getattr(resp2, "status", 200))
                prof = await asyncio.to_thread(rp_mod.profile_reflection,
                                               ptext, ptok)
            except (BudgetExhausted, CircuitOpen):
                raise  # Phase 86: the sandwich probe was stopped on purpose
            except Exception:
                prof = None
            if prof is not None and not prof.get("full_reflection"):
                try:
                    cands = await asyncio.to_thread(rp_mod.prioritize_payloads,
                                                    prof, cands)
                except Exception:
                    pass
                try:
                    gen_pls = await asyncio.to_thread(gen_mod.generate, prof,
                                                      context)
                    gen_strs = [g["payload"] for g in gen_pls]
                    known = set(cands)
                    cands = [g for g in gen_strs if g not in known] + cands
                except Exception:
                    pass
                # Phase 95: profile-backed escape convergence (sync parity).
                # ``is_marker_escaped`` cannot fire for a plain alphanumeric
                # marker echoed inside an element body (its neighbours are
                # the page's own structural characters, never encoded), so
                # escaped endpoints paid the full budget.  When the sandwich
                # probe proves every breakout-critical character comes back
                # encoded, converge to the small probe set.  Must run BEFORE
                # the WAF-bypass prepend below so the capped path stays clean.
                try:
                    converged = await asyncio.to_thread(
                        rp_mod.profile_says_encoded, prof, context)
                except Exception:
                    converged = False
                if converged:
                    marker_escaped = True
                    del cands[3:]

        # Phase 96: RCDATA breakout surfacing (sync parity).  When the
        # sandwich marker reflected inside <textarea>/<title>/<xmp>,
        # direct injections are inert while the closing-tag breakout is
        # the one vector that fires on raw echo.  Deliberately OUTSIDE
        # the ``not full_reflection`` branch: a raw-echoing RCDATA
        # endpoint keeps EVERY probed character (full reflection), yet
        # the breakout is exactly what must be tried there.  Only on the
        # non-converged path -- an escaping encoder mangles the closing
        # tag exactly like any other markup, so the breakout is dead
        # weight there and must not re-widen the converged list.  Runs
        # BEFORE the WAF-bypass prepend: on a raw-echoing RCDATA endpoint
        # the breakout outranks everything else.
        if prof is not None and not marker_escaped:
            try:
                cands, _rcd_tag = await asyncio.to_thread(
                    rp_mod.surface_rcdata_breakout_strs, prof, cands)
            except Exception:
                _rcd_tag = None
            if _rcd_tag:
                _log.debug(
                    f"[rcdata] reflection inside <{_rcd_tag}> -> "
                    "breakout variants lead the queue")

        # If WAF detected, prepend WAF-specific bypass chains.
        # Phase 93: not on an escaped reflection -- sync bounds these by
        # the small transform cap instead, and generative bypass bases
        # cannot help when the encoder eats their special characters.
        if self.waf_name and not marker_escaped:
            try:
                bypass_chains = await asyncio.to_thread(
                    bypass_mod.chains_for_waf, self.waf_name)
                bypass_payloads = [base for _, base, _, _ in bypass_chains[:3]]
                cands = bypass_payloads + cands
            except Exception:
                pass
        return cands, marker_escaped, prof
    async def _fire_probe_variants(self, session, url, method, param,
                                   params, data, is_body, context, marker,
                                   cands, marker_escaped, st,
                                   ) -> AsyncIterator[Finding]:
        """Phase 211 round 3: stages C/D/E of _probe_param, moved verbatim.

        The main variant loop (Phase 86/132/165/208), the concat-stamp retry
        (Phase 166) and the parameter position shift (Phase 37/47/164).

        Three values are written back onto ``st`` (_ProbeFireState) because
        an async generator cannot return them: param_confirmed,
        resp_headers and text.  Everything else in here is local to the
        stage.
        """
        text = st.text
        resp_headers = st.resp_headers

        # Phase 132: ``return`` on the first confirmed payload used to end
        # ``_probe_param`` outright, so the position shift, the CSP-nonce
        # exploit AND the L7 parameter layers were all skipped on exactly
        # the endpoints that were easiest to confirm -- async reported the
        # reflected hit and nothing else (13 requests vs sync's 45 on
        # pos-clobber-01, where sync also reports dom_clobber).  Sync breaks
        # out of its loop and keeps going (scanner.py:667 gates the loop on
        # ``not confirmed`` and reaches _run_advanced_layers unconditionally),
        # so this mirrors that: flag + break, later stages gated on the flag.
        param_confirmed = False
        for payload in cands:
            if param_confirmed:
                break
            marked = verifier.mark(payload, marker)
            # Phase 86: WAF/filter evasion parity with the sync _try_payload.
            # Until now the async path fired only the bare marked payload plus
            # one polyglot, so every evasion variant the sync engine tries
            # (mixed case, entity/percent encoding, comment breaks, ...) was
            # never sent -- self.max_transforms was stored but unused, which
            # left async with a large false-negative gap on filtered targets.
            variants = await asyncio.to_thread(
                self._build_variants, marked, context, marker,
                2 if marker_escaped else None)
            try:
                # Polyglot probe for unknown contexts.
                poly = poly_mod.build_polyglot(marker)
                if not any(v == poly for _, v in variants):
                    variants.append((["polyglot"], poly))
            except Exception:
                pass

            for tchain, variant in variants:
                send_params, send_data = self._probe_kv(
                    params, data, param, variant, is_body)
                try:
                    async with self._semaphore:
                        await self._throttle(url)
                        async with session.request(
                            method, url, params=send_params or None,
                            headers=self._req_headers(self.headers), proxy=self._next_proxy(),
                            **_body_kwargs(send_data),
                        ) as resp:
                            text = await _read_text(resp)
                            # Phase 43: capture headers for the verifier's
                            # CSP gate (sync parity) -- without them the
                            # CSP-blocks-inline check is skipped and strict
                            # CSP endpoints false-positive.  Defensive
                            # getattr: fake sessions in tests may omit
                            # headers entirely.
                            resp_headers = dict(getattr(resp, "headers", None) or {})
                            self.requests_made += 1
                            self._record_status(getattr(resp, "status", 200))
                except (BudgetExhausted, CircuitOpen):
                    raise        # Phase 86: stop instead of "next variant"
                except Exception:
                    continue
                # Verify execution (CPU-bound) -- run in thread.
                v = await asyncio.to_thread(verifier.verify_semantic,
                                            text, marker,
                                            response_headers=resp_headers)
                # Phase 165 (sync parity, scanner._try_payload): the token
                # survived -- did the PAYLOAD?  Keep looking otherwise.
                if v["confirmed"] and verifier.payload_survived(text, variant):
                    # Phase 208: a polyglot variant is a BROADER claim than
                    # a context-specific hit (it tries several breakouts at
                    # once), so it is graded like the sync polyglot layer
                    # (medium/medium, low on a non-HTML response) instead of
                    # as a plain reflected hit.  Previously identical
                    # evidence came out high/high here and medium/medium in
                    # sync -- measured on /r/url03.
                    _is_poly = "polyglot" in (tchain or [])
                    _sev, _conf = (_polyglot_grade(resp_headers) if _is_poly
                                   else _non_html_grade(resp_headers))
                    yield Finding(
                        url=url, method=method, param=param,
                        context=context,
                        sink_context=v.get("context"),
                        payload=variant,
                        severity=_sev,
                        evidence=text[max(0, text.find(marker)-30):
                                      text.find(marker)+len(marker)+30],
                        type=("polyglot_reflection" if _is_poly
                              else "reflected"),
                        confidence=_conf,
                        content_type=_content_type(resp_headers),
                        transform=tchain,
                        # Phase 164 (sync parity, scanner._record): record
                        # WHERE the payload rode so the PoC replays the same
                        # carrier instead of guessing it from the method.
                        param_in="body" if is_body else "query",
                        evidence_class=EVIDENCE_MODEL,
                    )
                    param_confirmed = True
                    break  # leave the variant loop; outer loop re-checks

            # Phase 166 (sync parity, scanner._try_payload:1112): the plain
            # stamp confirmed nothing for THIS payload.  A keyword filter
            # rewrites a LITERAL callable (``alert(`` -> ``blocked(``) while
            # letting the concatenated form through, so retry with the CONCAT
            # stamp -- bounded to two requests, exactly like sync pays them
            # per base payload.  This used to exist only inside the
            # position-shift block below, which requires a WAF *fingerprint*;
            # a WAF-less keyword filter never gets there (neg-filter-05:
            # sync confirms via the concat stamp, async paid 106 requests
            # and reported nothing).
            # Skipped when the marker came back HTML-escaped: the encoder
            # eats the concat variant just as dead as the plain one, and the
            # Phase 27-1 convergence budget must not grow by 2/payload
            # (test_async_escaped_convergence pins that ceiling).
            if not param_confirmed and not marker_escaped:
                concat_marked = verifier.mark(payload, marker, style="concat")
                if concat_marked != marked:
                    concat_retry: list = [([], concat_marked)]
                    for tchain, _v in variants[:1]:
                        v2 = concat_marked
                        for t in tchain:
                            v2 = await asyncio.to_thread(transform_mod.apply,
                                                         t, v2)
                        concat_retry.append(
                            (list(tchain) + ["concat_stamp"], v2))
                    for tchain, variant in concat_retry:
                        if marker not in variant:
                            continue
                        send_params, send_data = self._probe_kv(
                            params, data, param, variant, is_body)
                        try:
                            async with self._semaphore:
                                await self._throttle(url)
                                async with session.request(
                                    method, url, params=send_params or None,
                                    headers=self._req_headers(self.headers),
                                    proxy=self._next_proxy(),
                                    **_body_kwargs(send_data),
                                ) as resp:
                                    text = await _read_text(resp)
                                    resp_headers = dict(getattr(
                                        resp, "headers", None) or {})
                                    self.requests_made += 1
                                    self._record_status(
                                        getattr(resp, "status", 200))
                        except (BudgetExhausted, CircuitOpen):
                            raise
                        except Exception:
                            continue
                        v = await asyncio.to_thread(
                            verifier.verify_semantic, text, marker,
                            response_headers=resp_headers)
                        if (v["confirmed"]
                                and verifier.payload_survived(text, variant)):
                            idx = text.find(marker)
                            param_confirmed = True
                            # Phase 208: same polyglot grading as the main
                            # variant loop (the concat retry can ride on a
                            # polyglot base variant).
                            _is_poly = "polyglot" in (tchain or [])
                            _sev, _conf = (
                                _polyglot_grade(resp_headers) if _is_poly
                                else _non_html_grade(resp_headers))
                            yield Finding(
                                url=url, method=method, param=param,
                                context=context,
                                sink_context=v.get("context"),
                                payload=variant,
                                severity=_sev,
                                evidence=text[max(0, idx - 30):
                                              idx + len(marker) + 30],
                                type=("polyglot_reflection" if _is_poly
                                      else "reflected"),
                                confidence=_conf,
                                content_type=_content_type(resp_headers),
                                transform=tchain,
                                param_in="body" if is_body else "query",
                                evidence_class=EVIDENCE_MODEL,
                            )
                            break

        # Phase 37: parameter position shift (sync parity).  WAFs often
        # guard only the ORIGINAL parameter location -- re-fire the top
        # payloads with the param cloned into the OTHER location.
        # Phase 132: gated on ``not param_confirmed`` -- sync's call site
        # (scanner.py:693) has the same guard, and re-firing after a
        # confirmed hit would only add requests.
        if not param_confirmed:
            for payload in cands[:3]:
                marked = verifier.mark(payload, marker)
                # Phase 47: flipped is_body routes through _probe_kv so a
                # JSON-mode query->body shift lands in the JSON document
                # instead of a form body the server ignores.
                sp, sd = self._probe_kv(params, data, param, marked,
                                        not is_body)
                try:
                    async with self._semaphore:
                        await self._throttle(url)
                        async with session.request(
                            method, url, params=sp or None,
                            headers=self._req_headers(self.headers), proxy=self._next_proxy(),
                            **_body_kwargs(sd),
                        ) as resp:
                            text = await _read_text(resp)
                            resp_headers = dict(getattr(resp, "headers", None) or {})  # CSP gate parity
                            self.requests_made += 1
                        self._record_status(getattr(resp, "status", 200))
                except (BudgetExhausted, CircuitOpen):
                    raise            # Phase 86: stop instead of "next param"
                except Exception:
                    continue
                v = await asyncio.to_thread(verifier.verify_semantic,
                                            text, marker,
                                            response_headers=resp_headers)
                if (v["confirmed"]
                        and verifier.payload_survived(text, marked)):
                    idx = text.find(marker)
                    yield Finding(
                        url=url, method=method, param=param,
                        context=context,
                        sink_context=v.get("context"),
                        payload=marked,
                        severity=_non_html_grade(resp_headers)[0],
                        evidence=text[max(0, idx - 30):idx + len(marker) + 30],
                        type="reflected",
                        confidence=_non_html_grade(resp_headers)[1],
                        content_type=_content_type(resp_headers),
                        transform=["position_shift"],
                        # Phase 164: the shift re-fires the parameter into the
                        # OTHER location, so the carrier here is the FLIPPED
                        # one -- exactly the value the PoC needs.
                        param_in="query" if is_body else "body",
                        evidence_class=EVIDENCE_MODEL,
                    )
                    param_confirmed = True
                    break

            # Phase 166 (sync parity, scanner._try_payload): the plain stamp
            # confirmed nothing.  A keyword filter rewrites a LITERAL callable
            # while letting the concatenated form through, so retry with the
            # CONCAT stamp -- the only form that survives such a filter AND can
            # carry the marker.  Bounded to two requests, reached only when
            # everything above failed.
            if not param_confirmed:
                concat_marked = verifier.mark(payload, marker, style="concat")
                retry: list = [([], concat_marked)]
                for tchain, _v in variants[:1]:
                    v2 = concat_marked
                    for t in tchain:
                        v2 = await asyncio.to_thread(transform_mod.apply, t, v2)
                    retry.append((list(tchain) + ["concat_stamp"], v2))
                for tchain, variant in retry:
                    if marker not in variant:
                        continue
                    send_params, send_data = self._probe_kv(
                        params, data, param, variant, is_body)
                    try:
                        async with self._semaphore:
                            await self._throttle(url)
                            async with session.request(
                                method, url, params=send_params or None,
                                headers=self._req_headers(self.headers),
                                proxy=self._next_proxy(),
                                **_body_kwargs(send_data),
                            ) as resp:
                                text = await _read_text(resp)
                                resp_headers = dict(
                                    getattr(resp, "headers", None) or {})
                                self.requests_made += 1
                                self._record_status(
                                    getattr(resp, "status", 200))
                    except (BudgetExhausted, CircuitOpen):
                        raise
                    except Exception:
                        continue
                    v = await asyncio.to_thread(verifier.verify_semantic,
                                                text, marker,
                                                response_headers=resp_headers)
                    if (v["confirmed"]
                            and verifier.payload_survived(text, variant)):
                        idx = text.find(marker)
                        param_confirmed = True
                        yield Finding(
                            url=url, method=method, param=param,
                            context=context,
                            sink_context=v.get("context"),
                            payload=variant,
                            severity=_non_html_grade(resp_headers)[0],
                            evidence=text[max(0, idx - 30):
                                          idx + len(marker) + 30],
                            type="reflected",
                            confidence=_non_html_grade(resp_headers)[1],
                            content_type=_content_type(resp_headers),
                            transform=tchain,
                            param_in="body" if is_body else "query",
                            evidence_class=EVIDENCE_MODEL,
                        )
                        break


        st.text = text
        st.resp_headers = resp_headers
        st.param_confirmed = param_confirmed
