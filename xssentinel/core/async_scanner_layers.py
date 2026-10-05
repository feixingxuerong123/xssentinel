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
from .findings import (EVIDENCE_BROWSER_EXECUTED, EVIDENCE_MODEL,
                       EVIDENCE_NO_BROWSER, EVIDENCE_OOB)
from .requester import CountingRequester
from . import payloads as payloads_mod
from . import verifier
from . import pre_encode as pre_mod
from . import cors_check as cors_mod   # Phase 54: sync CORS audit parity
from . import dom_engine as dom_engine_mod  # Phase 65: DOM-dynamic parity
from . import xs_leaks as xsleak_mod   # Phase 54: sync XS-Leaks audit parity
from .budget import BudgetExhausted, CircuitOpen
from .stealth import (marker as _stem_marker)
from .async_scanner_common import (
    _AsyncScannerShim, _JSONP_CALLBACK_NAMES, _body_kwargs, _log, _non_html_grade,
)


class AsyncDetectionLayersMixin:
    """The async engine's per-layer detection methods.

    Mixed into ``AsyncScanner``; every method below is verbatim from the
    pre-split file.
    """
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
                        text = await resp.text()
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
                    context=v.get("context") or context,
                    payload=enc,
                    severity=_non_html_grade(resp_headers)[0],
                    evidence=text[max(0, idx - 30):idx + len(marker) + 30],
                    type="reflected",
                    confidence=_non_html_grade(resp_headers)[1],
                    transform=[f"pre_encode:{struct}"],
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
                              params: dict | None = None
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
        try:
            from . import dom as dom_mod
            static_results = await asyncio.to_thread(
                dom_mod.analyze, page_text, is_html=True)
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
                yield Finding(
                    url=url, method="GET", param=None,
                    context=d.get("sink"),
                    payload=d.get("snippet", ""),
                    severity="high",
                    confidence=d.get("confidence", "high"),
                    detail=d.get("detail", ""),
                    type="dom_dynamic",
                    headless={"available": True, "confirmed": True,
                              "outcome": "fired",
                              "detail": "marker executed in real browser sink"},
                    proof=d.get("snippet", ""),
                    evidence_class=EVIDENCE_BROWSER_EXECUTED,
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
                              html: str = ""
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

    async def _scan_xsleak_audit_async(self, url: str, resp_headers: dict
                                       ) -> AsyncIterator[Finding]:
        """Phase 54: XS-Leaks surface audit -- sync _scan_xsleak_audit parity.

        Opt-in (self.xsleak_audit); reuses the baseline response headers
        already fetched by scan() (zero extra requests); one low
        xs_leak_surface finding per origin.
        """
        if not self.xsleak_audit:
            return
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
                            text = await resp.text()
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
                            stext = await sresp.text()
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
                            text = await resp.text()
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
                            stext = await sresp.text()
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
                            text = await resp.text()
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
                            text = await resp.text()
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
                            await resp.text()
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
