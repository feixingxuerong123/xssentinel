# -*- coding: utf-8 -*-
"""Hidden-parameter mining, endpoint/source-map mining, BFS crawl.

Phase 191: pure movement out of ``async_scanner.py``.  No method body
was edited here -- ``dev/_p191_baseline.py after`` hashes every method's
source and compares it against the pre-split snapshot.
"""
from __future__ import annotations
import asyncio
from typing import AsyncIterator
from urllib.parse import urlparse, urljoin
from .scanner import Finding
from .requester import CountingRequester
from . import layer_guard
from .budget import BudgetExhausted, CircuitOpen
from .async_scanner_common import (
    _AsyncScannerShim, _extract_links, _log,
)


class _OfflineSession:
    """Refuses every request (Phase 200 hermeticity guard).

    Stands in for ``Requester.session`` while no real aiohttp transport
    is active: the sync layers' probes must not leak to the real network
    from a stubbed session.  Implements the small surface the layers and
    the Requester touch -- everything raises, the attributes exist so
    unrelated attribute reads do not explode.
    """

    headers: dict = {}
    proxies: dict = {}
    cookies: dict = {}
    verify = True

    def request(self, method, url, **kw):
        raise RuntimeError(
            "sync-layer transport is offline: no aiohttp-backed session "
            "is active, so this probe would leak to the real network")

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)

    def send(self, request, **kw):
        return self.request(request.method, request.url)

    def close(self):
        pass


class AsyncCrawlMixin:
    """Hidden-parameter mining, endpoint/source-map mining, BFS crawl.

    Mixed into ``AsyncScanner``; every method below is verbatim from the
    pre-split file.
    """
    async def _mine_hidden_params_async(self, url: str, method: str,
                                        params: dict, data: dict) -> dict:
        """Phase 133: hidden-parameter mining (sync parity).

        Sync merges ``param_miner``'s discoveries into the endpoint's
        params *before* probing it (scanner.py:302-324).  Async never had
        an equivalent, so an endpoint whose interesting parameter has no
        UI hint was only ever probed with the parameters already in the
        URL -- benchmark case pos-pmmine-01 was a clean sync TP / async FN
        (sync 46 requests, async 10).

        ``param_miner`` issues blocking requests, so this runs the sync
        miner in a worker thread against the shared sync Requester.

        BAV is deliberately NOT enabled here: the CLI documents ``--bav`` as
        sync-only, and half-implementing it would be worse than not
        claiming it.
        """
        shim = _AsyncScannerShim(self)
        try:
            # Counting proxy: the miner never bumps a counter itself, so
            # without this its ~N probe requests would not show up at all.
            shim.req = CountingRequester(self._get_sync_requester(),
                                     shim._bump)
            found = await asyncio.to_thread(
                shim._mine_hidden_params, url, method, params, data, False)
            self.requests_made += shim.requests_made
            return dict(found or {})
        except (BudgetExhausted, CircuitOpen) as e:
            # Phase 142: a budget stop while mining must NOT abort the scan.
            # The page tasks created afterwards include layers that cost no
            # requests at all (L6 CSP header analysis, L3 DOM static), and
            # re-raising here meant they never ran -- a bypassable CSP went
            # unreported purely because the miner had spent the cap first.
            # Record the reason and fall through; the request-driven layers
            # still raise on their own through _throttle, which propagates
            # out of _drain_agen exactly as before.
            _log.debug("async hidden-param mining stopped early: %s", e)
            return {}
        except Exception as e:
            _log.warning("async hidden-param mining error: %s", e,
                         exc_info=self.verbose)
            return {}

    def _get_sync_requester(self):
        """Lazily-built sync Requester for thread-offloaded sync layers.

        The transport layers (header/path/cookie/error XSS) need a
        blocking ``requests`` client.  The async scanner has none -- the
        shim's ``req`` is None and those layers' own try/except used to
        degrade to no-ops.  Build one sharing the scan's timeout / headers
        / cookies / proxy / TLS / rate-limit settings, once per scan.

        Phase 200 hermeticity guard: this requester hits the REAL network,
        which is only legitimate while a real aiohttp transport is active
        (``scan()`` sets ``_sync_layers_online``).  CONSTRUCTION stays
        legal -- wiring tests capture the requester and assert it is
        passed through -- but while no live transport exists its session
        is replaced with one that REFUSES every request, so the layers
        degrade to "unavailable" (their own try/except) instead of
        leaking probes to the real network from a stubbed session:
        measured, 6 leaked L7 probes x 7-11s of DNS timeout each was the
        "55s per _probe_param" recorded in OPTIMIZATION 3.8.
        """
        req = getattr(self, "_sync_requester", None)
        if req is None:
            from .requester import Requester
            req = Requester(
                timeout=self.timeout,
                proxy=self._next_proxy(),
                headers=dict(self.headers),
                cookies=dict(self.cookies),
                verify_ssl=self.verify_ssl,
                rate_limit=self.rate_limit,
                jitter=self.jitter_ratio,
            )
            if not getattr(self, "_sync_layers_online", False):
                req.session = _OfflineSession()
            self._sync_requester = req
        return req

    async def _crawl_mine_endpoints(self, text: str, url: str, depth: int,
                                    findings: list | None = None
                                    ) -> list[tuple[str, str, dict, dict]]:
        """Phase 176s: form + JS endpoint mining (sync parity).

        ``_extract_links`` collects ``<a href>`` and bare form *actions* --
        with no fields attached.  Two whole discovery classes were therefore
        missing from ``--async`` crawls:

          * forms: ``form_miner`` also recovers textarea / select /
            checkbox / radio / hidden inputs, so the endpoint gets probed
            with the fields the server actually reads
            (scanner_crawl.py:250).
          * JS routes: endpoints referenced in inline or external script but
            never linked via ``<a href>`` -- the common SPA case
            (scanner_crawl.py:300).

        Either way an endpoint discovered without its parameters cannot
        reflect anything, so these were silent false negatives rather than
        merely thinner coverage (pos-formmine-01 / pos-jsmine-01).

        External scripts are fetched at depth 0 only, mirroring sync's
        request-volume guard.

        ``findings`` is an optional out-list: a source-map disclosure is not
        an endpoint, and this function's contract (and its two wiring tests)
        is a list of endpoints, so observations go there for the caller to
        yield.
        """
        found: list[tuple[str, str, dict, dict]] = []
        sink_findings = findings if findings is not None else []
        origin = urlparse(url).netloc
        # 1) forms -> endpoint with the fields the markup declares.
        try:
            from . import form_miner
            for f_url, f_method, f_params, f_data in (
                    form_miner.forms_to_endpoints(text, url) or []):
                if urlparse(f_url).netloc != origin:
                    continue
                found.append((f_url, f_method or "GET", dict(f_params or {}),
                              dict(f_data or {})))
        except Exception as e:
            # Wiring defects escalate before the swallow.  Sync does the
            # same at scanner_crawl.py:349-352 ("silent layer loss is worse
            # than a noisy crawl") -- a debug-level catch here would hide a
            # renamed layer function as "this page had no forms", which is
            # the exact shape that cost the async engine its ctx.classify
            # outage (see tests/test_async_wiring.py).
            if layer_guard.is_wiring_error(e):
                _log.warning("[layer:async_form_miner] %s: %s",
                             type(e).__name__, e)
            _log.debug("async form mining failed on %s: %s", url, e)
        # 2) routes defined in JS rather than in markup.
        try:
            from . import js_miner
            res = js_miner.mine_html(text, url) or {}
            eps = list(res.get("inline_endpoints") or [])
            # Phase 209 (sync parity, scanner_crawl.py): routes a hash-routing
            # SPA reaches only through location.hash.  Inline script text is
            # part of `text`, so one pass covers it.  Resolved as server paths
            # they are probed against a route the client never reads.
            hash_urls: list[str] = list(js_miner.hash_route_urls(text, url))
            if depth == 0:
                for s_url in (res.get("external_scripts") or [])[:8]:
                    try:
                        # _throttle FIRST, then send, then count -- the
                        # ordering every other async send uses.  Without it
                        # this mining traffic sailed past --max-requests and
                        # inflated the total, which is Phase 142's bug in a
                        # new place.
                        await self._throttle(s_url)
                        req = self._get_sync_requester()
                        sj = await asyncio.to_thread(req.get, s_url)
                        self.requests_made += 1
                        eps.extend(
                            (js_miner.mine_js_file(sj.text or "") or {})
                            .get("endpoints", []))
                        hash_urls.extend(
                            js_miner.hash_route_urls(sj.text or "", url))
                        # Phase 189: mine the bundle's source map too -- the
                        # un-minified original carries routes the minifier
                        # renamed away (sync: CrawlMixin._mine_source_maps).
                        await self._mine_source_maps(
                            s_url, sj.text or "", sink_findings)
                    except (BudgetExhausted, CircuitOpen):
                        raise    # a budget stop is not a mining bug
                    except Exception:
                        continue
            for ep_url, _kind in eps:
                resolved = urljoin(url, ep_url)
                if urlparse(resolved).netloc != origin:
                    continue
                params: dict = {}
                if "?" in resolved:
                    q = resolved.split("?", 1)[1]
                    params = {k.split("=")[0]: "xss"
                              for k in q.split("&") if k}
                    resolved = urljoin(
                        resolved, urlparse(resolved).path or "/")
                found.append((resolved, "GET", params, {}))
            # Register the fragment-routed pages verbatim: the part of the
            # URL that matters here is the part the server never sees.
            # Capped on the union (sync parity, scanner_crawl.py) -- this list
            # accumulates the inline block and up to 8 fetched bundles.
            _have = {f[0] for f in found}
            for h_url in list(dict.fromkeys(hash_urls))[
                    :js_miner.MAX_HASH_ROUTES]:
                if h_url not in _have:
                    _have.add(h_url)
                    found.append((h_url, "GET", {}, {}))
        except Exception as e:
            if layer_guard.is_wiring_error(e):
                _log.warning("[layer:async_js_miner] %s: %s",
                             type(e).__name__, e)
            _log.debug("async JS mining failed on %s: %s", url, e)
        return found

    async def _mine_source_maps(self, script_url: str, js_text: str,
                                findings: list) -> list:
        """Async twin of ``CrawlMixin._mine_source_maps`` (Phase 189).

        Same two limits: one map fetched per script, never off-origin.  The
        disclosure goes into the caller's ``findings`` out-list because this
        is not an endpoint; see ``_crawl_mine_endpoints``.
        """
        from . import js_miner
        from . import sourcemap

        origin = urlparse(script_url).netloc
        extra: list = []
        for map_url in sourcemap.map_urls(script_url, js_text)[:1]:
            if urlparse(map_url).netloc != origin:
                continue
            try:
                await self._throttle(map_url)
                req = self._get_sync_requester()
                resp = await asyncio.to_thread(req.get, map_url)
                self.requests_made += 1
            except (BudgetExhausted, CircuitOpen):
                raise        # a budget stop is not a mining bug
            except Exception as e:
                if layer_guard.is_wiring_error(e):
                    _log.warning("[layer:async_js_miner] %s: %s -- source-map "
                                 "ingestion OFF until the defect is fixed",
                                 type(e).__name__, e)
                continue
            result = sourcemap.analyze_map(resp.text or "")
            if not result["ok"] or not result["js"]:
                continue
            extra.extend(js_miner.mine_js_file(result["js"]).get("endpoints", []))
            fields = sourcemap.disclosure(map_url, result, script_url)
            if fields:
                findings.append(Finding(**fields))
        return extra

    async def _crawl_page_layers(self, url: str, text: str,
                                 resp_headers: dict, params: dict,
                                 method: str = "GET",
                                 data: dict | None = None):
        """Phase 214/215/216: the page-level layers a CRAWLED endpoint gets.

        The parity target is ``scan_endpoint``'s stack.  CSP rides the
        endpoint's OWN response headers (Phase 215 plumbing) -- the seed
        gets the same layer from the main loop with the seed's headers.
        Phase 216 adds the L8 request-injection carriers and the JSONP
        audit: sync runs both on every crawled endpoint, and neither needs
        anything but the endpoint itself (JSONP opens its own short-lived
        session; L8's probes are a handful of requests).

        CORS and the XS-Leaks audit stay OUT deliberately: both dedupe per
        ORIGIN inside the layer (``_cors_checked`` / ``_xsleak_audited``),
        so a per-endpoint call is structurally unreachable after the seed's
        run -- wiring it would be a decorative call that can never fire.
        """
        async for finding in self._scan_dom_async(url, text, method, params):
            yield finding
        async for finding in self._scan_advanced_page(url, text, params):
            yield finding
        async for finding in self._scan_csp_async(url, resp_headers, text):
            yield finding
        async for finding in self._scan_request_layers(
                url, method, params, data or {}):
            yield finding
        async for finding in self._scan_jsonp_async(
                url, method, params, data or {}):
            yield finding

    async def _crawl_and_scan(self, session, start_url: str,
                              start_text: str) -> AsyncIterator[Finding]:
        """L7 crawl: discover linked endpoints and scan them.

        Uses BFS with the configured ``crawl_depth``.  Link extraction
        runs in a thread (BeautifulSoup parse).

        Phase 24-1: switched from ``list.pop(0)`` (O(n) per pop) to
        ``collections.deque.popleft()`` (O(1)) so large crawl frontiers
        don't suffer quadratic slowdown.
        """
        try:
            from bs4 import BeautifulSoup  # noqa: F401  (可选依赖可用性探测:导入即使用)
        except ImportError:
            return
        from collections import deque

        visited: set[str] = {start_url}
        # Phase 176s: mined endpoints are keyed by (method, url, fields)
        # because the same URL reached with different fields is a different
        # target -- and the bare form action is already in `visited`.
        mined_seen: set[tuple] = set()
        # Phase 214: queue entries carry the delivery params and WHERE the
        # entry came from.  The seed must not be page-layered again at pop
        # time (the main loop already ran the full pipeline on it -- sync
        # parity: scanner_crawl registers the start URL as endpoints[0]
        # precisely so it is not scanned twice).
        queue: deque[tuple[str, int, dict, str]] = deque(
            [(start_url, 0, {}, "seed")])
        # Phase 215: a page is page-layered ONCE, keyed on the
        # fragment-stripped URL (sync registers /x#a and /x#b as one
        # endpoint; see the pop-time block below).
        layered_seen: set[str] = set()
        while queue:
            current_url, depth, pop_params, origin = queue.popleft()
            # Phase 214: only the SEED keeps the old depth short-circuit (the
            # main loop already ran the full pipeline on it; with
            # crawl_depth=0 the crawl adds nothing).  LINK entries at max
            # depth are now fetched and page-layered -- before this phase
            # they were never fetched at all and only ever got the
            # discovery-time reflection probe.
            if origin == "seed" and depth >= self.crawl_depth:
                continue
            # Fetch the page (or reuse start_text for the seed).
            if current_url == start_url:
                text = start_text
                resp_headers: dict = {}
            else:
                try:
                    async with self._semaphore:
                        await self._throttle(current_url)
                        async with session.get(
                            current_url, headers=self._req_headers(self.headers),
                            proxy=self._next_proxy(),
                        ) as resp:
                            text = await resp.text()
                            resp_headers = dict(resp.headers)
                            self.requests_made += 1
                            self._record_status(getattr(resp, "status", 200))
                except (BudgetExhausted, CircuitOpen):
                    raise        # Phase 86: stop crawling instead of skipping
                except Exception as e:
                    _log.debug("crawl fetch failed for %s: %s", current_url, e)
                    continue
            # Phase 214/215: page-level layers for LINK-discovered endpoints,
            # at the point where the page's OWN text is in hand.  At discovery
            # time only the parent's text exists -- analyzing that would be
            # static analysis of the wrong page -- but at pop time the
            # endpoint has just been fetched for link extraction anyway, so
            # the layers cost zero extra fetches (sync parity: every
            # registered endpoint gets the full scan_endpoint stack,
            # including the browser DOM layer).  The 2.1.1 record: before
            # this, a linked page with a DOM sink was invisible to --async,
            # whatever the marker reached through.  Phase 215: fragment-
            # bearing anchors layer too (the fragment is a taint source only
            # the browser reads), deduped on the fragment-stripped URL --
            # findings._norm drops fragments, so sync registers /x#a and
            # /x#b as ONE endpoint; two browser passes would be cost without
            # information.
            if origin == "link" and self.advanced_layers:
                layer_key = current_url.split("#", 1)[0]
                if layer_key not in layered_seen:
                    layered_seen.add(layer_key)
                    # De-parameterised URL + params dict, the shape
                    # scanner_crawl registers for sync.  This is a WIRE-SHAPE
                    # contract, not a delivery one (measured, mutation M2,
                    # 2026-10-11): handing the browser ``/sink?v=1`` plus
                    # ``params={"v": ...}`` does NOT lose the marker -- the
                    # engine's own named probes re-mark EVERY matching key
                    # (``_with_param_value`` assigns each ``k == name`` in
                    # the pair list), so even the merged ``?v=1&v=xss`` fires
                    # the sink.  What the bare URL buys is that the
                    # navigation carries one clean copy of the query instead
                    # of a doubled one.
                    bare_url = current_url.split("?", 1)[0]
                    async for finding in self._crawl_page_layers(
                            bare_url, text, resp_headers, pop_params):
                        yield finding            # Phase 214: extraction and mining stay depth-bounded exactly as
            # before -- a max-depth LINK entry was fetched for its OWN page
            # layers above, but contributes no child frontier.
            if depth >= self.crawl_depth:
                continue
            # Extract links (CPU-bound) -- run in thread.
            links = await asyncio.to_thread(_extract_links, text, current_url)
            for link in links:
                if link in visited:
                    continue
                visited.add(link)
                # Scan the discovered endpoint for reflected XSS.  Phase 46:
                # a link carrying query params (?q=hi&debug=1) is scanned as
                # a GET endpoint with those params in the params dict and the
                # URL de-parameterised -- the old call passed ({}, {}) so the
                # query never reached the reflection probe and every crawled
                # query-param endpoint was silently skipped (sync crawler
                # parity: scanner_crawl.py).  Phase 214: the same params ride
                # the queue so the pop-time page layers (below) see the
                # delivery shape too; the queue keeps the FULL link, exactly
                # as before.
                cparams: dict = {}
                scan_url = link
                if "?" in link:
                    fu = urlparse(link)
                    q = link.split("?", 1)[1]
                    cparams = {k.split("=")[0]: "xss"
                               for k in q.split("&") if k}
                    scan_url = urljoin(link, fu.path or "/")
                queue.append((link, depth + 1, cparams, "link"))
                async for finding in self._scan_reflected(
                        session, scan_url, "GET", cparams, {}, text):
                    yield finding

            # Phase 176s: form + JS mining, in addition to <a href> links.
            # These arrive WITH their parameters, so unlike the link loop
            # above they can actually carry a payload.
            mined_observations: list[Finding] = []
            for m_url, m_method, m_params, m_data in await (
                    self._crawl_mine_endpoints(text, current_url, depth,
                                               mined_observations)):
                # Phase 209: a fragment-bearing endpoint is a client-side
                # route.  The ``split("?")`` below would cut the route's own
                # query away (that "?" sits INSIDE the fragment, which the
                # server never sees), and reflection-only probing then walks
                # past a sink that can only be examined in a browser.  Sync
                # registers these URLs verbatim and runs its DOM layer on
                # crawled endpoints; measured on OWASP Juice Shop 20.2.0, the
                # same target gave sync 1 browser-executed high DOM finding
                # and async 0 findings over 374 requests.
                if urlparse(m_url).fragment:
                    frag_key = (m_method, m_url, ())
                    if frag_key in mined_seen:
                        continue
                    mined_seen.add(frag_key)
                    if self.advanced_layers:
                        async for finding in self._scan_dom_async(
                                m_url, text, m_method, m_params):
                            yield finding
                    continue
                m_base = m_url.split("?", 1)[0]
                key = (m_method, m_base,
                       tuple(sorted(set(m_params) | set(m_data))))
                if key in mined_seen:
                    continue
                mined_seen.add(key)
                async for finding in self._scan_reflected(
                        session, m_base, m_method, m_params, m_data, text):
                    yield finding
                if self.advanced_layers and not urlparse(m_url).fragment:
                    # Phase 215: mined NON-fragment endpoints get the page
                    # layers too.  Nothing else ever fetches them (they are
                    # not walked), so this GET is the page-text source --
                    # sync pays the same GET inside scan_endpoint.  The DOM
                    # layer's own static gates (page_has_client_js /
                    # page_can_run_sink) keep the browser off non-HTML
                    # endpoints, so an API form action costs a GET, not a
                    # browser pass.
                    try:
                        async with self._semaphore:
                            await self._throttle(m_base)
                            async with session.get(
                                    m_base,
                                    headers=self._req_headers(self.headers),
                                    proxy=self._next_proxy()) as m_resp:
                                m_text = await m_resp.text()
                                m_headers = dict(m_resp.headers)
                                self.requests_made += 1
                                self._record_status(
                                    getattr(m_resp, "status", 200))
                    except (BudgetExhausted, CircuitOpen):
                        raise        # Phase 86: stop instead of skipping
                    except Exception as e:
                        _log.debug("crawl page-layer fetch failed for %s: %s",
                                   m_base, e)
                        m_text, m_headers = "", {}
                    if m_text:
                        async for finding in self._crawl_page_layers(
                                m_base, m_text, m_headers, m_params,
                                method=m_method, data=m_data):
                            yield finding
            for f in mined_observations:
                yield f
