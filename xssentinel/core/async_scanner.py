"""Async scanner using aiohttp.

A high-throughput async scanner that mirrors the full detection pipeline
of the synchronous Scanner.  Useful for large-scale audits (crawl depth
5+, hundreds of endpoints) where the sync ThreadPoolExecutor becomes
I/O-bound.

Phase 17 (this version) integrates ALL detection layers from the sync
scanner, not just L1 reflected:
  * L1 reflected + context-aware payloads (original)
  * L2 WAF detection + adaptive bypass chains (new)
  * L3 DOM static analysis (new)
  * L4 blind/OOB injection + auto-confirm (new)
  * L5 advanced layers: postMessage / prototype / SW / worker / redirect
      / framework / header / path / cookie / error / markdown (new)
  * L6 CSP analysis + JSONP + polyglot + mXSS + template (new)
  * L7 crawl with BFS (new)

Detection modules run in ``asyncio.to_thread`` so CPU-bound parsing
(BeautifulSoup, regex matching) does not block the event loop.  I/O
(requests) stays fully async via aiohttp.

Falls back gracefully if aiohttp is not installed: importing this module
won't fail, but ``scan()`` will report "aiohttp not available".
"""
from __future__ import annotations
import asyncio
import copy
import time
import secrets
from typing import AsyncIterator
from urllib.parse import urljoin

from .scanner import Finding, json_leaf_paths, _set_json_leaf
from .findings import (EVIDENCE_MODEL,
                       EVIDENCE_NO_BROWSER)
from .requester import JsonBody
from . import payloads as payloads_mod
from . import context as ctx
from . import verifier
from . import waf as wafmod
from . import polyglot as poly_mod
from . import bypass as bypass_mod
# Phase 35: pre-encoding pipeline parity with the sync scanner (Phase 34).
from . import pre_encode as pre_mod
# Phase 37: reflection-profile + generator parity (sync Phases 31/32).
from . import reflection_profile as rp_mod
from . import generator as gen_mod
from . import csp as csp_mod           # Phase 100: CSP nonce-leak parity
from . import dom_engine as dom_engine_mod  # Phase 65: DOM-dynamic parity
# Phase 86: budget/circuit stops must be catchable by name at every layer --
# _throttle() raises them, and the generic ``except Exception`` handlers that
# surround every probe used to swallow them (see _probe_param).
from .budget import BudgetExhausted, CircuitOpen
from .egress import EgressPolicy

# Phase 191 split of this file (pure movement; see async_scanner_common.py and
# the three mixins below).  The helper names are re-imported here because
# callers and tests import them from the engine module.  `_EGRESS_JAR` is
# deliberately NOT re-exported: `from x import name` copies the value, so a
# test that resets the cache would then be writing an alias while
# `_egress_cookie_jar_cls` keeps reading the real binding in
# async_scanner_common -- a guard that silently stops guarding anything.
from .async_scanner_common import (  # noqa: E402  (must follow the block above)
    _AsyncScannerShim,  # noqa: F401  (engine import surface; used by layers/crawl)
    _body_kwargs,
    _drain_agen,
    _egress_cookie_jar_cls,
    _extract_links,  # noqa: F401  (engine import surface; used by crawl)
    _FakeResp,
    _JSONP_CALLBACK_NAMES,  # noqa: F401  (engine import surface; used by layers)
    _log,
    _non_html_grade,
)
from .async_scanner_verify import AsyncHeadlessVerifyMixin
from .async_scanner_layers import AsyncDetectionLayersMixin
from .async_scanner_crawl import AsyncCrawlMixin






from .findings import _DEFAULT_TRANSFORMS  # noqa: E402
from . import transform as transform_mod  # noqa: E402
from .stealth import (marker as _stem_marker, HeaderRotator as _HeaderRotator, ProxyPool as _ProxyPool,  # noqa: E402
                      jitter_interval, load_proxies as _load_proxies)




class AsyncScanner(AsyncHeadlessVerifyMixin, AsyncDetectionLayersMixin,
                   AsyncCrawlMixin):
    """Async XSS scanner with full detection pipeline.

    Construct with the same options as Scanner; call ``await scan(url, ...)``
    to get an async iterator of Finding objects.
    """

    def __init__(self, *, max_concurrent: int = 20,
                 per_host_delay: float = 0.0,
                 jitter: float = 0.0,
                 max_payloads: int = 14,
                 max_transforms: int = 8,
                 timeout: int = 15,
                 headers: dict | None = None,
                 cookies: dict | None = None,
                 proxy: str | None = None,
                 verify_ssl: bool = True,
                 verbose: bool = False,
                 crawl: bool = False,
                 crawl_depth: int = 2,
                 oob=None,
                 advanced_layers: bool = True,
                 dom_engine: str = "off",
                 waf_name: str | None = None,
                 rate_limit: float = 0.0,
                 max_requests: int | None = None,
                 max_requests_per_endpoint: int | None = None,
                 breaker_threshold: int = 0,
                 json_body: dict | None = None,
                 proxy_pool: list | None = None,
                 rotate_headers: bool = False,
                 jitter_ratio: float = 0.0,
                 xsleak_audit: bool = False,
                 upload_fields: list[str] | None = None,
                 auth_headers: dict | None = None,
                 auth_cookies: list | None = None,
                 auth_local_storage: dict | None = None,
                 use_headless: bool = False,
                 headless_concurrency: int = 1,
                 skip_params: set | None = None):
        # Phase 183 (option B): headless confirmation wiring.  The pool
        # itself is created lazily on first verification (see _verify_pool)
        # so __new__-built test scanners and non-headless scans never pay
        # for it.  headless_concurrency bounds BOTH in-flight replays and
        # total Chromium instances (one per pool worker thread).
        self.use_headless = bool(use_headless)
        # Phase 184: parity with the sync engine's --skip-param handling
        # (probe-loop filter in _probe_params + mining via the shared
        # scanner_crawl hook).
        self.skip_params = {str(p).strip().lower()
                            for p in (skip_params or ()) if str(p).strip()}
        self.headless_concurrency = max(1, int(headless_concurrency or 1))
        self.max_concurrent = max_concurrent
        self.per_host_delay = per_host_delay
        # Phase 93: default jitter 0.0 (was 0.1).  Unlike the sync engine,
        # where jitter is a RATIO of the rate-limit interval and therefore
        # costs nothing without --rate-limit, this is an ABSOLUTE
        # per-request sleep of jitter*(0.5+rand) seconds in _throttle().
        # With the 0.1 default every --async request waited 50-150ms that
        # sync did not: neg-escape-03 spent 22 of its 23s asleep
        # (cProfile: 0.33s of scanner work, 22.9s parked in
        # GetQueuedCompletionStatus), which is the entire async-vs-sync
        # throughput gap.  cli_runner never passed it, so the CLI had no
        # way to turn it off.  Pacing is opt-in now, exactly like sync.
        self.jitter = jitter
        # Phase 46 (pentest-readiness): --rate-limit previously never
        # reached this constructor (cli_runner bug) and async traffic had
        # no budget guard.  rate_limit = global max requests/sec;
        # max_requests / max_requests_per_endpoint stop the scan when spent.
        self.rate_limit = max(0.0, float(rate_limit or 0))
        self._min_interval = 1.0 / self.rate_limit if self.rate_limit > 0 else 0.0
        self._last_global_request = 0.0
        self._ep_counts: dict[str, int] = {}
        self.max_requests = max_requests if (max_requests is None or max_requests > 0) else None
        self.max_requests_per_endpoint = max_requests_per_endpoint \
            if (max_requests_per_endpoint is None or max_requests_per_endpoint > 0) else None
        # Phase 46: circuit breaker (0 = disabled).  Consecutive 5xx/429
        # responses within a 2-minute window trip it; _throttle() then
        # raises CircuitOpen so the scan stops hammering a dead target.
        self.breaker_threshold = max(0, int(breaker_threshold or 0))
        self._fail_times: list[float] = []
        self.budget_exhausted_reason: str | None = None
        # Phase 47: JSON-body carrier (async parity with the sync scanner).
        # When set, body params are the LEAF paths of this document
        # (dot/index notation, e.g. "user.name", "tags[0]") and every body
        # probe is sent as application/json -- the old async path only ever
        # sent form-encoded bodies, so JSON APIs -- the majority of modern
        # POST endpoints -- could not be tested in --async mode at all.
        self.json_body = json_body
        self.max_payloads = max_payloads
        self.max_transforms = max_transforms
        self.timeout = timeout
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.proxy = proxy
        # Phase 51 (async parity): rotate egress across a proxy pool
        # instead of one static proxy; dead relays are evicted.
        self.proxy_pool = _ProxyPool(_load_proxies(proxy_pool)) \
            if proxy_pool else None
        # Phase 51: per-request header rotation (async parity with the sync
        # Requester).  Headers are passed per call, so nothing is persisted.
        self.rotate_headers = bool(rotate_headers)
        self.header_rotator = _HeaderRotator(headers.get("User-Agent")) \
            if (rotate_headers and isinstance(headers, dict)) else None
        # Phase 51: jitter the GLOBAL pacing interval (a fixed cadence is a
        # WAF/SIEM fingerprint, same rationale as the sync path).
        self.jitter_ratio = max(0.0, min(1.0, float(jitter_ratio or 0.0)))
        # Phase 54: XS-Leaks surface audit parity with the sync Scanner
        # (opt-in; OFF keeps async scans byte-for-byte as before).
        self.xsleak_audit = bool(xsleak_audit)
        # Phase 150: authenticated session state for the real-browser DOM
        # layer (see sync Scanner for the full rationale).
        self.auth_headers: dict = dict(auth_headers or {})
        self.auth_cookies: list = list(auth_cookies or [])
        self.auth_local_storage: dict = dict(auth_local_storage or {})
        # Phase 58: multipart upload-filename probing parity (sync Phase 48).
        self.upload_fields: list[str] = list(upload_fields or [])
        # Phase 64: blind OOB state -- sync parity (pending injections are
        # attributed per param and collected in batch at the end of scan()).
        self._oob_pending: list = []
        self._oob_started = False
        self.oob_timeout = 12
        self.oob_keep_listening = False
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.crawl = crawl
        self.crawl_depth = crawl_depth
        self.oob = oob
        self.advanced_layers = advanced_layers
        self.dom_engine = dom_engine
        self.waf_name = waf_name
        self.requests_made = 0
        self.findings: list[Finding] = []
        self._semaphore: asyncio.Semaphore | None = None
        self._last_request_time: dict[str, float] = {}
        # py3.9: asyncio.Lock() binds whatever loop is current at
        # construction.  Built HERE it would either raise (host thread
        # without a loop: pytest, --serve, library embedding) or -- if
        # this code first installed a loop of its own -- bind to a loop
        # the caller's asyncio.run() never uses, which turns a clean
        # error into a HANG.  So: create it lazily, inside the loop that
        # is actually running us.
        self._lock: asyncio.Lock | None = None
        self._aiohttp_available = self._check_aiohttp()

    def _get_lock(self) -> asyncio.Lock:
        """The scan-wide lock, created inside the running loop.

        See __init__: constructing it eagerly bound it to whatever loop
        happened to be current (or raised in a host thread), and a lock
        bound to a dead loop hangs every ``async with`` on it.
        """
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    def _next_proxy(self) -> str | None:
        """Next proxy from the pool, or the static --proxy."""
        if self.proxy_pool is None:
            return self.proxy
        p = self.proxy_pool.next()
        return p if p is not None else self.proxy

    def _req_headers(self, headers: dict | None = None) -> dict:
        """Per-request headers: rotated browser bundle + caller overrides."""
        base = dict(headers or {})
        if self.header_rotator is not None:
            merged = self.header_rotator.next_headers()
            merged.update(base)          # caller wins
            return merged
        return base

    def _egress(self) -> "EgressPolicy":
        """Credential-egress policy shared by every session this scanner opens.

        ``getattr`` guards mirror ``_verify_pool``: tests build this scanner
        with ``__new__`` to skip ``__init__``, and a missing header bundle
        simply means "scrub the built-in credential names".
        """
        policy = getattr(self, "_egress_policy", None)
        if policy is None:
            names = dict(getattr(self, "headers", None) or {})
            names.update(dict(getattr(self, "auth_headers", None) or {}))
            policy = EgressPolicy(operator_headers=names)
            self._egress_policy = policy
        return policy

    def _session_kwargs(self, url: str) -> dict:
        """``ClientSession`` kwargs that keep operator credentials on their origin.

        aiohttp 3.13.3 measured here: it forwards the request header dict to
        every redirect hop, and it applies the cookie jar when it *builds*
        each hop -- after ``on_request_redirect`` has run -- so a header
        scrub alone cannot reach jar cookies.  Hence two mechanisms: the
        redirect listener strips header secrets, the jar subclass stays shut
        for an origin the operator never named.  ``cookies=`` cannot be passed
        alongside ``cookie_jar=``, so the operator cookies are seeded here.
        """
        import aiohttp
        policy = self._egress()
        policy.note(url)
        jar_cls = _egress_cookie_jar_cls()
        jar = jar_cls(policy)
        cookies = getattr(self, "cookies", None)
        if cookies:
            jar.update_cookies(dict(cookies))
        tc = aiohttp.TraceConfig()

        async def _named(session, ctx, params):
            # Fires once per top-level request, never for a redirect hop --
            # which is exactly the distinction this policy turns on.
            policy.note(params.url)

        async def _scrub_hop(session, ctx, params):
            location = params.response.headers.get("Location")
            if not location:
                return
            target = urljoin(str(params.response.url), str(location))
            removed = policy.scrub(params.headers, target)
            if removed:
                _log.warning("withheld %s from cross-origin redirect to %s",
                             "+".join(sorted(removed)), target)

        tc.on_request_start.append(_named)
        tc.on_request_redirect.append(_scrub_hop)
        return {"trace_configs": [tc], "cookie_jar": jar}

    @staticmethod
    def _check_aiohttp() -> bool:
        try:
            import aiohttp  # noqa: F401  (可选依赖可用性探测:导入即使用)
            return True
        except ImportError:
            return False

    async def scan(self, url: str, method: str = "GET",
                   params: dict | None = None,
                   data: dict | None = None) -> AsyncIterator[Finding]:
        """Scan a single URL asynchronously. Yields Finding objects.

        Phase 183 (decision: option B): ``--headless`` now works in async
        mode.  The layer stack is wrapped here -- at the OUTERMOST
        generator -- so every finding passes through the same blocking
        browser confirmation the sync engine runs per finding from
        ``Scanner._record``, without touching the 15+ yield sites.

        The replay runs on a DEDICATED loop-free thread pool
        (``_headless_pool``), not the default executor: Playwright's sync
        API is thread-bound (``dom_engine.get_shared_browser`` keeps one
        Chromium per thread and refuses to start under a running loop), so
        the pool's ``max_workers`` IS the concurrency cap -- at most that
        many browser instances exist, one shared per worker thread, for
        the whole scan.  Replays are deduped on the exact replay tuple
        (url, param, payload): a confirmation is a request, and identical
        replays are identical evidence.
        """
        if not getattr(self, "use_headless", False):
            async for f in self._scan_raw(url, method, params, data):
                yield f
            return
        try:
            seen: set = set()
            async for f in self._scan_raw(url, method, params, data):
                yield await self._headless_verify_finding(f, seen)
        finally:
            # The pool outlives individual findings; release the worker
            # threads (and with them, their thread-bound Chromiums) once
            # the scan generator is closed -- whether it ran to completion
            # or the consumer stopped early (GeneratorExit propagates
            # through here the same way).
            self.shutdown_headless()

    async def _scan_raw(self, url: str, method: str = "GET",
                        params: dict | None = None,
                        data: dict | None = None) -> AsyncIterator[Finding]:
        """Scan a single URL asynchronously. Yields Finding objects.

        Raises RuntimeError if aiohttp is not installed.
        """
        if not self._aiohttp_available:
            raise RuntimeError(
                "aiohttp is not installed. Install with: pip install aiohttp"
            )
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.max_concurrent)

        import aiohttp

        params = params or {}
        data = data or {}

        # Phase 142: hidden-parameter mining used to run HERE, before the
        # baseline.  It is the most request-hungry step in the scan, so at a
        # small --max-requests it spent the whole cap before the baseline was
        # even attempted, `_throttle` then rejected the baseline, and the
        # scan exited without ever building `page_tasks`.  The miner does not
        # read the baseline response, so it now runs right after it -- still
        # before the page tasks, which is all the ordering it ever needed.

        timeout = aiohttp.ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(ssl=self.verify_ssl, limit=50)
        # Phase 86: a budget/circuit stop is NOT a scan failure -- it is a
        # deliberate early stop.  Capture it, log it once, and still emit the
        # findings collected before the cap was hit (sync parity: scanner.py
        # catches the same pair in scan_target and keeps its findings).
        stop: BaseException | None = None
        try:
            async with aiohttp.ClientSession(timeout=timeout,
                                             connector=connector,
                                             **self._session_kwargs(url)
                                             ) as session:
                # 1) Baseline: get the page for reflection + DOM + advanced.
                try:
                    async with self._semaphore:
                        await self._throttle(url)
                        # Phase 47: JSON-carrier baseline -- a POST baseline
                        # in JSON mode must carry the document (as
                        # application/json) or the reflected text used for
                        # DOM/context analysis is a misleading empty/error
                        # body.
                        _dkw = _body_kwargs(
                            JsonBody(dict(self.json_body))
                            if (self.json_body is not None
                                and method.upper() != "GET")
                            else data)
                        async with session.request(
                            method, url, params=params or None,
                            headers=self._req_headers(self.headers),
                            proxy=self._next_proxy(), **_dkw,
                        ) as resp:
                            text = await resp.text()
                            status = getattr(resp, "status", 200)
                            resp_headers = dict(resp.headers)
                            self.requests_made += 1
                            self._record_status(status)
                except (BudgetExhausted, CircuitOpen):
                    raise          # Phase 86: stop the scan, never "retry"
                except Exception as e:
                    _log.warning("async baseline error: %s", e,
                                 exc_info=self.verbose)
                    return

                # 2) Hidden-parameter mining (Phase 133 sync parity, moved
                #    after the baseline by Phase 142 -- see the note above).
                #    Sync enriches the endpoint's params before probing it;
                #    without this, an endpoint whose interesting parameter has
                #    no UI hint was only probed with the params already in the
                #    URL (sync TP / async FN on pos-pmmine-01).  Discoveries
                #    override existing names, matching sync's
                #    ``{**ep_params, **extra_params}`` merge.  It stays ahead
                #    of the page tasks so the L1 probes see the new names.
                if self.advanced_layers:
                    _extra = await self._mine_hidden_params_async(url, method,
                                                                  params, data)
                    if _extra:
                        params = {**params, **_extra}

                # 3) L2 WAF detection (runs in thread -- CPU light but sync API).
                waf_info = None
                try:
                    waf_info = await asyncio.to_thread(
                        wafmod.detect, _FakeResp(text, status, resp_headers))
                    if waf_info.get("waf"):
                        self.waf_name = waf_info["waf"]
                        _log.info("async WAF detected: %s", self.waf_name)
                except Exception as e:
                    _log.debug("async WAF detect error: %s", e)

                # 3) Launch page-level detection layers in parallel.
                #    Each runs in a thread to avoid blocking the event loop.
                #    Phase 94: (name, agen) pairs so an isolated failure can
                #    be attributed to the layer that raised it.
                page_tasks = []

                # L1 reflected: per-param probe (original async behavior).
                page_tasks.append(("L1_reflected", self._scan_reflected(
                    session, url, method, params, data, text)))

                # L3 DOM static analysis.
                # Phase 176t: pass method+params.  The real-browser pass reads
                # the page, so it must be pointed at a URL that carries the
                # user-controlled query -- sync re-attaches them for exactly
                # this reason (scanner.py:479-486).  Async keeps `url` and
                # `params` apart internally, so handing the browser the bare
                # url showed it an empty location.search and made every
                # source-read DOM vector structurally unconfirmable
                # (measured: pos-dom-02 async FN / sync TP).
                if self.advanced_layers:
                    page_tasks.append(("L3_dom", self._scan_dom_async(
                        url, text, method, params)))

                # L5 advanced page layers (postMessage / prototype / SW / etc).
                # Phase 87: pass the endpoint params -- run_page_layers uses
                # them for user-controlled reflection sub-layers (import map,
                # CSSI, dangling markup); the old call left them at None so
                # those sub-layers saw no params in async mode.
                if self.advanced_layers:
                    page_tasks.append(("L5_advanced_page", self._scan_advanced_page(
                        url, text, params)))

                # Phase 87: L8 request-injection layers (header / path /
                # cookie / error-page XSS).  Async mode never called
                # run_request_layers, so these four carrier classes went
                # completely untested in --async scans.
                if self.advanced_layers:
                    page_tasks.append(("L8_request", self._scan_request_layers(
                        url, method, params, data)))

                # L6 CSP analysis.
                if self.advanced_layers:
                    page_tasks.append(("L6_csp", self._scan_csp_async(
                        url, resp_headers)))

                # L6 JSONP callback detection.
                if self.advanced_layers:
                    page_tasks.append(("L6_jsonp", self._scan_jsonp_async(
                        url, method, params, data)))

                # Phase 54: sync parity -- L7 CORS origin-reflection audit and
                # the opt-in XS-Leaks surface audit.
                if self.advanced_layers:
                    page_tasks.append(("L7_cors", self._scan_cors_async(
                        session, url, method)))
                if self.advanced_layers and self.xsleak_audit:
                    page_tasks.append(("L7_xsleaks", self._scan_xsleak_audit_async(
                        url, resp_headers)))

                # Phase 58/63: multipart upload-filename probing parity (sync
                # Phase 48) -- body-carrying endpoints without a JSON carrier
                # (POST, plus PUT/PATCH RESTful uploads), matching the sync
                # trigger.
                if self.advanced_layers and self.upload_fields \
                        and method.upper() in ("POST", "PUT", "PATCH") \
                        and self.json_body is None:
                    self._upload_method = method.upper()
                    page_tasks.append(("L9_upload", self._probe_upload_async(
                        session, url, params, data)))

                # L4 blind/OOB injection (if listener configured).
                if self.oob:
                    page_tasks.append(("L4_blind", self._inject_blind_async(
                        session, url, method, params, data)))

                # Stream findings as they complete.  NOTE (Phase 43 fix): the
                # old code passed async generators to asyncio.as_completed(),
                # which requires awaitables -- async generators are NOT
                # awaitables, so every scan() raised TypeError here (silently
                # swallowed upstream, leaving async mode with zero findings).
                # Drain via tasks instead: layers stay concurrent, per-layer
                # exceptions stay isolated, and results come back in
                # completion order.
                sink: list = []
                drain_tasks = [asyncio.create_task(
                                   _drain_agen(g, sink, name=name))
                               for name, g in page_tasks]
                if drain_tasks:
                    # Phase 86: gather with return_exceptions so one layer's
                    # budget stop does not orphan its siblings (plain gather
                    # re-raises immediately and leaves the rest running), then
                    # re-raise the stop AFTER the findings already collected
                    # in ``sink`` have been emitted below.
                    results = await asyncio.gather(*drain_tasks,
                                                   return_exceptions=True)
                    stop = next((r for r in results
                                 if isinstance(r, (BudgetExhausted,
                                                   CircuitOpen))), None)
                for finding in sink:
                    await self._add_finding(finding)
                    yield finding
                if stop is not None:
                    raise stop

                # 4) Optional crawl: discover more endpoints and scan them.
                if self.crawl:
                    async for finding in self._crawl_and_scan(session, url, text):
                        await self._add_finding(finding)
                        yield finding
        except (BudgetExhausted, CircuitOpen) as e:
            # Phase 86: graceful early stop (sync parity: scanner.py logs and
            # keeps its findings).  Findings already yielded above stay with
            # the caller; the pending OOB poll below still runs because a
            # callback is proof of execution we must not throw away.
            stop = e

        if stop is not None:
            self._log_budget_stop(stop)
        # 5) L4 blind: batch-collect OOB callbacks after ALL injections
        # (sync collect_oob parity).  Only callbacks become findings.
        if self.oob and self._oob_pending:
            async for finding in self.collect_oob_async():
                await self._add_finding(finding)
                yield finding

    async def _scan_reflected(self, session, url: str, method: str,
                              params: dict, data: dict,
                              baseline_text: str
                              ) -> AsyncIterator[Finding]:
        """L1 reflected XSS: probe each parameter with context-aware payloads."""
        # Phase 47: JSON-carrier mode -- body params are the LEAF paths of
        # the document (sync scan_endpoint parity), so nested API bodies get
        # full payload coverage in async mode too.  The old code only ever
        # probed top-level ``data`` keys, so {user:{name:..}} endpoints were
        # scanned against zero body params.
        if self.json_body is not None:
            param_items = [(p, False) for p in params] + \
                          [(path, True)
                           for path in json_leaf_paths(self.json_body)]
        else:
            param_items = [(p, False) for p in params] + \
                          [(p, True) for p in data]
        # Phase 184: operator --skip-param (getattr for __new__-built
        # scanners).
        _skip = getattr(self, "skip_params", None) or set()
        if _skip:
            param_items = [(p, b) for p, b in param_items
                           if str(p).lower() not in _skip]
        # Phase 43 fix: _probe_param returns async GENERATORS, which
        # asyncio.as_completed() rejects (not awaitables) -- the whole L1
        # layer silently produced nothing under scan().  Drain via tasks.
        sink: list = []
        tasks = []
        for param, is_body in param_items:
            tasks.append(asyncio.create_task(_drain_agen(
                self._probe_param(session, url, method, param, params, data,
                                  is_body, baseline_text), sink,
                name=f"L1_param:{param}")))
        stop = None
        if tasks:
            # Phase 86: return_exceptions so one param's budget stop does not
            # orphan its siblings; the stop is re-raised (below) only after
            # the findings collected so far have been yielded.
            results = await asyncio.gather(*tasks, return_exceptions=True)
            stop = next((r for r in results
                         if isinstance(r, (BudgetExhausted, CircuitOpen))),
                        None)
        for finding in sink:
            yield finding
        if stop is not None:
            raise stop

    async def _probe_param(self, session, url: str, method: str,
                           param: str, params: dict, data: dict,
                           is_body: bool, baseline_text: str
                           ) -> AsyncIterator[Finding]:
        """Probe a single parameter for XSS. Yields findings."""
        stem = _stem_marker("xssentinel_async_")
        marker = f"{stem}{param}_{secrets.token_hex(2)}"
        probe_params, probe_data = self._probe_kv(
            params, data, param, marker, is_body)
        try:
            async with self._semaphore:
                await self._throttle(url)
                async with session.request(
                    method, url, params=probe_params or None,
                    headers=self._req_headers(self.headers), proxy=self._next_proxy(),
                    **_body_kwargs(probe_data),
                ) as resp:
                    text = await resp.text()
                    # Phase 100: keep this response's headers AND body --
                    # the CSP nonce-leak exploit (sync _try_csp_nonce
                    # parity) runs on the marker-reflection response.  The
                    # loop below overwrites ``text`` on every variant, so
                    # without this snapshot the exploit inspects the LAST
                    # payload's response, where the marker (and thus the
                    # nonce-proximity check) is gone.
                    probe_headers = dict(getattr(resp, "headers", None) or {})
                    probe_text = text
                    self.requests_made += 1
                    self._record_status(getattr(resp, "status", 200))
        except (BudgetExhausted, CircuitOpen):
            raise        # Phase 86: never treated as "this param failed"
        except Exception:
            return
        if marker not in text:
            # Phase 178c (sync parity): a container param whose endpoint
            # echoes only the DECODED value never reflects a plain marker
            # probe -- try the pre-encode pipeline from the ORIGINAL value
            # before giving up (Range3 /gob64: 0 probes, silent FN).
            orig_value0 = (data.get(param) if is_body
                           else params.get(param)) or ""
            enc0 = (pre_mod.detect_structure(orig_value0)
                    if orig_value0 else "none")
            if enc0 != "none":
                async for f in self._try_pre_encoded_async(
                        session, url, method, param, params, data, is_body,
                        orig_value0, enc0, "html_element", marker):
                    yield f
                return

        # Classify context (CPU-bound) -- run in thread.
        # `ctx.classify` never existed: this call raised AttributeError on every
        # parameter and the bare `except` swallowed it, so the async engine
        # selected payloads from "html_element" ALWAYS -- the url_href / cdata /
        # css sibling corpora were never consulted, which is why it could spend
        # 104 requests and still miss pos-url-04 and pos-cdata-01 that sync
        # confirms with 59.  Now uses the same function sync uses, with NO
        # swallow: a broken wiring must surface as a failed layer, not as a
        # silently degraded scan (`core/layer_guard.py` exists because this
        # pattern hid the async L1 outage in Phase 63).
        # Phase 177: classify EVERY reflection point (sync parity via the
        # same shared analyzer) -- the first byte-stream occurrence is
        # frequently an inert comment/nav highlight while the live sink
        # comes later; picking by execution priority is the whole fix.
        # Single-reflection pages keep exactly the old answer.
        _sel = await asyncio.to_thread(ctx.analyze_all, text, marker)
        context = _sel["context"]
        _extra_contexts = [c for c in _sel["contexts"] if c != context][:2]

        # Phase 93: escaped-reflection convergence (sync parity).  When the
        # marker reflects but the input around it is HTML-encoded, the
        # server is doing context-aware output encoding and almost every
        # payload variant will be encoded too.  The sync engine has shrunk
        # its budget for this case since Phase 27-1 (3 payloads x 2
        # transforms instead of max_payloads x max_transforms); async had
        # no equivalent, so once the Phase 91/92 verifier stopped
        # wrongly confirming those reflections the async path paid the
        # whole 168-request budget -- neg-escape-03 went from ~2s to ~23s.
        marker_escaped = await asyncio.to_thread(
            ctx.is_marker_escaped, text, marker)

        # Phase 35: structured-param pre-encoding (parity with the sync
        # scanner).  Container values (base64/JWT/JSON) never see raw
        # payloads -- fire container-wrapped probes first; a hit ends the
        # param, a miss falls through to the plain-text loop.
        orig_value = (data.get(param) if is_body else params.get(param)) or ""
        enc_struct = pre_mod.detect_structure(orig_value)
        if enc_struct != "none":
            async for f in self._try_pre_encoded_async(
                    session, url, method, param, params, data, is_body,
                    orig_value, enc_struct, context, marker):
                yield f
            return

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
                        headers=self._req_headers(self.headers), proxy=self._next_proxy(),
                        **_body_kwargs(sd),
                    ) as resp2:
                        ptext = await resp2.text()
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
                            text = await resp.text()
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
                    yield Finding(
                        url=url, method=method, param=param,
                        context=v.get("context") or context,
                        payload=variant,
                        severity=_non_html_grade(resp_headers)[0],
                        evidence=text[max(0, text.find(marker)-30):
                                      text.find(marker)+len(marker)+30],
                        type="reflected",
                        confidence=_non_html_grade(resp_headers)[1],
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
                                    text = await resp.text()
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
                            yield Finding(
                                url=url, method=method, param=param,
                                context=v.get("context") or context,
                                payload=variant,
                                severity=_non_html_grade(resp_headers)[0],
                                evidence=text[max(0, idx - 30):
                                              idx + len(marker) + 30],
                                type="reflected",
                                confidence=_non_html_grade(resp_headers)[1],
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
                            text = await resp.text()
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
                        context=v.get("context") or context,
                        payload=marked,
                        severity=_non_html_grade(resp_headers)[0],
                        evidence=text[max(0, idx - 30):idx + len(marker) + 30],
                        type="reflected",
                        confidence=_non_html_grade(resp_headers)[1],
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
                                text = await resp.text()
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
                            context=v.get("context") or context,
                            payload=variant,
                            severity=_non_html_grade(resp_headers)[0],
                            evidence=text[max(0, idx - 30):
                                          idx + len(marker) + 30],
                            type="reflected",
                            confidence=_non_html_grade(resp_headers)[1],
                            transform=tchain,
                            param_in="body" if is_body else "query",
                            evidence_class=EVIDENCE_MODEL,
                        )
                        break

        # Phase 100: CSP nonce-leak exploitation (sync _try_csp_nonce
        # parity).  A nonce CSP blocks plain inline payloads, so the loop
        # above ends unconfirmed -- but when the nonce itself is echoed
        # into the page (the classic "nonce in a template/JSON blob" leak)
        # a script carrying the REAL nonce executes.  The async path had no
        # equivalent, so --async silently missed every nonce-leak endpoint
        # that sync reported (pos-csp-01: sync TP, async FN).
        #
        # The verifier allowlists the nonce against the response's own CSP
        # header, so a server that rotates nonces per request still cannot
        # be falsely confirmed.
        csp_hdr = ""
        try:
            csp_hdr = probe_headers.get("Content-Security-Policy") or ""
        except Exception:
            csp_hdr = ""
        # Phase 132: also gated on ``not param_confirmed`` -- sync's nonce
        # step (scanner.py:656) carries the same guard, and the block is
        # only reached on an unconfirmed param anyway.
        if not param_confirmed and csp_hdr:
            try:
                _nonces = csp_mod.extract_nonces_from_csp(csp_hdr)
            except Exception:
                _nonces = []
            if _nonces:
                try:
                    _near = csp_mod.detect_nonce_near_marker(
                        csp_hdr, probe_text or text or "", marker)
                except Exception:
                    _near = {}
                if _near.get("nonce_exposed_near_marker"):
                    _n = _near.get("nonce_value") or _nonces[0]
                    _ntok = "xssv_" + secrets.token_hex(4)
                    _npay = (f"<script nonce='{_n}'>"
                             f"alert('{_ntok}')</script>")
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
                                _ntext = await nresp.text()
                                _nhdrs = dict(
                                    getattr(nresp, "headers", None) or {})
                                self.requests_made += 1
                                self._record_status(
                                    getattr(nresp, "status", 200))
                    except (BudgetExhausted, CircuitOpen):
                        raise
                    except Exception:
                        _ntext = ""
                        _nhdrs = {}
                    if _ntext:
                        _nv = await asyncio.to_thread(
                            verifier.verify_semantic, _ntext, _ntok,
                            response_headers=_nhdrs)
                        if (_nv.get("confirmed") and
                                verifier.payload_survived(_ntext, _npay)):
                            _idx = _ntext.find(_ntok)
                            yield Finding(
                                url=url, method=method, param=param,
                                context=_nv.get("context") or context,
                                payload=_npay,
                                severity=_non_html_grade(resp_headers)[0],
                                evidence=_ntext[max(0, _idx - 30):
                                                _idx + len(_ntok) + 30],
                        type="reflected",
                        confidence=_non_html_grade(resp_headers)[1],
                        transform=["csp_nonce"],
                        param_in="body" if is_body else "query",
                        evidence_class=EVIDENCE_MODEL,
                    )

        # Phase 187: CSP gadget chain (sync _try_csp_gadget parity).  A strict
        # script-src that still allowlists a known gadget host (JSONP endpoint,
        # Angular CDN, ...) re-opens script execution; inline payloads cannot
        # confirm it.  Framework-gadget payloads (Angular template expression)
        # confirm through the SAME static template_angular machinery the
        # corpus uses; JSONP-shaped ones have no honest static verdict (the
        # token rides a src attribute) -- sync measures those under headless,
        # the async emission stays on the static machinery like every other
        # finding here.  Capped at two gadget payloads per (url, param).
        if not param_confirmed and csp_hdr:
            try:
                _gadgets = csp_mod.gadget_bypass_payloads(csp_hdr)
            except Exception:
                _gadgets = []
            _gtried = getattr(self, "_csp_gadget_tried", None)
            if _gtried is None:
                _gtried = set()
                self._csp_gadget_tried = _gtried
            if ((url, param) not in _gtried
                    and csp_mod.gadget_chain_relevant(csp_hdr)):
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
                                _gtext = await gresp.text()
                                _ghdrs = dict(
                                    getattr(gresp, "headers", None) or {})
                                self.requests_made += 1
                                self._record_status(
                                    getattr(gresp, "status", 200))
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
                        # JSONP-shaped gadgets have no honest static verdict
                        # (the token rides a src attribute).  Sync measures
                        # those under headless; here the Phase-183 wrapper is
                        # the browser -- but only when one EXISTS.  Without
                        # Playwright the emission would be a browserless
                        # claim sync never makes, so stay silent instead.
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
                                f"'{_g['host']}' which hosts "
                                f"{_g['gadget']}; the JSONP gadget payload "
                                "reflected.  Static verdict is honestly "
                                "silent (the token rides a src attribute) "
                                "-- browser confirmation pending."),
                        )
                        break
                    if not verifier.payload_survived(_gtext, _gpay):
                        continue
                    _gidx = _gtext.find(_gtok)
                    yield Finding(
                        url=url, method=method, param=param,
                        context=_gv.get("context") or context,
                        payload=_gpay,
                        severity=_non_html_grade(_ghdrs)[0],
                        evidence=_gtext[max(0, _gidx - 30):
                                        _gidx + len(_gtok) + 30],
                        type="reflected",
                        confidence=_non_html_grade(_ghdrs)[1],
                        transform=["csp_gadget"],
                        param_in="body" if is_body else "query",
                        evidence_class=EVIDENCE_MODEL,
                    )
                    break

        # Phase 193: HPP (HTTP Parameter Pollution, sync _try_hpp parity).
        # The parameter is sent twice -- first occurrence benign, second the
        # payload; a filter inspecting only the first occurrence passes the
        # request while the backend renders the payload occurrence.  WAF
        # gate mirrors sync (no WAF, no reason); query position only this
        # round; capped at two payloads per (url, param).
        if self.waf_name and not param_confirmed and not is_body:
            _htried = getattr(self, "_hpp_tried", None)
            if _htried is None:
                _htried = set()
                self._hpp_tried = _htried
            if (url, param) not in _htried:
                _htried.add((url, param))
                for _cand in cands[:2]:
                    _htok = "xssv_" + secrets.token_hex(4)
                    _hpay = verifier.mark(_cand, _htok)
                    if _hpay == _cand:
                        continue
                    _hpairs = [(k, v) for k, v in (params or {}).items()
                               if k != param]
                    _hpairs.append((param, "xsssafe"))
                    _hpairs.append((param, _hpay))
                    try:
                        async with self._semaphore:
                            await self._throttle(url)
                            async with session.request(
                                method, url, params=_hpairs,
                                headers=self._req_headers(self.headers),
                                proxy=self._next_proxy(),
                                **_body_kwargs(data),
                            ) as hresp:
                                _htext = await hresp.text()
                                _hhdrs = dict(
                                    getattr(hresp, "headers", None) or {})
                                self.requests_made += 1
                                self._record_status(
                                    getattr(hresp, "status", 200))
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
                        context=_hv.get("context") or context,
                        payload=_hpay,
                        severity="high",
                        evidence=_htext[max(0, _hidx - 30):
                                        _hidx + len(_htok) + 30],
                        type="reflected",
                        confidence="high",
                        transform=["hpp"],
                        param_in="query",
                        evidence_class=EVIDENCE_MODEL,
                        detail=(
                            "HPP: the parameter was sent twice (first "
                            "occurrence benign, second the payload) and "
                            "the payload-carrying occurrence is what the "
                            "application rendered -- a filter inspecting "
                            "only the first occurrence was bypassed"),
                    )
                    break

        # Phase 132: L7 parameter layers (mutation / DOM clobber / template
        # / polyglot / markdown).  Sync reaches these at the end of
        # ``_scan_param``; async stopped after the CSP-nonce block, so the
        # whole family was async-only FN.  Reached only when the marker
        # actually reflected, matching the sync call site.
        async for _f in self._scan_advanced_param_layers(
                url, method, params, data, param, is_body, marker,
                probe_text or text or ""):
            yield _f

        # Phase 176s: time-based (OOB) fallback -- sync parity with
        # scanner.py:1122.  The marker reflected but nothing confirmed, so
        # a strict CSP is the prime suspect; resource-fetch payloads prove
        # the markup was parsed as HTML even when inline script is blocked.
        # Reached only when this param produced no confirmed finding, and
        # only with an OOB listener configured (same guards as sync).
        if self.oob and self.advanced_layers and not param_confirmed:
            async for _f in self._scan_time_based(url, method, params, data,
                                                  param, is_body):
                yield _f

    def _build_variants(self, marked: str, context: str, marker: str,
                        cap_override: int | None = None
                        ) -> list[tuple[list[str], str]]:
        """Phase 86: build the WAF/filter evasion variants of ``marked``.

        Mirror of the sync ``Scanner._try_payload`` variant ladder (the
        async path previously had none, so ``max_transforms`` was dead
        config).  Same sources, same order, same cap:

          1. the static ``_DEFAULT_TRANSFORMS`` ladder (base first);
          2. context-aware mutations from ctx_mutation (Phase 13b);
          3. multi-encoding chains (Phase 13c) -- WAF detected only;
          4. WAF-specific bypass chains (Phase 29-2) -- WAF detected only.

        The token stays inside ``marked``: transforms are applied to the
        whole MARKED payload exactly like the sync engine does, so the
        verifier can still attribute the hit to this param.  Duplicate
        variants are dropped -- they cost a request and can prove nothing.

        Phase 93: ``cap_override`` reproduces the sync
        ``max_transforms_override=2`` for escaped reflections.
        """
        cap = max(1, int(cap_override or self.max_transforms or 1))
        variants: list[tuple[list[str], str]] = []

        def _add(chain, variant):
            if len(variants) >= cap:
                return
            if variant and not any(v == variant for _, v in variants):
                variants.append((chain, variant))

        # Source 1: static transform ladder (always, cheapest first).
        for tset in _DEFAULT_TRANSFORMS[:cap]:
            variant = marked
            for t in tset:
                variant = transform_mod.apply(t, variant)
            _add(list(tset), variant)

        # Source 2: context-aware mutations (Phase 13b parity).
        if len(variants) < cap:
            try:
                from . import ctx_mutation as ctx_mut
                for chain, variant in ctx_mut.mutate_for_context(
                        marked, context,
                        max_variants=max(4, cap - len(variants))):
                    if len(variants) >= cap:
                        break
                    _add(chain, variant)
            except Exception as e:
                if self.verbose:
                    _log.debug("    [!] async ctx_mutation error: %s", e)

        waf = self.waf_name
        if waf and len(variants) < cap:
            # Source 3: multi-encoding chains (Phase 13c parity).
            try:
                from . import multi_encode as me_mod
                for name, steps, variant in me_mod.all_chain_variants(
                        marked, context, waf,
                        max_variants=max(2, cap - len(variants))):
                    if len(variants) >= cap:
                        break
                    _add([f"me:{name}"], variant)
            except Exception as e:
                if self.verbose:
                    _log.debug("    [!] async multi_encode error: %s", e)
            # Source 4: WAF-specific bypass chains (Phase 29-2 parity).
            try:
                for _waf, base, chain, _why in bypass_mod.chains_for_waf(waf):
                    if len(variants) >= cap:
                        break
                    try:
                        variant = bypass_mod.apply_chain(
                            verifier.mark(base, marker), chain)
                    except Exception:
                        variant = base
                    _add([f"bp:{waf}"], variant)
            except Exception as e:
                if self.verbose:
                    _log.debug("    [!] async bypass_chain error: %s", e)

        return variants

    async def _add_finding(self, finding: Finding) -> None:
        """Thread-safe append to the findings list."""
        async with self._get_lock():
            self.findings.append(finding)

    def _log_budget_stop(self, exc: BaseException) -> None:
        """Phase 86: record + report a budget/circuit stop exactly once.

        ``_throttle()`` already filled ``budget_exhausted_reason``; before
        Phase 86 nothing ever read it, so an operator hitting --max-requests
        got a normal-looking scan with no explanation.  Mirror the sync
        scanner's warning (scanner.py) and keep the reason on the instance
        so callers/reports can surface it.
        """
        reason = str(exc) or exc.__class__.__name__
        self.budget_exhausted_reason = reason
        _log.warning("[!] Async scan stopped early (%s) -- findings so far: "
                     "%d", reason, len(self.findings))

    def _record_status(self, status: int) -> None:
        """Feed one response status into the circuit breaker (Phase 46).

        Called inline right after each response is read; a failure streak
        of ``breaker_threshold`` 5xx/429 responses within 120s trips the
        breaker and _throttle() starts raising CircuitOpen.
        """
        if self.breaker_threshold <= 0:
            return
        if status >= 500 or status == 429:
            now = time.monotonic()
            self._fail_times = [t for t in self._fail_times
                                if now - t <= 120.0]
            self._fail_times.append(now)
        else:
            self._fail_times.clear()

    def _probe_kv(self, params: dict, data: dict, param: str, value,
                  is_body: bool) -> tuple[dict, dict]:
        """Clone the endpoint inputs and set ``param`` to ``value`` on the
        right carrier (sync Scanner._set_param parity, Phase 47).

        Form mode: a body param lands in the form dict.  JSON mode: a body
        ``param`` is a LEAF PATH of the document ("user.name", "tags[0]")
        -- the value is set inside a deep copy and the result wrapped in
        JsonBody so the request goes out as application/json.
        """
        p = dict(params)
        if is_body and self.json_body is not None:
            try:
                obj = copy.deepcopy(self.json_body)
                _set_json_leaf(obj, param, value)
            except Exception:
                obj = dict(self.json_body)
                obj[param] = value
            return p, JsonBody(obj)
        d = dict(data)
        if is_body:
            d[param] = value
        else:
            p[param] = value
        return p, d

    async def _throttle(self, url: str) -> None:
        """Apply global rate limiting, per-host delay, jitter, and the
        request budget.  Raises BudgetExhausted / CircuitOpen when a cap
        is spent / the breaker tripped."""
        from urllib.parse import urlparse
        import random

        # -- budget + breaker check (always runs, even with no delay) -----
        async with self._get_lock():
            if self.max_requests is not None \
                    and self.requests_made >= self.max_requests:
                self.budget_exhausted_reason = (
                    f"total request budget exhausted "
                    f"(>={self.max_requests} requests)")
                raise BudgetExhausted(self.budget_exhausted_reason)
            if self.breaker_threshold > 0 \
                    and len(self._fail_times) >= self.breaker_threshold:
                self.budget_exhausted_reason = (
                    f"circuit open: {len(self._fail_times)} recent "
                    f"5xx/429 responses from the target")
                raise CircuitOpen(self.budget_exhausted_reason)
            if self.max_requests_per_endpoint is not None:
                p = urlparse(url)
                key = f"{p.scheme}://{p.netloc}{p.path}"
                count = self._ep_counts.get(key, 0)
                if count >= self.max_requests_per_endpoint:
                    self.budget_exhausted_reason = (
                        f"per-endpoint request budget exhausted for "
                        f"{key} (>={self.max_requests_per_endpoint} requests)")
                    raise BudgetExhausted(self.budget_exhausted_reason)
                self._ep_counts[key] = count + 1
            # -- global rate limit (token-interval style) ------------------
            if self._min_interval > 0:
                now = time.monotonic()
                wait = self._min_interval - (now - self._last_global_request)
                if wait > 0:
                    if self.jitter_ratio > 0:
                        wait = jitter_interval(wait, self.jitter_ratio)
                    await asyncio.sleep(wait)
                self._last_global_request = time.monotonic()

        # -- per-host delay + jitter (best-effort, no lock needed) --------
        if self.per_host_delay <= 0 and self.jitter <= 0:
            return
        host = urlparse(url).netloc
        now = time.monotonic()
        last = self._last_request_time.get(host, 0.0)
        elapsed = now - last
        wait = self.per_host_delay - elapsed
        if self.jitter > 0:
            wait += self.jitter * (0.5 + random.random())
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_request_time[host] = time.monotonic()












def is_available() -> bool:
    """Whether async scanning is available (aiohttp installed)."""
    try:
        import aiohttp  # noqa: F401  (可选依赖可用性探测:导入即使用)
        return True
    except ImportError:
        return False
