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
from urllib.parse import urljoin, urlparse

from .scanner import Finding, json_leaf_paths, _set_json_leaf
from .requester import JsonBody
from .page_relevance import redirect_landing_drops_input
from . import csp as csp_mod
from . import document_kind as dk_mod
from . import context as ctx
from . import coverage as cov_mod
from . import verifier
from . import waf as wafmod
from . import bypass as bypass_mod
# Phase 91/208: the polyglot probe and its grading live with the variant
# loop now (async_scanner_layers._fire_probe_variants, Phase 211 round 3).
# Phase 35: pre-encoding pipeline parity with the sync scanner (Phase 34).
from . import pre_encode as pre_mod
# Phase 37/43/96: corpus sampling, reflection profile and generative payloads
# now live in async_scanner_layers._build_probe_candidates (Phase 211 round 2).
# Phase 100 / 187: CSP nonce-leak and gadget-chain exploitation now live in
# async_scanner_layers (_probe_csp_nonce / _probe_csp_gadget), which is where
# the Phase 65 dom_engine import also moved to (Phase 211 first cut).
#
# Phase 221: that move silently deleted a NAME other code patched.  Both
# tests/test_async_deep.py and tests/test_async_wiring.py reach the DOM
# engine through `patch("xssentinel.core.async_scanner.dom_engine_mod....")`
# and `monkeypatch.setattr(ASYNC.dom_engine_mod, ...)`; with the alias gone
# they died with ModuleNotFoundError / AttributeError, which is exactly the
# signature of a move that forgot a re-export.  The binding is re-asserted
# here for that reason ONLY -- the LAYER code must keep using
# async_scanner_layers' own binding, or patching this alias would stop
# steering anything (same trap the _EGRESS_JAR note below describes).
from . import dom_engine as dom_engine_mod  # noqa: F401  (re-export)
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
    # Phase 211 round 3: grading and the fire-state now belong to the
    # variant loop in async_scanner_layers.
    _ProbeFireState,
    safe_accept_encoding,
)
from .async_scanner_verify import AsyncHeadlessVerifyMixin
from .async_scanner_layers import AsyncDetectionLayersMixin
from .async_scanner_crawl import AsyncCrawlMixin






from .findings import _DEFAULT_TRANSFORMS, cap_unverified_severity  # noqa: E402
from . import transform as transform_mod  # noqa: E402
from .stealth import (marker as _stem_marker, HeaderRotator as _HeaderRotator, ProxyPool as _ProxyPool,  # noqa: E402
                      jitter_interval, load_proxies as _load_proxies)


# Phase 290: which endpoint the scan is currently working on.  Request
# counting must attribute to THIS url, not to the probe url -- the path /
# error-page layers inject payloads into the URL itself, so counting by
# probe url invented 17 extra endpoint rows in the report (measured on the
# parity fixture: 20 rows for 3 real endpoints).  Set by _scan_raw (seed)
# and by the crawl's page-layer bundle (crawled pages); the layers that
# self-record pass the scan url themselves.
_current_scan_url: str | None = None


def _set_current_scan_url(url: str | None) -> None:
    global _current_scan_url
    _current_scan_url = url


def _attributed_url(probe_url) -> str:
    """The endpoint a request should be counted against."""
    return _current_scan_url or str(probe_url)


class _CountingSession:
    """Phase 290: aiohttp session wrapper that counts every request.

    Async issues its traffic through ~21 scattered ``session.get/post/
    request`` sites across three files; counting at each site would be
    mechanical and easy to miss one.  The wrapper counts the four verbs
    explicitly and delegates everything else (``close``, ``cookie_jar``,
    ``headers``, the context-manager protocol, ...) untouched via
    ``__getattr__``, so no call site can tell the difference.

    The count feeds ``CoverageTracker.record_request`` -- the same tracker
    the sync engine has filled since Phase 20-3.  Before this, an --async
    report claimed "0 requests" while the scan was making hundreds.
    """

    def __init__(self, session, coverage):
        self._session = session
        self._coverage = coverage

    def _count(self, method: str, url) -> None:
        try:
            self._coverage.record_request(_attributed_url(url), method)
        except Exception:
            pass  # the instrument must never break the scan

    # NB: these are PLAIN methods on purpose.  aiohttp's verb methods return
    # a _RequestContextManager, which is BOTH awaitable and an async context
    # manager; call sites use both spellings (``await session.get(...)`` and
    # ``async with session.get(...)``).  An ``async def`` wrapper would
    # return a coroutine, breaking every ``async with`` site -- measured:
    # async dropped from 4 findings to 0 on the parity fixture.  Counting
    # then returning the original call's object keeps both spellings intact.
    def request(self, method, url, **kw):
        self._count(method.upper(), url)
        return self._session.request(method, url, **kw)

    def get(self, url, **kw):
        self._count("GET", url)
        return self._session.get(url, **kw)

    def post(self, url, **kw):
        self._count("POST", url)
        return self._session.post(url, **kw)

    def put(self, url, **kw):
        self._count("PUT", url)
        return self._session.put(url, **kw)

    def patch(self, url, **kw):
        self._count("PATCH", url)
        return self._session.patch(url, **kw)

    def delete(self, url, **kw):
        self._count("DELETE", url)
        return self._session.delete(url, **kw)

    def head(self, url, **kw):
        self._count("HEAD", url)
        return self._session.head(url, **kw)

    def __getattr__(self, name):
        return getattr(self._session, name)




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
        # Phase 290: the coverage tracker the sync engine has had since
        # Phase 20-3.  Without it every --async report's coverage section
        # read "0 endpoints / 0% layers / 0 requests" for a scan that had
        # just produced findings -- a silently zeroed instrument, the same
        # bug family as the Phase 267 range gate that passed with the
        # browser never having run.  The tracker is thread-safe (its own
        # lock), which matters because the layers run via to_thread.
        self.coverage = cov_mod.CoverageTracker()
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
        # Phase 208: silence is a stronger signal than a 5xx, so it stops
        # the scan sooner -- same rule as CircuitBreaker.transport_threshold.
        self._transport_threshold = max(
            1, min(self.breaker_threshold or 1, 5)
        ) if self.breaker_threshold > 0 else 0
        self._fail_times: list[float] = []
        # Phase 208: requests that never got a response, kept apart from
        # 5xx/429 responses.  Same reasoning as CircuitBreaker: one bad
        # endpoint is worth retrying elsewhere, a target that is not
        # answering at all is worth stopping for.
        self._fail_silent: list[float] = []
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
        # Phase 208: async parity for the completeness gate.  The sync engine
        # reports both `attempted` and `failed` (Requester.tally), and
        # __main__'s exit-3 rule needs the pair: "attempted N, M of them never
        # answered" is the difference between a clean target and one that was
        # never reached.  Async had `requests_made` only, so the CLI printed
        # "completeness check offline" and an async scan that found nothing
        # was indistinguishable from one that never touched the target.
        self.failed_requests = 0
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
            base = merged
        # Phase 209: advertise only what aiohttp can decode.  A browser-shaped
        # bundle that promises `br` the decoder cannot handle makes the TARGET
        # answer in that encoding, and then every response -- baseline included
        # -- raises `Can not decode content-encoding: br`, which is how --async
        # reported 0 findings against a healthy real application.  An operator
        # who set the header by hand wins: they know their own proxy.
        if not any(k.lower() == "accept-encoding" for k in base):
            base["Accept-Encoding"] = safe_accept_encoding()
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

    @staticmethod
    def _transport_is_real(aiohttp_mod, session) -> bool:
        """Is this session a genuine aiohttp transport, or a stand-in?

        Phase 208.  ``_sync_layers_online`` gates whether the thread-
        offloaded sync layers may speak HTTP (``_get_sync_requester``
        otherwise installs ``_OfflineSession``).  It has to be answered by
        the transport that will actually carry their requests, because the
        decision is "may I go to the network", and only the real thing can
        grant that.

        Checked in the order that costs the least and settles it fastest:

        * ``aiohttp`` must already be in ``sys.modules`` under its real
          name.  The usual substitution replaces the module object, so
          this is what catches ``sys.modules["aiohttp"] = fake`` -- and it
          is checked against the live registry rather than the module's own
          ``__name__`` attribute, which a fake sets to "aiohttp" for free
          (``types.ModuleType("aiohttp")`` passes that test; measured, see
          the test of the same name).
        * the session must be an instance of the genuine
          ``ClientSession`` class, so a stub that returns some other object
          is still refused;
        * that class must be defined *by* the aiohttp package -- a fake
          module whose ``ClientSession`` is the real class is still the
          fake in charge of handing it out.

        An unrecognised answer is treated as NOT real.  That direction is
        deliberate: a wrongly-offline layer degrades to its own
        ``except Exception`` (a missed probe), while a wrongly-online layer
        sends the operator's credentials somewhere a test named.
        """
        import sys as _sys
        if _sys.modules.get("aiohttp") is not aiohttp_mod:
            return False
        real_session = getattr(aiohttp_mod, "ClientSession", None)
        if real_session is None or not isinstance(real_session, type):
            return False
        if not isinstance(session, real_session):
            return False
        # The class must come from the aiohttp package itself, not from
        # whatever module merely handed it out.
        return getattr(real_session, "__module__", "").split(".")[0] == "aiohttp"

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
                # Phase 218: the evidence-shape severity cap at the engine's
                # FINAL yield -- after any in-place evidence mutation, so a
                # finding is capped on its last word, not its first.
                cap_unverified_severity(f.data)
                yield f
            return
        try:
            seen: set = set()
            async for f in self._scan_raw(url, method, params, data):
                f = await self._headless_verify_finding(f, seen)
                cap_unverified_severity(f.data)
                yield f
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
        # Phase 290: every request issued below is attributed to THIS
        # endpoint (see _attributed_url); the crawl overrides it per page.
        _set_current_scan_url(url)

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
                # Phase 290: count every request the scan makes.  Async
                # issues its traffic through ~21 scattered aiohttp call
                # sites (session.get/post/request across three files), so
                # the count is taken once here, at the session boundary,
                # rather than at each site.  Everything else delegates
                # untouched.
                session = _CountingSession(session, self.coverage)
                # Phase 200: a real aiohttp transport is now active, so the
                # thread-offloaded sync layers (L7 advanced params, crawl
                # mining, transport layers) may use their sync Requester.
                # Without this flag, tests that drive _probe_param with a
                # STUB session leaked the layers' probes through a real
                # Requester to whatever host the test named -- each
                # unresolvable lookup costing seconds of DNS timeout on a
                # degraded resolver (measured: 6 leaked requests x 7-11s
                # = the "55s per _probe_param" recorded in 3.8).
                #
                # Phase 208: this used to be set unconditionally on ENTRY
                # to the block, which only proves we got inside
                # ``async with``.  The guard it feeds asks a different
                # question -- "is there a live TRANSPORT?" -- and a test
                # that replaces sys.modules["aiohttp"] with a stub enters
                # this block perfectly happily while speaking no HTTP at
                # all.  The flag therefore read True over a fake session
                # and _get_sync_requester handed the sync layers a REAL
                # requests.Session; _scan_cookie_tossing / _scan_header_xss
                # then did req.get() against the stub-session's host name
                # and blocked in getaddrinfo forever.  That is not a test
                # annoyance: it is the same reachable-by-a-real-scan path
                # that left range3's /admin/report wedged, and it hung the
                # whole CI run at 2%.
                #
                # Decide from the module that actually built the session, so
                # a substituted aiohttp keeps the layers offline.  The real
                # ClientSession is a class from the genuine module; a stub is
                # a stand-in, and type(session).__module__ names the package
                # that defined it.
                # Phase 290: ask about the UNDERLYING aiohttp session --
                # _transport_is_real does an isinstance check, and the
                # counting wrapper is not a ClientSession.  Judging the
                # wrapper made every thread-offloaded sync layer believe
                # the transport was a stub, so they degraded to
                # _OfflineSession and produced zero findings (measured:
                # the header/path XSS test went from 2 findings to 0).
                self._sync_layers_online = self._transport_is_real(
                    aiohttp, getattr(session, "_session", session))
                # 1) Baseline: get the page for reflection + DOM + advanced.
                final_url = ""
                redirected = False
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
                            final_url = str(getattr(resp, "url", "") or "")
                            redirected = bool(
                                getattr(resp, "history", None) or ())
                            self.requests_made += 1
                            self._record_status(status)
                except (BudgetExhausted, CircuitOpen):
                    raise          # Phase 86: stop the scan, never "retry"
                except Exception as e:
                    # Phase 208: the baseline is the request that proves the
                    # target answers at all.  If it never came back, every
                    # later "0 findings" is an absence of evidence, not
                    # evidence of absence -- record it for both the counter
                    # __main__ reads and the breaker that should give up on a
                    # silent target.
                    self.failed_requests += 1
                    self._record_transport_failure()
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
                if self.advanced_layers and not urlparse(url).fragment:
                    # Phase 209 (sync parity, scanner.py): a fragment-bearing
                    # endpoint is a client-side route.  Hidden-parameter mining
                    # sends server-side query names, and the server never sees
                    # the fragment -- the DOM engine injects into the fragment
                    # itself.  Sync skips it for the same reason.
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
                        url, text, method, params,
                        redirect_landing=redirect_landing_drops_input(
                            url, final_url, redirected, params),
                        no_script_exec=csp_mod.script_execution_blocked(
                            resp_headers, text))))

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
                        url, resp_headers, text, method)))

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
                        url, resp_headers, method)))

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
        _set_current_scan_url(None)

    async def _scan_reflected(self, session, url: str, method: str,
                              params: dict, data: dict,
                              baseline_text: str
                              ) -> AsyncIterator[Finding]:
        """L1 reflected XSS: probe each parameter with context-aware payloads."""
        # Phase 290: sync parity -- scanner.py's L1 site touches coverage
        # once per endpoint and record_param per name.  Without this an
        # --async report's layer matrix showed L1 as "never ran".
        self._touch_coverage(url, "L1_reflected", method)
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
            # Phase 185: the names must also leave the request itself, not
            # just the iteration list.  Bound once so every async side layer
            # below (DOM, JSONP, CSP, CORS, XS-Leaks, upload, scenarios,
            # request layers) sees the filtered pair.
            params, data = self._drop_skip_params(params, data)
        # Phase 43 fix: _probe_param returns async GENERATORS, which
        # asyncio.as_completed() rejects (not awaitables) -- the whole L1
        # layer silently produced nothing under scan().  Drain via tasks.
        sink: list = []
        tasks = []
        for param, is_body in param_items:
            # Phase 290: the per-parameter row the sync engine records
            # (scanner.py's record_param call sites).  Kept next to the
            # probe that actually sends the payload.
            _cov = getattr(self, "coverage", None)
            if _cov is not None:
                _cov.record_param(url, param, in_body=is_body,
                                  method=method)
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
        # Phase 185: never transmit names the operator asked to withhold.
        # Phase 184 excluded them from the iteration list only.
        probe_params, probe_data = self._drop_skip_params(
            probe_params, probe_data)
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

        # Phase 211 round 2: candidate construction (Phase 43 corpus sampling,
        # Phase 37/95 profile + generative, Phase 96 RCDATA, Phase 29-2 WAF
        # bypass) moved to _build_probe_candidates.  marker_escaped comes back
        # because the profile convergence can set it, prof because the RCDATA
        # stage reads it.
        cands, marker_escaped, prof = await self._build_probe_candidates(
            session, url, method, param, params, data, is_body, context,
            marker, marker_escaped, _extra_contexts)


        # Phase 211 round 3: the variant loop, the concat-stamp retry and the
        # parameter position shift moved to _fire_probe_variants.  The three
        # values the tail stages read come back on the state object -- an
        # async generator cannot return them.
        _fire = _ProbeFireState(text)
        async for _f in self._fire_probe_variants(
                session, url, method, param, params, data, is_body,
                context, marker, cands, marker_escaped, _fire):
            yield _f
        param_confirmed = _fire.param_confirmed
        resp_headers = _fire.resp_headers
        text = _fire.text


        # Phase 211: the three tail stages below moved to
        # AsyncDetectionLayersMixin (_probe_csp_nonce / _probe_csp_gadget /
        # _probe_hpp).  csp_hdr is computed here because two of them read it.
        csp_hdr = ""
        try:
            csp_hdr = probe_headers.get("Content-Security-Policy") or ""
        except Exception:
            csp_hdr = ""
        # Phase 132: also gated on ``not param_confirmed`` -- sync's nonce
        # step (scanner.py:656) carries the same guard, and the block is
        # only reached on an unconfirmed param anyway.
        if not param_confirmed and csp_hdr:
            # Phase 290: the per-param tail stages touch coverage at their
            # call sites (method is in scope here; the mixin functions do
            # not carry it).  Sync records these at the same points.
            self._touch_coverage(url, "L7_csp_nonce", method)
            async for _f in self._probe_csp_nonce(
                    session, url, method, param, params, data, is_body,
                    marker, context, csp_hdr, probe_text, text,
                    resp_headers):
                yield _f
            self._touch_coverage(url, "L7_csp_gadget", method)
            async for _f in self._probe_csp_gadget(
                    session, url, method, param, params, data, is_body,
                    context, csp_hdr):
                yield _f

        if self.waf_name and not param_confirmed:
            self._touch_coverage(url, "L2_hpp", method)
            async for _f in self._probe_hpp(
                    session, url, method, param, params, data, is_body,
                    context, cands):
                yield _f


        # Phase 132: L7 parameter layers (mutation / DOM clobber / template
        # / polyglot / markdown).  Sync reaches these at the end of
        # ``_scan_param``; async stopped after the CSP-nonce block, so the
        # whole family was async-only FN.  Reached only when the marker
        # actually reflected, matching the sync call site.
        async for _f in self._scan_advanced_param_layers(
                url, method, params, data, param, is_body, marker,
                probe_text or text or "",
                param_confirmed=param_confirmed):
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
        # Phase 290: every finding flows through here (page tasks, crawl,
        # OOB collect), so this is the one choke point that keeps the
        # tracker's per-endpoint finding count honest.  Finding carries its
        # payload in ``.data`` -- it has NO .url/.method attributes, and
        # reaching for them here raised AttributeError into the except, so
        # the counter stayed silently at zero until the unit test caught it.
        try:
            _d = getattr(finding, "data", None) or {}
            if (_d.get("type") in ("reflected", "polyglot_reflection")
                    and _d.get("severity") == "low"
                    and dk_mod.is_data_only_media_type(
                        _d.get("content_type") or "")):
                # Sync parity (scanner._record): HTML markup reflected into
                # JSON/plain text is data; the low finding is noise.  Script
                # and XML media types are preserved (real JSONP/XML vectors).
                return
            self.coverage.record_finding(_d.get("url") or "",
                                         _d.get("method") or "GET")
        except Exception:
            pass
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

        Phase 208: a success clears the transport streak too, so a target
        that recovers mid-scan does not stay tripped by refusals that have
        stopped happening.
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
            self._fail_silent.clear()

    def _record_transport_failure(self) -> None:
        """Feed in a request that never received a response (Phase 208).

        Async parity with ``CircuitBreaker.record_transport_failure``.  A
        5xx means one endpoint misbehaved; silence means the target is not
        answering and no other endpoint can succeed while it holds, so it
        gets its own, tighter threshold (``_transport_threshold``).
        """
        if self.breaker_threshold <= 0:
            return
        now = time.monotonic()
        self._fail_silent = [t for t in self._fail_silent
                             if now - t <= 120.0]
        self._fail_silent.append(now)

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
            if self.breaker_threshold > 0 and (
                    len(self._fail_times) >= self.breaker_threshold
                    or len(self._fail_silent) >= self._transport_threshold):
                self.budget_exhausted_reason = (
                    f"circuit open: {len(self._fail_times)} 5xx/429 "
                    f"and {len(self._fail_silent)} unanswered request(s)")
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
