# -*- coding: utf-8 -*-
"""Shared async-engine helpers, split out of async_scanner.py (Phase 191).

These were module-level definitions of that file.  They live here because
``async_scanner`` imports the mixins -- a mixin importing back into it would
be a cycle.  ``async_scanner`` re-imports these names, so nothing that imports
from the engine had to change; the single exception is ``_EGRESS_JAR``, the
cache that ``_egress_cookie_jar_cls`` mutates, which stays readable only at its
real home (an ``import name`` alias would let a test reset a copy and think it
had reset the cache).
"""
from __future__ import annotations
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin
from .scanner import Finding
from .scanner_layers import AdvancedLayerMixin
from .scanner_crawl import CrawlMixin
from .requester import JsonBody
from . import layer_guard
from .budget import BudgetExhausted, CircuitOpen
from .egress import EgressPolicy
from .logger import get_logger  # noqa: E402
from .parser_utils import bs_parser as _bs_parser  # noqa: E402

if TYPE_CHECKING:  # annotation-only dependency: the shim wraps the engine
    from .async_scanner import AsyncScanner


_PROBE = b"xssentinel accept-encoding capability probe"


def _aiohttp_can_decode(encoding: str) -> bool:
    """Ask aiohttp's own decompressor, not its availability flags.

    Phase 209, found on a real application (OWASP Juice Shop): the async
    engine failed on EVERY request with
    ``400, message: Can not decode content-encoding: br`` while
    ``aiohttp.compression_utils.HAS_BROTLI`` read ``True``.  The flag says a
    brotli module is importable; the decoder then calls
    ``Decompressor.process(data, max_length)``, which the ``Brotli`` package
    (as opposed to ``brotlipy``/``brotlicffi``) does not accept -- one
    positional argument, so the call raises TypeError and aiohttp rewrites it
    as a 400.  Advertising an encoding we cannot decode is worse than
    advertising less: the target answers in that encoding and the scan then
    sees nothing at all, which is exactly how ``--async`` reports zero
    findings on a healthy site.

    So the question is answered by decompressing, once, through the same code
    path a real response will take.
    """
    if encoding == "br":
        try:
            from aiohttp.compression_utils import BrotliDecompressor
        except Exception:
            return False
        try:
            import brotlicffi as brotli  # type: ignore
        except Exception:
            try:
                import brotli  # type: ignore
            except Exception:
                return False
        try:
            packed = brotli.compress(_PROBE)
            out = BrotliDecompressor().decompress_sync(packed, len(_PROBE) + 16)
            return _PROBE.startswith(bytes(out))
        except Exception:
            return False
    if encoding == "zstd":
        try:
            from aiohttp.compression_utils import ZSTDDecompressor
        except Exception:
            return False
        try:
            import zstandard as zstd  # type: ignore
            packed = zstd.ZstdCompressor().compress(_PROBE)
            out = ZSTDDecompressor().decompress_sync(packed, len(_PROBE) + 16)
            return _PROBE.startswith(bytes(out))
        except Exception:
            return False
    return False


_ACCEPT_ENCODING_CACHE: dict[str, str] = {}


def safe_accept_encoding() -> str:
    """Accept-Encoding header the async engine can actually decode."""
    cached = _ACCEPT_ENCODING_CACHE.get("value")
    if cached:
        return cached
    encodings = ["gzip", "deflate"]
    for ext in ("br", "zstd"):
        if _aiohttp_can_decode(ext):
            encodings.append(ext)
    value = ", ".join(encodings)
    _ACCEPT_ENCODING_CACHE["value"] = value
    return value


_EGRESS_JAR: type | None = None


def _egress_cookie_jar_cls() -> type:
    """``aiohttp.CookieJar`` that stays shut for origins nobody asked to visit.

    Built on first use because aiohttp is an optional dependency, and cached
    because the class body costs nothing to reuse.  The jar is where the
    header scrub cannot reach: aiohttp applies it while constructing each
    redirect hop, after ``on_request_redirect`` has already fired.
    """
    global _EGRESS_JAR
    if _EGRESS_JAR is None:
        import aiohttp

        class _EgressCookieJar(aiohttp.CookieJar):
            def __init__(self, policy: EgressPolicy, **kwargs):
                super().__init__(**kwargs)
                self._policy = policy

            def filter_cookies(self, request_url):
                jar = super().filter_cookies(request_url)
                if jar and not self._policy.is_named(request_url):
                    return type(jar)()      # nothing leaves for this origin
                return jar

        _EGRESS_JAR = _EgressCookieJar
    return _EGRESS_JAR
def _content_type(resp_headers) -> str:
    """The response's Content-Type as sent (empty when unavailable)."""
    try:
        hdrs = resp_headers or {}
        return (hdrs.get("Content-Type")
                or hdrs.get("content-type") or "")
    except Exception:
        return ""


async def _read_text(resp) -> str:
    """Decode a body the way the sync engine's ``requests`` transport does.

    aiohttp's ``text()`` decodes strictly: a body that is not valid UTF-8 and
    carries no usable charset raises UnicodeDecodeError.  requests replaces
    undecodable bytes instead, so the same target that yields a readable
    (garbage) string to sync made async raise inside the probe -- and the
    probe's bare ``except Exception`` turned that into "this parameter has
    nothing", silently.  Measured on XSSMaze ``/decode/level1``: the marker
    probe answers 20 bytes of binary, async sent 0 encoded probes and reported
    nothing while sync confirmed the sink.

    Only the strict-decode failure is covered; every body aiohttp can already
    decode takes the identical path.
    """
    try:
        return await resp.text()
    except (UnicodeDecodeError, LookupError):
        data = await resp.read()
        try:
            return data.decode("utf-8", "replace")
        except Exception:
            return data.decode("latin-1", "replace")


def _non_html_grade(resp_headers) -> tuple[str, str]:
    """Phase 32 parity (scanner._record), Phase 179: markup reflected into a
    non-HTML response cannot execute in a browser tab -- keep the finding,
    downgrade severity AND confidence.  Severity-only consumers (benchmark
    FP gate, SARIF level, report highlighting) must not triage it like a
    live sink.
    """
    try:
        hdrs = resp_headers or {}
        ctype = (hdrs.get("Content-Type")
                 or hdrs.get("content-type") or "").lower()
    except Exception:
        ctype = ""
    if ctype and not any(t in ctype for t in (
            "text/html", "application/xhtml", "image/svg")):
        return "low", "low"
    return "high", "high"


def _polyglot_grade(resp_headers) -> tuple[str, str]:
    """Phase 208 parity with the sync polyglot layer
    (``scanner_layers.py``, ``type="polyglot_reflection"``).

    A polyglot hit is a BROADER claim than a context-specific reflected
    hit: the payload tries several breakouts at once, so it says "this
    endpoint is executable somewhere", not "this exact sink fires".  Sync
    has graded it medium/medium since Phase 198 for exactly that reason
    (and low on a non-HTML response).

    Before Phase 208 the async polyglot variant fell through to the
    generic ``reflected`` branch and came out high/high -- identical
    evidence, harsher verdict.  Measured on /r/url03 (meta_refresh):
    both engines model-only, both ``event_handler``, both polyglot.
    """
    sev, _conf = _non_html_grade(resp_headers)
    return ("low", "medium") if sev == "low" else ("medium", "medium")


class _ProbeFireState:
    """Phase 211 round 3: out-params for ``_fire_probe_variants``.

    That stage is an async generator, so it cannot hand values back with
    ``return`` -- the caller would need StopAsyncIteration plumbing.  Three
    values have to survive into the later stages: ``param_confirmed`` gates
    the CSP/HPP/L7/time-based stages, ``resp_headers`` is read by the CSP
    nonce stage, and ``text`` is read by both the nonce stage and L7.

    Deliberately NOT attributes on the scanner instance: this is
    per-parameter state and would otherwise leak into the next parameter's
    probe (the same reason ``param_confirmed`` stayed a local).
    """
    __slots__ = ("text", "resp_headers", "param_confirmed")

    def __init__(self, text: str = ""):
        self.text = text
        self.resp_headers: dict = {}
        self.param_confirmed = False


_log = get_logger("async_scanner")
# JSONP callback parameter names probed by the async JSONP layer.  Kept
# at module level so it is created once instead of per-scan.
_JSONP_CALLBACK_NAMES = ("callback", "cb", "jsonp", "jsonpCallback",
                         "fn", "function", "handler")
# =============================================================================
# Helper shims for delegating async -> sync detection modules
# =============================================================================

def _body_kwargs(data):
    """Translate a body value into aiohttp request kwargs.

    A JsonBody wrapper (the sync Requester convention) must leave as
    ``application/json`` -- aiohttp needs ``json=`` for that and would
    otherwise form-encode the dict subclass.  A plain dict keeps the
    default form encoding.  Returns a dict to splat with ``**`` so request
    call sites stay one line.
    """
    if isinstance(data, JsonBody):
        return {"data": None, "json": dict(data)}
    return {"data": data or None}
async def _drain_agen(agen, sink: list, name: str = "layer") -> None:
    """Consume an async generator into ``sink``, isolating its exceptions.

    asyncio.as_completed() requires awaitables -- async generators are NOT
    awaitables, so the old ``as_completed([agen, ...])`` pattern raised
    TypeError on every scan() call (silently swallowed upstream, leaving
    async mode with zero findings).  Draining via tasks keeps the layers
    concurrent while making results collectable; per-layer exceptions stay
    isolated so one broken layer cannot kill the batch.

    Phase 94: failures are attributed to ``name``, and wiring-class
    exceptions (ImportError / NameError / ...) escalate to a WARNING that
    names the layer -- those can never be the target's fault.
    """
    try:
        async for f in agen:
            sink.append(f)
    except (BudgetExhausted, CircuitOpen):
        raise        # Phase 86: a budget/circuit stop is NOT a layer bug
    except Exception as e:
        if layer_guard.is_wiring_error(e):
            _log.warning("[layer:%s] %s: %s -- this layer is OFF until the "
                         "defect is fixed; the remaining layers still run",
                         name, type(e).__name__, e)
            return
        _log.warning("async layer %s error: %s", name, e)
class _FakeResp:
    """Lightweight response object for sync WAF detection module."""

    def __init__(self, text: str, status: int, headers: dict):
        self.text = text
        self.status_code = status
        self.headers = headers
class _AsyncScannerShim(AdvancedLayerMixin, CrawlMixin):
    """Minimal scanner-like object for sync detection modules.

    The sync ``advanced_layers`` / ``jsonp`` / ``csp`` modules expect a
    scanner with ``_add()``, ``_bump()``, ``verbose``, ``findings``,
    ``_lock``, and ``waf_name`` attributes.  This shim provides them so
    we can reuse the sync detection code without rewriting it.

    Phase 63: every page-level sub-layer in ``layers/*.py`` starts with
    ``scanner.coverage.touch_layer(...)`` (58 call sites).  The shim had no
    ``coverage`` attribute at all, so the very first sub-layer
    (postMessage) raised AttributeError, the whole ``run_page_layers``
    aborted, and async mode silently reported NONE of the page-level
    layers -- postMessage, prototype pollution, service worker, web
    worker, open redirect, framework, GraphQL, WebSocket, Trusted Types,
    CSP nonce, cookie tossing, SRI, import map, sanitizer bypass, CSSI,
    dangling markup, SVG.  A no-op coverage facade keeps the sync code
    path intact while still recording layer touches for debugging.
    """

    class _NullCoverage:
        """Coverage facade for the sync modules run through the shim.

        Phase 63 gave this a memory-only stand-in so the 58 sync sub-layer
        ``scanner.coverage.touch_layer(...)`` call sites could run at all;
        Phase 290 points it at the async scanner's REAL tracker so those
        same calls finally reach the report.  ``touched`` stays: tests and
        debugging inspect it to prove a layer ran, and the delegation is
        additive on top of it.

        Every method takes ``*a, **kw`` on purpose: the sync layer sites
        call ``record_param(url, param, in_body=..., method=...,
        context=..., confirmed=...)`` and friends, and a narrow facade
        raised TypeError into the layer's own try/except -- which silently
        disabled whole layers (measured: header_xss/path_xss tests went to
        0 findings).  Forwarding verbatim keeps the facade shape-agnostic.
        """

        def __init__(self, real=None):
            self.touched: list[tuple] = []
            self._real = real

        def touch_layer(self, url, layer_id, *a, **kw):
            method = a[0] if a else kw.get("method", "GET")
            detail = a[1] if len(a) > 1 else kw.get("detail", "")
            self.touched.append((url, layer_id, method, detail))
            if self._real is not None:
                self._real.touch_layer(url, layer_id, *a, **kw)

        def record_layer(self, url, layer_id, *a, **kw):
            status = kw.get("status", a[0] if a else "ran")
            detail = kw.get("detail", a[1] if len(a) > 1 else "")
            self.touched.append((url, layer_id, status, detail))
            if self._real is not None:
                self._real.record_layer(url, layer_id, *a, **kw)

        def record_request(self, url, method="GET", *a, **kw):
            if self._real is not None:
                self._real.record_request(url, method, *a, **kw)

        def record_param(self, url, param, *a, **kw):
            if self._real is not None:
                self._real.record_param(url, param, *a, **kw)

        def record_finding(self, url, method="GET", *a, **kw):
            # Deliberately NOT forwarded: the async engine counts findings
            # at its own choke point (AsyncScanner._add_finding), and the
            # sync sub-layers also call record_finding for the same rows --
            # forwarding both double-counted (measured: 7 counted for 4
            # findings).  Sync keeps its layer-site semantics; async uses
            # the choke point, which is exact.
            pass

        def start_endpoint(self, url, method="GET", crawled=False):
            if self._real is not None:
                self._real.start_endpoint(url, method, crawled)

        def end_endpoint(self, url, method="GET"):
            if self._real is not None:
                self._real.end_endpoint(url, method)

    def __init__(self, async_scanner: AsyncScanner):
        self._async = async_scanner
        self._findings: list[Finding] = []
        self.verbose = async_scanner.verbose
        self.findings = self._findings  # alias for advanced_layers
        self.waf_name = async_scanner.waf_name
        self.requests_made = 0
        # Phase 290: delegate to the scanner's real tracker when it has
        # one (always, for AsyncScanner; a bare test double may not).
        self.coverage = _AsyncScannerShim._NullCoverage(
            real=getattr(async_scanner, "coverage", None))
        # Page layers also reach for the requester (GraphQL / cookie
        # tossing follow-up probes).  Default None; callers that run
        # request-driven page layers must set a real one.
        #
        # Phase 176s: this used to be justified as "the layers' own
        # try/except degrades gracefully".  It does not -- it degrades
        # SILENTLY.  Cookie tossing needs a follow-up GET to read
        # Set-Cookie; with req=None it raised, swallowed the exception,
        # and proceeded with no headers, so it could never fire.  Async
        # has had a sync requester since Phase 87 (_get_sync_requester);
        # the note simply predated it and nobody re-read it.  Do not
        # reintroduce "it degrades gracefully" reasoning here.
        #
        # Annotated `Any` because the layers assign a real Requester over it;
        # left bare, mypy infers `req: None` from this line and every
        # `shim.req = CountingRequester(...)` becomes an assignment error.
        self.req: Any = None
        # Phase 132: the L7 parameter layers (mutation / DOM clobber /
        # template / polyglot / markup) read these two off the scanner.
        # Without them ``_run_advanced_layers`` would raise on the JSON
        # carrier path and skip the markup sub-layer entirely.
        # getattr: tests build the scanner with __new__ to skip __init__.
        self.json_body = getattr(async_scanner, "json_body", None)
        self._advanced_layers = True
        # Phase 176s: the OOB-aware layers (time-based) read ``scanner.oob``
        # and ``scanner._oob_started`` directly.  Async owns both -- it runs
        # its own listener -- so proxy them instead of letting the layer see
        # nothing and bail out.  Without this the time-based fallback raised
        # AttributeError on entry and every CSP-locked endpoint stayed a
        # silent false negative (pos-tb-01).
        self.oob = getattr(async_scanner, "oob", None)
        self._oob_started = bool(getattr(async_scanner, "_oob_started", False))
        # Phase 133: CrawlMixin._mine_hidden_params reads these.
        self.max_payloads = getattr(async_scanner, "max_payloads", 14)
        self.param_wordlist = None      # --param-wordlist stays sync-only
        self.bav = False                # --bav is documented sync-only
        import threading
        self._lock = threading.Lock()

    def _add(self, finding: Finding) -> None:
        with self._lock:
            self._findings.append(finding)

    def _bump(self) -> None:
        """Count one request the shim's sync layers are about to send.

        Phase 142.  This traffic used to be *counted but not constrained*:
        it sailed straight past ``--max-requests`` while inflating the scan
        total, which then made ``_throttle`` refuse the very next async
        request.  At a small budget the effect was that the baseline got
        rejected, ``page_tasks`` was never built, and every zero-cost layer
        (L6 CSP analysis, L3 DOM static) silently never ran -- so a
        bypassable CSP went unreported.  Found via
        tests/test_async_budget.py::test_scan_keeps_findings_collected_before_the_stop,
        failing since Phase 133 added the miner.

        The cap lives on the *scanner*, and its counter is only reconciled
        with this shim's afterwards, so the decision uses the sum of both.
        Check-then-count, mirroring ``_throttle``: ``requests_made`` never
        exceeds the cap and a rejected request is never sent.
        """
        scanner = self._async
        cap = getattr(scanner, "max_requests", None)
        if cap is not None:
            spent = getattr(scanner, "requests_made", 0) + self.requests_made
            if spent >= cap:
                scanner.budget_exhausted_reason = (
                    f"total request budget exhausted (>={cap} requests)")
                raise BudgetExhausted(scanner.budget_exhausted_reason)
        self.requests_made += 1
def _extract_links(html: str, base_url: str) -> list[str]:
    """Extract all links from an HTML page (runs in thread)."""
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, _bs_parser())
        links = set()
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href and not href.startswith(("#", "javascript:", "mailto:")):
                links.add(urljoin(base_url, href))
        # Also extract form actions.
        for form in soup.find_all("form", action=True):
            action = form["action"].strip()
            if action and not action.startswith(("javascript:", "mailto:")):
                links.add(urljoin(base_url, action))
        return list(links)
    except Exception:
        return []
