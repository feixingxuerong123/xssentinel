"""REST API server for XSSentinel (Phase 27-4).

Two backends are provided:

  * :class:`StdlibServer` -- built on ``http.server.ThreadingHTTPServer``.
    Always available, zero extra dependencies.  Suitable for development
    and single-process production deployments.

  * :class:`FlaskServer` -- thin adapter that mounts the same handlers
    under Flask when it is installed.  Useful for embedding XSSentinel
    inside an existing Flask application.

The routing table is shared so both backends expose identical behaviour.
"""
from __future__ import annotations

import hmac
import json
import re
import sys
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import urlparse, parse_qs

from .jobs import Job, JobManager, JobNotFoundError, JobState
from .validation import DEFAULT_MAX_BODY_BYTES, cors_origin_for, parse_cors_origins, validate_findings
from ..core.logger import get_logger

_log = get_logger("api")


# ---------------------------------------------------------------------------
# Version / info
# ---------------------------------------------------------------------------
def _version_info() -> dict:
    """Return scanner version + detection-layer list for /api/v1/info."""
    try:
        from xssentinel import __version__ as ver
    except Exception:
        ver = "0.0.0"
    # Detection layers (kept in sync with advanced_layers.run_page_layers).
    layers = [
        "L1_reflected", "L2_waf", "L3_dom", "L4_blind", "L5_advanced",
        "L6_csp_jsonp", "L7_sri_bypass", "L8_cookie_tossing",
        "L9_postmessage", "L10_prototype", "L11_service_worker",
        "L12_web_worker", "L13_open_redirect", "L14_header_xss",
        "L15_path_xss", "L16_error_page", "L17_markdown",
        "L18_graphql", "L19_websocket", "L20_trusted_types",
        "L21_csp_nonce", "L22_template_ssti", "L23_framework",
        "L24_second_order", "L25_time_based", "L26_fuzzer",
    ]
    return {
        "name": "XSSentinel",
        "version": ver,
        "description": "Comprehensive XSS detection framework",
        "detection_layers": layers,
        "api_version": "v1",
        "endpoints": [
            "GET    /api/v1/health",
            "GET    /api/v1/info",
            "GET    /api/v1/metrics",
            "POST   /api/v1/scans",
            "GET    /api/v1/scans",
            "GET    /api/v1/scans/{id}",
            "GET    /api/v1/scans/{id}/findings",
            "GET    /api/v1/scans/{id}/report?format=html|json|sarif|csv|junit|markdown",
            "DELETE /api/v1/scans/{id}",
            "POST   /api/v1/verify-fix",
            "POST   /api/v1/diff",
        ],
    }


# ---------------------------------------------------------------------------
# Scan worker -- runs in a daemon thread, drives the Scanner
# ---------------------------------------------------------------------------
def _build_requester(options: dict):
    """Construct a Requester from the scan options dict."""
    from xssentinel.core.requester import Requester

    headers = options.get("headers") or {}
    cookies = options.get("cookies") or {}
    return Requester(
        timeout=options.get("timeout", 15),
        proxy=options.get("proxy"),
        headers=headers or None,
        cookies=cookies or None,
        verify_ssl=options.get("verify_ssl", True),
        rate_limit=options.get("rate_limit", 0),
    )


def _record_scan_metrics(job: Job, findings: list[dict]) -> None:
    """Phase 28-3: increment Prometheus counters for a completed scan.

    Called from the ``_publish`` / ``_fail`` closures after the job has
    reached a terminal state.  Failures are swallowed -- metrics must
    never break the scan pipeline.
    """
    try:
        from .metrics import get_registry
        reg = get_registry()
        reg.inc_counter("xssentinel_scans_total", state=job.state)
        # Findings by severity.
        for f in findings:
            sev = (f.get("severity") or "info").lower()
            reg.inc_counter("xssentinel_findings_total", severity=sev)
        # Scan duration (wall time from creation to completion).
        if job._created_at_mono and job.finished_at:
            # _created_at_mono is monotonic; finished_at is wall clock.
            # Approximate duration using the monotonic delta from now.
            import time as _time
            duration = _time.monotonic() - job._created_at_mono
            if duration > 0:
                reg.observe("xssentinel_scan_duration_seconds", duration)
    except Exception:
        pass


def _parse_ai_models(raw) -> list[str] | None:
    """Accept ``"a,b"`` or ``["a", "b"]``; ``None`` means "no filter"."""
    if not raw:
        return None
    if isinstance(raw, str):
        names = [m.strip() for m in raw.split(",") if m.strip()]
    elif isinstance(raw, (list, tuple)):
        names = [str(m).strip() for m in raw if str(m).strip()]
    else:
        return None
    return names or None


def _generate_job_ai_report(job: Job, findings, meta: dict,
                            opts: dict | None = None) -> dict | None:
    """Phase 176: produce and cache the AI narrative section for one job.

    Returns the ``AIReport.to_meta()`` dict, or ``None`` if generation failed
    outright.  Three properties matter:

    * **Never raises.**  ``report_ai`` already degrades to the deterministic
      advice corpus when no provider answers; this wrapper only has to make
      sure that even a coding error inside it cannot change a scan's verdict
      or a job's state.  A narrative section is never worth failing a scan.
    * **Idempotent.**  Guarded by ``job._ai_lock`` plus the cached
      ``job._ai_report``, so concurrent report requests for one scan bill at
      most one model call.
    * **Server-configured pool.**  ``_ai_config`` is injected by the server's
      own startup flag, never read from the request body -- a client must not
      be able to point the pool loader at an arbitrary path.

    ``findings`` may be Finding objects or the plain dicts a job stores;
    ``report_ai`` handles both.
    """
    opts = opts or {}
    with job._ai_lock:
        if job._ai_report is not None:
            return job._ai_report
        try:
            from xssentinel.core import report_ai
            rep = report_ai.build_ai_report(
                findings, job.target_url, meta,
                config_path=opts.get("_ai_config"),
                models=opts.get("ai_models"),
                lang=opts.get("ai_lang") or "zh",
                timeout=opts.get("ai_timeout"),
                max_findings=int(opts.get("ai_max_findings") or 25),
            )
            job._ai_report = rep.to_meta()
            if rep.used_llm:
                _log.warning("api: AI report for %s written by %s "
                             "(%d failover(s), %.1fs)", job.scan_id,
                             rep.model or rep.provider, rep.failovers,
                             rep.elapsed)
            else:
                _log.warning("api: AI report for %s degraded to template -- %s",
                             job.scan_id, rep.error)
        except Exception as e:
            _log.warning("api: AI report generation failed for %s: %s",
                         job.scan_id, e)
        return job._ai_report


def _scan_worker(job: Job) -> None:
    """Worker thread body: build a Scanner, scan, publish findings.

    This mirrors the sync path in ``__main__._run_scan`` but with no
    CLI coupling -- all options come from the Job.options dict so the
    HTTP handler can serialise them straight from the request JSON.
    """
    from xssentinel.core.scanner import Scanner
    from xssentinel.core.budget import BudgetExhausted
    from urllib.parse import urlparse

    opt = job.options
    requester = _build_requester(opt)

    # Parse query parameters from the target URL (mirrors CLI behavior).
    parsed = urlparse(job.target_url)
    base_url = parsed.scheme + "://" + parsed.netloc + parsed.path
    params = dict(job.params) if job.params else {}
    if parsed.query:
        for pair in parsed.query.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params.setdefault(k, v)

    try:
        scanner = Scanner(
            requester=requester,
            use_headless=opt.get("headless", False),
            max_transforms=opt.get("max_transforms", 12),
            max_payloads=opt.get("max_payloads", 14),
            crawl=opt.get("crawl", False),
            crawl_depth=opt.get("crawl_depth", 2),
            scope=opt.get("scope"),
            threads=opt.get("threads", 4),
            oob=None,
            dom_engine=opt.get("dom_engine", "auto"),
            verbose=False,
            progress=None,
            checkpoint=None,
            custom_payloads=opt.get("custom_payloads", []) or [],
            crawl_engine=opt.get("crawl_engine", "auto"),
        )
        # Phase 180: wire the cooperative cancel flag into the Scanner --
        # the Phase 129 wiring that the comment promised but never landed.
        scanner.cancel_event = job._cancel_requested
        scanner.scan_target(
            base_url,
            method=job.method,
            params=params,
            data=job.data,
            oob_collect=False,
        )
        scanner.dedup()
        scanner.attach_pocs()

        # Cooperative cancel: if the client requested cancellation while
        # the scan was running, still publish the findings gathered so
        # far -- the JobManager will mark the state CANCELLED.
        findings = [f.to_dict() if hasattr(f, "to_dict") else f
                    for f in scanner.findings]

        # Coverage summary (lightweight -- avoid serialising the whole
        # tracker; just send the per-layer counts).
        cov_summary: dict | None = None
        cov = getattr(scanner, "coverage", None)
        if cov is not None:
            try:
                # CoverageTracker.to_dict() if available, else best-effort.
                if hasattr(cov, "to_dict"):
                    cov_summary = cov.to_dict()
                elif hasattr(cov, "summary"):
                    cov_summary = cov.summary()
            except Exception:
                cov_summary = None

        # Phase 176: optional AI narrative, generated on the job's OWN worker
        # thread -- no HTTP request ever waits on a model.  Done BEFORE
        # publishing on purpose: the job reaches COMPLETED only once its
        # report is complete, so a client that polls and then fetches the
        # report gets the section in one round trip instead of racing the
        # generator.  Skipped for a cancelled scan (partial findings are not
        # worth spending provider quota on); `?ai=1` can still generate later.
        if opt.get("ai_report") and not job._cancel_requested.is_set():
            _generate_job_ai_report(job, scanner.findings, {
                "target": job.target_url,
                "generated": datetime.now().isoformat(timespec="seconds"),
                "requests": getattr(scanner, "requests_made", 0),
                "waf": getattr(scanner, "waf_name", None),
            }, opt)

        # Mark completed (or cancelled if requested).
        # We need to peek the cancel flag through the manager -- but the
        # worker doesn't have a back-reference.  The JobManager wraps the
        # worker in _run_worker and checks _cancel_requested itself; we
        # just need to publish findings.
        # Note: mark_completed checks _cancel_requested internally.
        # We reach back to the manager via a closure set in start().
        _publish = job.options.get("_publish_fn")
        if _publish is None:
            # Fallback: directly mutate via the Job (less ideal but works
            # for unit tests that bypass the manager).
            job.findings = findings
            job.finding_count = len(findings)
            job.high_severity_count = sum(
                1 for f in findings
                if (f.get("severity") or "").lower() in ("high", "critical")
            )
            job.requests_made = getattr(scanner, "requests_made", 0)
            job.waf_name = getattr(scanner, "waf_name", None)
            job.coverage_summary = cov_summary
            job.state = JobState.CANCELLED if job._cancel_requested.is_set() \
                else JobState.COMPLETED
            job.finished_at = datetime.now().isoformat(timespec="seconds")
        else:
            _publish(
                findings=findings,
                requests_made=getattr(scanner, "requests_made", 0),
                waf_name=getattr(scanner, "waf_name", None),
                coverage_summary=cov_summary,
            )
    except BudgetExhausted:
        if job._cancel_requested.is_set():
            # Phase 180: cooperative cancellation -- publish the findings
            # gathered so far.  mark_completed checks the set flag itself
            # and reports CANCELLED, not COMPLETED.
            findings = [f.to_dict() if hasattr(f, "to_dict") else f
                        for f in scanner.findings]
            _publish = job.options.get("_publish_fn")
            if _publish is not None:
                _publish(
                    findings=findings,
                    requests_made=getattr(scanner, "requests_made", 0),
                    waf_name=getattr(scanner, "waf_name", None),
                    coverage_summary=None,
                )
            return
        raise
    except Exception as e:
        # Phase 180: the flag is the source of truth.  Intermediate broad
        # handlers (crawl per-endpoint, _scan_param failure paths) swallow
        # the BudgetExhausted abort, so whatever exception surfaces here,
        # a set cancel flag means the operator asked for this stop:
        # publish the findings gathered so far as CANCELLED, not FAILED.
        if job._cancel_requested.is_set():
            findings = [f.to_dict() if hasattr(f, "to_dict") else f
                        for f in scanner.findings]
            _publish = job.options.get("_publish_fn")
            if _publish is not None:
                _publish(
                    findings=findings,
                    requests_made=getattr(scanner, "requests_made", 0),
                    waf_name=getattr(scanner, "waf_name", None),
                    coverage_summary=None,
                )
            return
        # Publish the failure.  Same closure pattern.
        _fail = job.options.get("_fail_fn")
        if _fail is not None:
            _fail(f"{type(e).__name__}: {e}")
        else:
            job.state = JobState.FAILED
            job.error = f"{type(e).__name__}: {e}"
            job.finished_at = datetime.now().isoformat(timespec="seconds")
        raise


# ---------------------------------------------------------------------------
# Canonical route table (shared by both backends)
# ---------------------------------------------------------------------------
# Each route: (method, regex, handler).  The handler signature is
# ``handler(ctx, match, body, query) -> Response`` where:
#   - ctx: RequestCtx (server, headers, etc.)
#   - match: re.Match object for the path regex
#   - body: parsed JSON body (dict) or None
#   - query: dict of query-string values (lists)
# Response: (status_code, headers, body_bytes) or (status, headers, body_str).

# ---------------------------------------------------------------------------
# Phase 70 (extended Phase 196): the same-origin defence, shared by every
# front-end that speaks HTTP.
# ---------------------------------------------------------------------------
# This lived inside ``StdlibServer._same_origin_ok`` only, which meant the
# documented ``--use-flask`` deployment enforced nothing: with no ``--api-key``
# a DNS-rebound page could read scan results and a cross-site form POST could
# start scans.  One implementation, called by both, so a fix to the gate is a
# fix to every way we serve.
_MUTATING_METHODS = ("POST", "PUT", "PATCH", "DELETE")


def host_name_of(host_header: str) -> str:
    """Strip the port from a Host header, keeping bracketed IPv6 intact."""
    h = (host_header or "").lower()
    if h.startswith("["):                       # [::1]:8000
        return h.split("]", 1)[0].lstrip("[")
    if h.count(":") == 1:
        return h.rsplit(":", 1)[0]
    return h


def same_origin_ok(method: str, headers: dict | None, local_hosts: set,
                   has_api_key: bool) -> tuple:
    """Anti DNS-rebinding + anti cross-site state change.

    * DNS rebinding: a page re-resolves its own domain to 127.0.0.1, so the
      Host header carries the ATTACKER domain and same-origin rules then let
      its script read our responses.
    * Cross-site request: a browser says which site it was driven from via
      ``Sec-Fetch-Site`` -- a header the page cannot set -- and a simple-form
      POST also carries a foreign ``Origin`` (no preflight to block it).

    Non-browser clients (curl / SDKs) send none of these and pass untouched;
    ``--api-key`` remains an independent layer.  The Host allowlist is the
    whole defence when no secret is configured; once one is set, the secret
    gates and a remote caller must be allowed to name the host it actually
    reached (``--host 0.0.0.0 --api-key ...`` used to 403 every legitimate
    remote client -- measured in Phase 190).
    """
    lower = {str(k).lower(): (v or "") for k, v in (headers or {}).items()}
    host_hdr = lower.get("host", "")
    host_name = host_name_of(host_hdr)
    if (host_name and host_name not in local_hosts
            and not has_api_key):
        return False, f"host header {host_hdr!r} is not a local host"
    sfs = lower.get("sec-fetch-site", "").strip().lower()
    if sfs == "cross-site":
        return False, (f"browser reports this {method} as cross-site "
                       "(Sec-Fetch-Site: cross-site)")
    if method in _MUTATING_METHODS:
        origin = lower.get("origin", "")
        if origin:
            try:
                ohost = urlparse(origin).hostname or ""
            except Exception:
                ohost = ""
            if ohost.lower() not in local_hosts:
                return False, (f"cross-origin state change from "
                               f"{origin!r} is not allowed")
    return True, ""


def base_local_hosts(bind_host: str | None = None) -> set:
    """Host names a server answers for: loopback names + the bind address."""
    hosts = {"127.0.0.1", "localhost", "[::1]", "::1", "0.0.0.0"}
    if bind_host:
        hosts.add(bind_host)
    return {h.lower() for h in hosts}


class RequestCtx:
    """Per-request context shared with route handlers."""
    def __init__(self, server: "StdlibServer", headers: dict) -> None:
        self.server = server
        self.headers = headers
        self.api_key_valid = server._check_api_key(headers)


class Response:
    """Convenience response builder."""

    def __init__(self, status: int = 200, body: Any = None,
                 headers: dict | None = None,
                 content_type: str = "application/json") -> None:
        self.status = status
        self.headers = headers or {}
        self.content_type = content_type
        if isinstance(body, (dict, list)):
            self.body = json.dumps(body, default=str).encode("utf-8")
            self.headers.setdefault("Content-Type", content_type)
        elif isinstance(body, bytes):
            self.body = body
            self.headers.setdefault("Content-Type", content_type)
        elif body is None:
            self.body = b""
            self.headers.setdefault("Content-Type", content_type)
        else:
            self.body = str(body).encode("utf-8")
            self.headers.setdefault("Content-Type", content_type)

    @classmethod
    def json(cls, status: int, obj: Any) -> "Response":
        return cls(status, obj, content_type="application/json")

    @classmethod
    def text(cls, status: int, text: str,
             content_type: str = "text/plain") -> "Response":
        r = cls(status, text.encode("utf-8"), content_type=content_type)
        return r

    @classmethod
    def error(cls, status: int, message: str, detail: str = "") -> "Response":
        body = {"error": message}
        if detail:
            body["detail"] = detail
        return cls(status, body, content_type="application/json")
# Route handlers --------------------------------------------------------
def _handle_health(ctx, m, body, query) -> Response:
    return Response.json(200, {
        "status": "ok",
        "time": datetime.now().isoformat(timespec="seconds"),
    })


def _handle_info(ctx, m, body, query) -> Response:
    return Response.json(200, _version_info())


def _handle_metrics(ctx, m, body, query) -> Response:
    """Phase 28-3: Prometheus text exposition endpoint.

    The metrics endpoint is intentionally **not** behind API-key auth --
    Prometheus scrapers typically cannot send custom headers, and the
    exposed data contains only aggregate counters (no PII or target
    URLs).  Deployments that need auth should put a reverse proxy in
    front.
    """
    from .metrics import get_registry
    text = get_registry().render()
    return Response(
        200,
        {"Content-Type": "text/plain; version=0.0.4; charset=utf-8"},
        text.encode("utf-8"),
    )


def _handle_create_scan(ctx, m, body, query) -> Response:
    if not ctx.api_key_valid:
        return Response.error(401, "unauthorized", "missing or invalid API key")
    if not isinstance(body, dict):
        return Response.error(400, "invalid_request",
                              "request body must be a JSON object")
    url = body.get("url") or body.get("target")
    if not url:
        return Response.error(400, "invalid_request",
                              "'url' field is required")
    method = (body.get("method") or "GET").upper()
    if method not in ("GET", "POST"):
        return Response.error(400, "invalid_request",
                              "method must be GET or POST")
    params = body.get("params") or {}
    data = body.get("data") or {}
    if not isinstance(params, dict) or not isinstance(data, dict):
        return Response.error(400, "invalid_request",
                              "'params' and 'data' must be objects")

    # Build the scanner-options snapshot from the request.  Anything not
    # provided falls back to a sane default.
    options = {
        "timeout": int(body.get("timeout", 15)),
        "proxy": body.get("proxy"),
        "headers": body.get("headers") or {},
        "cookies": body.get("cookies") or {},
        "verify_ssl": bool(body.get("verify_ssl", True)),
        "rate_limit": float(body.get("rate_limit", 0)),
        "headless": bool(body.get("headless", False)),
        "max_transforms": int(body.get("max_transforms", 12)),
        "max_payloads": int(body.get("max_payloads", 14)),
        "crawl": bool(body.get("crawl", False)),
        "crawl_depth": int(body.get("crawl_depth", 2)),
        "scope": body.get("scope"),
        "threads": int(body.get("threads", 4)),
        "dom_engine": body.get("dom_engine", "auto"),
        "crawl_engine": body.get("crawl_engine", "auto"),
        "custom_payloads": body.get("custom_payloads") or [],
        # Phase 176: AI narrative, opt-in per scan.  Off by default because
        # enabling it sends the target URL, parameters and payloads to a
        # third-party model provider.  Note `_ai_config` is server-side only:
        # a client picks which models may be used, never a filesystem path for
        # the server to load.
        "ai_report": bool(body.get("ai_report", False)),
        "ai_lang": str(body.get("ai_lang") or "zh"),
        "ai_models": _parse_ai_models(body.get("ai_model")),
        "ai_timeout": body.get("ai_timeout"),
        "ai_max_findings": int(body.get("ai_max_findings") or 25),
        "_ai_config": getattr(ctx.server, "ai_config", None),
    }

    mgr = ctx.server.job_manager
    job = mgr.create(url, method=method, params=params, data=data,
                     options=options)

    # Inject the publish/fail closures so the worker can transition the
    # job state through the manager (which holds the lock).
    def _publish(*, findings, requests_made, waf_name, coverage_summary):
        mgr.mark_completed(
            job.scan_id, findings=findings, requests_made=requests_made,
            waf_name=waf_name, coverage_summary=coverage_summary)
        # Phase 28-2: fire webhook on terminal state.
        try:
            ctx.server.webhook.notify_scan_complete(job.to_summary())
        except Exception:
            pass
        # Phase 28-3: record metrics.
        _record_scan_metrics(job, findings)
    def _fail(err: str):
        mgr.mark_failed(job.scan_id, err)
        try:
            ctx.server.webhook.notify_scan_complete(job.to_summary())
        except Exception:
            pass
        _record_scan_metrics(job, [])
    # Stash on options dict (consumed by _scan_worker).
    job.options["_publish_fn"] = _publish
    job.options["_fail_fn"] = _fail

    # Launch the worker.
    try:
        mgr.start(job.scan_id, _scan_worker)
    except Exception as e:
        return Response.error(500, "scan_start_failed", str(e))

    return Response.json(202, {
        "scan_id": job.scan_id,
        "state": job.state,
        "target_url": job.target_url,
        "created_at": job.created_at,
        "status_url": f"/api/v1/scans/{job.scan_id}",
    })


def _handle_list_scans(ctx, m, body, query) -> Response:
    if not ctx.api_key_valid:
        return Response.error(401, "unauthorized", "missing or invalid API key")
    state = (query.get("state") or [None])[0]
    limit_raw = (query.get("limit") or ["50"])[0]
    try:
        limit = max(1, min(500, int(limit_raw)))
    except ValueError:
        limit = 50
    jobs = ctx.server.job_manager.list_jobs(state=state, limit=limit)
    return Response.json(200, {
        "count": len(jobs),
        "scans": [j.to_summary() for j in jobs],
    })


def _handle_get_scan(ctx, m, body, query) -> Response:
    if not ctx.api_key_valid:
        return Response.error(401, "unauthorized", "missing or invalid API key")
    scan_id = m.group("id")
    try:
        job = ctx.server.job_manager.get(scan_id)
    except JobNotFoundError:
        return Response.error(404, "not_found", f"scan '{scan_id}' not found")
    return Response.json(200, job.to_detail())


def _handle_get_findings(ctx, m, body, query) -> Response:
    if not ctx.api_key_valid:
        return Response.error(401, "unauthorized", "missing or invalid API key")
    scan_id = m.group("id")
    try:
        job = ctx.server.job_manager.get(scan_id)
    except JobNotFoundError:
        return Response.error(404, "not_found", f"scan '{scan_id}' not found")
    severity = (query.get("severity") or [None])[0]
    findings = job.findings
    if severity:
        sev_low = severity.lower()
        findings = [f for f in findings
                    if (f.get("severity") or "").lower() == sev_low]
    return Response.json(200, {
        "scan_id": scan_id,
        "state": job.state,
        "count": len(findings),
        "findings": findings,
    })


def _handle_get_report(ctx, m, body, query) -> Response:
    if not ctx.api_key_valid:
        return Response.error(401, "unauthorized", "missing or invalid API key")
    scan_id = m.group("id")
    try:
        job = ctx.server.job_manager.get(scan_id)
    except JobNotFoundError:
        return Response.error(404, "not_found", f"scan '{scan_id}' not found")
    if job.state not in JobState.TERMINAL:
        return Response.error(409, "not_ready",
                              f"scan is {job.state}; report not available yet")
    fmt = ((query.get("format") or ["html"])[0]).lower()
    if fmt not in ("html", "json", "csv", "sarif", "junit", "markdown"):
        return Response.error(400, "invalid_format",
                              "format must be one of: html, json, csv, sarif, junit, markdown")

    from xssentinel.core import report as reportmod
    from xssentinel.core.scanner import Scanner

    # Build a lightweight shim so the report writer (which expects a
    # Scanner with .findings/.requests_made/.waf_name/.coverage) works.
    shim = Scanner(requester=None)
    # Reconstitute Finding objects from the stored dicts.
    # Phase 29-1: validate stored findings before rendering so corrupted
    # persistence data cannot crash the report writer.
    from xssentinel.core.scanner import Finding
    stored_findings = job.findings or []
    valid_stored, _ = validate_findings(stored_findings)
    shim.findings = [Finding(**f) if isinstance(f, dict) else f
                     for f in valid_stored]
    shim.requests_made = job.requests_made
    shim.waf_name = job.waf_name

    meta = {
        "target": job.target_url,
        "generated": job.finished_at or datetime.now().isoformat(timespec="seconds"),
        "requests": job.requests_made,
        "waf": job.waf_name,
    }

    # Phase 176: the AI narrative travels with the report.  Two ways in:
    #   * the scan asked for it up front (``options.ai_report``) -> already
    #     cached, so this costs no request latency at all;
    #   * ``?ai=1`` for a scan that did not ask -> generated NOW, which BLOCKS
    #     this request for as long as the provider pool takes (seconds, or up
    #     to the pool's attempt budget when providers are rate-limited).  Use
    #     the scan-time option when request latency matters.
    # ``?ai=refresh`` drops the cache first, to re-generate after the findings
    # or the pool changed.  A degraded (template) section is a valid result,
    # never an error: the pool falling over must not fail the report.
    ai_flag = (query.get("ai") or [""])[0].strip().lower()
    if ai_flag == "refresh":
        job._ai_report = None
    if job._ai_report is not None:
        meta["ai_report"] = job._ai_report
    elif ai_flag in ("1", "true", "yes", "on", "refresh"):
        meta["ai_report"] = _generate_job_ai_report(
            job, shim.findings, meta, job.options)

    builder = {
        "html": reportmod.build_html, "json": reportmod.build_json,
        "csv": reportmod.build_csv, "sarif": reportmod.build_sarif,
        "junit": reportmod.build_junit, "markdown": reportmod.build_markdown,
    }[fmt]
    content_type = {
        "html": "text/html", "json": "application/json",
        "csv": "text/csv", "sarif": "application/json",
        "junit": "application/xml", "markdown": "text/markdown",
    }[fmt]
    out = builder(shim.findings, job.target_url, meta)
    return Response(200, out, content_type=content_type)


def _handle_cancel_scan(ctx, m, body, query) -> Response:
    if not ctx.api_key_valid:
        return Response.error(401, "unauthorized", "missing or invalid API key")
    scan_id = m.group("id")
    try:
        ok = ctx.server.job_manager.request_cancel(scan_id)
    except JobNotFoundError:
        return Response.error(404, "not_found", f"scan '{scan_id}' not found")
    if not ok:
        return Response.json(200, {
            "scan_id": scan_id,
            "message": "scan already terminal; nothing to cancel",
        })
    return Response.json(202, {
        "scan_id": scan_id,
        "message": "cancellation requested; scan will be reported as cancelled when it finishes",
    })


def _handle_delete_scan(ctx, m, body, query) -> Response:
    if not ctx.api_key_valid:
        return Response.error(401, "unauthorized", "missing or invalid API key")
    scan_id = m.group("id")
    try:
        ctx.server.job_manager.get(scan_id)
    except JobNotFoundError:
        return Response.error(404, "not_found", f"scan '{scan_id}' not found")
    ok = ctx.server.job_manager.delete(scan_id)
    if not ok:
        return Response.error(409, "conflict",
                              "cannot delete a running scan; cancel it first")
    return Response.json(200, {"scan_id": scan_id, "deleted": True})


def _handle_verify_fix(ctx, m, body, query) -> Response:
    """One-shot verify-fix: takes findings JSON, replays, returns results.

    Request body::

        {"findings": [...], "options": {"timeout": 15, ...}}

    Returns the verify results as JSON.
    """
    if not ctx.api_key_valid:
        return Response.error(401, "unauthorized", "missing or invalid API key")
    if not isinstance(body, dict):
        return Response.error(400, "invalid_request",
                              "request body must be a JSON object")
    findings = body.get("findings")
    if not isinstance(findings, list):
        return Response.error(400, "invalid_request",
                              "'findings' must be a list")
    # Phase 29-1: validate finding schema before processing.
    valid_findings, errors = validate_findings(findings)
    if not valid_findings and errors:
        # If all findings were rejected, return the errors.
        return Response.json(400, {
            "error": "invalid_findings",
            "details": errors[:20],  # cap error list size
        })
    options = body.get("options") or {}
    requester = _build_requester(options)
    from xssentinel.core import verify_fix as vf
    results = vf.verify_findings(valid_findings, requester, verbose=False)
    s = vf.summarize(results)
    return Response.json(200, {
        "summary": s,
        "results": [{**r, "verify": r.get("verify")} for r in results],
        "validation_warnings": [e for e in errors if "warning" in e],
    })


def _handle_diff(ctx, m, body, query) -> Response:
    """One-shot diff: takes two findings lists, returns the diff."""
    if not ctx.api_key_valid:
        return Response.error(401, "unauthorized", "missing or invalid API key")
    if not isinstance(body, dict):
        return Response.error(400, "invalid_request",
                              "request body must be a JSON object")
    baseline = body.get("baseline") or []
    current = body.get("current") or []
    target = body.get("target") or ""
    if not isinstance(baseline, list) or not isinstance(current, list):
        return Response.error(400, "invalid_request",
                              "'baseline' and 'current' must be lists")
    # Phase 29-1: validate finding schemas (non-blocking -- diff still
    # works on valid findings even if some are rejected).
    valid_baseline, base_errors = validate_findings(baseline)
    valid_current, curr_errors = validate_findings(current)
    if not valid_baseline and base_errors:
        return Response.json(400, {
            "error": "invalid_baseline",
            "details": base_errors[:20],
        })
    if not valid_current and curr_errors:
        return Response.json(400, {
            "error": "invalid_current",
            "details": curr_errors[:20],
        })
    from xssentinel.core import diff_report as dr
    diff = dr.diff_findings(valid_baseline, valid_current)
    return Response.json(200, {
        "target": target,
        "summary": diff["summary"],
        "diff": diff,
    })


# ---------------------------------------------------------------------------
# Phase 324: MCP Streamable HTTP transport (POST /mcp)
# ---------------------------------------------------------------------------
# The same JSON-RPC dispatch the stdio ``--mcp`` mode serves, exposed on the
# REST API so agent platforms that attach tools by URL (ARTEX/Claude/Cursor
# style) can use the scanner without spawning a process.  Stateless by
# design: no session id is issued, so a client can post every message
# independently -- the tools are stateless too, so a session would only be
# state that can go stale.  Auth reuses the API server's ``--api-key``; the
# shared same-origin gate (Phase 70/196) already polices browser callers.
def _handle_mcp(ctx, m, body, query) -> Response:
    """One JSON-RPC message (or batch) -> one JSON-RPC response."""
    if not ctx.api_key_valid:
        return Response.error(401, "unauthorized", "missing or invalid API key")
    from .mcp_server import dispatch_message

    # The shared dispatch layer answers malformed JSON with HTTP 400 for
    # the REST routes; MCP says a parse error must be a JSON-RPC error
    # (-32700) instead, so ``_dispatch`` hands the marker through to us.
    if isinstance(body, dict) and body.get("_invalid_json"):
        return Response.json(200, {
            "jsonrpc": "2.0", "id": None,
            "error": {"code": -32700,
                      "message": f"parse error: {body['_invalid_json']}"},
        })

    batch = isinstance(body, list)
    msgs = body if batch else [body]
    responses: list = []
    for msg in msgs:
        if not isinstance(msg, dict):
            responses.append({"jsonrpc": "2.0", "id": None,
                              "error": {"code": -32600,
                                        "message": ("invalid request: "
                                                    "expected object")}})
            continue
        resp = dispatch_message(msg)
        if resp is not None:                  # notifications never answer
            responses.append(resp)
    if not responses:
        # Notifications only: JSON-RPC forbids a response body; the
        # Streamable HTTP transport answers 202 Accepted.
        return Response(202, None)
    return Response.json(200, responses if batch else responses[0])


def _handle_mcp_unsupported(ctx, m, body, query) -> Response:
    """GET/DELETE ``/mcp``: this transport is POST-only.

    No SSE stream is offered (the server produces one response per
    request), and there is no session to terminate -- the spec's 405 for
    both.  Answered explicitly so a client probing for an SSE upgrade
    gets a clear "not here" instead of a generic 404.
    """
    resp = Response.error(
        405, "method_not_allowed",
        "MCP Streamable HTTP endpoint is POST-only: post a JSON-RPC "
        "message to /mcp")
    resp.headers["Allow"] = "POST"
    return resp



# Route table ----------------------------------------------------------
# Order matters: more specific routes first.
_ROUTES: list[tuple[str, re.Pattern, Callable]] = [
    ("GET",    re.compile(r"^/api/v1/health/?$"),                 _handle_health),
    ("GET",    re.compile(r"^/api/v1/info/?$"),                   _handle_info),
    ("GET",    re.compile(r"^/api/v1/metrics/?$"),                _handle_metrics),
    ("POST",   re.compile(r"^/api/v1/scans/?$"),                  _handle_create_scan),
    ("GET",    re.compile(r"^/api/v1/scans/?$"),                  _handle_list_scans),
    ("GET",    re.compile(r"^/api/v1/scans/(?P<id>[^/]+)/findings/?$"),
              _handle_get_findings),
    ("GET",    re.compile(r"^/api/v1/scans/(?P<id>[^/]+)/report/?$"),
              _handle_get_report),
    ("DELETE", re.compile(r"^/api/v1/scans/(?P<id>[^/]+)/?$"),    _handle_delete_scan),
    ("GET",    re.compile(r"^/api/v1/scans/(?P<id>[^/]+)/?$"),    _handle_get_scan),
    ("POST",   re.compile(r"^/api/v1/scans/(?P<id>[^/]+)/cancel/?$"),
              _handle_cancel_scan),
    ("POST",   re.compile(r"^/api/v1/verify-fix/?$"),             _handle_verify_fix),
    ("POST",   re.compile(r"^/api/v1/diff/?$"),                   _handle_diff),
    # Phase 324: MCP Streamable HTTP transport (POST-only; GET/DELETE 405).
    ("POST",   re.compile(r"^/mcp/?$"),                           _handle_mcp),
    ("GET",    re.compile(r"^/mcp/?$"),                           _handle_mcp_unsupported),
    ("DELETE", re.compile(r"^/mcp/?$"),                           _handle_mcp_unsupported),
]


def _match_route(method: str, path: str):
    """Return (handler, match) or (None, None) if no route matches."""
    for rmethod, rregex, handler in _ROUTES:
        if rmethod != method:
            continue
        m = rregex.match(path)
        if m:
            return handler, m
    return None, None


# ---------------------------------------------------------------------------
# Stdlib backend
# ---------------------------------------------------------------------------
class _StdlibHandler(BaseHTTPRequestHandler):
    """Per-request handler for :class:`StdlibServer`."""

    # Quieter logging -- the default implementation prints every request.
    def log_message(self, fmt, *args):
        # Route through Python logging if verbose, else silent.
        if self.server.verbose:  # type: ignore[attr-defined]
            BaseHTTPRequestHandler.log_message(self, fmt, *args)

    # -- helpers --------------------------------------------------------
    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length <= 0:
            return b""
        # Phase 29-1: enforce max body size before reading.
        xss_server = getattr(self.server, "_xss_server", None)
        max_bytes = getattr(xss_server, "max_body_bytes", DEFAULT_MAX_BODY_BYTES
                            ) if xss_server else DEFAULT_MAX_BODY_BYTES
        if length > max_bytes:
            # Drain the socket to avoid connection reset issues, then
            # return empty so the handler sees a missing body rather than
            # a partial read.
            try:
                self.rfile.read(max_bytes)
            except Exception:
                pass
            return b""
        return self.rfile.read(length)

    def _parse_json_body(self) -> Any:
        raw = self._read_body()
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            return {"_invalid_json": str(e)}

    def _send_response(self, resp: Response) -> None:
        # Phase 29-1: CORS allowlist.  Only emit Access-Control-Allow-Origin
        # when the request Origin matches the configured allowlist.  This
        # prevents arbitrary third-party pages from issuing authenticated
        # cross-origin requests to the API.
        origin = self.headers.get("Origin")
        headers = dict(resp.headers)
        xss_server = getattr(self.server, "_xss_server", None)
        allowed_origins = getattr(xss_server, "cors_origins", []) if xss_server else []
        allow_origin = cors_origin_for(origin, allowed_origins) if origin else None
        if allow_origin:
            headers["Access-Control-Allow-Origin"] = allow_origin
            # Allow-Credentials only when not using wildcard (CORS spec).
            if allow_origin != "*":
                headers["Access-Control-Allow-Credentials"] = "true"
        headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
        headers["Access-Control-Allow-Headers"] = (
            "Content-Type, Authorization, X-API-Key")
        headers["X-Content-Type-Options"] = "nosniff"

        self.send_response(resp.status)
        for k, v in headers.items():
            self.send_header(k, str(v))
        self.send_header("Content-Length", str(len(resp.body)))
        self.end_headers()
        if resp.body:
            self.wfile.write(resp.body)

    def _headers_dict(self) -> dict:
        return {k: v for k, v in self.headers.items()}

    def _dispatch(self, method: str) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query, keep_blank_values=True)
        # Phase 70/71: same-origin addressing -- checked BEFORE routing.
        # Host is validated for EVERY method (a rebound GET reads scan data
        # same-origin); Origin only for state-changing methods (GET carries
        # no Origin from normal navigation).
        xss_server = getattr(self.server, "_xss_server", None) or self.server
        if hasattr(xss_server, "_same_origin_ok"):
            ok, reason = xss_server._same_origin_ok(method,
                                                    self._headers_dict())
            if not ok:
                self._send_response(Response.error(
                    403, "cross_origin_blocked", reason))
                return
        handler, m = _match_route(method, path)
        if handler is None:
            self._send_response(Response.error(
                404, "not_found",
                f"no route for {method} {path}"))
            return
        # The StdlibServer instance is attached to the ThreadingHTTPServer
        # via the `_xss_server` attribute (set in serve_forever /
        # start_in_thread).  Route handlers reach the JobManager and the
        # API-key check through it.
        xss_server = getattr(self.server, "_xss_server", None)
        if xss_server is None:
            # Fallback: treat the bare HTTPServer as the server (only
            # works when no API key is configured -- used in some unit
            # tests that bypass the full StdlibServer).
            xss_server = self.server
        ctx = RequestCtx(xss_server, self._headers_dict())  # type: ignore[arg-type]
        body = None
        if method in ("POST", "PUT", "PATCH"):
            body = self._parse_json_body()
            # Phase 324: /mcp answers malformed JSON with the JSON-RPC
            # parse error (-32700) the MCP spec requires -- the generic
            # HTTP 400 marker is for the REST routes only.
            if (isinstance(body, dict) and body.get("_invalid_json")
                    and path.rstrip("/") != "/mcp"):
                self._send_response(Response.error(
                    400, "invalid_json", body["_invalid_json"]))
                return
        try:
            resp = handler(ctx, m, body, query)
        except Exception as e:
            resp = Response.error(500, "internal_error", str(e))
        self._send_response(resp)

    # -- HTTP verbs -----------------------------------------------------
    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def do_OPTIONS(self):
        # CORS preflight -- echo allowed methods.  Phase 85: the echoed
        # Origin must pass the same allowlist as real responses (the old
        # code echoed ANY Origin with credentials -- a policy hole even if
        # actual reads were blocked).
        self.send_response(204)
        origin = self.headers.get("Origin")
        xss_server = getattr(self.server, "_xss_server", None) or self.server
        allowed = origin and hasattr(xss_server, "cors_origin_for") and \
            xss_server.cors_origin_for(origin) == origin
        if origin and allowed:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Methods",
                         "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers",
                         "Content-Type, Authorization, X-API-Key")
        self.end_headers()


class StdlibServer:
    """Zero-dependency REST API server.

    Built on :class:`http.server.ThreadingHTTPServer` so each request
    runs in its own thread -- a long-running scan worker does not block
    status/health checks from other clients.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8000,
                 api_key: str | None = None, max_jobs: int = 200,
                 verbose: bool = False, db_path: str | None = None,
                 webhook_urls: list[str] | None = None,
                 webhook_secret: str | None = None,
                 cors_origins: str | list[str] | None = None,
                 max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
                 ai_config: str | None = None) -> None:
        self.host = host
        self.port = port
        self.api_key = api_key
        self.verbose = verbose
        # Phase 176: LLM provider pool config for scans that ask for an AI
        # narrative.  A server-side setting on purpose -- a request body may
        # choose models, but never a filesystem path for the server to load.
        self.ai_config = ai_config
        # Phase 29-1: CORS allowlist.  When empty, no Access-Control-Allow-Origin
        # header is emitted (browsers block cross-origin requests).  When set
        # to "*" or a list of origins, only matching origins are allowed.
        self.cors_origins = parse_cors_origins(cors_origins)
        # Phase 29-1: maximum inbound request body size (DoS mitigation).
        self.max_body_bytes = max_body_bytes
        # Phase 28-1: optional SQLite persistence.  When db_path is set,
        # the JobManager reloads terminal jobs on startup and mirrors
        # every state transition to disk so history survives restarts.
        store = None
        if db_path:
            from .persistence import SqliteJobStore
            store = SqliteJobStore(db_path)
            print(f"[+] SQLite persistence enabled: {db_path}")
        self.job_manager = JobManager(max_jobs=max_jobs, store=store)
        # Phase 28-2: optional webhook notifier.  When webhook_urls is
        # non-empty, every scan that reaches a terminal state fires a
        # POST to each URL with a JSON summary of the result.
        from .notifications import WebhookNotifier
        self.webhook = WebhookNotifier(
            urls=webhook_urls, secret=webhook_secret)
        if webhook_urls:
            print(f"[+] Webhook notifications enabled: {len(webhook_urls)} URL(s)")
            if webhook_secret:
                print("[+] Webhook HMAC signing enabled")
        self._httpd: ThreadingHTTPServer | None = None

    # -- Phase 70: same-origin defence (DNS rebinding / cross-site POST) ----
    def _local_hosts(self) -> set:
        """Host names this server answers for (loopback + bound address)."""
        return base_local_hosts(self.host)

    def _same_origin_ok(self, method: str, headers: dict) -> tuple:
        """See :func:`same_origin_ok` -- the shared gate, not a second one."""
        return same_origin_ok(method, headers, self._local_hosts(),
                              bool(self.api_key))

    def _check_api_key(self, headers: dict) -> bool:
        """Return True if the request is authorised.

        No API key configured -> always authorised.  Otherwise the
        request must carry ``X-API-Key`` matching the configured key.
        HTTP header names are case-insensitive (RFC 7230 §3.2), so we
        normalise to lowercase before comparing -- ``urllib.request``
        normalises ``X-API-Key`` to ``X-Api-Key`` on the wire, and
        other clients may send any casing.
        """
        if not self.api_key:
            return True
        # Build a lowercase->value map for case-insensitive lookup.
        lower = {k.lower(): v for k, v in headers.items()}
        provided = lower.get("x-api-key")
        return bool(provided) and hmac.compare_digest(provided, self.api_key)

    def serve_forever(self) -> None:
        """Start the HTTP server (blocking)."""
        self._httpd = ThreadingHTTPServer(
            (self.host, self.port), _StdlibHandler)
        self._httpd.verbose = self.verbose  # type: ignore[attr-defined]
        # Expose this StdlibServer instance to the handler so route
        # handlers can reach ``job_manager`` and ``_check_api_key``.
        self._httpd._xss_server = self  # type: ignore[attr-defined]
        # Allow quick restart during tests.
        self._httpd.daemon_threads = True
        # If port=0 was requested, capture the actual bound port.
        self.port = self._httpd.server_address[1]
        print(f"[+] XSSentinel REST API listening on "
              f"http://{self.host}:{self.port}/api/v1/")
        if self.api_key:
            print("[+] API key authentication enabled (X-API-Key header)")
        try:
            self._httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Shutting down ...")
        finally:
            self._httpd.shutdown()
            self._httpd.server_close()

    def start_in_thread(self) -> threading.Thread:
        """Start the server in a background thread (test helper).

        Binds to the configured ``host``/``port`` (use port=0 for an
        ephemeral port), then serves in a daemon thread.  The actual
        port is available as ``self.port`` after this returns.
        """
        self._httpd = ThreadingHTTPServer(
            (self.host, self.port), _StdlibHandler)
        self._httpd.verbose = self.verbose  # type: ignore[attr-defined]
        self._httpd._xss_server = self  # type: ignore[attr-defined]
        self._httpd.daemon_threads = True
        self.port = self._httpd.server_address[1]
        self.base_url = f"http://{self.host}:{self.port}"
        thread = threading.Thread(target=self._httpd.serve_forever,
                                  daemon=True)
        thread.start()
        return thread

    def shutdown(self) -> None:
        """Stop the server (test helper)."""
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None


# ---------------------------------------------------------------------------
# Optional Flask backend
# ---------------------------------------------------------------------------
class FlaskServer:
    """Optional Flask adapter.

    Mounts the same route handlers under a Flask app when Flask is
    installed.  Useful when XSSentinel must coexist with other Flask
    blueprints in an existing service mesh.

    Usage::

        from xssentinel.api.server import FlaskServer
        app = FlaskServer().app   # get the Flask app
        app.run(port=8000)

    Or mount as a blueprint in an existing app::

        from flask import Flask
        from xssentinel.api.server import FlaskServer
        my_app = Flask(__name__)
        FlaskServer().register_as_blueprint(my_app, url_prefix="/xss")
    """

    def __init__(self, api_key: str | None = None,
                 max_jobs: int = 200, verbose: bool = False,
                 cors_origins: str | list[str] | None = None,
                 max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
                 ai_config: str | None = None) -> None:
        try:
            from flask import Flask
        except ImportError as e:
            raise RuntimeError(
                "FlaskServer requires Flask; install with: pip install flask"
            ) from e
        self.api_key = api_key
        self.verbose = verbose
        # Phase 176: see StdlibServer.__init__ -- server-side pool path.
        self.ai_config = ai_config
        self.cors_origins = parse_cors_origins(cors_origins)
        self.max_body_bytes = max_body_bytes
        self.job_manager = JobManager(max_jobs=max_jobs)
        self.app = Flask("xssentinel-api")
        self._register_routes()
        # Phase 29-1: enforce body size cap at the Flask level.
        @self.app.before_request
        def _limit_body_size():
            from flask import request as _req
            cl = int(_req.headers.get("Content-Length", 0) or 0)
            if cl > self.max_body_bytes:
                from flask import jsonify as _jsonify
                return _jsonify({"error": "request_body_too_large",
                                 "max_bytes": self.max_body_bytes}), 413

        # Phase 196: the same-origin gate the stdlib front-end has enforced
        # since Phase 70 -- this front-end enforced none of it, so a
        # DNS-rebound page could read scan results and a cross-site form POST
        # could start scans whenever no --api-key was configured.  Registered
        # as before_request so it runs BEFORE routing and before auth, which
        # is how the stdlib dispatch does it.
        @self.app.before_request
        def _same_origin_gate():
            from flask import jsonify as _jsonify, request as _req
            # CORS preflight is not a state change and carries no data; the
            # stdlib front-end answers it in a separate do_OPTIONS that never
            # consults this gate.  Gating it here would 403 the preflight of
            # exactly the origins --cors-origins exists to allow (measured:
            # an allowed cross-site OPTIONS got 403), so the browser would
            # never reach the real request that the gate does police.
            if _req.method == "OPTIONS":
                return None
            ok, reason = self._same_origin_ok(_req.method,
                                              dict(_req.headers))
            if not ok:
                return _jsonify({"error": "cross_origin_blocked",
                                 "reason": reason}), 403

    def _local_hosts(self) -> set:
        """Same allowlist the stdlib front-end enforces (FlaskServer has no
        bind host of its own -- it is mounted into an app by the caller)."""
        return base_local_hosts()

    def _same_origin_ok(self, method: str, headers: dict) -> tuple:
        return same_origin_ok(method, headers, self._local_hosts(),
                              bool(self.api_key))

    def _check_api_key(self, headers) -> bool:
        if not self.api_key:
            return True
        from flask import request
        provided = request.headers.get("X-API-Key")
        return bool(provided) and hmac.compare_digest(provided, self.api_key)

    def _wrap(self, handler, with_match=False):
        from flask import request, jsonify, Response as FResp
        def _view(**kwargs):
            ctx = RequestCtx(self, dict(request.headers))  # type: ignore[arg-type]
            if not ctx.api_key_valid:
                return jsonify({"error": "unauthorized"}), 401
            body = request.get_json(silent=True) if request.method in (
                "POST", "PUT", "PATCH") else None
            query = {k: v for k, v in request.args.items()}
            # Convert single-value lists for compatibility with stdlib handler.
            query_lists = {k: ([v] if isinstance(v, str) else v)
                           for k, v in query.items()}
            # Build a fake match object if the handler needs the id.
            class _M:
                def __init__(self, d):
                    self._d = d
                def group(self, name):
                    return self._d.get(name)
            m = _M(kwargs)
            try:
                resp = handler(ctx, m, body, query_lists)
            except Exception as e:
                resp = Response.error(500, "internal_error", str(e))
            # Phase 29-1: apply CORS allowlist.
            origin = request.headers.get("Origin")
            allow_origin = cors_origin_for(origin, self.cors_origins) if origin else None
            flask_resp = FResp(resp.body, status=resp.status,
                               mimetype=resp.content_type)
            if allow_origin:
                flask_resp.headers["Access-Control-Allow-Origin"] = allow_origin
                if allow_origin != "*":
                    flask_resp.headers["Access-Control-Allow-Credentials"] = "true"
            flask_resp.headers["Access-Control-Allow-Methods"] = (
                "GET, POST, DELETE, OPTIONS")
            flask_resp.headers["Access-Control-Allow-Headers"] = (
                "Content-Type, Authorization, X-API-Key")
            flask_resp.headers["X-Content-Type-Options"] = "nosniff"
            return flask_resp
        return _view

    def _register_routes(self) -> None:
        # Map each stdlib route to a Flask rule.
        routes = [
            ("GET",    "/api/v1/health",            _handle_health),
            ("GET",    "/api/v1/info",              _handle_info),
            ("GET",    "/api/v1/metrics",           _handle_metrics),
            ("POST",   "/api/v1/scans",             _handle_create_scan),
            ("GET",    "/api/v1/scans",             _handle_list_scans),
            ("GET",    "/api/v1/scans/<id>/findings", _handle_get_findings),
            ("GET",    "/api/v1/scans/<id>/report",   _handle_get_report),
            ("DELETE", "/api/v1/scans/<id>",        _handle_delete_scan),
            ("GET",    "/api/v1/scans/<id>",        _handle_get_scan),
            ("POST",   "/api/v1/scans/<id>/cancel", _handle_cancel_scan),
            ("POST",   "/api/v1/verify-fix",        _handle_verify_fix),
            ("POST",   "/api/v1/diff",              _handle_diff),
            # Phase 324: MCP Streamable HTTP transport (same handlers).
            ("POST",   "/mcp",                      _handle_mcp),
            ("GET",    "/mcp",                      _handle_mcp_unsupported),
            ("DELETE", "/mcp",                      _handle_mcp_unsupported),
        ]
        for method, rule, handler in routes:
            view = self._wrap(handler)
            view.__name__ = handler.__name__
            # Phase 324: one handler can own two rules (GET/DELETE /mcp ->
            # 405).  ``_wrap`` returns a NEW closure per call, so Flask's
            # "same endpoint must be the same view function" assertion would
            # fire on a shared endpoint name -- suffix the second one.
            endpoint = handler.__name__
            if endpoint in self.app.view_functions:
                endpoint = f"{endpoint}_{method.lower()}"
            self.app.add_url_rule(rule, endpoint=endpoint,
                                  view_func=view, methods=[method, "OPTIONS"])

    def register_as_blueprint(self, parent_app, url_prefix: str = "") -> None:
        """Mount the API under an existing Flask app at ``url_prefix``."""
        from flask import Blueprint
        bp = Blueprint("xssentinel_api", __name__)
        # Re-register routes against the blueprint with the prefix.
        original_rules = list(self.app.url_map.iter_rules())
        for rule in original_rules:
            if rule.endpoint == "static":
                continue
            view = self.app.view_functions[rule.endpoint]
            full_rule = url_prefix + rule.rule
            methods = sorted(rule.methods - {"HEAD", "OPTIONS"})
            bp.add_url_rule(full_rule, endpoint=rule.endpoint,
                            view_func=view, methods=methods)
        parent_app.register_blueprint(bp)

    def run(self, host: str = "127.0.0.1", port: int = 8000) -> None:
        self.app.run(host=host, port=port, threaded=True)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

# Hosts that only ever accept connections from this machine.  Anything else
# (0.0.0.0, a LAN address, a public interface) means the API is reachable by
# other hosts.
_LOOPBACK_BINDS = {"127.0.0.1", "localhost", "::1", "[::1]"}


def _warn_unauthenticated_external_bind(host: str,
                                        api_key: str | None) -> None:
    """``--host 0.0.0.0`` is an advertised option; ``--api-key`` is optional.

    Together they make an unauthenticated, network-reachable service that will
    fetch any URL you give it (from the machine it runs on, with the operator's
    ``-b``/``-H`` credentials attached) and hand the results back to whoever can
    reach the port -- an SSRF oracle plus a finding disclosure endpoint.

    The Phase 70 same-origin defence is NOT the access-control layer here.  It
    is browser-shaped by design: a web page cannot forge ``Host`` or ``Origin``,
    so the allowlist stops a drive-by page from reaching a local API.  A
    scripted client on the network picks its own ``Host`` header (``curl -H
    'Host: localhost'`` passes) -- measured, not assumed.

    We warn rather than refuse: binding externally behind a reverse proxy that
    terminates auth is a legitimate deployment.
    """
    if api_key or (host or "").strip().lower() in _LOOPBACK_BINDS:
        return
    print(f"[!] Bound to {host!r} with NO --api-key: anyone who can reach this "
          "port can start scans, read results, and make the scanner fetch "
          "arbitrary URLs (with your -b/-H credentials).  Set --api-key, or "
          "bind 127.0.0.1 and put a proxy in front.", file=sys.stderr)


def run_stdio(host: str = "127.0.0.1", port: int = 8000,
              api_key: str | None = None, verbose: bool = False,
              max_jobs: int = 200, use_flask: bool = False,
              db_path: str | None = None,
              webhook_urls: list[str] | None = None,
              webhook_secret: str | None = None,
              cors_origins: str | list[str] | None = None,
              max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
              ai_config: str | None = None) -> int:
    """Start the API server.  Used by the CLI ``--serve`` flag."""
    _warn_unauthenticated_external_bind(host, api_key)
    if use_flask:
        try:
            server = FlaskServer(api_key=api_key, max_jobs=max_jobs,
                                 verbose=verbose,
                                 cors_origins=cors_origins,
                                 max_body_bytes=max_body_bytes,
                                 ai_config=ai_config)
            server.run(host=host, port=port)
            return 0
        except RuntimeError as e:
            print(f"[!] {e}")
            return 1
    server = StdlibServer(host=host, port=port, api_key=api_key,
                          max_jobs=max_jobs, verbose=verbose,
                          db_path=db_path,
                          webhook_urls=webhook_urls,
                          webhook_secret=webhook_secret,
                          cors_origins=cors_origins,
                          max_body_bytes=max_body_bytes,
                          ai_config=ai_config)
    server.serve_forever()
    return 0
