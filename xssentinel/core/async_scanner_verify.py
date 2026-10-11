# -*- coding: utf-8 -*-
"""Headless (Playwright) confirmation of async findings -- Phase 183.

Phase 191: pure movement out of ``async_scanner.py``.  No method body
was edited here -- ``dev/_p191_baseline.py after`` hashes every method's
source and compares it against the pre-split snapshot.
"""
from __future__ import annotations
import asyncio
from .scanner import Finding
from .findings import (EVIDENCE_OOB,
                       _grade_evidence)
from . import verifier
from .async_scanner_common import (
    _log,
)


class AsyncHeadlessVerifyMixin:
    """Headless (Playwright) confirmation of async findings -- Phase 183.

    Mixed into ``AsyncScanner``; every method below is verbatim from the
    pre-split file.
    """
    def _verify_headers(self) -> dict:
        """Identity the headless replay should carry: the same base +
        auth headers the probes rode, so an authed reflection is confirmed
        against the authed page, not bounced by a login wall."""
        h = dict(getattr(self, "headers", None) or {})
        h.update(dict(getattr(self, "auth_headers", None) or {}))
        return h

    def _verify_pool(self):
        """Lazily create the dedicated verification executor.  getattr
        guards throughout: tests build this scanner with ``__new__`` to
        skip ``__init__``, so every knob must survive that shape."""
        pool = getattr(self, "_headless_pool", None)
        if pool is None:
            import concurrent.futures
            cap = max(1, int(getattr(self, "headless_concurrency", 1) or 1))
            pool = concurrent.futures.ThreadPoolExecutor(
                max_workers=cap, thread_name_prefix="xss-headless")
            self._headless_pool = pool
        return pool

    def shutdown_headless(self) -> None:
        """Release the verification executor (idempotent).  With the worker
        threads gone, their thread-bound Chromiums become collectable; the
        process-wide registry in dom_engine still closes stragglers atexit."""
        pool = getattr(self, "_headless_pool", None)
        if pool is not None:
            pool.shutdown(wait=False)
            self._headless_pool = None

    @staticmethod
    def _probe_token(payload: str) -> str | None:
        """Phase 217: delegates to the shared ``findings.
        extract_replay_token`` -- one copy of the carrier contract for both
        engines (the docstring and stamp order live there now)."""
        from .findings import extract_replay_token
        return extract_replay_token(payload)

    async def _headless_verify_finding(self, f: Finding, seen: set):
        """Browser-confirm one finding, or return it untouched when a dialog
        replay cannot prove anything new.  Re-grades confidence/evidence
        through the SAME ``_grade_evidence`` the sync engine uses, so the
        two engines state identical evidence vocabulary."""
        d = f.data
        if d.get("headless") is not None:
            return f            # already carries browser evidence (e.g. the
                                # DOM-dynamic layer's real-browser verdict)
        if d.get("evidence_class") == EVIDENCE_OOB:
            return f            # OOB callback hit: no dialog to check, and
                                # the report already renders the stronger line
        url = d.get("url")
        if not url:
            return f
        payload = d.get("payload") or ""
        if payload.startswith("(") and payload.endswith(")"):
            return f            # placeholder audit observation, not a
                                # runnable replay (same guard as the
                                # nuclei exporter's Phase 85 rule)
        token = self._probe_token(payload)
        if not token:
            return f            # unattributable replay: verifying could
                                # only produce an unproven "not-fired"
        is_body = d.get("param_in") == "body"
        if is_body and getattr(self, "json_body", None) is not None:
            return f            # JSON carrier: the form-body replay would
                                # confirm the wrong content type (sync's
                                # Phase 46 skip rule, mirrored)
        key = (url, d.get("param"), payload)
        if key in seen:
            return f            # dedup: identical replay, identical evidence
        seen.add(key)
        param = d.get("param") or ""
        loop = asyncio.get_running_loop()
        try:
            result = await loop.run_in_executor(
                self._verify_pool(),
                lambda: verifier.verify_headless(
                    url, d.get("method") or "GET",
                    params=None if is_body else {param: payload},
                    data={param: payload} if is_body else None,
                    headers=self._verify_headers(),
                    token=token))
        except Exception as e:
            _log.warning("headless verification failed for %s: %s",
                         url, e, exc_info=getattr(self, "verbose", False))
            result = {"available": False, "confirmed": False,
                      "outcome": "errored",
                      "detail": f"async headless verify error: {e}"}
        _cls, _conf, _det = _grade_evidence(
            result, d.get("confidence"), d.get("detail") or "")
        d["headless"] = result
        d["evidence_class"] = _cls
        d["confidence"] = _conf
        d["detail"] = _det
        return f
