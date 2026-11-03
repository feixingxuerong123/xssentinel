"""Stored-XSS auto-discovery mixin (Phase 352).

Separated from ``scanner_stored.py`` to respect that Mixin's pinned line
budget: this is orchestration (fetch the page, discover forms/viewers, run the
stored round-trip), while the round-trip itself stays in StoredBlindMixin.
"""
from __future__ import annotations

from urllib.parse import urlparse

from .budget import BudgetExhausted, CircuitOpen
from .logger import get_logger
from .stored_discovery import discover_view_urls, discover_write_faces

_log = get_logger("scanner.stored_auto")


class StoredAutoMixin:
    """Default sync path: URL-only targets get stored testing without a flag."""

    def scan_stored_auto(self, page_url: str, page_text: str | None = None,
                         max_forms: int = 2, max_fields: int = 2) -> int:
        """Discover the page's own write forms and prove stored XSS.

        Flow:
          1. GET the page (unless the caller already has the text).
          2. Extract same-origin POST forms with a text field; skip login.
          3. Locate viewer candidates: write page, POST redirect landing,
             viewer-shaped same-origin links, and an API endpoint the page's
             JS fetches into an XSS sink.
          4. Run ``scan_stored(auto=True, poll=True)``.

        Returns the number of form/field pairs exercised.  Budget exhaustion
        and circuit-open propagate: they are scanner control flow, not a
        reason to silently skip a whole stored pass.
        """
        if not getattr(self, "stored_auto", True):
            return 0
        try:
            if page_text is None:
                resp = self.req.get(page_url)
                self._bump()
                page_text = getattr(resp, "text", "") or ""
                page_url = (getattr(resp, "url", "") or page_url)
        except (BudgetExhausted, CircuitOpen):
            raise
        except Exception as e:
            if getattr(self, "verbose", False):
                _log.debug("stored auto: page fetch failed for %s: %s",
                           page_url, e)
            return 0
        if "<form" not in (page_text or "").lower():
            return 0

        faces = discover_write_faces(page_text, page_url, max_forms=max_forms,
                                     max_fields=max_fields)
        ran = 0
        for face in faces:
            action = face["action"]
            views, api_views = discover_view_urls(page_text, page_url, action)
            # L4_second_order: the inject -> viewer shape, visible in the
            # coverage matrix without inventing a new layer id.
            self.coverage.touch_layer(action, "L4_second_order", "POST",
                                      detail=f"auto viewer discovery "
                                             f"({len(views)} candidate(s))")
            for field in face["fields"]:
                companion = {k: v for k, v in face["data"].items()
                             if k != field}
                try:
                    confirmed = self.scan_stored(
                        action, view_url=action, method="POST", param=field,
                        extra_fields=companion, extra_view_urls=views[1:],
                        auto=True, poll=True, api_views=api_views)
                except (BudgetExhausted, CircuitOpen):
                    raise
                except Exception as e:
                    if getattr(self, "verbose", False):
                        _log.debug("stored auto: %s field=%s failed: %s",
                                   action, field, e)
                    continue
                ran += 1
                if confirmed:
                    # One proven viewer per form is enough; the remaining
                    # fields would only re-prove the same rendering site.
                    break
        return ran

    def scan_stored_auto_pages(self, entry_url: str, endpoints: list,
                               max_pages: int = 3) -> int:
        """Run :meth:`scan_stored_auto` over the entry page and crawled pages.

        The entry page is always first.  Crawled GET pages are deduplicated by
        path and capped, so the auto pass stays a bounded add-on rather than a
        second crawler.  Asset URLs, fragments and non-GET endpoints are
        skipped -- a stored write form lives on an HTML page.
        """
        pages: list = []

        def _add(raw: str):
            try:
                p = urlparse(raw or "")
            except Exception:
                return
            if p.scheme not in ("http", "https") or not p.netloc:
                return
            if p.fragment or (p.path or "").lower().endswith(
                    (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                     ".ico", ".woff", ".woff2", ".map", ".json", ".xml")):
                return
            base = f"{p.scheme}://{p.netloc}{p.path or '/'}"
            if base not in pages:
                pages.append(base)

        _add(entry_url)
        for ep in endpoints or []:
            try:
                if str(ep[1]).upper() != "GET":
                    continue
            except Exception:
                continue
            _add(ep[0])
        ran = 0
        for page in pages[:max_pages]:
            ran += self.scan_stored_auto(page)
        return ran
