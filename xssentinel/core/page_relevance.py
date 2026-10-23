# -*- coding: utf-8 -*-
"""Is a page-level hint about the resource we were asked to scan?

When a response redirects to a different path and drops the injected
parameters, the document the page layers analyze is a *different resource*
than the scanned URL.  Its framework / Trusted-Types / WebSocket hints are
real properties of that document, but attributing them to the scanned URL
is a false positive: the payload never reached it.  Measured on XSSMaze's
`redirect/level1..4` controls (302 to `/`, empty body; our report carried
six medium hints against a URL whose value only ever appeared in a
Location header).

The rule is deliberately narrow:

* no redirect, or the redirect kept the same host+path -> relevant;
* a different host -> not the same resource -> not relevant;
* a different path whose final URL still carries a query -> relevant
  (the landing page may be parameterized);
* a different path with an empty final query -> not relevant **when the
  scan had parameters to lose** (the original query or the params dict).

Unknown shapes return "relevant": a gate that suppresses on missing data
would turn an unobserved redirect into silent lost coverage.
"""
from __future__ import annotations

from urllib.parse import urlparse


def _norm_path(path: str) -> str:
    return (path or "/").rstrip("/") or "/"


def redirect_landing_drops_input(requested_url: str | None,
                                 final_url: str | None,
                                 redirected: bool,
                                 params: dict | None = None) -> bool:
    """True when page-level hints no longer describe the scanned resource."""
    if not redirected or not requested_url or not final_url:
        return False
    try:
        rq = urlparse(str(requested_url))
        fn = urlparse(str(final_url))
    except Exception:  # noqa: BLE001 - odd URL shapes must not gate anything
        return False
    if not fn.scheme or not fn.netloc:
        return False
    if (rq.hostname or "").lower() != (fn.hostname or "").lower():
        return True
    if _norm_path(rq.path) == _norm_path(fn.path):
        return False
    if fn.query:
        return False
    return bool(params) or bool(rq.query)
