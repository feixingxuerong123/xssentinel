"""Wayback Machine (CDX) URL-source import (Phase 188, absorbed from the
gau / waymore / ParamSpider recon pipeline).

``--wayback example.com`` queries the Internet Archive CDX API for every
historically-crawled URL of that host (optionally narrowed to a path
prefix) and turns the results into scan targets.  This is the input face
the competitors pipe through ``gau | gf xss | dalfox``; here it is one
flag, with the same scope discipline as the other imports.

Design notes:

  * The CDX query pins ``fl=original`` (the ARCHIVED url, not the
    wayback-rewritten one), ``collapse=urlkey`` (one row per canonical
    variant), ``filter=statuscode:200`` (redirects and dead captures are
    noise for XSS probing) and a ``limit`` -- the archive can hold
    millions of rows for a busy host, and every one of them becomes a
    scan request, so the cap is a safety belt, not decoration.
  * Scope policy mirrors the Phase 184 sitemap import: the operator named
    ONE host; the archive covers the whole web, and a historical capture
    of someone else's CDN is still someone else's system.  Partitioning
    happens in ``cli_runner`` via ``scoping.partition_by_scope``, exactly
    like --har / --openapi / --sitemap.
  * The response is untrusted text: only lines that parse as http(s) URLs
    survive, and a defensive strip removes wayback-rewritten prefixes
    (``web.archive.org/web/<ts>/``) should ``fl=original`` ever leak one.
"""
from __future__ import annotations

from urllib.parse import urlparse, urlunparse, urlencode

__all__ = ["wayback_to_urls", "build_cdx_url"]

_CDX_ENDPOINT = "http://web.archive.org/cdx/search/cdx"

_WAYBACK_PREFIX = "web.archive.org/web/"


def normalize_target(target: str) -> str:
    """``example.com/sub`` -> ``http://example.com/sub`` (scheme required
    by urlparse; http vs https makes no difference to the CDX match)."""
    t = (target or "").strip()
    if "://" not in t:
        t = "http://" + t
    return t


def build_cdx_url(target: str, max_urls: int = 500) -> str:
    """Target -> the CDX query URL.

    A bare host matches the whole domain (``example.com/*``); a URL with a
    path narrows the match to that prefix (``example.com/app/*``).
    """
    p = urlparse(normalize_target(target))
    host = p.netloc.lower()
    # urlparse happily returns "not a host" as a netloc -- a CDX query for a
    # space-bearing host is garbage, reject it instead of querying the
    # archive with it.
    if not host or any(c in host for c in " /\t"):
        raise ValueError(f"wayback target has no host: {target!r}")
    path = p.path.rstrip("/")
    match = host + ("/" + path.strip("/") + "/*" if path else "/*")
    query = urlencode({
        "url": match,
        "output": "text",
        "fl": "original",
        "collapse": "urlkey",
        "filter": "statuscode:200",
        "limit": max_urls,
    })
    return f"{_CDX_ENDPOINT}?{query}"


def _strip_wayback_prefix(url: str) -> str:
    """``http://web.archive.org/web/20240101/http://x/y`` -> ``http://x/y``.

    ``fl=original`` should never emit these, but the API has form-dependent
    quirks; a rewritten URL that slipped through would otherwise become a
    scan target that attacks the ARCHIVE instead of the target.
    """
    low = url.lower()
    idx = low.find(_WAYBACK_PREFIX)
    if idx == -1:
        return url
    rest = url[idx + len(_WAYBACK_PREFIX):]
    # <timestamp>/<original>  (the original may itself carry a scheme)
    parts = rest.split("/", 1)
    if len(parts) == 2 and (parts[1].lower().startswith("http://")
                            or parts[1].lower().startswith("https://")):
        return parts[1]
    return url


def wayback_to_urls(target: str, timeout: int = 30, max_urls: int = 500,
                    fetch=None) -> list[str]:
    """Query the CDX API and return deduplicated scan-target URLs.

    Raises on unreachable CDX endpoints / bad targets; an EMPTY archive
    (host never captured, or the API found nothing) is ``[]``, not an
    error -- callers surface the "zero URLs" message either way.
    """
    cdx_url = build_cdx_url(target, max_urls)
    if fetch is not None:                       # injectable for tests
        text = fetch(cdx_url)
    else:
        import requests
        r = requests.get(cdx_url, timeout=timeout,
                         headers={"User-Agent": "xssentinel-wayback/1.0"},
                         stream=True)
        r.raise_for_status()
        text = r.raw.read(8 * 1024 * 1024 + 1, decode_content=True).decode(
            "utf-8", errors="replace")[:8 * 1024 * 1024]
    urls: list[str] = []
    seen: set[str] = set()
    for ln in (text or "").splitlines():
        ln = _strip_wayback_prefix(ln.strip())
        if not ln or ln.startswith("#"):
            continue
        p = urlparse(ln)
        if p.scheme not in ("http", "https") or not p.netloc:
            continue
        # keep the fragment out: a scan target with a #fragment is the same
        # request, and the dedup below treats it as a duplicate otherwise
        clean = urlunparse(p._replace(fragment=""))
        if clean in seen:
            continue
        seen.add(clean)
        urls.append(clean)
        if len(urls) >= max_urls:
            break
    return urls
