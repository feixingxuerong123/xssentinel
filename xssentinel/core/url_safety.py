# -*- coding: utf-8 -*-
"""One definition of "a URL we are willing to request".

A ``Location`` response header is attacker-controlled bytes.  requests'
redirect loop turns ``javascript:...`` into the next hop's PreparedRequest
and then fails with ``InvalidSchema``; counting that as a transport failure
makes a healthy scan look ``partial`` (measured on the official XSSMaze
target, 2026-11-08: 14-16 of 86 targets).  aiohttp rejects the same hop
with ``NonHttpUrlRedirectClientError`` -- same family, different exception.

Resolve FIRST, then allowlist.  A raw Location of ``/next`` or ``//cdn/x``
has no scheme but is a legal redirect; ``urljoin`` leaves unknown schemes
untouched (verified on Python 3.12), so an allowlist on the resolved URL
rejects ``javascript:`` / ``data:`` / ``vbscript:`` / ``file:`` / ``blob:``
/ ``mailto:`` and case / tab / newline variants without a blacklist.
"""
from __future__ import annotations

from urllib.parse import urljoin, urlparse

_ALLOWED_SCHEMES = frozenset(("http", "https"))


def is_safe_redirect(base_url: str, location: str | None) -> bool:
    """True when following ``location`` from ``base_url`` stays on http(s).

    ``base_url`` is the URL of the response carrying the Location header.
    An empty location means "no redirect" and is always safe.
    """
    if not location:
        return True
    try:
        resolved = urljoin(base_url or "", location)
        parsed = urlparse(resolved)
    except (TypeError, ValueError):
        return False
    return (parsed.scheme.lower() in _ALLOWED_SCHEMES
            and bool(parsed.netloc))


def is_crawlable_link(base_url: str, href: str | None) -> bool:
    """One definition for the link extractors of BOTH engines.

    The sync crawler and the async ``_extract_links`` each hand-wrote a
    scheme blacklist, and they drifted: sync skips ``tel:`` / ``data:``,
    async skips neither; neither skips ``vbscript:`` / ``blob:`` / ``file:``
    or case / tab variants.  Both relied on a later ``netloc != origin``
    check as an implicit second line of defence.

    Resolve first, then allowlist -- relative / protocol-relative / query /
    fragment-only links are decided the same way as redirect hops.  Pure
    ``#fragment`` links are excluded explicitly: they never name a new page
    and both engines skipped them before.
    """
    if not href:
        return False
    href = href.strip()
    if not href or href.startswith("#"):
        return False
    return is_safe_redirect(base_url, href)
