"""ONE definition of "split a target URL into a query-free base + params".

Why this exists (Phase 365)
---------------------------
An external CLI-agent e2e found that ``xssentinel_profile`` reported
``reflected: false`` for a URL that ``xssentinel_scan`` reported as a high
reflected XSS. Root cause: the tool passed a query-bearing ``url`` straight to
``requester.request("GET", url, params={param: probe})``. ``requests`` APPENDS
to an existing query, producing ``?q=hello&q=<probe>``; servers that read the
FIRST same-named parameter never see the injected value. Because
``SKILL.md`` tells agents to use profile as a cheap gate before scanning, that
false negative silently skipped whole scans.

The same hand-rolled shape existed in ``xssentinel_verify`` and
``core/llm_propose.propose_and_verify`` (including their headless replay
paths), while ``xssentinel_scan`` had a correct but separately hand-written
version -- the "same contract written twice" family once more.

Rule
----
Whenever a GET parameter is injected into a caller-supplied URL, call
:func:`split_target_url` first, then pass the query-free base URL with a
params dict in which the target key is REPLACED (not appended). POST keeps its
query untouched: the body is a separate channel, so no collision is possible.

Fragment is deliberately dropped: it never reaches the server, and SPA hash
routes are a crawler concern, not an injection-point concern.
"""
from __future__ import annotations

from urllib.parse import urlparse

__all__ = ["split_target_url"]


def split_target_url(url: str) -> tuple[str, dict]:
    """Return ``(base_url, params)`` for a caller-supplied target URL.

    ``base_url`` has query and fragment removed. Query values are kept as raw
    (still-encoded) strings and NOT decoded -- this is exactly what
    ``xssentinel_scan`` has always fed the engine, and ``requests`` re-encodes
    them on the way out. Repeated keys keep the FIRST value, matching the
    server-side ``parse_qs(...)[0]`` behaviour that exposed the bug. Callers
    are expected to have validated ``scheme`` / ``netloc`` already.
    """
    parsed = urlparse(url or "")
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params: dict = {}
    for pair in (parsed.query or "").split("&"):
        if "=" in pair:
            key, value = pair.split("=", 1)
            params.setdefault(key, value)
    return base_url, params
