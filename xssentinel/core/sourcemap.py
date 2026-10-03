"""Source-map ingestion: read the source the bundle was minified from.

Two payoffs, in the order the target usually cares about them:

1. **Input surface.**  A ``.js.map`` carrying ``sourcesContent`` hands us the
   UN-MINIFIED original files -- routes, API paths and ``innerHTML =`` sinks
   in their real identifier names, before a minifier renamed, split or
   tree-shook them away.  Mining the shipped bundle alone cannot see what the
   bundle no longer contains; this is the same move the AST-extraction tools
   made once source maps became common in CI-built front ends.
2. **Information disclosure.**  Serving maps to production browsers is an
   audit finding on its own (full source, internal paths, comments, and from
   time to time a hardcoded key), so when we can read one back we say so.

Nothing here issues a request: :func:`map_urls` says what is worth fetching
and :func:`analyze_map` judges the body it is handed.  Each engine fetches in
its own idiom (requests in the sync crawler, aiohttp in the async one), which
keeps this module offline-testable and keeps one implementation for both.

``sourcesContent`` is not free: a map without it leaks file names only, so
:func:`disclosure` stays silent -- and the whole point of reading the body
back is to tell those two cases apart, not to flag every ``.map`` URL.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from urllib.parse import urljoin, urlparse

#: ``//# sourceMappingURL=app.js.map`` -- the spec's ``//#`` form plus the
#: legacy ``//@``, as a line comment or inside a block one.  The comment does
#: not have to start the line: minifiers append it after the last statement
#: (``;//# sourceMappingURL=...``), and the spec looks for the pattern anywhere
#: in a LineComment.  A trailing ``*/`` is stripped in :func:`references`.
SOURCE_MAPPING_URL_RE = re.compile(
    r"(?://|/\*)[#@]\s*sourceMappingURL\s*=\s*([^\s'\"]+)",
    re.IGNORECASE,
)

# Maps are big and there are often several per page; both caps exist to keep
# this from turning a depth-0 crawl into a multi-megabyte download spree.
MAX_MAPS_PER_SCRIPT = 2
MAX_MAP_BYTES = 4_000_000
MAX_JOINED_SOURCE_BYTES = 2_000_000


def references(js_text: str) -> list:
    """Every ``sourceMappingURL`` referenced by a script, in order, deduped."""
    out = []
    for m in SOURCE_MAPPING_URL_RE.finditer(js_text or ""):
        ref = m.group(1).strip()
        if ref.endswith("*/"):        # /*# sourceMappingURL=x.map*/ block form
            ref = ref[:-2].rstrip()
        if ref and ref not in out:
            out.append(ref)
    return out


def resolve(ref: str, script_url: str) -> str:
    """Absolute URL for a map reference, or "" when it is not fetchable."""
    if not ref or ref.startswith("data:"):
        return ""
    try:
        absolute = urljoin(script_url or "", ref)
    except (ValueError, TypeError):
        return ""
    if urlparse(absolute).scheme.lower() not in ("http", "https"):
        return ""
    return absolute


def map_urls(script_url: str, js_text: str) -> list:
    """Fetchable map URLs for one script, capped at MAX_MAPS_PER_SCRIPT.

    The LAST reference wins in browsers, but bundles that concatenate several
    files can leave more than one; fetching the first couple catches both
    without letting a page dictate the request count.
    """
    urls = []
    for ref in references(js_text)[:MAX_MAPS_PER_SCRIPT]:
        url = resolve(ref, script_url)
        if url and url not in urls:
            urls.append(url)
    return urls


def inline_map(js_text: str) -> str:
    """Body of a base64/percent-encoded ``data:`` map, or "" when not inline.

    Webpack's ``devtool: inline-source-map`` and Rollup's ``inline: true``
    both ship the whole map inside the script, so this needs no request -- and
    no exposed .map URL to report either.
    """
    for ref in references(js_text):
        if not ref.startswith("data:"):
            continue
        _, _, payload = ref.partition(",")
        if ";base64" in ref.split(",", 1)[0].lower():
            try:
                return base64.b64decode(payload).decode("utf-8", "replace")
            except (binascii.Error, ValueError):
                return ""
        from urllib.parse import unquote
        return unquote(payload)
    return ""


def analyze_map(text: str) -> dict:
    """Judge a fetched map body.

    Returns ``{"ok", "js", "sources", "has_content", "reason"}``.  ``js`` is
    the recovered original sources joined for mining; ``has_content`` is the
    disclosure condition -- a map with only ``sources`` (file names) and no
    ``sourcesContent`` leaks names, not code, so it is not reported as source
    exposure.
    """
    empty = {"ok": False, "js": "", "sources": 0, "has_content": False,
             "reason": "empty"}
    if not text:
        return dict(empty)
    if len(text) > MAX_MAP_BYTES:
        return dict(empty, reason=f"map larger than {MAX_MAP_BYTES} bytes")
    try:
        doc = json.loads(text)
    except (ValueError, TypeError):
        return dict(empty, reason="not JSON")
    if not isinstance(doc, dict):
        return dict(empty, reason="map is not an object")
    contents = [s for s in (doc.get("sourcesContent") or []) if isinstance(s, str)]
    sources = doc.get("sources") or []
    if not contents:
        return {"ok": True, "js": "", "sources": len(sources),
                "has_content": False, "reason": "no sourcesContent"}
    joined = "\n;\n".join(contents)[:MAX_JOINED_SOURCE_BYTES]
    return {"ok": True, "js": joined, "sources": len(sources) or len(contents),
            "has_content": True, "reason": ""}


def disclosure(map_url: str, result: dict, page_url: str = "",
               method: str = "GET") -> dict | None:
    """Finding fields for a readable map, or None when there is nothing to say.

    The dict is the COMPLETE keyword set for one Finding -- `page_url` and
    `method` included -- so every emit site is a plain
    ``Finding(**fields)``.  That shape is deliberate:
    ``tests/test_evidence_coverage.py`` audits findings statically, and a site
    that bolts its own kwargs onto ``**fields`` hides the evidence tier from
    that audit even when the helper states it correctly.  The tier stays
    declared exactly once, here.
    """
    if not result.get("has_content"):
        return None
    from .findings import EVIDENCE_NO_BROWSER

    return {
        "url": page_url,
        "method": method,
        "type": "source_map_exposed",
        "severity": "low",
        "context": "script_source",
        "param": "",
        "payload": "",
        # Not a browser-execution claim: this was measured by fetching and
        # parsing the map, so it is as firm as an HTTP response can be.
        "evidence_class": EVIDENCE_NO_BROWSER,
        "confidence": "firm",
        "evidence": map_url,
        "detail": (f"production source map reachable at {map_url}; it carries "
                   f"{result.get('sources', 0)} original file(s) in "
                   f"sourcesContent, so the un-minified front-end source "
                   f"(paths, comments, internal APIs) is public"),
    }
