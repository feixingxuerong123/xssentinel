"""Stored-XSS write/view discovery (Phase 352).

Kept out of ``scanner_stored.py`` on purpose: the stored Mixin has a pinned
line budget (``tests/test_architecture_scale.py``), and the pure discovery
functions here are independently testable.  Nothing in this module issues a
request -- callers own the requester and the budget.

The explicit ``--stored-inject`` path needs an operator to name the viewer
page.  On a URL-only target (the official XSSMaze runner, a handed-over scope
list, a crawled page) stored detection used to be structurally unreachable.
The helpers here discover the page's own POST forms, injectable text fields,
and candidate viewers: the write page itself, same-origin viewer-shaped links,
and a JSON API the page's own JS fetches into an XSS sink.
"""
from __future__ import annotations

import hashlib
import os
import re
from urllib.parse import urljoin, urlparse

from . import form_miner

# Seven raw shapes: element / attribute / RCDATA / no-JS element.  A stored
# sink is a rendering context, not a WAF puzzle; the identity transform ladder
# keeps the cost at one POST + one GET per view per shape.
STORED_AUTO_BASES = (
    {"context": "html_element", "confidence": "high",
     "payload": "<img src=x onerror=alert(1)>",
     "tags": ["stored_auto"], "note": "element body -> img onerror"},
    {"context": "html_element", "confidence": "high",
     "payload": "<svg onload=alert(1)>",
     "tags": ["stored_auto"], "note": "element body -> svg onload"},
    {"context": "html_element", "confidence": "high",
     "payload": "<script>alert(1)</script>",
     "tags": ["stored_auto"], "note": "server-rendered document body"},
    {"context": "html_attribute_dq", "confidence": "high",
     "payload": "\"><img src=x onerror=alert(1)>",
     "tags": ["stored_auto"], "note": "double-quoted attribute breakout"},
    {"context": "html_attribute_dq", "confidence": "high",
     "payload": "\" onmouseover=\"alert(1)",
     "tags": ["stored_auto"], "note": "attribute value stays quoted"},
    {"context": "html_element", "confidence": "medium",
     "payload": "</title><img src=x onerror=alert(1)>",
     "tags": ["stored_auto"], "note": "RCDATA title breakout"},
    {"context": "html_element", "confidence": "medium",
     "payload": "<details open ontoggle=alert(1)>",
     "tags": ["stored_auto"], "note": "no-JS-required element"},
)

_AUTO_TEXT_TYPES = frozenset({"text", "search", "email", "url", "tel",
                              "textarea", "number", "range"})
_AUTO_FIELD_PREF = re.compile(
    r"title|body|msg|message|comment|bio|subject|note|review|query|content|"
    r"text|description|about|feedback|post|entry|name|q$|^q$", re.I)
_AUTO_SKIP_FIELD = re.compile(
    r"csrf|xsrf|token|captcha|nonce|password|passwd|pass$|submit|button|"
    r"checkbox|radio|hidden|file|otp|authenticity|_wpnonce", re.I)
_AUTO_SKIP_FORM = re.compile(r"login|signin|sign-in|logout|register|auth", re.I)

_VIEW_LINK_WORDS = re.compile(
    r"view|list|search|profile|detail|comment|guestbook|feed|post|thread|"
    r"ticket|review|admin|account|user|blog|show|display|result|wall|chat|"
    r"entries|messages", re.I)
_JS_SINK_RE = re.compile(
    r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|"
    r"dangerouslySetInnerHTML|v-html|\.html\s*\(", re.I)
_API_REF_RE = re.compile(r"""['"]([^'"\s]{1,300}?(?:/api|/rest)(?:/[^'"\s]*)?)['"]""",
                         re.I)
_HTML_TAG_RE = re.compile(r"<a\b[^>]*\bhref\s*=\s*(['\"])(.*?)\1", re.I | re.S)


def same_origin(url: str, base: str) -> bool:
    a, b = urlparse(url), urlparse(base)
    return (a.scheme in ("http", "https") and b.scheme in ("http", "https")
            and a.netloc.lower() == b.netloc.lower())


def _benign_value(field: dict) -> str:
    return str(field.get("value") or "") or "xssentinel_test"


def discover_write_faces(html: str, page_url: str,
                         max_forms: int = 2, max_fields: int = 2) -> list[dict]:
    """Extract POST forms that can carry a stored payload.

    Returns ``[{action, method, fields, data}]``: ``fields`` are the text
    fields worth injecting (priority names first) and ``data`` is every OTHER
    form field filled with its server value or a benign placeholder, so a
    CSRF token / required companion field still rides along.

    Login forms are skipped: they have a password field or a login-shaped
    action, and injecting them probes credential handling, not storage.
    """
    out: list[dict] = []
    for form in form_miner.extract_forms(html, page_url):
        if (form.get("method") or "GET").upper() != "POST":
            continue
        action = form.get("action") or page_url
        if not same_origin(action, page_url):
            continue
        fields = form.get("fields") or []
        names = [str(f.get("name") or "") for f in fields]
        if not names:
            continue
        if any((f.get("type") or "").lower() == "password" for f in fields):
            continue
        if _AUTO_SKIP_FORM.search(urlparse(action).path or ""):
            continue
        candidates = [
            f for f in fields
            if (f.get("type") or "text").lower() in _AUTO_TEXT_TYPES
            and not _AUTO_SKIP_FIELD.search(str(f.get("name") or ""))
        ]
        if not candidates:
            continue
        # Priority names first; stable so a form with body+title injects both
        # only when max_fields allows it.
        candidates.sort(key=lambda f: 0 if _AUTO_FIELD_PREF.search(
            str(f.get("name") or "")) else 1)
        chosen = candidates[:max_fields]
        chosen_names = {str(c.get("name")) for c in chosen}
        data = {}
        for f in fields:
            name = str(f.get("name") or "")
            if name and name not in chosen_names:
                data[name] = _benign_value(f)
        out.append({
            "action": action,
            "method": "POST",
            "fields": [str(c.get("name")) for c in chosen],
            "data": data,
        })
        if len(out) >= max_forms:
            break
    return out


def discover_view_urls(html: str, page_url: str, action_url: str
                       ) -> tuple[list[str], set[str]]:
    """Candidate viewer URLs for a stored write, plus the JSON-API subset.

    Order matters: the write page itself first (the POST response often
    re-renders the list), then same-origin links whose path reads like a
    viewer, then API endpoints the page's own JS fetches *and* inserts into an
    XSS sink.  A bare JSON endpoint is NOT a viewer: JSON has no HTML
    execution context, so the API subset is returned separately and the
    caller only accepts it when its content-type is JSON and the page
    contains sink evidence (the XSSMaze stored-level4 shape).
    """
    views = [action_url]
    if page_url and page_url != action_url:
        views.append(page_url)
    for _q, href in _HTML_TAG_RE.findall(html or ""):
        href = (href or "").strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            continue
        full = urljoin(page_url, href)
        if not same_origin(full, page_url):
            continue
        if not _VIEW_LINK_WORDS.search(urlparse(full).path or ""):
            continue
        if full not in views:
            views.append(full)
        if len(views) >= 9:
            break
    api_views: set[str] = set()
    if _JS_SINK_RE.search(html or ""):
        for ref in _API_REF_RE.findall(html or ""):
            ref = ref.strip()
            if not ref:
                continue
            full = urljoin(page_url, ref).split("#", 1)[0]
            if not same_origin(full, page_url):
                continue
            api_views.add(full)
            if full not in views and len(views) < 9:
                views.append(full)
    return views, api_views


_ASYNC_VIEW_RE = re.compile(
    r"fetch\s*\(|XMLHttpRequest|setTimeout|setInterval|\bPromise\b|"
    r"\.then\s*\(|\basync\b|\bawait\b|addEventListener", re.I)


def view_poll_delays(html: str) -> tuple:
    """Retry delays after a changed viewer response.

    A server-rendered list is synchronous: one short re-read catches the
    write, and the old 0.4s+1.0s pair just waited.  Only a viewer with its
    own async code needs the longer ladder.
    """
    if (os.environ.get("XSS_BUDGET_V2", "1") != "0"
            and html and not _ASYNC_VIEW_RE.search(html)):
        return (0.15,)
    return (0.4, 1.0)


def resp_fingerprint(resp) -> tuple:
    """(status, ETag, Last-Modified, sha1(body)) -- the change detector."""
    headers = dict(getattr(resp, "headers", {}) or {})
    body = getattr(resp, "text", "") or ""
    return (getattr(resp, "status_code", None),
            str(headers.get("ETag") or headers.get("etag") or ""),
            str(headers.get("Last-Modified") or headers.get("last-modified") or ""),
            hashlib.sha1(body.encode("utf-8", "replace")).hexdigest())
