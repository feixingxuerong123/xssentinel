"""What kind of document did we just scan?

Layer judgement depends on it.  A JavaScript resource and an HTML page can
contain the same string -- ``location.href =`` -- and mean different things:
in a page it is behaviour the browser will run in this origin, in a bundle it
is one branch of one function that may never execute here at all.  Response
headers are the other half: page-policy claims (Content-Security-Policy,
Trusted Types) are answered by the *document*'s headers, and a ``.js``
response simply does not have them, so "no policy" on a script is guaranteed
to be true and tells nothing.

Measured on OWASP Juice Shop 20.2.0 (docs/OPTIMIZATION.md 1.5): the crawler
legitimately fetches ``/main.js``, ``/scripts.js`` and the Angular chunks, and
every page-shaped static layer fired on them.

Two rules, in this order:

  1. the response's media type, when it says so (a ``.js`` URL that answers
     ``text/html`` is an error page, not a bundle);
  2. otherwise the URL's extension -- the API and the offline paths do not
     always have a header to consult.
"""
from __future__ import annotations

from urllib.parse import urlparse

#: Media types that mean "this document is code, not a page".
SCRIPT_MEDIA_TYPES = frozenset({
    "application/javascript",
    "application/x-javascript",
    "application/ecmascript",
    "application/x-ecmascript",
    "text/javascript",
    "text/ecmascript",
    "text/jscript",
    "text/livescript",
})

#: ... and the extensions we trust when no header spoke up.
SCRIPT_SUFFIXES = (".js", ".mjs", ".cjs")

#: Media types where a reflected value is DATA, not a rendering context.
#: HTML markup in these cannot execute in a browser tab.  Script (JS) and
#: XML media types are deliberately absent: a JSONP callback is code the
#: browser executes, and an XML document is rendered by the XML parser
#: (XSSMaze `callback-level1` and `ctype-level1` are real positives that
#: are only reachable through those two media types).
DATA_ONLY_MEDIA_TYPES = frozenset({
    "application/json", "text/json", "text/plain",
})


def is_data_only_media_type(content_type: str) -> bool:
    """True for media types that carry data only (JSON, plain text)."""
    media = (content_type or "").split(";")[0].strip().lower()
    if not media:
        return False
    return media in DATA_ONLY_MEDIA_TYPES or media.endswith("+json")


def is_script_document(url: str, content_type: str = "") -> bool:
    """True when the scanned document is a JavaScript resource.

    ``content_type`` wins when it names a media type: ``text/html`` on a
    ``.js`` URL (an error page, a WAF interstitial) is a page, and
    ``application/javascript`` on a path-less route is still a script.
    """
    media = (content_type or "").split(";")[0].strip().lower()
    if media in SCRIPT_MEDIA_TYPES:
        return True
    if media:
        return False
    try:
        path = (urlparse(url).path or "").lower()
    except ValueError:
        return False
    return path.endswith(SCRIPT_SUFFIXES)
