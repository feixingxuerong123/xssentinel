"""JavaScript endpoint miner.

Extracts API endpoints, URL routes, and sink references from JavaScript
source files linked by the target page.  Many modern SPAs expose sensitive
endpoints only inside JS bundles -- the miner surfaces these so the
scanner can probe them automatically.

Extraction heuristics:
  * fetch('url') / axios.get('url') / $.ajax({url:'...'}) / XHR.open('GET','url')
  * Absolute or relative URLs in string literals (regex)
  * Vue/Angular route definitions (path: '/users')
  * window.location assignments
  * postMessage / addEventListener('message') sinks
  * Common dangerous sinks (eval, Function, innerHTML, etc.)
"""
from __future__ import annotations
import re
from urllib.parse import urljoin, urlparse

# Regex patterns for endpoint extraction.  Each entry: (pattern, group, kind)
EXTRACTORS: list[tuple[str, int, str]] = [
    # fetch('url'), fetch("url"), fetch(`url`)
    (r'''fetch\s*\(\s*['"`]([^'"`]+?)['"`]''', 1, "fetch"),
    # axios.get/post/put/delete('url')
    (r'''axios\.\w+\s*\(\s*['"`]([^'"`]+?)['"`]''', 1, "axios"),
    # $.ajax({url:'...'})
    (r'''\$\.\w+\s*\(\s*['"`]([^'"`]+?)['"`]''', 1, "jquery"),
    # XMLHttpRequest.open('METHOD','url', ...)
    (r'''\.open\s*\(\s*['"`](?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['"`]\s*,\s*['"`]([^'"`]+?)['"`]''',
     1, "xhr"),
    # Vue Router / Angular route: path: '/users'
    (r'''path\s*:\s*['"`]([^'"`]+?)['"`]''', 1, "route"),
    # location.assign('url') / location.href = 'url'
    (r'''location(?:\.\w+)?\s*(?:=|\()\s*['"`]([^'"`]+?)['"`]''', 1, "location"),
    # window.open('url')
    (r'''window\.open\s*\(\s*['"`]([^'"`]+?)['"`]''', 1, "window_open"),
]

# Sinks that, if present in JS, indicate the page renders user input
# dangerously -> XSS candidates.
DANGEROUS_SINKS = [
    ("innerHTML", "Element.innerHTML assignment"),
    ("outerHTML", "Element.outerHTML assignment"),
    ("insertAdjacentHTML", "Element.insertAdjacentHTML"),
    ("document.write", "document.write"),
    ("document.writeln", "document.writeln"),
    ("Range.createContextualFragment", "Range.createContextualFragment"),
    ("DOMParser", "DOMParser.parseFromString"),
    ("eval(", "eval()"),
    ("Function(", "new Function()"),
    ("setTimeout(", "setTimeout with string"),
    ("setInterval(", "setInterval with string"),
    ("jQuery.parseHTML", "jQuery.parseHTML"),
    ("$.parseHTML", "$.parseHTML"),
    (".html(", "jQuery .html()"),
    ("postMessage", "window.postMessage"),
    ("addEventListener('message'", "message event listener (postMessage sink)"),
    ('addEventListener("message"', "message event listener (postMessage sink)"),
]

# Match <script src="..."> tags to find external JS files.
SCRIPT_SRC_RE = re.compile(
    r'''<script[^>]+src\s*=\s*['"]([^'"]+)['"]''',
    re.IGNORECASE,
)

# Match inline <script>...</script> blocks.
INLINE_SCRIPT_RE = re.compile(
    r'<script(?![^>]+src=)[^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)


def extract_endpoints(js_source: str) -> list[tuple[str, str]]:
    """Extract endpoint URLs from a JS source string.

    Returns [(url, source_kind), ...] deduplicated.
    """
    if not js_source:
        return []
    seen = set()
    out = []
    for pattern, group, kind in EXTRACTORS:
        for m in re.finditer(pattern, js_source, re.IGNORECASE):
            url = m.group(group).strip()
            # Filter data:, blob:, javascript: URIs and obvious false positives.
            if not url or url.startswith(("data:", "blob:", "javascript:",
                                          "mailto:", "tel:", "#")):
                continue
            if len(url) < 2 or len(url) > 500:
                continue
            key = (url, kind)
            if key in seen:
                continue
            seen.add(key)
            out.append((url, kind))
    return out


#: Cap on client-side routes one page may contribute.  Each one is a browser
#: probe pass, so this is a cost ceiling, not a coverage aspiration.
MAX_HASH_ROUTES = 12

#: ``router.navigate(['/search'], i)`` -- Angular (and the same shape in
#: minified Vue Router) targets a route *path*, not a URL the server has.
#: Whitespace is optional: an un-minified source (plain JS, or the original
#: recovered from a source map -- Phase 189) writes ``navigate( [ '/x' ], q``
#: and a minified-only pattern loses every route on that target.
_NAV_TARGET_RE = re.compile(
    r'''navigate\(\s*\[\s*['"`](/[A-Za-z0-9_\-./:$%{}]+)['"`]''')
#: ``i={queryParams:{q:e}}`` -- the keys of the object the app itself puts on
#: that navigation.  This is where a param NAME comes from without guessing.
_QUERY_PARAMS_RE = re.compile(r'queryParams:\s*\{([^}]{1,120})\}')
_QUERY_KEY_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]{0,24})\s*:')


def spa_query_params(js_source: str) -> dict[str, list[str]]:
    """Map each SPA route target to the query-param names the app uses on it.

    Minified bundles bind the params object to a variable
    (``let i={queryParams:{q:e}}; ... navigate(['/search'],i)``, so the
    pairing is recovered from a window around the navigation call rather than
    from a syntax tree -- there is no parser available for arbitrary
    minified JS here, and the window is what the app's own code puts the
    object next to.

    Returns {} for non-SPA sources.  Measured on OWASP Juice Shop 20.2.0
    (1.2 MB bundle, 45 route paths): 5 routes paired cleanly, including
    ``search -> ['q']`` -- the route whose component binds
    ``[innerHTML]="searchValue"``, i.e. its actual DOM XSS.
    """
    if not js_source:
        return {}
    out: dict[str, list[str]] = {}
    for m in _NAV_TARGET_RE.finditer(js_source):
        route = m.group(1).strip("/")
        if not route or any(c in route for c in ":*{}$%"):
            continue  # needs a real id / wildcard, not a probeable URL
        window = js_source[max(0, m.start() - 320):m.end() + 320]
        names = out.setdefault(route, [])
        for q in _QUERY_PARAMS_RE.finditer(window):
            for k in _QUERY_KEY_RE.findall(q.group(1)):
                if k not in names:
                    names.append(k)
    return {r: n for r, n in out.items() if n}


def hash_route_urls(js_source: str, base_url: str) -> list[str]:
    """Absolute ``origin/#/route?param=x`` URLs for client-side routes.

    Why the fragment: an app using hash location strategy reads its route
    from ``location.hash`` only.  ``urljoin(origin, 'search')`` -- which is
    what ``extract_endpoints``' ``route`` kind produces -- yields
    ``origin/search``, a *server* path the SPA never routes.  The server
    answers it with the same shell it answers everything with, so the
    scanner ends up firing an HTTP probe ladder at a string the client-side
    router cannot see, while the real sink (a query param inside the
    fragment) goes unprobed.

    Measured on OWASP Juice Shop 20.2.0: a root-URL crawl produced 74
    endpoints, **zero** of them carrying a fragment; handed
    ``/#/search?q=apple`` directly the same build reports a
    browser-executed high DOM XSS.  This function is the difference between
    those two measurements.
    """
    if not js_source or not base_url:
        return []
    p = urlparse(base_url)
    if not p.netloc:
        return []
    origin = f"{p.scheme}://{p.netloc}"
    out: list[str] = []
    for route, names in spa_query_params(js_source).items():
        if len(out) >= MAX_HASH_ROUTES:
            break
        q = "&".join(f"{n}=xss" for n in names[:3])
        url = f"{origin}/#/{route}?{q}"
        if url not in out:
            out.append(url)
    return out[:MAX_HASH_ROUTES]


def find_dangerous_sinks(js_source: str) -> list[tuple[str, str]]:
    """Find dangerous sinks in JS source.

    Returns [(sink, description), ...]
    """
    if not js_source:
        return []
    found = []
    for needle, desc in DANGEROUS_SINKS:
        if needle in js_source:
            found.append((needle, desc))
    return found


def extract_script_srcs(html: str) -> list[str]:
    """Extract <script src=...> URLs from an HTML page."""
    if not html:
        return []
    out = []
    for m in SCRIPT_SRC_RE.finditer(html):
        out.append(m.group(1))
    return out


def extract_inline_scripts(html: str) -> list[str]:
    """Extract inline <script> block contents from an HTML page."""
    if not html:
        return []
    return [m.group(1) for m in INLINE_SCRIPT_RE.finditer(html)]


def resolve_urls(urls: list[str], base_url: str) -> list[str]:
    """Resolve relative URLs against a base URL."""
    out = []
    for u in urls:
        try:
            resolved = urljoin(base_url, u)
            # Filter cross-origin URLs (different scheme/host).
            base_host = urlparse(base_url).netloc
            tgt_host = urlparse(resolved).netloc
            if not tgt_host or tgt_host == base_host:
                out.append(resolved)
        except Exception:
            continue
    return out


def mine_html(html: str, base_url: str) -> dict:
    """Full mine of an HTML page: extract endpoints from inline + external JS.

    Returns: {
        "external_scripts": list[str],   # resolved script src URLs
        "inline_endpoints": list[tuple[url, kind]],
        "external_endpoints": list[tuple[url, kind]],  # filled by mine_js_file
        "sinks": list[tuple[sink, desc]],
    }
    """
    inline = extract_inline_scripts(html)
    srcs = extract_script_srcs(html)
    resolved_srcs = resolve_urls(srcs, base_url)

    endpoints = []
    sinks = []
    for block in inline:
        endpoints.extend(extract_endpoints(block))
        sinks.extend(find_dangerous_sinks(block))

    return {
        "external_scripts": resolved_srcs,
        "inline_endpoints": endpoints,
        "external_endpoints": [],   # filled by caller via mine_js_file
        "sinks": sinks,
    }


def mine_js_file(js_source: str) -> dict:
    """Mine a single JS file's source for endpoints and sinks."""
    return {
        "endpoints": extract_endpoints(js_source),
        "sinks": find_dangerous_sinks(js_source),
    }
